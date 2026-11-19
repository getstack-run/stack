// The data trail follows the data.
//
// The data-flow rule (lib/scope-wall.ts) refuses a call that carries content
// read from a service the destination's scope does not list in
// allow_data_from. That only works if the record of "what was read" goes
// wherever the content goes. This module carries it across the three hops
// that used to drop it:
//
//   1. A Passport change. Observations are read by Mission, so refresh,
//      delegation and a second root Passport on the same Mission keep them.
//      Only the last DATA_TRAIL_WINDOW_SECONDS count, so an agent account's
//      standing Mission, which is extended in place and never replaced, does
//      not carry every source it ever read.
//   2. A hand-off between agents (drop-off, A2A). At deposit the payload is
//      matched against the depositor's Mission observations and the ORIGINAL
//      sources are stored on the drop-off. At collection the collector's
//      Mission records those items as read from those sources.
//   3. An LLM call. A response is attributed to the sources its prompt
//      carried, so a summary that copies the figures is still bank data.
//
// Never recorded anywhere here: the content itself. Security events carry
// sources, stage and match method only.
//
// REFUSING FOLLOWS THE CONTROLS, FOR AN ACCOUNT'S AGENT. The trail is always
// kept and a disallowed flow is always recorded, but an agent that belongs to
// an agent account has it refused only when its owner's controls are on
// (the entitlements' controlsEnabled, through trailPosture). With controls
// off a failure to follow or record the trail raises a warning that never
// blocks the agent, and the call goes through: the account has zero limits
// unless its owner switched controls on. An agent outside an account is
// unchanged: a disallowed flow is always refused, and a rule or trail that
// cannot be evaluated fails closed in enforced mode only, whatever its
// owner's controls say (trailPosture).

import {
  attributePayload,
  type ControlActionType,
  collectStrings,
  contentFingerprints,
  extractEntities,
  indexObserved,
  inheritedObservations,
  isFinancialProvider,
  parseFlowSource,
  ServiceUnavailableError,
  safeErrorSummary,
  type DropoffProvenance,
  type ObservedItem,
} from '@stack/shared';
import type { Services } from '../config/services.js';

export type ObservedRows = Awaited<
  ReturnType<NonNullable<Services['passportClaimsRepo']>['findObservedContentForFlow']>
>;

/** What the provenance of a hand-off needs of the services: the trail, the claim registry, the posture and the alarm. */
export type ProvenanceServices = Pick<
  Services,
  'passportClaimsRepo' | 'claimRegistry' | 'securityEvent' | 'accountDetection' | 'entitlements' | 'controlPosture'
>;

/** The accountability mode of the Passport a call runs under. */
export type TrailMode = 'enforced' | 'logged' | 'standard' | undefined;

/**
 * Whether a call fails closed when the data-flow rule cannot be evaluated
 * (or, for the LLM gateway, when a response's provenance cannot be recorded),
 * for an account whose controls are on. Writes and sends (every non-GET
 * method) always do; reads do in enforced mode only. A GET in
 * logged/standard mode fails open with an alarm. With controls off nothing
 * fails closed, whatever this returns: `trailPosture` combines them.
 */
export function dataFlowFailsClosed(mode: TrailMode, method: string): boolean {
  return mode === 'enforced' || method.toUpperCase() !== 'GET';
}

/** What a disallowed flow, and a trail that cannot be followed, mean for one agent. */
export interface TrailPosture {
  /**
   * A flow the rule disallows is refused. False only for an account's agent
   * whose owner's controls are off: it is recorded as a warning that never
   * blocks the agent.
   */
  refuses: boolean;
  /** Whether a rule or trail that cannot be evaluated fails closed for a call with this HTTP method. */
  failsClosed(method: string): boolean;
}

const STRICT_POSTURE: TrailPosture = { refuses: true, failsClosed: () => true };

/**
 * The data trail's posture for an agent's call.
 *
 * An agent that belongs to an agent account follows its owner's controls: on,
 * a disallowed flow is refused and a failure to follow the trail fails closed
 * for writes (and for reads in enforced mode); off, nothing is refused and
 * nothing fails closed. An agent outside an account keeps the behaviour it
 * always had, keyed on its Passport's accountability mode: a disallowed flow
 * is always refused, and a failure fails closed in enforced mode only. When
 * the agent or its owner's controls cannot be read the posture is strict, so
 * an unreadable account is never quietly let through.
 */
export async function trailPosture(
  services: {
    accountDetection: Pick<Services['accountDetection'], 'forAgent'>;
    entitlements: Pick<Services['entitlements'], 'controlsEnabled'>;
    controlPosture?: Pick<Services['controlPosture'], 'hostedApplies'>;
  },
  input: { operatorId: string; agentId: string; mode: TrailMode; action?: ControlActionType | null },
): Promise<TrailPosture> {
  let belongsToAccount: boolean;
  try {
    belongsToAccount = (await services.accountDetection.forAgent(input.operatorId, input.agentId)) !== null;
  } catch {
    return STRICT_POSTURE;
  }
  if (!belongsToAccount) return { refuses: true, failsClosed: () => input.mode === 'enforced' };
  const controls = await dataTrailRefuses(services, input.operatorId, input.action ?? null);
  return { refuses: controls, failsClosed: (method) => controls && dataFlowFailsClosed(input.mode, method) };
}

/**
 * Whether an agent account's owner has controls on, so the data trail refuses
 * for the account's agent. Fails closed: when the controls status cannot be
 * read the answer is yes, so an unreadable account is never quietly let
 * through. Only for a surface that is the account's own (its mail and texts);
 * a call an agent makes asks `trailPosture`.
 */
export async function dataTrailRefuses(
  services: {
    entitlements: Pick<Services['entitlements'], 'controlsEnabled'>;
    controlPosture?: Pick<Services['controlPosture'], 'hostedApplies'>;
  },
  operatorId: string,
  action: ControlActionType | null = null,
): Promise<boolean> {
  try {
    // The data-flow rule is one of STACK's hosted checks: it refuses for a kind
    // of action the customer chose to check, and only while their controls are on.
    return services.controlPosture
      ? await services.controlPosture.hostedApplies(operatorId, action)
      : await services.entitlements.controlsEnabled(operatorId);
  } catch {
    return true;
  }
}

/** The one Mission an action runs under, or null to fall back to the Passport's own record. */
export function flowMissionId(missionIds: readonly string[] | null | undefined): string | null {
  return missionIds && missionIds.length === 1 ? missionIds[0]! : null;
}

/** What this Mission (or, without one, this Passport) has read, for the data-flow rule. */
export function readObservedRows(
  services: Pick<Services, 'passportClaimsRepo'>,
  input: { operatorId: string; passportJti: string; missionId: string | null },
): Promise<ObservedRows> {
  return services.passportClaimsRepo.findObservedContentForFlow({
    operatorId: input.operatorId,
    passportId: input.passportJti,
    missionId: input.missionId,
  });
}

/**
 * Rows to items. An observation recorded before source_service existed has
 * no known origin and is skipped rather than guessed: treating unknown
 * provenance as "from anywhere" would deny ordinary traffic.
 *
 * What the agent itself SENT to the service (the entities its observation
 * lists as `request_entities`: the request's own host, path and query) is not
 * content read from it, so it is not an item. What the service returned is,
 * and so is an entity that appears in both (the service echoed it back), which
 * the observation does not list as the request's own. A row recorded before
 * `request_entities` lists none, and all of its entities count as read.
 */
export function observedItemsFromRows(rows: ObservedRows): ObservedItem[] {
  const observed: ObservedItem[] = [];
  for (const row of rows) {
    if (!row.sourceService) continue;
    const sent = new Set((row.requestEntities ?? []).map((e) => String(e).toLowerCase()));
    for (const e of row.entities ?? []) {
      if (sent.has(String(e).toLowerCase())) continue;
      observed.push({ value: String(e), kind: 'entity', service: row.sourceService });
    }
    for (const f of row.fingerprints ?? []) observed.push({ value: String(f), kind: 'shingle', service: row.sourceService });
  }
  return observed;
}

/**
 * At deposit: where the hand-off's content came from.
 *
 * For an account's agent with controls on it fails CLOSED, in every
 * accountability mode; for an agent outside an account, in enforced mode. A
 * deposit whose provenance cannot be established is then refused with a
 * retryable 503 and an alarm. The depositor still holds the payload, nothing
 * is lost, and the alternative is a hand-off that silently launders bank data
 * into an untracked agent. Otherwise the deposit goes through with no sources
 * recorded, and the alarm does not block an account's agent when its controls
 * are off.
 */
export async function computeDepositProvenance(
  services: ProvenanceServices,
  input: {
    operatorId: string;
    agentId: string;
    passportJti: string | null;
    missionId: string | null;
    payload: unknown;
    /** What the content is deposited by: the engine's are `dropoff` and `a2a`; a deployment names its own. */
    producer: string;
    /** The Passport's accountability mode, for an agent outside an account. */
    mode?: TrailMode;
    /** The kind of action the content is deposited under: a drop-off's deposit unless it says otherwise. */
    action?: ControlActionType;
    /** What is refused when the posture fails closed and the provenance cannot be recorded. */
    refusal?: string;
  },
): Promise<DropoffProvenance> {
  if (!input.passportJti || !input.missionId) {
    return attributePayload({ payload: input.payload, missionId: null, observed: [] });
  }
  try {
    const rows = await readObservedRows(services, {
      operatorId: input.operatorId,
      passportJti: input.passportJti,
      missionId: input.missionId,
    });
    return attributePayload({
      payload: input.payload,
      missionId: input.missionId,
      observed: indexObserved(observedItemsFromRows(rows)),
    });
  } catch (err) {
    const posture = await trailPosture(services, { operatorId: input.operatorId, agentId: input.agentId, mode: input.mode, action: input.action ?? 'dropoff.deposit' });
    const failClosed = posture.failsClosed('POST');
    await raiseProvenanceAlarm(services, {
      operatorId: input.operatorId,
      agentId: input.agentId,
      passportJti: input.passportJti,
      missionId: input.missionId,
      stage: `${input.producer}_deposit`,
      err,
      failed: failClosed ? 'closed' : 'open',
      refuses: posture.refuses,
    });
    if (!failClosed) return attributePayload({ payload: input.payload, missionId: null, observed: [] });
    throw new ServiceUnavailableError(
      input.refusal ?? 'Could not record where this hand-off\'s content came from, so it was not deposited. Retry shortly.',
    );
  }
}

/**
 * At collection: record the hand-off's items on the collector's Mission as
 * read from their ORIGINAL sources. Runs inside the collect transaction,
 * before custody transfers, so where the posture fails closed (controls on for
 * an account's agent, enforced mode outside an account) a failure rolls the
 * collection back (the payload stays deposited and the call can be retried)
 * rather than handing over content with no record. Otherwise the failure is an
 * alarm and the collection completes. Idempotent per drop-off
 * and source.
 *
 * Returns the sources recorded.
 */
export async function recordCollectedProvenance(
  services: ProvenanceServices,
  input: {
    operatorId: string;
    collectorAgentId: string;
    passportJti: string;
    missionId: string;
    dropoffId: string;
    fromAgentId: string;
    payload: unknown;
    provenance: unknown;
    /** The Passport's accountability mode, for an agent outside an account. */
    mode?: TrailMode;
  },
): Promise<string[]> {
  return recordCarriedProvenance(services, {
    operatorId: input.operatorId,
    collectorAgentId: input.collectorAgentId,
    passportJti: input.passportJti,
    missionId: input.missionId,
    payload: input.payload,
    provenance: input.provenance,
    mode: input.mode,
    operationKey: `dropoff:${input.dropoffId}`,
    stage: 'dropoff_collect',
    action: 'dropoff.deposit',
    metadata: { source: 'dropoff_collect', dropoff_id: input.dropoffId, from_agent: input.fromAgentId },
  });
}

/**
 * The one way carried content joins a reader's Mission: the items of `payload`
 * the carrier's provenance names are recorded as read from their ORIGINAL
 * sources. A drop-off's collect and an agent's read of a drive file both come
 * through here. `operationKey` makes the record idempotent per carrier and
 * source for a hand-off a retry can repeat (a drop-off's collect). An agent's read of a drive file or of memory gives a
 * fresh key each time (a durable claim's identity includes its signed content, so a repeated key would conflict), and
 * a second read by the same Mission records its own claim.
 */
export async function recordCarriedProvenance(
  services: ProvenanceServices,
  input: {
    operatorId: string;
    collectorAgentId: string;
    passportJti: string;
    missionId: string;
    payload: unknown;
    provenance: unknown;
    /** The Passport's accountability mode, for an agent outside an account. */
    mode?: TrailMode;
    /** What identifies this carrier, for this reader: unique per hand-off, and per Mission for a file read again and again. */
    operationKey: string;
    stage: string;
    /** The kind of action the carried content entered under (the posture is the customer's per-kind choice). */
    action: ControlActionType | null;
    /** What the claim says about the carrier: never content. */
    metadata: Record<string, unknown>;
  },
): Promise<string[]> {
  const inherited = inheritedObservations(input.payload, input.provenance);
  const perSourceIndex = new Map<string, number>();
  try {
    for (const observation of inherited) {
      const index = perSourceIndex.get(observation.source) ?? 0;
      perSourceIndex.set(observation.source, index + 1);
      await services.claimRegistry.registerClaim({
        operatorId: input.operatorId,
        passportJti: input.passportJti,
        claimType: 'entity_observation',
        sourceOperationId: input.operationKey,
        sourceRole: `provenance:${observation.source}:${index}`,
        payload: {
          type: 'entity_observation',
          entities: observation.entities,
          entity_types: observation.entity_types,
          agent_id: input.collectorAgentId,
          source_service: observation.source,
          content_fingerprints: observation.fingerprints,
          metadata: { extraction_method: 'provenance', ...input.metadata },
          observed_at: Date.now(),
          mission_ref: input.missionId,
        },
      });
    }
  } catch (err) {
    const posture = await trailPosture(services, { operatorId: input.operatorId, agentId: input.collectorAgentId, mode: input.mode, action: input.action });
    const failClosed = posture.failsClosed('POST');
    await raiseProvenanceAlarm(services, {
      operatorId: input.operatorId,
      agentId: input.collectorAgentId,
      passportJti: input.passportJti,
      missionId: input.missionId,
      stage: input.stage,
      err,
      failed: failClosed ? 'closed' : 'open',
      refuses: posture.refuses,
    });
    if (failClosed) throw err;
  }
  return [...perSourceIndex.keys()].sort();
}

/** Text of an LLM response the agent will read: the assistant content, not envelope ids. */
export function llmResponseText(body: unknown): string {
  if (!body || typeof body !== 'object') return typeof body === 'string' ? body : '';
  const record = body as Record<string, unknown>;
  const parts: string[] = [];
  if (Array.isArray(record['content'])) {
    for (const block of record['content'] as unknown[]) {
      if (block && typeof block === 'object' && typeof (block as Record<string, unknown>)['text'] === 'string') {
        parts.push((block as Record<string, string>)['text']!);
      }
    }
  }
  if (Array.isArray(record['choices'])) {
    for (const choice of record['choices'] as unknown[]) {
      const message = choice && typeof choice === 'object' ? (choice as Record<string, unknown>)['message'] : null;
      const content = message && typeof message === 'object' ? (message as Record<string, unknown>)['content'] : null;
      if (typeof content === 'string') parts.push(content);
      else if (Array.isArray(content)) parts.push(...collectStrings(content));
    }
  }
  return parts.length > 0 ? parts.join('\n') : collectStrings(body).join(' ');
}

/**
 * An LLM response inherits the sources its prompt carried. A summary that
 * copies the bank's figures, or retells them in prose built from the prompt,
 * is recorded as read from the bank, so posting it where bank data may not
 * go is refused like the bank response itself.
 *
 * Money and account numbers are recognised in the response when any carried
 * source is a financial provider.
 */
export async function recordInheritedResponse(
  services: Services,
  input: {
    operatorId: string;
    agentId: string;
    passportJti: string;
    missionId: string;
    sources: readonly string[];
    text: string;
    provider: string;
  },
): Promise<void> {
  if (input.sources.length === 0 || !input.text) return;
  // A source is a label (`service@connection`); whether it is a bank is a fact about the service.
  const financial = input.sources.some((source) => isFinancialProvider(parseFlowSource(source).service));
  const entities = extractEntities({ text: input.text }, { financial });
  const fingerprints = contentFingerprints(input.text);
  if (entities.length === 0 && fingerprints.length === 0) return;
  for (const source of input.sources) {
    await services.claimRegistry.registerClaim({
      operatorId: input.operatorId,
      passportJti: input.passportJti,
      claimType: 'entity_observation',
      payload: {
        type: 'entity_observation',
        entities: entities.map((e) => e.entity),
        entity_types: entities.map((e) => e.entity_type),
        agent_id: input.agentId,
        source_service: source,
        content_fingerprints: fingerprints,
        metadata: {
          extraction_method: 'inherited',
          source: 'llm_response',
          provider: input.provider,
        },
        observed_at: Date.now(),
        mission_ref: input.missionId,
      },
    });
  }
}

/** A critical alarm that provenance could not be established or recorded. Never carries content. */
export async function raiseProvenanceAlarm(
  services: Pick<Services, 'securityEvent'>,
  input: {
    operatorId: string;
    agentId: string;
    passportJti: string;
    missionId: string | null;
    stage: string;
    err: unknown;
    failed?: 'open' | 'closed';
    /**
     * Whether the posture refuses (trailPosture). An account's agent with
     * controls off: a warning, and the agent is never auto-blocked by it.
     * Otherwise critical.
     */
    refuses: boolean;
  },
): Promise<void> {
  await services.securityEvent
    .record({
      operatorId: input.operatorId,
      agentId: input.agentId,
      passportJti: input.passportJti,
      signalType: 'credential_outside_scope',
      severity: input.refuses ? 'critical' : 'warning',
      ...(input.refuses ? {} : { skipAgentAutoBlock: true }),
      message: `Where content came from could not be recorded (${input.stage}); the data-flow rule could not follow it`,
      metadata: {
        provenance_unavailable: true,
        stage: input.stage,
        error: input.err instanceof Error ? input.err.name : 'Error',
        failed: input.failed ?? 'closed',
      },
      ...(input.missionId ? { missionIds: [input.missionId] } : {}),
    })
    .catch((emitErr) => {
      console.error('[provenance] alarm failed to record:', safeErrorSummary(emitErr));
    });
}

/**
 * Records an LLM response's inherited sources, deciding what a failure means:
 * a model call is a write, so for an account's agent with controls on, when
 * the record cannot be made the response is withheld in every accountability
 * mode while its bytes are still ours (503); outside an account, in enforced
 * mode. Bytes a stream already sent can only alarm. Otherwise the response is
 * delivered and the alarm does not block an account's agent with controls off.
 */
export async function recordLlmResponseProvenance(
  services: Services,
  input: Parameters<typeof recordInheritedResponse>[1] & {
    /** The Passport's accountability mode, for an agent outside an account. */
    mode: TrailMode;
    bytesAlreadySent: boolean;
  },
): Promise<void> {
  if (input.sources.length === 0) return;
  const { mode, bytesAlreadySent, ...record } = input;
  try {
    await recordInheritedResponse(services, record);
  } catch (err) {
    const posture = await trailPosture(services, { operatorId: input.operatorId, agentId: input.agentId, mode, action: 'model.call' });
    const failClosed = posture.failsClosed('POST') && !bytesAlreadySent;
    await raiseProvenanceAlarm(services, {
      operatorId: input.operatorId, agentId: input.agentId, passportJti: input.passportJti, missionId: input.missionId,
      stage: 'llm_response', err, failed: failClosed ? 'closed' : 'open', refuses: posture.refuses,
    });
    if (failClosed) {
      throw new ServiceUnavailableError(
        'Could not record where this response\'s content came from, so it was withheld. Retry shortly.',
      );
    }
  }
}
