// The wall, in one place.
//
// Three gates decide whether a call an agent has already proven it is allowed
// to make may carry what it is carrying:
//
//   1. Closed-operation policy - the operation must be declared, and every
//      field the request carries must be declared with it. A field nobody
//      anticipated is refused for want of permission, not for want of a
//      prohibition.
//   2. The data-flow rule - content this Mission read from another service
//      may not ride out to this one unless the operator declared the movement.
//      Both calls are individually in scope; the violation is the movement
//      between them, which no per-call check can see. The rule always runs and
//      always records; it REFUSES only for an account whose controls are on
//      (the billing account's controls decision). With controls off a flow the
//      scope does not declare is a warning-severity security event that never
//      blocks the agent, and the call goes through.
//   3. Parameter constraints - the value rules the scope pins.
//
// WHY THIS FILE EXISTS. These gates were written for /v1/proxy. The LLM
// gateway is the higher-volume door and ran none of them, so a scope that was
// closed for proxy calls was open for LLM calls. Copying the block would have
// left two security-critical implementations to keep in sync, and this
// codebase has already been bitten by exactly that: the notification webhook
// create path was fixed in one place and stayed open in the legacy one. One
// implementation, every call site: the proxy, the LLM gateway and an agent
// account's own sends (email and texts).
//
// Order matters and is preserved from proxy.ts: policy first because it is the
// stronger statement, then the data-flow rule, then constraints. All of it
// runs BEFORE any credential is retrieved, so nothing leaves on a refusal.

import type { Services } from '../config/services.js';
import {
  type ControlActionType,
  ForbiddenError,
  redactRequestPath,
  findFailingConstraint,
  evaluateScopePolicy,
  evaluateSourceMatches,
  flowServiceKey,
  flowSourceAllowed,
  parseFlowSource,
  matchObservedSources,
  carriedSources,
  collectStrings,
  extractEntities,
  safeErrorSummary,
  trailEntityDigest,
  type Constraint,
  type NormalizedRequest,
  type ScopePolicyShape,
  isEncodedEmailRequest,
  deriveRequestEmail,
} from '@stack/shared';
import {
  trailPosture,
  dataFlowFailsClosed,
  type TrailPosture,
  flowMissionId,
  observedItemsFromRows,
  readObservedRows,
  type ObservedRows,
} from './provenance.js';
import { denialDedup } from './denial-dedup.js';

/** The passport ServiceScope entry for the destination service, if it has one. */
export interface WallServiceScope {
  service_name: string;
  constraints?: Constraint[];
  policy?: ScopePolicyShape;
  allow_data_from?: string[];
}

/**
 * The Passport scope the wall judges a call against: the one for the connection the call resolved to. A scope that
 * names no connection stands only for the provider's single shared connection, so it is taken only when it is the one
 * such scope. Never the first scope of the provider: with several connections that would judge a call against another
 * connection's policy.
 */
export function scopeForConnection<T extends { service_name: string; connection_id?: string }>(
  scopes: readonly T[],
  provider: string,
  connectionId: string,
): T | undefined {
  const ofProvider = scopes.filter((scope) => scope.service_name === provider);
  const exact = ofProvider.find((scope) => scope.connection_id === connectionId);
  if (exact) return exact;
  const unpinned = ofProvider.filter((scope) => !scope.connection_id);
  return unpinned.length === 1 ? unpinned[0] : undefined;
}

export interface ScopeWallInput {
  services: Services;
  operatorId: string;
  agentId: string;
  passportJti: string;
  mode: 'enforced' | 'logged' | 'standard' | undefined;
  missionIds: readonly string[] | undefined;
  /** Where this call is going. Also the data-flow destination. */
  destinationService: string;
  /** The connection of that service the call resolved to, when it has one: two connections of one service are two sources. */
  destinationConnectionId?: string | null;
  serviceScope: WallServiceScope | undefined;
  /** The request as the agent submitted it, normalized for path resolution. */
  normalized: NormalizedRequest;
  /** Absolute request URL, used for entity extraction (may carry a query string). */
  rawUrl: string;
  /** `named_intent` recorded on a denial claim, e.g. `resend:http:proxy`. */
  namedIntent: string;
  /** Log prefix identifying the caller, e.g. `[proxy]`. */
  producer: string;
  /**
   * The kind of action this call is, for an account's agent: the data-flow rule
   * refuses only for a kind the customer chose to check (`ControlPosture`).
   */
  controlAction?: ControlActionType | null;
  /**
   * The data-flow rule's read, already started by the caller so it overlaps
   * earlier gates. Must be `readObservedRows(services, { operatorId,
   * passportJti, missionId: flowMissionId(missionIds) })` for this same
   * Passport and Mission. A rejection is handled exactly like a failed read
   * made here. Absent: the read is made here.
   */
  observedRows?: Promise<ObservedRows>;
}

export interface ScopeWallResult {
  /**
   * Sources whose content this call carries, by the same test the rule
   * refuses on, all of them permitted (same service or a declared flow) or
   * allowed because controls are off. A caller whose response is derived from
   * the request (the LLM gateway) attributes the response to these, so the
   * trail follows the content.
   */
  carriedSources: string[];
}

/**
 * Decoded email content.
 *
 * A Gmail send carries the message as base64url RFC 822 in `body.raw`, and a
 * Graph send may carry MIME; neither the entity catalogue nor content
 * fingerprints can read that. The proxy attaches `deriveRequestEmail`
 * (`packages/shared/src/utils/derived-email.ts`, a bounded, fail-closed
 * header and text reader) to the normalized request as `derived.email`
 * BEFORE the wall runs:
 *
 *   derived.email.text        decoded subject and text parts -> fingerprints + entities
 *   derived.email.subject     decoded subject                -> fingerprints + entities
 *   derived.email.recipients  every To, Cc and Bcc address   -> entities
 *   derived.email.from        From addresses                 -> entities
 *
 * The wall derives it itself when a caller did not attach it. When the
 * request is an encoded email send and the message cannot be read, the
 * data-flow rule fails closed for it.
 */
function derivedEmail(normalized: NormalizedRequest): Record<string, unknown> | null {
  const derived = (normalized as NormalizedRequest & { derived?: { email?: unknown } }).derived;
  // A caller that did not attach it still gets the decoded message: the
  // wall never depends on every call site remembering to.
  const email = derived?.email ?? deriveRequestEmail(normalized);
  return email && typeof email === 'object' && !Array.isArray(email) ? email as Record<string, unknown> : null;
}

export { dataFlowFailsClosed };

/**
 * The request the wall judges: the normalized request plus, for a Gmail or
 * Outlook send, its decoded message as `derived.email`. Returns the same
 * object when there is no readable email. Computed from the body only, so a
 * caller hashing the request for idempotency hashes the input, not this.
 */
export function withDerivedEmail<T extends NormalizedRequest>(normalized: T): T {
  const email = deriveRequestEmail(normalized);
  return email ? { ...normalized, derived: { email } } : normalized;
}

/**
 * Entities and free text the outbound call carries, decoded email included.
 *
 * An entity is offered in two forms: as extracted, and as the one-way digest
 * the trail keeps for an agent account's own mail and texts (`trailEntity`),
 * so content read from the account's inbox is recognised without the inbox's
 * addresses and names ever being stored.
 */
export function outboundContent(normalized: NormalizedRequest, rawUrl: string): { entities: string[]; text: string[] } {
  const email = derivedEmail(normalized);
  const emailText = email ? collectStrings([email['subject'], email['text']]) : [];
  const entities = extractEntities(
    {
      url: rawUrl,
      body: normalized.body,
      query: normalized.query,
      ...(email ? { email: { subject: email['subject'], text: email['text'], recipients: email['recipients'], from: email['from'] } } : {}),
    },
    // Money and account numbers are compared on every outbound call; they
    // are only ever RECORDED from financial providers, so outside a Mission
    // that read one there is nothing for them to match.
    { financial: true },
  )
    // The destination's own host is where the call goes, not content it
    // carries. Counting it let any read that merely mentioned the host (a
    // shared API host, a link in a chat message) refuse every later call to
    // it. Path, query and body still count.
    .filter((c) => !(c.entity_type === 'url_host' && c.entity === normalized.url.host.toLowerCase()))
    .flatMap((c) => c.entity_type === 'money_amount' || c.entity_type === 'account_number'
      ? [c.entity]
      : [c.entity, trailEntityDigest(c.entity)]);
  return { entities, text: [...collectStrings(normalized.body), ...emailText] };
}

/**
 * Run the three gates. Returns normally when the call may proceed; throws
 * ForbiddenError on a refusal, having first recorded the security event and,
 * where the shape allows it, a signed intent denial.
 *
 * Severity is graded by what the refusal says. A refusal because the grant or
 * the Passport is too narrow (a closed-operation policy that does not list the
 * call, a parameter constraint the call is outside of) is a warning in every
 * mode: it is still refused, it just does not page the owner or block the
 * agent for asking for something the owner has not allowed yet. Data leaving
 * for another service is what looks like exfiltration, so it keeps the house
 * rule: `logged` mode grades it to warning, everything else is critical; it
 * refuses only with controls on, and with controls off it records a warning
 * that never auto-blocks the agent.
 *
 * Identical denials (same agent, service, method, place and reason) are one
 * event with a count for ten minutes (`denialDedup`).
 */
export async function enforceScopeWall(input: ScopeWallInput): Promise<ScopeWallResult> {
  const {
    services, operatorId, agentId, passportJti, mode, missionIds,
    destinationService, destinationConnectionId = null, serviceScope, normalized, rawUrl, namedIntent, producer, controlAction = null,
  } = input;

  const severity = mode === 'logged' ? 'warning' : 'critical';
  const action = `${normalized.method} ${redactRequestPath(normalized.url.pathname)}`;
  /** The gate that folds repeats of this denial into one event. `op` is what refused it. */
  const dedupOf = (op: string) => denialDedup({
    agentId,
    service: destinationService,
    method: normalized.method,
    host: normalized.url.host,
    pathname: normalized.url.pathname,
    op,
  });

  // What a violation, or the rule failing to run, means for this agent (an
  // account's agent follows its owner's controls; any other keeps its
  // mode), read once and only when a decision needs it.
  let posture: Promise<TrailPosture> | undefined;
  const trail = () => (posture ??= trailPosture(services, { operatorId, agentId, mode, action: controlAction }));

  const recordDenial = async (
    denialReason: 'constraint_violation',
    message: string,
    metadata: Record<string, unknown>,
  ) => {
    try {
      await services.claimRegistry.recordIntentDenial({
        operatorId,
        passportJti,
        attemptedIntent: {
          type: 'intent_claim',
          intent_type: 'http_call',
          agent_id: agentId,
          named_intent: namedIntent,
          target: destinationService,
          action,
          parameters: { service: destinationService, method: normalized.method },
          estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
          accountability: mode ?? 'standard',
          reason: null,
          requires: [],
          user_subject: null,
          mission_ref: null,
          submitted_at: Date.now(),
        },
        denialReason,
        message,
        metadata,
      });
    } catch (err) {
      console.error('[scope-wall] intent_denial emission failed:', producer, safeErrorSummary(err));
    }
  };

  // ── 1. Closed-operation policy ─────────────────────────────────────────
  //
  // A scope with no policy, or one in `open` mode, is unaffected: the legacy
  // behaviour is preserved so existing passports keep working.
  if (serviceScope?.policy) {
    const denial = evaluateScopePolicy(serviceScope.policy, normalized);
    if (denial) {
      await services.securityEvent.record({
        operatorId,
        agentId,
        passportJti,
        signalType: 'credential_outside_scope',
        // The scope is too narrow for what was asked: refused, but a warning, in every mode.
        severity: 'warning',
        message: `Request to ${destinationService} refused by closed operation policy: ${denial.reason}`,
        // Field NAMES and operation ids only - never the values, which are the
        // caller's data and frequently PII.
        metadata: {
          policy_denial: denial.reason,
          detail: denial.detail,
          destination_service: destinationService,
          ...('field' in denial ? { undeclared_field: denial.field } : {}),
          ...('operation' in denial ? { operation: denial.operation } : {}),
        },
        missionIds,
        ...dedupOf(`policy:${denial.reason}:${'field' in denial ? denial.field : ''}:${'operation' in denial ? denial.operation : ''}`),
      });
      await recordDenial('constraint_violation', denial.detail, {
        policy_denial: denial.reason,
      });
      throw new ForbiddenError(denial.detail);
    }
  }

  // ── 2. Data-flow rule ──────────────────────────────────────────────────
  //
  // Reads only entity_observation rows, three JSONB fields, by MISSION: what
  // the agent read under any Passport of this job (refresh, delegation, a
  // second root Passport) and what hand-offs, LLM responses and an account's
  // own mail carried into it, newest-N per source within the rolling window
  // (lib/provenance.ts, passport-claims-repo findObservedContentForFlow). The
  // general findActiveByPassportId would pull every claim with its COSE
  // envelope and is not usable per-request.
  let carried: string[] = [];
  if (services.passportClaimsRepo) {
    try {
      const observedRows = await (input.observedRows
        ?? readObservedRows(services, { operatorId, passportJti, missionId: flowMissionId(missionIds) }));
      const observed = observedItemsFromRows(observedRows);

      // An email whose encoded message could not be read carries unknown
      // content. When this Mission holds content from a service that may not
      // flow here, that unknown content is flagged (and refused with
      // controls on) rather than called clean.
      if (observed.length > 0 && isEncodedEmailRequest(normalized) && !derivedEmail(normalized)) {
        const declared = (serviceScope?.allow_data_from ?? []).map((from) => ({ from, to: destinationService }));
        // Foreign by the rule the evaluation uses: not the destination's own content (another connection of the
        // service is foreign), and not declared by its label or by its service.
        const foreign = [...new Set(observed.map((item) => item.service))]
          .find((label) => !flowSourceAllowed(label, destinationService, destinationConnectionId, declared));
        if (foreign) {
          const foreignSource = shownSource(parseFlowSource(foreign), destinationService);
          const refused = (await trail()).refuses;
          await services.securityEvent.record({
            operatorId,
            agentId,
            passportJti,
            signalType: 'credential_outside_scope',
            severity: refused ? severity : 'warning',
            ...(refused ? {} : { skipAgentAutoBlock: true }),
            message:
              `Request to ${destinationService} sends an email STACK could not read, ` +
              `after this Mission read content from ${readFrom(foreignSource.service, destinationService)}`,
            metadata: {
              data_flow_from: foreignSource.service,
              data_flow_to: destinationService,
              ...(foreignSource.connectionId ? { data_flow_from_connection: foreignSource.connectionId } : {}),
              ...(destinationConnectionId ? { data_flow_to_connection: destinationConnectionId } : {}),
              matched_via: 'unreadable_email',
              data_flow_refused: refused,
            },
            missionIds,
            ...dedupOf(`flow:unreadable_email:${foreign}:${refused ? 'refused' : 'allowed'}`),
          });
          if (refused) {
            const message =
              `Refusing to send an email STACK could not read to "${destinationService}": this Mission ` +
              `holds content read from ${readFrom(foreignSource.service, destinationService, true)}. Send a plain message, or declare the flow on the ` +
              `${destinationService} scope (allow_data_from) if it is intended.`;
            await recordDenial('constraint_violation', message, {
              data_flow_from: foreignSource.service,
              data_flow_to: destinationService,
              ...(foreignSource.connectionId ? { data_flow_from_connection: foreignSource.connectionId } : {}),
              ...(destinationConnectionId ? { data_flow_to_connection: destinationConnectionId } : {}),
              matched_via: 'unreadable_email',
            });
            throw new ForbiddenError(message);
          }
        }
      }

      if (observed.length > 0) {
        const outbound = outboundContent(normalized, rawUrl);
        const matches = matchObservedSources({
          outboundEntities: outbound.entities,
          outboundText: outbound.text,
          observed,
        });
        const violation = evaluateSourceMatches(
          destinationService,
          matches,
          (serviceScope?.allow_data_from ?? []).map((from) => ({ from, to: destinationService })),
          undefined,
          destinationConnectionId,
        );
        carried = carriedSources(matches);

        if (violation) {
          // The service the person knows: a long custom service travels as a key, which is never shown for the
          // destination's own service. A key for a different long service stays a key (its name is not in the label).
          const shown = shownSource({ service: violation.sourceService, connectionId: violation.sourceConnectionId }, violation.destinationService);
          const refused = (await trail()).refuses;
          await services.securityEvent.record({
            operatorId,
            agentId,
            passportJti,
            signalType: 'credential_outside_scope',
            severity: refused ? severity : 'warning',
            // Controls off: the call goes through, so nothing about this
            // warning may block the agent, whatever its on_critical says.
            ...(refused ? {} : { skipAgentAutoBlock: true }),
            message:
              `Request to ${violation.destinationService} carries content read from ` +
              `${readFrom(shown.service, violation.destinationService)}`,
            // Source, destination and HOW it was recognised. Never the content:
            // it is the caller's data, frequently PII, and a security event is
            // retained.
            metadata: {
              data_flow_from: shown.service,
              data_flow_to: violation.destinationService,
              ...(violation.sourceConnectionId ? { data_flow_from_connection: violation.sourceConnectionId } : {}),
              ...(destinationConnectionId ? { data_flow_to_connection: destinationConnectionId } : {}),
              matched_via: violation.via,
              data_flow_refused: refused,
            },
            missionIds,
            ...dedupOf(`flow:${flowLabelOf(violation)}:${violation.via}:${refused ? 'refused' : 'allowed'}`),
          });
          if (refused) {
            const message =
              `Refusing to send content read from ${readFrom(shown.service, violation.destinationService, true)} to ` +
              `"${violation.destinationService}". Declare the flow on the ` +
              `${violation.destinationService} scope (allow_data_from) if it is intended.`;
            // A signed denial, like the other two gates. Services and match
            // method only: the matched content is the caller's data.
            await recordDenial('constraint_violation', message, {
              data_flow_from: shown.service,
              data_flow_to: violation.destinationService,
              ...(violation.sourceConnectionId ? { data_flow_from_connection: violation.sourceConnectionId } : {}),
              ...(destinationConnectionId ? { data_flow_to_connection: destinationConnectionId } : {}),
              matched_via: violation.via,
            });
            throw new ForbiddenError(message);
          }
        }
      }
    } catch (err) {
      // A ForbiddenError here is the decision, not a failure - rethrow.
      if (err instanceof ForbiddenError) throw err;
      const decided = await trail();
      const refused = decided.refuses;
      const failClosed = decided.failsClosed(normalized.method);

      // The data-flow rule could not be evaluated - a DB hiccup, or an attacker
      // deliberately inducing load to switch the exfiltration control off. This
      // used to be a console.error and an unconditional allow, which the
      // reachability benchmark demonstrated: induce an error, and the
      // read-here-send-there movement went through, silently
      // (the threat model, cell dataflow.fails-open-under-error).
      //
      // The silence was the real vulnerability, so the first thing this does now
      // is RAISE A REAL ALARM regardless of what it decides next: a security
      // event the operator sees, not a log line nobody reads. With controls on
      // it is critical, so an attacker can no longer disable the control
      // without the operator learning the control was disabled. With controls
      // off no control was disabled: it is a warning, and it never blocks the
      // agent.
      await services.securityEvent
        .record({
          operatorId,
          agentId,
          passportJti,
          signalType: 'credential_outside_scope',
          severity: refused ? 'critical' : 'warning',
          ...(refused ? {} : { skipAgentAutoBlock: true }),
          message:
            `Data-flow rule could not be evaluated for a call to ${destinationService}; ` +
            `the cross-service movement check did not run`,
          metadata: {
            data_flow_rule_unavailable: true,
            destination_service: destinationService,
            // The failure mode, never the query internals.
            error: err instanceof Error ? err.message : String(err),
            // What the account's controls decided below - so a reviewer can
            // tell a call that was blocked from one that was let through with
            // this alarm.
            failed: failClosed ? 'closed' : 'open',
          },
          missionIds,
        })
        .catch((emitErr) => {
          console.error('[scope-wall] data-flow unavailability alarm failed to record:', producer, safeErrorSummary(emitErr));
        });

      // Then decide. With controls on, a write or a send is how data leaves,
      // so any non-GET call fails CLOSED when the rule cannot run, in every
      // mode: a rare unavailability refusing it is acceptable and safe. An
      // enforced-mode passport fails closed on reads too. A GET in
      // logged/standard mode fails OPEN, but loudly (the alarm above). With
      // controls off every call fails open, loudly. Every OTHER gate (scope,
      // closed-operation policy, constraints, host binding) already ran; only
      // this one cross-service check is unavailable.
      if (failClosed) {
        throw new ForbiddenError(
          `Refusing the call to "${destinationService}": the data-flow rule could not be ` +
            `evaluated, and this call fails closed. Retry shortly.`,
        );
      }
      console.error('[scope-wall] data-flow evaluation failed and was allowed:', producer, safeErrorSummary(err));
    }
  }

  // ── 3. Parameter constraints ───────────────────────────────────────────
  //
  // AND semantics: any failing constraint denies. A scope with no constraints
  // skips this entirely.
  if (serviceScope?.constraints && serviceScope.constraints.length > 0) {
    const failed = findFailingConstraint(serviceScope.constraints, normalized);
    if (failed) {
      // A choice of rules names the constraint that failed in each of its rules (the path and the op, never a value).
      const alternatives = failed.op === 'any_of' ? failedAlternatives(failed, normalized) : [];
      const message = failed.op === 'any_of'
        ? `Request is outside every rule the passport allows on ${destinationService}: ${alternatives
          .map((alt, index) => `rule ${index + 1} fails on ${alt.path} (${alt.op})`).join('; ')}`
        : `Request violates passport constraint on ${failed.path} (${failed.op})`;
      await services.securityEvent.record({
        operatorId,
        agentId,
        passportJti,
        signalType: 'credential_outside_scope',
        // The constraint is narrower than what was asked: refused, but a warning, in every mode.
        severity: 'warning',
        message: failed.op === 'any_of'
          ? `Request to ${destinationService} is outside every rule the passport allows`
          : `Request to ${destinationService} violates passport constraint on ${failed.path}`,
        // Only the path + op + request path - never the body values themselves
        // (PII risk, e.g. body.email).
        metadata: {
          failed_constraint: { path: failed.path, op: failed.op },
          ...(alternatives.length > 0 ? { failed_alternatives: alternatives } : {}),
          request_method: normalized.method,
          request_path: redactRequestPath(normalized.url.pathname),
          destination_service: destinationService,
        },
        missionIds,
        ...dedupOf(`constraint:${failed.path}:${failed.op}`),
      });
      await recordDenial('constraint_violation', message, {
        failed_constraint: { path: failed.path, op: failed.op },
        ...(alternatives.length > 0 ? { failed_alternatives: alternatives } : {}),
        request_method: normalized.method,
        request_path: redactRequestPath(normalized.url.pathname),
      });
      throw new ForbiddenError(message);
    }
  }

  return { carriedSources: carried };
}

/** The full source label of a violation, for a dedup key: two connections of one service are two denials. */
function flowLabelOf(violation: { sourceService: string; sourceConnectionId: string | null }): string {
  return violation.sourceConnectionId ? `${violation.sourceService}@${violation.sourceConnectionId}` : violation.sourceService;
}

/** A source as it is shown: when it is the destination's own service, under the destination's real name, not its key. */
function shownSource(
  source: { service: string; connectionId: string | null },
  destinationService: string,
): { service: string; connectionId: string | null } {
  return source.service === flowServiceKey(destinationService) ? { ...source, service: destinationService } : source;
}

/** What follows "content read from" in a refusal: another connection of the destination's own service, or the source service. */
function readFrom(sourceService: string, destinationService: string, quoted = false): string {
  if (sourceService === destinationService) return `another connection of "${destinationService}"`;
  return quoted ? `"${sourceService}"` : sourceService;
}

/** For a choice of rules the call fits none of: the first constraint each rule fails on, its path and op only. */
function failedAlternatives(failed: Constraint, request: Parameters<typeof findFailingConstraint>[1]): Array<{ path: string; op: string }> {
  if (failed.op !== 'any_of' || !Array.isArray(failed.value)) return [];
  return (failed.value as Constraint[][]).map((group) => {
    const own = findFailingConstraint(group, request);
    return own ? { path: own.path, op: own.op } : { path: 'any_of', op: 'any_of' };
  });
}
