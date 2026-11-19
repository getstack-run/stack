/**
 * Pure forensic-timeline reconstruction from a set of claim bodies.
 *
 * interpretation layer (NOT evidence) per the 5.4.0 ADR
 * Design decision 1. Used by:
 *
 *   - `@stack/vault/ReplayService.reconstructMissionTimeline` — live
 *     variant; reads claims from the DB and feeds them here.
 *   - `@getstackrun/verify` — pack variant; COSE
 *     decodes every envelope from the manifest's `claims[]`, parses
 *     each body, and feeds them here.
 *
 * Single shared helper guarantees both surfaces produce the same
 * timeline shape from the same underlying claim set.
 *
 * Inputs: a list of `ClaimInput` rows (type + parsed body + envelope
 * metadata) for one mission's scope. The helper does NOT validate
 * claim signatures (that's the verifier's job in 5.4.8); it ONLY
 * interprets parsed bodies into a chronologically-ordered event list
 * plus the four named slots (`behavioral_diff`, `cap_usage`,
 * `dossiers`, `twin_divergence`).
 *
 * Output kinds are locked here. Adding a new kind is additive (older
 * consumers see the new value and SHOULD default to graceful handling
 * per the additive-only rule).
 */

export type ReplayedEventKind =
  | 'mission_open'
  | 'mission_close'
  | 'intent_submitted'
  | 'intent_outcome'
  | 'intent_denial'
  | 'intent_simulation'
  | 'entity_observation'
  | 'detector_signal'
  | 'checkpoint_approval'
  | 'skill_invocation'
  | 'behavioral_genome'
  | 'operator_decision'
  | 'operator_review'
  | 'dossier'
  | 'twin_divergence';

export interface ReplayedEvent {
  kind: ReplayedEventKind;
  /** Envelope's issued_at unix ms — the producer's timestamp. */
  at_ms: number;
  claim_id?: string | null;
  claim_hash?: string | null;
  /**
   * The parsed claim body. Shape varies per kind — consumers narrow on
   * `kind` to access typed fields. The schema for each kind lives in
   * `packages/shared/src/schemas/passport-claims/<kind>.ts`.
   */
  body: Record<string, unknown>;
}

export interface ReplayedMission {
  mission_id: string;
  operator_id: string;
  /** Open-claim body — the first mission claim emitted. */
  open?: Record<string, unknown>;
  /** Close-claim body — the terminal-state mission claim (may equal open if not yet closed). */
  close?: Record<string, unknown>;
  /** Convenience flag: true when a close claim with a terminal_state is present. */
  closed: boolean;
}

export interface ReplayedCapUsage {
  /** From the terminal mission claim's max_actions field, when set. */
  max_actions: number | null;
  /** From the terminal mission claim's max_dropoff_bytes field. */
  max_dropoff_bytes: number | null;
  /** From the terminal mission claim's coverage_cap_cents field. */
  coverage_cap_cents: number | null;
  /** Sum of intent_outcome.wallet_cents over the mission window (best-effort). */
  observed_wallet_cents: number;
  /** Count of intent_outcome envelopes seen. */
  observed_action_count: number;
}

export interface ReplayedTimeline {
  mission: ReplayedMission;
  events: ReplayedEvent[];
  /** From the terminal mission claim's behavioral_diff field, when set. */
  behavioral_diff: {
    max_z: number;
    l2_norm: number;
    per_dimension: Record<string, number>;
  } | null;
  cap_usage: ReplayedCapUsage;
  /** Zero or more dossiers ordered by `authored_at_ms`. */
  dossiers: ReplayedEvent[];
  /** Legacy dossiers and new Operator reviews in one chronological revision chain. */
  operator_reviews: ReplayedEvent[];
  /** At most one twin_divergence claim per mission (latest if multiple). */
  twin_divergence: ReplayedEvent | null;
}

/**
 * Input shape — one claim row with parsed body. Both the live path
 * and the from-pack path pre-normalise to this shape.
 *
 * `claim_id` + `claim_hash` are optional (the verifier may or may not
 * carry them depending on what's in the manifest); when present they
 * appear on the resulting event for cross-referencing.
 *
 * `issued_at_ms` is required — every event needs a timestamp for
 * ordering. Producers MUST stamp it (envelope's issued_at field).
 */
export interface ReconstructClaimInput {
  type: string;
  body: Record<string, unknown>;
  issued_at_ms: number;
  claim_id?: string | null;
  claim_hash?: string | null;
}

/**
 * Reconstruct a mission timeline from the union of its claim bodies.
 *
 * Steps:
 *   1. Split claims by type. Mission claims (open + close) drive the
 *      `mission` slot. Dossier + twin_divergence get pulled into named
 *      slots. All non-mission claims become events.
 *   2. Order events by `at_ms` ascending. Stable: ties resolve by
 *      claim_id (when present) for deterministic verifier output.
 *   3. Derive `behavioral_diff` from the LATEST mission claim.
 *   4. Derive `cap_usage` from the LATEST mission claim's cap fields
 *      plus a running sum over intent_outcome.wallet_cents.
 *
 * @param missionId Expected `ms_*` id. The helper filters mission
 *                  claims to those whose body's `mission_id` matches
 *                  (defensive against pack scopes that included
 *                  unrelated mission claims).
 * @param operatorId Expected `op_*` id. Surfaces on the result so the
 *                   caller can sanity-check; not validated against
 *                   each claim.
 * @param claims The full pool of claim bodies for the mission scope.
 */
export function reconstructTimeline(
  missionId: string,
  operatorId: string,
  claims: readonly ReconstructClaimInput[],
): ReplayedTimeline {
  const missionClaims: ReconstructClaimInput[] = [];
  const dossierClaims: ReconstructClaimInput[] = [];
  const operatorReviewClaims: ReconstructClaimInput[] = [];
  const twinClaims: ReconstructClaimInput[] = [];
  const otherEvents: ReplayedEvent[] = [];

  for (const c of claims) {
    if (c.type === 'mission') {
      const claimMissionId = (c.body as { mission_id?: string }).mission_id;
      if (claimMissionId === missionId) missionClaims.push(c);
      continue;
    }
    if (c.type === 'dossier') {
      dossierClaims.push(c);
      continue;
    }
    if (c.type === 'operator_review') {
      operatorReviewClaims.push(c);
      continue;
    }
    if (c.type === 'twin_divergence') {
      twinClaims.push(c);
      continue;
    }
    const kind = classifyKind(c.type);
    if (kind === null) continue; // unknown claim type — not surfaced in v1 timeline
    otherEvents.push({
      kind,
      at_ms: c.issued_at_ms,
      claim_id: c.claim_id ?? null,
      claim_hash: c.claim_hash ?? null,
      body: c.body,
    });
  }

  // Order mission claims chronologically so we can identify open vs close.
  missionClaims.sort((a, b) => a.issued_at_ms - b.issued_at_ms);
  const firstMission = missionClaims[0];
  const lastMission = missionClaims[missionClaims.length - 1];

  // Build mission-level events bracketing the timeline.
  const missionEvents: ReplayedEvent[] = [];
  if (firstMission) {
    missionEvents.push({
      kind: 'mission_open',
      at_ms: firstMission.issued_at_ms,
      claim_id: firstMission.claim_id ?? null,
      claim_hash: firstMission.claim_hash ?? null,
      body: firstMission.body,
    });
  }
  // Close event only when the terminal mission claim carries a
  // terminal_state. Operator-completed missions emit a second mission
  // claim with terminal_state set; missions still active have a single
  // mission claim with terminal_state null.
  if (lastMission && firstMission && lastMission !== firstMission) {
    const terminalState = (lastMission.body as { terminal_state?: string | null }).terminal_state;
    if (terminalState) {
      missionEvents.push({
        kind: 'mission_close',
        at_ms: lastMission.issued_at_ms,
        claim_id: lastMission.claim_id ?? null,
        claim_hash: lastMission.claim_hash ?? null,
        body: lastMission.body,
      });
    }
  }

  // Merge + order all events. Stable tie-break on claim_id.
  const allEvents = [...missionEvents, ...otherEvents].sort((a, b) => {
    if (a.at_ms !== b.at_ms) return a.at_ms - b.at_ms;
    const aId = a.claim_id ?? '';
    const bId = b.claim_id ?? '';
    return aId < bId ? -1 : aId > bId ? 1 : 0;
  });

  // Dossiers — order by authored_at_ms then claim_id for determinism.
  const dossierEvents: ReplayedEvent[] = dossierClaims
    .map((c) => ({
      kind: 'dossier' as const,
      at_ms:
        typeof (c.body as { authored_at_ms?: number }).authored_at_ms === 'number'
          ? (c.body as { authored_at_ms: number }).authored_at_ms
          : c.issued_at_ms,
      claim_id: c.claim_id ?? null,
      claim_hash: c.claim_hash ?? null,
      body: c.body,
    }))
    .sort((a, b) => {
      if (a.at_ms !== b.at_ms) return a.at_ms - b.at_ms;
      return (a.claim_id ?? '') < (b.claim_id ?? '') ? -1 : 1;
    });

  const operatorReviewEvents: ReplayedEvent[] = [
    ...dossierEvents,
    ...operatorReviewClaims.map((c) => ({
      kind: 'operator_review' as const,
      at_ms:
        typeof (c.body as { authored_at_ms?: number }).authored_at_ms === 'number'
          ? (c.body as { authored_at_ms: number }).authored_at_ms
          : c.issued_at_ms,
      claim_id: c.claim_id ?? null,
      claim_hash: c.claim_hash ?? null,
      body: c.body,
    })),
  ].sort((a, b) => {
    if (a.at_ms !== b.at_ms) return a.at_ms - b.at_ms;
    const aId = a.claim_id ?? '';
    const bId = b.claim_id ?? '';
    return aId < bId ? -1 : aId > bId ? 1 : 0;
  });

  // Twin divergence — pick the latest (one expected per mission).
  twinClaims.sort((a, b) => a.issued_at_ms - b.issued_at_ms);
  const lastTwin = twinClaims[twinClaims.length - 1];
  const twin_divergence: ReplayedEvent | null = lastTwin
    ? {
        kind: 'twin_divergence',
        at_ms: lastTwin.issued_at_ms,
        claim_id: lastTwin.claim_id ?? null,
        claim_hash: lastTwin.claim_hash ?? null,
        body: lastTwin.body,
      }
    : null;

  // Behavioral diff from latest mission claim (may carry it on
  // complete/revoke). Validate shape minimally; treat malformed as
  // null best-effort discipline.
  const rawDiff = (lastMission?.body as { behavioral_diff?: unknown } | undefined)?.behavioral_diff;
  const behavioral_diff = isBehavioralDiff(rawDiff) ? rawDiff : null;

  // Cap usage — caps come from latest mission claim; observed totals
  // come from a running scan over intent_outcome bodies.
  const cap_usage: ReplayedCapUsage = {
    max_actions: numberOrNull((lastMission?.body as { max_actions?: unknown })?.max_actions),
    max_dropoff_bytes: numberOrNull((lastMission?.body as { max_dropoff_bytes?: unknown })?.max_dropoff_bytes),
    coverage_cap_cents: numberOrNull((lastMission?.body as { coverage_cap_cents?: unknown })?.coverage_cap_cents),
    observed_wallet_cents: sumIntentOutcomeWalletCents(claims),
    observed_action_count: claims.filter((c) => c.type === 'intent_outcome').length,
  };

  return {
    mission: {
      mission_id: missionId,
      operator_id: operatorId,
      ...(firstMission ? { open: firstMission.body } : {}),
      ...(lastMission ? { close: lastMission.body } : {}),
      closed: Boolean(
        lastMission && (lastMission.body as { terminal_state?: string | null }).terminal_state,
      ),
    },
    events: allEvents,
    behavioral_diff,
    cap_usage,
    dossiers: dossierEvents,
    operator_reviews: operatorReviewEvents,
    twin_divergence,
  };
}

// ─── Internals ──────────────────────────────────────────────────────

function classifyKind(claimType: string): ReplayedEventKind | null {
  switch (claimType) {
    case 'intent_claim':
      return 'intent_submitted';
    case 'intent_outcome':
      return 'intent_outcome';
    case 'intent_denial':
      return 'intent_denial';
    case 'intent_simulation':
      return 'intent_simulation';
    case 'entity_observation':
      return 'entity_observation';
    case 'detector_signal':
      return 'detector_signal';
    case 'checkpoint_approval':
      return 'checkpoint_approval';
    case 'skill_invocation':
      return 'skill_invocation';
    case 'behavioral_genome':
      return 'behavioral_genome';
    case 'operator_decision':
      return 'operator_decision';
    default:
      return null;
  }
}

function isBehavioralDiff(value: unknown): value is {
  max_z: number;
  l2_norm: number;
  per_dimension: Record<string, number>;
} {
  if (!value || typeof value !== 'object') return false;
  const v = value as { max_z?: unknown; l2_norm?: unknown; per_dimension?: unknown };
  return (
    typeof v.max_z === 'number' &&
    typeof v.l2_norm === 'number' &&
    v.per_dimension !== null &&
    typeof v.per_dimension === 'object'
  );
}

function numberOrNull(value: unknown): number | null {
  return typeof value === 'number' ? value : null;
}

function sumIntentOutcomeWalletCents(claims: readonly ReconstructClaimInput[]): number {
  let total = 0;
  for (const c of claims) {
    if (c.type !== 'intent_outcome') continue;
    const wc = (c.body as { wallet_cents?: unknown }).wallet_cents;
    if (typeof wc === 'number') total += wc;
  }
  return total;
}
