// Pure mission helpers: lifetime limits, the default cap behaviour table, the twin policy decision,
// the scope subset check, and the row to view and output schema functions.

import Ajv from 'ajv';
import {
  DEFAULT_MISSION_CAP_BEHAVIOR,
  InvalidRequestError,
  SchemaValidationError,
  assertSafeJsonSchema,
  readRecipientPins,
  type CoverageCapPeriod,
  type MissionCapBehavior,
  type MissionCapName,
} from '@stack/shared';
import { ForbiddenError } from '@stack/shared';
import type {
  MissionRepository,
  MissionRevokeReason,
  MissionTerminalState,
} from '../../repositories/mission-repo.js';
import { type MissionView } from './types.js';

export const DEFAULT_MISSION_TTL_SECONDS = 900; // 15 min
// A Mission has no maximum length and needs no limit of its own at any length; it may still carry
// a spend limit or an action limit.

/** The latest end a Mission can have, 31 December 9999: a date past it is refused instead of becoming a year no system writes the same way. */
const LATEST_EXPIRY_MS = Date.UTC(9999, 11, 31, 23, 59, 59, 999);

/**
 * Checks the end of a Mission that is opened or renewed. The only refusal is an end no date can
 * hold, answered in plain words.
 */
export function assertMissionEnd(expiresAtMs: number): void {
  if (!Number.isFinite(expiresAtMs) || expiresAtMs > LATEST_EXPIRY_MS) {
    throw new InvalidRequestError('A Mission cannot end after 31 December 9999. Choose an earlier end.');
  }
}

/**
 * What each cap does when the Mission's `cap_behavior` leaves it out: every cap pauses the Mission for its owner's
 * review. A Mission may set any cap to `refuse_action` or `end_mission` instead when it opens.
 */
export const DEFAULT_CAP_BEHAVIOR: Readonly<Record<MissionCapName, MissionCapBehavior>> = {
  coverage_cap_cents: DEFAULT_MISSION_CAP_BEHAVIOR,
  max_dropoff_bytes: DEFAULT_MISSION_CAP_BEHAVIOR,
  max_concurrent_intents: DEFAULT_MISSION_CAP_BEHAVIOR,
  max_actions: DEFAULT_MISSION_CAP_BEHAVIOR,
  max_duration_seconds: DEFAULT_MISSION_CAP_BEHAVIOR,
  max_actions_per_service: DEFAULT_MISSION_CAP_BEHAVIOR,
};

/**
 * The `cap_behavior` a new signed Mission claim carries. The claim's schema is published and names only the earlier
 * values (auto_revoke, deny_and_flag), so the behaviour lives on the Mission row and the claim carries an empty map.
 */
export const CLAIM_CAP_BEHAVIOR: Record<string, never> = {};

/**
 * pure helper that resolves the twin firing decision
 * from (agent.twin_policy, explicit run_twin override, mission shape).
 * Exported standalone for direct unit testing without spinning up the
 * full MissionService.
 *
 * Rules:
 *   - run_twin explicit → use it (true OR false)
 *   - policy='always' → true
 *   - policy='never' → false
 *   - policy='high_stakes_only' → true if coverage_cap_cents is non-null
 *     OR any cap_behavior value is 'end_mission'. Operators self-flag
 *     high stakes by setting either a wallet cap or a cap that ends the
 *     mission.
 *   - policy='per_mission' (default) → false unless explicit
 */
export type TwinPolicyEnum = 'always' | 'high_stakes_only' | 'never' | 'per_mission';

export function resolveTwinPolicy(args: {
  policy: TwinPolicyEnum;
  explicitRunTwin?: boolean;
  mission: {
    coverage_cap_cents: number | null;
    cap_behavior: Partial<Record<string, MissionCapBehavior>>;
  };
}): boolean {
  if (args.explicitRunTwin !== undefined) return args.explicitRunTwin;
  if (args.policy === 'always') return true;
  if (args.policy === 'never') return false;
  if (args.policy === 'high_stakes_only') {
    if (args.mission.coverage_cap_cents !== null) return true;
    for (const beh of Object.values(args.mission.cap_behavior)) {
      if (beh === 'end_mission') return true;
    }
    return false;
  }
  // 'per_mission' default
  return false;
}

/**
 * Mission scope subset check. Scope narrowing primitive: each
 * service in the mission's intent_services must appear in the
 * parent passport's superset. We do NOT yet validate parameter-
 * level constraint subsetting here (that would require the mission
 * to carry per-service constraints, which v1 does not — the proxy
 * still enforces the passport's per-service constraints on top of
 * the mission scope check).
 *
 * Compares the two service lists as sets of service names.
 */
export function assertScopeIsSubset(
  narrowerServices: readonly string[],
  widerServices: readonly string[],
): void {
  if (narrowerServices.length === 0) return; // empty mission scope is always a subset
  const widerSet = new Set(widerServices);
  const missing = narrowerServices.filter((s) => !widerSet.has(s));
  if (missing.length > 0) {
    throw new ForbiddenError(
      `mission scope is not a subset of parent passport scope. Mission requests services [${narrowerServices.join(', ')}] but passport only allows [${widerServices.join(', ')}]. Missing: [${missing.join(', ')}]`,
    );
  }
  // Service-level subset OK. Parameter-level constraints are
  // enforced by the proxy gate's existing per-call constraint
  // evaluation against the passport's constraints — the mission
  // doesn't redeclare those in v1. When v2 lands per-service
  // constraint narrowing on the mission, this method will call
  // constraintsAreSubset from @stack/shared on each declared
  // constraint pair.
}

export function clamp(n: number, lo: number, hi: number): number {
  if (n < lo) return lo;
  if (n > hi) return hi;
  return n;
}

export function isOperatorCleanReason(reason: MissionRevokeReason): boolean {
  return reason === 'operator_initiated_clean';
}

/**
 * Get the effective cap_behavior for a given cap on a mission,
 * applying mission overrides on top of the default behavior table.
 */
export function effectiveCapBehavior(
  mission: { cap_behavior: Partial<Record<string, MissionCapBehavior>> },
  capName: MissionCapName,
): MissionCapBehavior {
  return mission.cap_behavior[capName] ?? DEFAULT_CAP_BEHAVIOR[capName];
}

export type MissionRow = NonNullable<Awaited<ReturnType<MissionRepository['findById']>>>;

export function rowToView(row: MissionRow): MissionView {
  return {
    assigned_agent_id: row.assigned_agent_id ?? null,
    authorization_digest: row.authorization_digest ?? null,
    mission_id: row.mission_id,
    operator_id: row.operator_id,
    claim_id: row.claim_id,
    passport_jti: row.passport_jti ?? null,
    intent_summary: row.intent_summary,
    intent_services: row.intent_services,
    expected_counterparties: row.expected_counterparties,
    max_actions: row.max_actions,
    max_dropoff_bytes: row.max_dropoff_bytes,
    coverage_cap_cents: row.coverage_cap_cents,
    max_duration_seconds: row.max_duration_seconds,
    max_concurrent_intents: row.max_concurrent_intents,
    max_actions_per_service: row.max_actions_per_service,
    cap_behavior: row.cap_behavior,
    coverage_cap_period: (row.coverage_cap_period ?? 'mission') as CoverageCapPeriod,
    cap_time_zone: row.cap_time_zone ?? 'UTC',
    paused_at: row.paused_at ?? null,
    paused_cap: (row.paused_cap ?? null) as MissionCapName | null,
    paused_service: row.paused_service ?? null,
    making_orders_up_to_cents: row.making_orders_up_to_cents ?? null,
    baseline_profile: row.baseline_profile ?? null,
    expected_output_shape: row.expected_output_shape ?? null,
    recipient_pins: readRecipientPins(row.recipient_pins),
    started_at: row.started_at,
    expires_at: row.expires_at,
    completed_at: row.completed_at ?? null,
    revoked_at: row.revoked_at ?? null,
    revoked_reason: (row.revoked_reason ?? null) as MissionRevokeReason | null,
    terminal_state: (row.terminal_state ?? null) as MissionTerminalState | null,
  };
}

export function compileOutputSchema(schema: Record<string, unknown>) {
  try {
    assertSafeJsonSchema(schema);
    // No remote schema loading and no shared unbounded cache of caller schemas.
    const ajv = new (Ajv as unknown as typeof Ajv.default)({ strict: true, allErrors: false });
    return ajv.compile(schema);
  } catch {
    throw new SchemaValidationError({ field: 'expected_output_shape' });
  }
}
