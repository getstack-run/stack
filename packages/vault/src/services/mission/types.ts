// Dependencies, views, inputs and verdicts for the mission service. Re-exported from
// mission-service.ts, which stays the import path for every other package.

import type { Redis } from 'ioredis';
import type { CoverageCapPeriod, DecisionReachedHook, MissionCapBehavior, MissionCapName, RecipientPin } from '@stack/shared';
import type { KmsService } from '../../crypto/kms.js';
import type {
  MissionRepository,
  MissionRevokeReason,
  MissionTerminalState,
  MissionTransaction,
} from '../../repositories/mission-repo.js';
import type { ClaimRegistryService } from '../claim-registry-service.js';
import type { BehavioralGenomeService } from '../behavioral-genome-service.js';
import type { MissionSpendSource } from '../spend/spend-ledger.js';

export interface MissionServiceDeps {
  kms?: Pick<KmsService, 'encrypt' | 'decrypt'>;
  repo: MissionRepository;
  claimRegistry: ClaimRegistryService;
  /**
   * ends every Passport bound to the Mission when the Mission
   * ends: on complete() (every terminal state, including the worker's
   * expiry sweep) and on revoke() (every reason). The database revoke
   * runs inside the transaction that records the Mission's terminal
   * state, so a failure rolls the Mission transition back rather than
   * leaving live Passports under a dead Mission. Production (API and
   * worker) always wires it; it is optional only so unit fixtures and
   * scripts can run the lifecycle without a Passport store.
   */
  passportRevoker?: MissionPassportRevoker;
  /**
   * pub/sub on the canonical revocation
   * channel (stack:revoked). Publishes a `bulk_mission` RevocationEvent
   * variant carrying the Passports the Mission end revoked. Fired on
   * revoke() and, when Passports were revoked, on complete() (with
   * revoke_reason set to the terminal state). Best-effort: the database
   * revoke is authoritative, so a publish failure is logged only.
   */
  publishMissionRevocation?: (event: {
    operator_id: string;
    mission_id: string;
    revoke_reason: string;
    cascaded_passport_jtis: string[];
  }) => Promise<void>;
  /**
   * behavioral genome service for baseline snapshot at
   * open() and mission-window diff at complete()/revoke(). Optional:
   * when unset, mission open/complete/revoke fall through to legacy
   * behavior (baseline_profile + behavioral_diff stay null).
   */
  behavioralGenome?: BehavioralGenomeService;
  /**
   * Redis for `genome_drift_fired:<jti>` key del on
   * mission open (re-arm the drift detector for the new baseline
   * window). Optional: when unset, the detector waits up to 24h for
   * its natural TTL.
   */
  redis?: Redis;
  /**
   * LLM usage repo for the coverage_cap_cents gross-cost
   * sum. Option A semantic: mission cap counts the FULL LLM bill under
   * the mission (provider cost plus any fee), not just a fee slice.
   * Without this dep wired, the cap counts only the credit side and an
   * operator-paid-direct provider bill is invisible to the cap —
   * surprising for "max $100 LLM spend under this mission" semantics.
   * Optional for backward compat: when unset, checkGate counts only the
   * Mission's credit spend.
   */
  llmUsageRepo?: {
    sumTotalCostByMission(operatorId: string, missionId: string, before?: Date, since?: Date): Promise<number>;
  };
  /**
   * What the Mission has spent on credit, and whether it is an agent account's standing Mission
   * (whose spend the account's budget governs). Absent: no credit spend and no accounts, which is
   * an install without a wallet.
   */
  missionSpend?: MissionSpendSource;
  /**
   * Counts a Mission's action limits (`max_actions`, `max_actions_per_service`) per Mission with a single conditional
   * update. Absent (an install), the gate counts the Mission's intent claims instead, which parallel calls can pass.
   */
  missionActions?: MissionActionCounter;
  /**
   * Told when a cap pauses a Mission, after the pause is stored: the owner's review is waiting (STACK publishes a
   * `mission.paused` notification). A failure is logged and never undoes the pause.
   */
  onPaused?: (event: MissionPausedEvent) => Promise<void>;
  /**
   * Told the owner's decision on a paused Mission (raised, continued, closed), for the agent the Mission was opened
   * for. A failure is logged and never undoes the decision.
   */
  onDecision?: DecisionReachedHook;
  /** The audit chain: a pause and the owner's review each leave a row. Optional for unit fixtures. */
  audit?: { write(input: MissionAuditInput): Promise<unknown> };
  /**
   * for resolving agent.twin_policy at mission open.
   * Optional for backward compat. When wired alongside
   * twinOrchestration + passportRepo, open() fires startTwinForMission
   * when the agent's policy resolves true for this mission.
   */
  agentRepo?: {
    findById(
      agentId: string,
    ): Promise<{ twin_policy?: string | null; [key: string]: unknown } | null | undefined>;
  };
  /** passport lookup to resolve the agent from the
   * open input's passportJti. */
  passportRepo?: {
    findByJti(
      jti: string,
    ): Promise<{ agent_id: string; [key: string]: unknown } | null | undefined>;
  };
  /** fired in open when twin_policy resolves true.
   * An earlier change adds evaluateDivergence wiring at complete/revoke. */
  twinOrchestration?: {
    startTwinForMission(input: {
      missionId: string;
      realPassportJti: string;
    }): Promise<{ twinPassportJti: string; twinRunId: string }>;
    evaluateDivergence(input: {
      missionId: string;
      operatorId: string;
    }): Promise<{ divergenceClaimId: string | null }>;
  };
}

/**
 * What a reserved Mission action is settled with when the call ends: `commit` counts it for good, `release` gives it back
 * (the call was refused or failed). Either may be called once; a second call does nothing.
 */
export interface MissionActionReservation {
  commit(): Promise<void>;
  release(): Promise<void>;
}

/**
 * The atomic counter behind a Mission's action limits. An action is reserved once, when the gate admits it, in one
 * conditional update per counter that refuses it when the limit has no room, so any number of parallel calls pass at most
 * the limit. The counters belong to the Mission, so every agent under it shares them. A deployment with no accounts has no
 * counter, and the gate counts the Mission's intent claims instead.
 */
export interface MissionActionCounter {
  /** What has been counted for a Mission, by scope (absent: nothing yet). */
  counts(input: { missionId: string; scopes: readonly string[] }): Promise<Record<string, number>>;
  /**
   * Reserve one action under `rules`, all or none. `ok: false` names the limit with no room. A rule with a limit of zero
   * refuses at once.
   */
  reserve(input: {
    missionId: string;
    rules: ReadonlyArray<{ cap: 'max_actions' | 'max_actions_per_service'; limit: number; scope: string }>;
  }): Promise<
    | { ok: true; reservation: MissionActionReservation }
    | { ok: false; cap: 'max_actions' | 'max_actions_per_service'; limit: number }
  >;
}

/**
 * the Passport side of "a Mission's end kills its Passports".
 * Implemented in passport-service.ts (createMissionPassportRevoker) and
 * injected here, so MissionService never imports PassportService.
 */
export interface MissionPassportRevoker {
  /** Runs inside the Mission's terminal transaction with the operator lock held. Throwing rolls the transition back. */
  revokeInTransaction(
    tx: MissionTransaction,
    input: { operatorId: string; missionId: string; reason: string; revokeAttachedClaims: boolean },
  ): Promise<Array<{ jti: string; expires_at: Date }>>;
  /** Post-commit cache sync (Redis `revoked:<jti>`). The database revoke is authoritative. */
  afterCommit(rows: Array<{ jti: string; expires_at: Date }>): Promise<void>;
}

export interface MissionView {
  assigned_agent_id?: string | null;
  authorization_digest?: string | null;
  mission_id: string;
  operator_id: string;
  claim_id: string; // latest claim_id (lifecycle pointer)
  /**
   * baseline-source passport JTI. Set when open carried
   * an explicit passportJti for baseline snapshotting. Read by
   * complete()/revoke() to compute behavioral_diff over the mission
   * window. NOT a runtime-authority edge — passport.mission_ids[] is.
   */
  passport_jti: string | null;
  intent_summary: string;
  intent_services: string[];
  expected_counterparties: string[];
  max_actions: number | null;
  max_dropoff_bytes: number | null;
  coverage_cap_cents: number | null;
  max_duration_seconds: number | null;
  max_concurrent_intents: number | null;
  max_actions_per_service: Record<string, number>;
  /** What each cap does when it is reached; a cap left out pauses the Mission. */
  cap_behavior: Record<string, MissionCapBehavior>;
  /** Whether the money cap counts the whole Mission or one day ending at midnight in cap_time_zone. */
  coverage_cap_period: CoverageCapPeriod;
  cap_time_zone: string;
  /** Set while a cap paused the Mission, with the cap (and the service of a per-service cap) that paused it. */
  paused_at: Date | null;
  paused_cap: MissionCapName | null;
  paused_service: string | null;
  /** What the owner pre-approved of the Mission's print-on-demand orders, in cents across all of them; null: none. */
  making_orders_up_to_cents: number | null;
  baseline_profile: Record<string, unknown> | null;
  expected_output_shape: Record<string, unknown> | null;
  /** Who the Mission may send to under a per-job rule; null when it pins no one. */
  recipient_pins?: RecipientPin[] | null;
  started_at: Date;
  expires_at: Date;
  completed_at: Date | null;
  revoked_at: Date | null;
  revoked_reason: MissionRevokeReason | null;
  terminal_state: MissionTerminalState | null;
}

export interface MissionListItem extends MissionView {
  dossier_count: number;
  evidence_pack_count: number;
}

export interface MissionListResult {
  items: MissionListItem[];
  page: number;
  limit: number;
  total: number;
  has_more: boolean;
}

export interface OpenInput {
  operatorId: string;
  /** Reserved by a durable server-side start operation, never a public override. */
  missionId?: string;
  authorizationDigest?: string;
  assignedAgentId?: string;
  intent_summary: string;
  intent_services?: string[];
  expected_counterparties?: string[];
  /**
   * When provided, scope_check validates `intent_services` is a subset
   * of these. Caller is typically PassportService.issue, which
   * has the passport's full services[] in hand; for standalone mission
   * creation against an existing passport, the caller derives the
   * superset from the passport's services + intent_services and
   * passes it here.
   *
   * When omitted, no subset check runs. This is correct for missions
   * issued WITHOUT a parent passport bound at open time (operator
   * opens a mission as a future-bind container, passports get issued
   * later with mission_ids referencing it). Validation in that mode
   * happens at passport-issue time instead.
   */
  parentPassportServices?: readonly string[];
  baseline_profile?: Record<string, unknown> | null;
  expected_output_shape?: Record<string, unknown> | null;
  max_actions?: number | null;
  max_dropoff_bytes?: number | null;
  coverage_cap_cents?: number | null;
  max_duration_seconds?: number | null;
  max_concurrent_intents?: number | null;
  max_actions_per_service?: Record<string, number>;
  /** What each cap does when it is reached: pause (the default), refuse_action or end_mission. */
  cap_behavior?: Partial<Record<MissionCapName, MissionCapBehavior>>;
  /** `day`: the money cap is what the Mission may spend in one day of cap_time_zone (default UTC). */
  coverage_cap_period?: CoverageCapPeriod;
  cap_time_zone?: string;
  /** What the owner pre-approves of the Mission's print-on-demand orders, in cents; set only by the owner or an admin. */
  making_orders_up_to_cents?: number | null;
  /**
   * Who this Mission may send to, for the policy send rules that leave their recipients to each Mission
   * (built by `buildRecipientPins`). Fixed at open: a Mission's pins are never changed or widened.
   */
  recipient_pins?: RecipientPin[] | null;
  /** Mission TTL in seconds. Default 900. No maximum, and no limit is needed at any length. */
  expiresInSeconds?: number;
  /**
   * opt-in baseline snapshot source. When provided AND
   * MissionService is wired with a BehavioralGenomeService, open()
   * fetches the passport's most recent behavioral_genome claim into
   * baseline_profile and stores passport_jti on the row + claim for
   * complete()/revoke() to find at mission end. When omitted,
   * baseline_profile + behavioral_diff stay null (legacy
   * behavior). The JTI is also used to del the
   * `genome_drift_fired:<jti>` Redis key so the drift detector
   * re-arms for the new baseline window.
   */
  passportJti?: string;
  /**
   * per-mission twin override. When set, ignores
   * agent.twin_policy and uses this value directly:
   *   - undefined: fall through to agent.twin_policy
   *   - true: fire twin runtime (mirrors 'always' for this one mission)
   *   - false: skip twin runtime (mirrors 'never' for this mission)
   */
  run_twin?: boolean;
}

export interface OpenResult {
  mission_id: string;
  claim_id: string;
  expires_at: Date;
}

export interface CompleteInput {
  /** Omitted only by trusted internal lifecycle callers, such as expiry sweeps. */
  actor?: { operatorId: string; agentId?: string };
  /**
   * Final output validated here and KMS encrypted before claim persistence.
   */
  output?: Record<string, unknown>;
  /**
   * When true, force terminal_state to 'completed_cap_breached'
   * regardless of other context. Used by the auto-revoke path for
   * soft caps (the worker hits the cap, marks the mission as
   * cap-breached + completed instead of revoked-adversarial).
   */
  capBreached?: boolean;
  /**
   * When true, this completion was triggered by the worker expiry
   * sweep. Sets terminal_state to 'completed_expired' instead
   * of 'completed_successful'.
   */
  expired?: boolean;
}

export interface CompleteResult {
  mission_id: string;
  claim_id: string;
  terminal_state: MissionTerminalState;
  completed_at: Date;
  /** True when this call performed the transition; false when the mission was already complete (idempotent no-op). */
  transitioned: boolean;
}

/**
 * Move a live Mission's expiry and coverage cap forward. Used only by the
 * agent-account renewal, which keeps an open account's standing Mission alive.
 */
export interface ExtendInput {
  expiresAt: Date;
  coverageCapCents: number | null;
}

export interface ExtendResult {
  mission_id: string;
  claim_id: string;
  expires_at: Date;
  coverage_cap_cents: number | null;
}

export interface RevokeInput {
  reason: MissionRevokeReason;
  /** Optional human-readable note attached to the claim's revoke_reason field via claim metadata (future extension). */
  notes?: string;
}

export interface RevokeResult {
  mission_id: string;
  claim_id: string;
  terminal_state: MissionTerminalState;
  revoked_at: Date;
  revoke_reason: MissionRevokeReason;
  /** True when this call performed the transition; false when the mission was already revoked (idempotent no-op). */
  transitioned: boolean;
}

/**
 * proxy gate verdict.
 *
 * Closed enum of reasons. Reasons starting with `cap_` carry a
 * `capBehavior` field the caller dispatches on; lifecycle / scope
 * reasons are hard denies with no cap path.
 */
export type GateReason =
  | 'mission_not_found'
  | 'mission_revoked'
  | 'mission_completed'
  | 'mission_paused'
  | 'mission_scope_mismatch'
  | 'cap_max_actions'
  | 'cap_max_actions_per_service'
  | 'cap_max_concurrent_intents'
  | 'cap_max_duration_seconds'
  | 'cap_coverage_cap_cents'
  | 'cap_max_dropoff_bytes';

export type GateVerdict =
  | { allowed: true; mission: MissionView; /** The Mission action this call reserved, to settle when it ends. */ reservation?: MissionActionReservation }
  | {
      allowed: false;
      reason: 'mission_not_found';
      message: string;
      mission?: undefined;
      capBehavior?: undefined;
    }
  | {
      allowed: false;
      reason: 'mission_revoked' | 'mission_completed' | 'mission_paused' | 'mission_scope_mismatch';
      message: string;
      mission: MissionView;
      capBehavior?: undefined;
    }
  | {
      allowed: false;
      reason:
        | 'cap_max_actions'
        | 'cap_max_actions_per_service'
        | 'cap_max_concurrent_intents'
        | 'cap_max_duration_seconds'
        | 'cap_coverage_cap_cents'
        | 'cap_max_dropoff_bytes';
      message: string;
      mission: MissionView;
      capBehavior: MissionCapBehavior;
      /** The service of a per-service cap. */
      capService?: string;
    };

/** A cap paused a Mission: the owner's review is waiting. */
export interface MissionPausedEvent {
  operatorId: string;
  missionId: string;
  /** The agent the Mission was opened for, when it names one. */
  agentId: string | null;
  cap: MissionCapName;
  service: string | null;
}

/** The audit row a pause or a review writes (the audit service's own input, named here so the engine needs no import of it). */
export interface MissionAuditInput {
  ctx: { trace_id: string; span_id: string; operator_id: string; agent_id: string; passport_jti: string };
  layer: 'system' | 'vault';
  action: string;
  outcome: 'success' | 'blocked';
  duration_ms: number;
  error?: { code: string; message: string };
}

/** The owner's decision on a paused Mission. */
export interface ReviewInput {
  operatorId: string;
  decision: 'raise' | 'continue' | 'close';
  /** The new limit of the cap that paused the Mission; only with `raise`, and above the old one. */
  limit?: number;
}

export interface ReviewResult {
  mission_id: string;
  decision: 'raise' | 'continue' | 'close';
  /** raised, continued or closed. */
  result: 'raised' | 'continued' | 'closed';
  mission: MissionView;
}
