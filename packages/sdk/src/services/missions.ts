// MissionsService TS SDK wrapper.
//
// Thin typed surface over /v1/missions/*. Core
// methods mirroring the REST routes:
//
//   start()     → POST /v1/missions/start (open + issue passport, one call)
//   open()      → POST /v1/missions
//   complete()  → POST /v1/missions/:id/complete
//   revoke()    → POST /v1/missions/:id/revoke
//   get()       → GET  /v1/missions/:id
//   list()      → GET  /v1/missions
//
// Wire shapes mirror the route handlers; types stay loose so SDK
// consumers don't take a peer-dep on @stack/shared schemas.

import type { HttpClient } from '../client.js';
import type { IssuePassportInput } from '../types.js';
import type { FleetMissionStartInput, FleetMissionResult, FleetAccess, FleetOperationAccess, FleetLimits } from './fleets.js';

export type MissionTerminalState =
  | 'completed_successful'
  | 'completed_expired'
  | 'completed_cap_breached'
  | 'revoked_adversarial'
  | 'revoked_operator_clean';

export type MissionRevokeReason =
  | 'adversarial'
  | 'cap_breach_hard'
  | 'operator_initiated_clean'
  | 'cascade_from_passport';

export type MissionCapName =
  | 'coverage_cap_cents'
  | 'max_dropoff_bytes'
  | 'max_concurrent_intents'
  | 'max_actions'
  | 'max_duration_seconds'
  | 'max_actions_per_service';

/**
 * What a cap does when it is reached. `pause` (the default for every cap): the Mission is paused, every action under it
 * is refused with `MISSION_PAUSED` and nothing is revoked, until the owner reviews it (`missions.review`).
 * `refuse_action`: only the action that would pass the cap is refused. `end_mission`: the Mission ends, and its Passports.
 */
export type MissionCapBehavior = 'pause' | 'refuse_action' | 'end_mission';

/** What the money cap counts: everything the Mission spends, or what it spends in one day of `cap_time_zone`. */
export type CoverageCapPeriod = 'mission' | 'day';

/** The owner's decision on a paused Mission. */
export type MissionReviewDecision = 'raise' | 'continue' | 'close';

export interface MissionReviewInput {
  decision: MissionReviewDecision;
  /** With `raise` only: the new limit of the cap that paused the Mission, above the old one, in that cap's unit. */
  limit?: number;
}

export interface MissionReviewResult {
  mission_id: string;
  decision: MissionReviewDecision;
  /** What the agent was told: raised, continued or closed. */
  result: 'raised' | 'continued' | 'closed';
  mission: MissionRecord;
}

/** A pin on this path applies to every recipient field a send names; a recipient inside the URL matches the path or one of its segments. */
export const MISSION_RECIPIENT_ANY_PATH = '*' as const;

/**
 * One recipient pin: who a Mission may send to at one field. `path` is `"*"` or a request field such as `body.to`,
 * `derived.email.recipients` or `url.pathname`; `eq` takes one exact value, `in` a list of exact values (up to 1,000
 * recipients). One pin per path, up to 64.
 */
export interface MissionRecipientPin {
  path: string;
  op: 'eq' | 'in';
  value: string | number | string[];
}

/**
 * Recipients: who a Mission may send to. A policy rule that leaves recipients to each Mission (`recipients:
 * "per_mission"`) allows a send only to these. Set when the Mission is opened; the owner can add more to a running
 * Mission with {@link MissionService.addRecipients}.
 */
export interface MissionRecipientsInput {
  /** Exact addresses, numbers or ids this Mission may send to, applied at every recipient field a send names. An address may be in any case; one listed twice is kept once. */
  recipients?: string[];
  /** Pins on named request fields, `"*"` for every recipient field a send names. One pin per path. */
  recipient_pins?: MissionRecipientPin[];
  /**
   * Reply to a message: the id of a message the agent's account received (an email, text or voicemail), or of an
   * incoming call the agent answered or declined (`acall_*`). Pins the Mission to the sender of that message or the caller, so the agent can answer that person and no one else. Combines with
   * `recipients` into one list. 404 `NOT_FOUND` when the message is not a readable one of the agent's own account, and 422 `MESSAGE_SENDER_NOT_VERIFIED` when it is an email the receiving server failed on DMARC.
   */
  reply_to_message?: string;
}

export interface OpenMissionInput extends MissionRecipientsInput {
  fleet_policy_id?: string;
  idempotency_key?: string;
  requested_access?: FleetAccess[];
  requested_operations?: FleetOperationAccess[];
  limits?: FleetLimits;
  authority_binding_ids?: string[];
  intent_summary: string;
  intent_services?: string[];
  expected_counterparties?: string[];
  baseline_profile?: Record<string, unknown> | null;
  expected_output_shape?: Record<string, unknown> | null;
  max_actions?: number | null;
  max_dropoff_bytes?: number | null;
  coverage_cap_cents?: number | null;
  max_duration_seconds?: number | null;
  max_concurrent_intents?: number | null;
  max_actions_per_service?: Record<string, number>;
  cap_behavior?: Partial<Record<MissionCapName, MissionCapBehavior>>;
  /** `mission` (default) or `day`: the money cap counts one day, ending at midnight in `cap_time_zone`. */
  coverage_cap_period?: CoverageCapPeriod;
  /** IANA time zone of a day of the money cap. Default UTC. */
  cap_time_zone?: string;
  /** What the owner pre-approves of the Mission's print-on-demand orders, in cents across all of them. Owner or admin only. */
  making_orders_up_to_cents?: number | null;
  expires_in_seconds?: number;
  /** Validates intent_services as a subset of these. Caller typically
   *  passes the resolved passport's services. Omit for unconstrained. */
  parent_passport_services?: string[];
  /** Passport used to bind the mission baseline and runtime window. */
  passport_jti?: string;
  /**
   * The agent (`agt_*`) this Mission is assigned to. Only that agent's
   * passport can bind it. An agent caller is always assigned itself.
   */
  agent_id?: string;
}

export interface OpenMissionResult {
  mission_id: string;
  claim_id: string;
  expires_at: string;
}

/** Mission spec for the one-call start: an ordinary open body without agent_id. */
export type OperatorMissionSpec = Omit<
  OpenMissionInput,
  | 'agent_id'
  | 'fleet_policy_id'
  | 'idempotency_key'
  | 'requested_access'
  | 'requested_operations'
  | 'limits'
  | 'authority_binding_ids'
>;

/**
 * Body of the operator form of `POST /v1/missions/start`: open a Mission
 * for `agent_id` and issue that agent's passport bound to it, in one call.
 * Usable with an operator API key, a white-label tenant key or a Connect
 * grant (which also needs `passports:write`).
 */
export interface OperatorMissionStartInput {
  agent_id: string;
  mission: OperatorMissionSpec;
  /**
   * Optional passport fields. When `intent` is omitted it defaults to the
   * Mission's intent_summary and intent_services.
   */
  passport?: Omit<IssuePassportInput, 'agent_id' | 'mission_ids'> & {
    identity_claim_ids?: string[];
    checkpoint_interval_seconds?: number;
  };
}

export interface OperatorMissionStartResult {
  mission_id: string;
  claim_id: string;
  expires_at: string;
  passport: { token: string; jti: string; expires_at: string };
}

export interface CompleteMissionInput {
  output?: Record<string, unknown>;
}

export interface CompleteMissionResult {
  mission_id: string;
  claim_id: string;
  terminal_state: MissionTerminalState;
  completed_at: string;
  transitioned: boolean;
}

export interface RevokeMissionInput {
  reason: 'adversarial' | 'operator_initiated_clean';
  notes?: string;
}

export interface RevokeMissionResult {
  mission_id: string;
  claim_id: string;
  terminal_state: MissionTerminalState;
  revoked_at: string;
  revoke_reason: MissionRevokeReason;
  transitioned: boolean;
}

export interface MissionRecord {
  fleet?: {
    policy_id: string;
    policy_name: string;
    policy_revision: number;
    current_policy_revision: number;
    policy_status: string;
    agent_id: string;
    membership_id: string;
    authorized_access: FleetAccess[];
    authorized_operations: FleetOperationAccess[];
    limits: FleetLimits;
    usage: FleetUsage;
    fleet_limits: FleetLimits;
    fleet_usage: FleetUsage;
    window_started_at: string;
    window_seconds: number;
  } | null;
  assigned_agent_id?: string | null;
  authorization_digest?: string | null;
  mission_id: string;
  operator_id: string;
  claim_id: string;
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
  cap_behavior: Partial<Record<MissionCapName, MissionCapBehavior>>;
  coverage_cap_period: CoverageCapPeriod;
  cap_time_zone: string;
  /** When a cap paused the Mission, and which (with the service for a per-service cap); null while it runs. */
  paused_at: string | null;
  paused_cap: MissionCapName | null;
  paused_service: string | null;
  making_orders_up_to_cents: number | null;
  baseline_profile: Record<string, unknown> | null;
  expected_output_shape: Record<string, unknown> | null;
  /** Who the Mission may send to, as pinned when it opened; null when it pinned no one. */
  recipient_pins: MissionRecipientPin[] | null;
  started_at: string;
  expires_at: string;
  completed_at: string | null;
  revoked_at: string | null;
  revoked_reason: MissionRevokeReason | null;
  terminal_state: MissionTerminalState | null;
  dossier_count?: number;
  evidence_pack_count?: number;
  output?: unknown;
  output_salt?: string;
  output_digest?: string;
}

export interface FleetUsage {
  actions: number;
  concurrent_actions: number;
  reserved_spend_cents: number;
  dropoff_bytes: number;
  unknown_actions: number;
}

export interface ListMissionsQuery {
  /** Only this agent's missions. */
  agent_id?: string;
  /** `paused`: the Missions a cap paused, waiting for the owner's review. */
  status?: 'active' | 'completed' | 'revoked' | 'paused';
  page?: number;
  limit?: number;
}

export interface ListMissionsResult {
  items: MissionRecord[];
  page: number;
  limit: number;
  total: number;
  has_more: boolean;
}

// Mission activity and Operator review reads.

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
  | 'dossier'
  | 'operator_review'
  | 'twin_divergence';

export interface ReplayedEvent {
  kind: ReplayedEventKind;
  at_ms: number;
  claim_id?: string | null;
  claim_hash?: string | null;
  body: Record<string, unknown>;
}

export interface ReplayedTimeline {
  mission: {
    mission_id: string;
    operator_id: string;
    closed: boolean;
    open?: Record<string, unknown>;
    close?: Record<string, unknown>;
  };
  events: ReplayedEvent[];
  behavioral_diff: {
    max_z: number;
    l2_norm: number;
    per_dimension: Record<string, number>;
  } | null;
  cap_usage: {
    max_actions: number | null;
    max_dropoff_bytes: number | null;
    coverage_cap_cents: number | null;
    observed_wallet_cents: number;
    observed_action_count: number;
  };
  dossiers: ReplayedEvent[];
  twin_divergence: ReplayedEvent | null;
}

export type IncidentClassification =
  | 'no_incident'
  | 'false_positive'
  | 'true_positive_handled'
  | 'true_positive_escalated'
  | 'inconclusive';

export interface DossierDecisionEntry {
  checkpoint_id: string;
  decision: string;
  rationale: string;
}

export interface DossierAlertEntry {
  detector_signal_claim_id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  narrative: string;
}

export interface CreateDossierInput {
  narrative: string;
  decision_tree?: DossierDecisionEntry[];
  alerts_walkthrough?: DossierAlertEntry[];
  lessons_learned: string;
  incident_classification: IncidentClassification;
}

export interface DossierClaim {
  type: 'dossier';
  mission_ref: string;
  authored_by_member_id: string;
  authored_at_ms: number;
  narrative: string;
  decision_tree: DossierDecisionEntry[];
  alerts_walkthrough: DossierAlertEntry[];
  lessons_learned: string;
  incident_classification: IncidentClassification;
  prior_dossier_ref: string | null;
}

export interface CreateDossierResult {
  claim_id: string;
  claim: DossierClaim;
}

export interface DossierEnvelope {
  claim_id: string;
  operator_id: string | null;
  issued_at_ms: number | null;
  body: DossierClaim;
}

export interface ListDossiersResult {
  items: DossierEnvelope[];
}

export type OperatorReviewAuthor =
  | { kind: 'operator_owner'; operator_id: string }
  | { kind: 'team_member'; member_id: string; role_at_signing: 'standard' | 'admin' };

export interface OperatorReviewClaim {
  type: 'operator_review';
  mission_ref: string;
  operator_id: string;
  authored_by: OperatorReviewAuthor;
  authored_at_ms: number;
  overall_judgment: string;
  checkpoint_notes: Array<{ checkpoint_claim_id: string; note: string }>;
  decision_rationales: Array<{
    operator_decision_claim_id: string;
    rationale: string;
  }>;
  alert_explanations: Array<{ detector_claim_id: string; explanation: string }>;
  incident_classification: IncidentClassification;
  lessons_learned: string;
  prior_review_ref: string | null;
  assessment_basis: 'operator_organization_assessment';
}

export interface OperatorReviewEnvelope {
  claim_id: string;
  claim_type?: 'dossier' | 'operator_review';
  claim: OperatorReviewClaim | DossierClaim;
  issued_at_ms: number | null;
}

export interface ListOperatorReviewsResult {
  items: OperatorReviewEnvelope[];
}

export class MissionsService {
  constructor(private client: HttpClient) {}

  /**
   * Open a Mission and issue its passport in one call.
   *
   * Operator form (`agent_id` + `mission`): opens a Mission assigned to the
   * agent and returns it with the passport bound to it. If issuance fails
   * the API revokes the Mission, so no passport-less Mission is left live.
   *
   * ```ts
   * const started = await stack.missions.start({
   *   agent_id: 'agt_x',
   *   mission: { intent_summary: 'Triage inbox', intent_services: ['gmail'], expires_in_seconds: 3600 },
   * });
   * // started.passport.token
   * ```
   *
   * Fleet form (`fleet_policy_id`): a fleet agent starts work under its
   * fleet policy. Unchanged.
   */
  async start(input: OperatorMissionStartInput): Promise<OperatorMissionStartResult>;
  async start(input: FleetMissionStartInput): Promise<FleetMissionResult>;
  async start(
    input: OperatorMissionStartInput | FleetMissionStartInput,
  ): Promise<OperatorMissionStartResult | FleetMissionResult> {
    return this.client.post('/v1/missions/start', input);
  }

  async renew(missionId: string): Promise<FleetMissionResult> {
    return this.client.post(`/v1/missions/${encodeURIComponent(missionId)}/renew`, {});
  }

  /**
   * Open a new mission. Returns the signed mission_open claim_id +
   * the stable mission_id (ms_*). Every passport is issued for exactly
   * one Mission: pass it as `mission_ids: [mission_id]` to
   * `passports.issue`. Pass `agent_id` to assign the Mission to that
   * agent. Opening a Mission is not metered; issuing the passport is.
   */
  async open(input: OpenMissionInput): Promise<OpenMissionResult> {
    return this.client.post<OpenMissionResult>('/v1/missions', input);
  }

  /**
   * Mark a mission complete (terminal_state='completed_successful').
   * Revokes every passport bound to the mission in the same transaction.
   * Idempotent — second call returns the prior terminal state with
   * transitioned=false. Throws ConflictError-shaped 409 if the
   * mission was already revoked.
   */
  async complete(
    missionId: string,
    input: CompleteMissionInput = {},
  ): Promise<CompleteMissionResult> {
    return this.client.post<CompleteMissionResult>(
      `/v1/missions/${encodeURIComponent(missionId)}/complete`,
      input,
    );
  }

  /**
   * Revoke a mission. With either reason, every passport bound to the
   * mission is revoked in the same transaction: a passport never
   * outlives its Mission.
   */
  async revoke(
    missionId: string,
    input: RevokeMissionInput,
  ): Promise<RevokeMissionResult> {
    return this.client.post<RevokeMissionResult>(
      `/v1/missions/${encodeURIComponent(missionId)}/revoke`,
      input,
    );
  }

  /**
   * Add who a running Mission may send to: recipients, field pins or the sender of a received message, merged into the
   * pins it has (nothing already pinned is taken away). The owner's call; an agent's own credential is refused. Returns
   * the pins the Mission holds now. 409 for a Mission that has ended.
   */
  async addRecipients(missionId: string, input: MissionRecipientsInput): Promise<{ mission_id: string; recipient_pins: MissionRecipientPin[] }> {
    return this.client.post<{ mission_id: string; recipient_pins: MissionRecipientPin[] }>(
      `/v1/missions/${encodeURIComponent(missionId)}/recipients`,
      input,
    );
  }

  /**
   * Fetch a single mission by id. Returns 404 for unknown or
   * cross-tenant missions (existence hidden across operators).
   */
  async get(missionId: string): Promise<MissionRecord> {
    return this.client.get<MissionRecord>(
      `/v1/missions/${encodeURIComponent(missionId)}`,
    );
  }

  /**
   * List missions for the calling operator. Default ordering newest
   * first by started_at. Filter by status / pagination via query.
   */
  async list(query: ListMissionsQuery = {}): Promise<ListMissionsResult> {
    const params = new URLSearchParams();
    if (query.agent_id) params.set('agent_id', query.agent_id);
    if (query.status) params.set('status', query.status);
    if (query.page !== undefined) params.set('page', String(query.page));
    if (query.limit !== undefined) params.set('limit', String(query.limit));
    const suffix = params.toString();
    return this.client.get<ListMissionsResult>(
      `/v1/missions${suffix ? `?${suffix}` : ''}`,
    );
  }

  /**
   * Decide a Mission one of its caps paused: `raise` sets a new limit for the cap that paused it and lets it go on,
   * `continue` lets it go on as it is (a cap with no room left pauses it again), `close` ends it. The agent the Mission
   * was opened for is told the decision. The owner's or a member's own decision; an agent cannot decide its own pause.
   */
  async review(missionId: string, input: MissionReviewInput): Promise<MissionReviewResult> {
    return this.client.post<MissionReviewResult>(`/v1/missions/${encodeURIComponent(missionId)}/review`, input);
  }

  /**
   * Set what the owner pre-approves of a running Mission's print-on-demand orders, in cents across all of them; null
   * removes it. The owner or an admin only.
   */
  async setMakingAllowance(missionId: string, makingOrdersUpToCents: number | null): Promise<MissionRecord> {
    return this.client.put<MissionRecord>(`/v1/missions/${encodeURIComponent(missionId)}/making-allowance`, {
      making_orders_up_to_cents: makingOrdersUpToCents,
    });
  }

  /** View the current recorded activity for a mission. */
  /** View the current recorded activity for a mission. It reads the record, a controls feature: `ControlsRequiredError` (402) without controls. */
  async activity(missionId: string): Promise<ReplayedTimeline> {
    return this.client.get<ReplayedTimeline>(
      `/v1/missions/${encodeURIComponent(missionId)}/replay`,
    );
  }

  /** Compatibility alias for integrations that use the old method name. */
  async replay(missionId: string): Promise<ReplayedTimeline> {
    return this.activity(missionId);
  }

  /** List signed Operator review revisions for a mission. */
  async listOperatorReviews(missionId: string): Promise<ListOperatorReviewsResult> {
    return this.client.get<ListOperatorReviewsResult>(
      `/v1/missions/${encodeURIComponent(missionId)}/operator-reviews`,
    );
  }

  /** Download the exact signed COSE bytes for one Operator review. A controls feature: `ControlsRequiredError` without controls. */
  async downloadOperatorReview(missionId: string, claimId: string): Promise<Uint8Array> {
    return this.client.getBytes(
      `/v1/missions/${encodeURIComponent(missionId)}/operator-reviews/${encodeURIComponent(claimId)}/download`,
    );
  }

  /** Compatibility read for old dossier claims only. */
  async listDossiers(missionId: string): Promise<ListDossiersResult> {
    const reviews = await this.listOperatorReviews(missionId);
    return {
      items: reviews.items
        .filter((review): review is OperatorReviewEnvelope & { claim: DossierClaim } =>
          review.claim.type === 'dossier',
        )
        .map((review) => ({
          claim_id: review.claim_id,
          operator_id: null,
          issued_at_ms: review.issued_at_ms,
          body: review.claim,
        })),
    };
  }
}
