import { z } from 'zod';

/**
 * mission — sealed binding for a unit of agent work.
 *
 * of the Signed Primitive epic. Pillar 1 of
 * the Mission Layer (the Mission layer design).
 *
 * A mission binds:
 *   - the operator (the claim is operator-scoped; subjectOverride='operator')
 *   - the intent + scope for this run
 *   - an optional behavioural baseline at issue-time (placeholder; the
 *     full behavioral_genome claim is
 *   - an optional expected output shape and counterparty list
 *   - six resource caps (action count, drop-off bytes, money, wall-clock,
 *     concurrent intents, per-service action sub-caps)
 *   - per-cap behavior overrides (which caps revoke vs which deny-and-flag)
 *   - lifecycle timestamps (started, expires, completed)
 *   - terminal_state + revoke_reason (set on completion / revocation)
 *
 * Passports carry `mission_ids: string[]` in their JWT payload; each
 * intent_claim carries `mission_ref: pc_*` pointing to the mission
 * claim it belongs to. The proxy checks mission claim status on each
 * action — revoked or completed missions stop authorizing new work.
 * Per-mission revocation cascades via the `bulk_mission` RevocationEvent
 * variant; whether the parent passport(s) also revoke depends on the
 * mission's `revoke_reason` (adversarial / cap_breach_hard cascade;
 * operator_initiated_clean does not).
 *
 * Cap-hit behavior:
 *   - coverage_cap_cents      → auto_revoke (default; money exhaustion is adversarial)
 *   - max_dropoff_bytes       → auto_revoke (default; exfil shape)
 *   - max_concurrent_intents  → auto_revoke (default; loop-explosion shape)
 *   - max_actions             → deny_and_flag (default; behavioral overrun)
 *   - max_duration_seconds    → deny_and_flag (default; worker auto-completes on expires_at)
 *   - max_actions_per_service → deny_and_flag (default; scope misjudgment)
 * Operator overrides per cap via `cap_behavior` map.
 *
 * Missions run on every account.
 */
export const MissionClaim = z.object({
  type: z.literal('mission'),

  /** Mission identifier. ms_* prefix. */
  mission_id: z.string().regex(/^ms_[\w-]+$/, 'mission_id must be ms_*'),
  assigned_agent_id: z.string().nullable().optional(),
  /** Commitment to immutable server-resolved fleet authorization. */
  authorization_digest: z.string().regex(/^[a-f0-9]{64}$/).nullable().optional(),
  /** Salted commitment to separately encrypted output, stable across key rotation. */
  output_digest: z.string().regex(/^[a-f0-9]{64}$/).nullable().optional(),

  /** Issuing operator. Matches the envelope's issuer. */
  operator_id: z.string(),

  /**
   * baseline-source passport JTI. Set at mission open
   * when the operator opts into behavioral baseline snapshotting. NOT a
   * runtime-authority edge:'s `passport.mission_ids[]` is
   * the authority graph (which passports can act under this mission);
   * `mission.passport_jti` is purely the analytic provenance pointer
   * (which passport's recent behavioral_genome was snapshotted as
   * baseline_profile, and which passport's window we compute for
   * behavioral_diff at complete()). Mirror lives on the missions row
   * column for operational read; this schema field is the signed
   * forensic record. Null on legacy missions + missions
   * opened without baseline snapshotting.
   */
  passport_jti: z.string().nullable().default(null),

  /** Free-form human-readable intent: "wire $50k to Stripe", "publish blog post drafts". */
  intent_summary: z.string().max(500),

  /**
   * Services the mission expects to touch. Catalog membership not
   * validated at schema level (operator can name anything); the proxy
   * + scope-drift detector are responsible for runtime enforcement.
   */
  intent_services: z.array(z.string()).default([]),

  /**
   * Baseline behavioural fingerprint at issue time. stored
   * any operator-provided snapshot or null. Post-5.1.5: when
   * MissionService is wired with a BehavioralGenomeService AND open()
   * carries a passport_jti, this field is populated with the FULL
   * BehavioralGenomeClaim payload of the passport's most recent active
   * genome at mission-open time. Schema kept opaque
   * (z.record.nullable) for backward compat with
   * missions; consumers MUST safeParse against BehavioralGenomeClaim
   * and fall through to null-diff on parse failure (see
   * mission-service.ts complete()).
   */
  baseline_profile: z.record(z.string(), z.unknown()).nullable().default(null),

  /**
   * terminal-state behavioral diff. Computed at complete
   * AND revoke() when baseline_profile is a valid BehavioralGenomeClaim
   * payload AND passport_jti is populated. Shape mirrors
   * BehavioralDiffResult from BehavioralGenomeService (max_z + l2_norm +
   * per_dimension). Null at open, on legacy missions, on
   * missions without baseline snapshotting, or when diff math failed
   * (best-effort: mission MUST complete even if diff fails).
   */
  behavioral_diff: z.object({
    max_z: z.number(),
    l2_norm: z.number(),
    per_dimension: z.record(z.string(), z.number()),
  }).nullable().default(null),

  /**
   * Expected success shape. Optional. JSON Schema-ish object the
   * operator declared as "what success looks like." Replay + dossier
   * will diff actual outputs against this.
   */
  expected_output_shape: z.record(z.string(), z.unknown()).nullable().default(null),

  /**
   * Pre-registered counterparty URIs. Optional. For payments missions:
   * the wallet address / merchant ID. For comms missions: the recipient
   * address.
   *
   * Pre-declaring a counterparty here suppresses the first-touch
   * `undeclared_target` flag for it: the intent simulator seeds
   * the bound mission's expected_counterparties into the observed-entity set,
   * so a declared target is treated as already-observed and does not trip the
   * detector on first use. (Undeclared targets still flag on first touch and
   * self-clear after the first successful call, as before.)
   */
  expected_counterparties: z.array(z.string()).default([]),

  /** Hard cap on proxy/skill actions for this mission. Null = unbounded. */
  max_actions: z.number().int().positive().nullable().default(null),

  /** Hard cap on drop-off bytes. Null = unbounded. */
  max_dropoff_bytes: z.number().int().nonnegative().nullable().default(null),

  /**
   * Coverage cap in cents. Null = uncovered. Basis for the insurance
   * SKU; v1 carries the value, no actual underwriter is enforcing yet.
   */
  coverage_cap_cents: z.number().int().nonnegative().nullable().default(null),

  /**
   * Wall-clock cap from started_at, in seconds. Null = bounded only by
   * expires_at. When set, the worker auto-completes the mission with
   * terminal_state='completed_expired' when (now - started_at) > cap.
   */
  max_duration_seconds: z.number().int().positive().nullable().default(null),

  /**
   * Maximum number of intents in-flight at once under this mission.
   * Null = unbounded. Prevents loop-explosion (agent spawning intents
   * faster than they resolve). Checked at intent-submission time.
   */
  max_concurrent_intents: z.number().int().positive().nullable().default(null),

  /**
   * Per-service action sub-caps. Empty map = no per-service limits.
   * Total proxy/skill actions to a given service can't exceed the
   * value here even if global max_actions has headroom. Use when one
   * service in the mission carries different risk than others
   * (e.g. mission can do 50 Slack messages but only 1 Stripe charge).
   */
  max_actions_per_service: z.record(z.string(), z.number().int().positive()).default({}),

  /**
   * Per-cap behavior override. Key is the cap field name; value is the
   * response when that cap is crossed. Empty map = defaults from the
   * table in the schema docstring above (adversarial-shape caps
   * auto-revoke; behavioral-shape caps deny-and-flag).
   *
   * Operator can set per-mission to alter response. Example: a mission
   * with strict accountability might set
   * `cap_behavior: { max_actions: 'auto_revoke' }` to escalate any
   * overrun to revocation.
   */
  cap_behavior: z.record(
    z.enum([
      'coverage_cap_cents',
      'max_dropoff_bytes',
      'max_concurrent_intents',
      'max_actions',
      'max_duration_seconds',
      'max_actions_per_service',
    ]),
    z.enum(['auto_revoke', 'deny_and_flag']),
  ).default({}),

  /** unix ms — mission started (claim issued). */
  started_at: z.number().int(),

  /** unix ms — mission expires (claim becomes stale). */
  expires_at: z.number().int(),

  /**
   * unix ms — mission completed. Null while active. Set by both
   * successful completion paths (explicit POST + output validated) and
   * worker auto-completion on expires_at. Read terminal_state below for
   * which path produced this timestamp. Runtime enforcement still keys
   * off revoked_at on the claim row for the revocation check.
   */
  completed_at: z.number().int().nullable().default(null),

  /**
   * Terminal state marker. Null while active. Set when mission reaches
   * a terminal state via one of five paths:
   *   - completed_successful   — explicit POST + output_shape validated
   *   - completed_expired      — worker tripped on expires_at or max_duration_seconds
   *   - completed_cap_breached — soft cap hit, operator left mission to expire
   *   - revoked_adversarial    — hard cap auto-revoke OR operator with reason=adversarial
   *   - revoked_operator_clean — operator killed for benign reason
   *
   * Distinct from completed_at + revoked_at row columns: this is the
   * signed audit-grade reason that gets sealed in the claim. The row
   * columns are denormalized caches for fast filtering.
   */
  terminal_state: z.enum([
    'completed_successful',
    'completed_expired',
    'completed_cap_breached',
    'revoked_adversarial',
    'revoked_operator_clean',
  ]).nullable().default(null),

  /**
   * Why the mission was revoked. Null unless terminal_state starts
   * with `revoked_`. Controls cascade behavior in MissionService.revoke:
   *   - adversarial             → cascade-revoke parent passport(s)
   *   - cap_breach_hard         → cascade-revoke parent passport(s)
   *   - operator_initiated_clean → leave passport(s) active, only kill mission scope
   *   - cascade_from_passport   → no further cascade (parent passport revoke already cascaded inward)
   */
  revoke_reason: z.enum([
    'adversarial',
    'cap_breach_hard',
    'operator_initiated_clean',
    'cascade_from_passport',
  ]).nullable().default(null),
});

export type MissionClaim = z.infer<typeof MissionClaim>;
