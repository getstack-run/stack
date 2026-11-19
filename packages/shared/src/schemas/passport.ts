import { z } from 'zod';
import { AssuranceLevel, PassportClaimRef } from './identity.js';
import { AuthorityReference } from './authority.js';
import { IntentRef } from '../intents/types.js';
import { DETECTOR_KEYS } from '../constants/detectors.js';

export { AssuranceLevel };

// Parameter-level scope constraint. Carried on ServiceScope to gate
// individual proxy calls against per-field predicates (e.g. Slack channel
// allowlist, GitHub repo allowlist). Evaluated by `findFailingConstraint`
// in shared/utils/constraints.ts. AND semantics across the array.
//
// `path` uses dotted notation into the NormalizedRequest view:
//   method | url.pathname | url.host | url.origin
//   headers.<name> (case-insensitive)
//   query.<key>            (URL parameters included; a repeated key is a list)
//   body.<dotted.path.into.json>
//   body.<list>[].<field>  (every element of an array: body.to[].email)
//   derived.email.recipients | .from | .subject | .text
//                          (an encoded Gmail or Outlook message, decoded;
//                          unreadable means absent, so a pin refuses it)
//
// `matches` values are compiled with RE2 (linear-time; no ReDoS) and
// capped at 256 chars. `in` / `not_in` accept string arrays only.
export const ConstraintOp = z.enum([
  'eq',
  'not_eq',
  'in',
  'not_in',
  'matches',
  'starts_with',
  // Numeric comparison. Without these a spend or size cap was unwritable —
  // and the intent catalogue told operators to write one anyway
  // (`stripe.create_charge`: "pair with an amount cap", and four siblings).
  // A numeric string is accepted so form-encoded bodies and query params,
  // which are always strings on the wire, can be capped too.
  'lt',
  'lte',
  'gt',
  'gte',
  // Presence. Every other op fails on a missing field, which made a
  // deny-list unusable: `not_eq` on an absent field denied every request
  // that simply omitted it. `custom.require_query_absent` was a broken
  // attempt at exactly this and denied the case it existed to allow.
  'exists',
  'not_exists',
]);
export type ConstraintOp = z.infer<typeof ConstraintOp>;

export const PlainConstraint = z
  .object({
    path: z.string().min(1).max(128),
    op: ConstraintOp,
    value: z.union([
      z.string().max(1024),
      z.number(),
      z.boolean(),
      z.array(z.string().max(1024)).max(256),
    ]),
  })
  .refine(
    (c) => {
      if (c.op === 'matches' || c.op === 'starts_with') {
        return typeof c.value === 'string';
      }
      if (c.op === 'in' || c.op === 'not_in') {
        return Array.isArray(c.value);
      }
      if (c.op === 'lt' || c.op === 'lte' || c.op === 'gt' || c.op === 'gte') {
        return typeof c.value === 'number' && Number.isFinite(c.value);
      }
      // exists / not_exists ignore `value`; the field must still be present
      // on the object so the wire shape stays uniform.
      return true;
    },
    { message: 'op requires a compatible value type' },
  )
  .refine(
    (c) => c.op !== 'matches' || (typeof c.value === 'string' && c.value.length <= 256),
    { message: 'matches value must be ≤ 256 chars' },
  );
export type PlainConstraint = z.infer<typeof PlainConstraint>;

/**
 * Several rules where any ONE admits the call: `value` is a list of groups,
 * each group a list of plain constraints that must all hold, and a request
 * passes when it satisfies every constraint of at least one group. This is
 * how a grant carries a read rule and a post rule on one connection without
 * the two cancelling out (a flat constraint list is AND). It sits among the
 * other constraints, so every one of them still has to hold as well, and it
 * travels wherever constraints do: a grant, a Passport scope, a delegation,
 * a policy rule. Groups do not nest.
 */
export const ANY_OF_OP = 'any_of';
export const ANY_OF_MAX_GROUPS = 16;
export const ANY_OF_MAX_LEAVES = 128;
export const AnyOfConstraint = z
  .object({
    path: z.literal(ANY_OF_OP),
    op: z.literal(ANY_OF_OP),
    value: z.array(z.array(PlainConstraint).min(1).max(32)).min(2).max(ANY_OF_MAX_GROUPS),
  })
  .refine((c) => c.value.reduce((sum, group) => sum + group.length, 0) <= ANY_OF_MAX_LEAVES, {
    message: `any_of holds at most ${ANY_OF_MAX_LEAVES} constraints in all`,
  });
export type AnyOfConstraint = z.infer<typeof AnyOfConstraint>;

export const Constraint = z.union([PlainConstraint, AnyOfConstraint]);
export type Constraint = z.infer<typeof Constraint>;

/**
 * How many choices of rules (`any_of`) one scope may hold. Comparing two scopes takes the product of their
 * choices, and a Passport that holds more would not fit in a request header anyway.
 */
export const MAX_ANY_OF_PER_SCOPE = 8;

/** A list of constraints of one scope: at most 32, and at most MAX_ANY_OF_PER_SCOPE of them a choice of rules. */
export const withinAnyOfBudget = (list: readonly { op: string }[]): boolean =>
  list.reduce((n, c) => n + (c.op === 'any_of' ? 1 : 0), 0) <= MAX_ANY_OF_PER_SCOPE;
export const ANY_OF_BUDGET_MESSAGE = `A scope holds at most ${MAX_ANY_OF_PER_SCOPE} choices of rules (any_of).`;

/**
 * How an operation's path is matched against `url.pathname`.
 */
export const PathMatch = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('exact'), value: z.string().min(1).max(512) }),
  z.object({ kind: z.literal('prefix'), value: z.string().min(1).max(512) }),
  z.object({ kind: z.literal('regex'), value: z.string().min(1).max(512) }),
]);
export type PathMatch = z.infer<typeof PathMatch>;

/**
 * One operation a scope may perform, and the fields it may carry.
 *
 * `allow_fields` is the inversion that matters. Constraints pin the fields
 * someone thought of; this declares the complete set, so a field nobody
 * anticipated is refused for want of permission rather than for want of a
 * prohibition.
 */
export const DeclaredOperation = z.object({
  id: z.string().min(1).max(128),
  methods: z.array(z.string().min(1).max(16)).min(1).max(8),
  path: PathMatch,
  allow_fields: z.array(z.string().min(1).max(256)).max(128).default([]),
  constraints: z.array(Constraint).max(32).optional(),
});
export type DeclaredOperation = z.infer<typeof DeclaredOperation>;

/**
 * A scope's operation policy.
 *
 * `open` is the legacy posture: anything not explicitly constrained is
 * permitted. `closed` enforces the declarations. Existing passports carry no
 * policy and are treated as open, so this can land without breaking them
 * while operators migrate.
 */
export const ScopePolicy = z.object({
  mode: z.enum(['closed', 'open']),
  operations: z.array(DeclaredOperation).max(64).default([]),
});
export type ScopePolicy = z.infer<typeof ScopePolicy>;

export const ServiceScope = z.object({
  service_id: z.string(),
  service_name: z.string(),
  scopes: z.array(z.string()),
  credential_ref: z.string(),
  // Canonical connection ID (`scon_*`). Required for new passports;
  // optional on the schema for backward-compat with tokens issued before
  // this field landed (old tokens drain within PASSPORT_MAX_TTL_SECONDS).
  // Used by passport-service.verify() freshness check + delegate() parent
  // service-find. Distinct from `credential_ref` (which is the KMS keyRef
  // for the encrypted credential blob — not a connection id).
  connection_id: z.string().optional(),
  // Optional parameter-level constraints. Missing → service-level scope only
  // (legacy behavior). Present → proxy enforces each constraint per request.
  constraints: z.array(Constraint).max(32).refine(withinAnyOfBudget, { message: ANY_OF_BUDGET_MESSAGE }).optional(),
  // Closed-operation policy. Absent → open, i.e. unchanged behaviour.
  policy: ScopePolicy.optional(),
  /**
   * Services whose content may flow INTO this one.
   *
   * The data-flow rule refuses a request that carries content the agent read
   * from a different service. That is the guestbook case: reading the names
   * is legitimate, mailing them elsewhere is not, and both calls are
   * individually in scope. Where an operator genuinely wants the movement —
   * a digest job that reads a database and emails a summary — they declare
   * it here, on the DESTINATION scope: "resend may receive content from
   * guestbook".
   *
   * Absent or empty means no cross-service movement into this service is
   * permitted. Content read from a service may always go back to that same
   * service; that is ordinary read-then-write and needs no declaration.
   */
  allow_data_from: z
    .array(z.string().min(1).max(128).refine((value) => value !== '*', {
      message: 'allow_data_from on a Passport must name exact services',
    }))
    .max(32)
    .optional(),
});
export type ServiceScope = z.infer<typeof ServiceScope>;

/**
 * (auth refactor): platform-intent claim values for passport-as
 * inbound-auth on STACK's own API. Only present when the passport
 * authenticates platform-staff or platform-monitor scope; regular
 * operator-scoped passports omit it. Issuance gated by
 * issuer.is_platform_staff (and issuer = op_stack_system for monitor).
 * NEVER survives delegation. See packages/vault/src/crypto/passport-
 * signer.ts; the scope hierarchy itself is mounted in apps/api/src/server.ts.
 */
export const PlatformIntent = z.enum(['staff', 'monitor']);
export type PlatformIntent = z.infer<typeof PlatformIntent>;

/** Server-derived references. Never accepted by public Passport issue input. */
export const FleetPassportBinding = z.object({
  policy_id: z.string().min(1).max(128),
  policy_revision: z.number().int().positive(),
  membership_id: z.string().min(1).max(128),
  mission_id: z.string().regex(/^ms_[\w-]+$/),
  internal_root: z.literal(true).optional(),
}).strict();
export type FleetPassportBinding = z.infer<typeof FleetPassportBinding>;

/**
 * Server-derived marker on a Passport made for one workspace command. It is never accepted from a caller (the public
 * issue input has no such field) and delegation carries it down. A Passport that has it reaches STACK's proxy and
 * nothing else, and is never refreshed: it is the command's credential, not an identity that can keep itself alive.
 */
export const WorkspaceCommandBinding = z.object({
  workspace_id: z.string().min(1).max(64),
}).strict();
export type WorkspaceCommandBinding = z.infer<typeof WorkspaceCommandBinding>;

// STACK-specific JWT claims
export const PassportClaims = z.object({
  operator_id: z.string(),
  agent_id: z.string(),
  agent_name: z.string(),
  services: z.array(ServiceScope),
  /** Claim references — Layer 1 & 3 data is inline, Layer 2 PII resolved server-side */
  identity_claims: z.array(PassportClaimRef).default([]),
  delegation_depth: z.number().int().min(0).max(4),
  parent_passport_id: z.string().optional(),
  session_id: z.string(),
  // Accountability
  accountability: z.enum(['enforced', 'logged', 'standard']).optional(),
  intent_summary: z.string().optional(),
  intent_services: z.array(z.string()).optional(),
  // Full intent references (name + params) preserved on the passport so
  // proxy telemetry (e.g. upstream_not_found) can surface the specific
  // intent responsible, not just the service list. Optional for backward
  // compatibility with tokens issued before this claim existed.
  intent_refs: z.array(IntentRef).optional(),
  checkpoint_interval: z.number().optional(),
  // platform-intent. Optional; never present on regular passports.
  platform_intent: PlatformIntent.optional(),
  // mission binding. When set, every intent
  // submitted under this passport implicitly references one of these
  // missions (producer auto-resolve picks the unique active one; explicit
  // mission_ref on the intent payload overrides). The proxy gate (5.0.5)
  // enforces each active mission's scope + caps on every action. Empty
  // / omitted = passport not under any mission (standard
  // behavior; the passport's services + intent_services are the only
  // scope). Multiple ms_* IDs supported (concurrent missions per
  // passport per architectural decision D4).
  mission_ids: z.array(z.string().regex(/^ms_[\w-]+$/, 'mission_id must be ms_*')).optional(),
  /**
   * Optional opaque references to the exact immutable authority bindings that
   * permit this Passport's agent to act. Each referenced binding resolves the
   * principal, proof set, receiver, purpose, scope, approvals, and lifecycle;
   * none of those values are copied into this bearer token.
   */
  authority_refs: z.array(AuthorityReference).max(8).optional(),
  fleet: FleetPassportBinding.optional(),
  /** Set only on a Passport made for one workspace command. See `WorkspaceCommandBinding`. */
  workspace_command: WorkspaceCommandBinding.optional(),
});
export type PassportClaims = z.infer<typeof PassportClaims>;

// ─── Online verification and revocation (wire shapes) ────────────────

/**
 * `POST /v1/passports/verify`. SDK clients send `service_id: null` when none
 * was given, so the field accepts null as well as absence.
 */
export const VerifyPassportInput = z.object({
  token: z.string(),
  service_id: z.string().nullish(),
});
export type VerifyPassportInput = z.infer<typeof VerifyPassportInput>;

/**
 * The answer to a Passport that is valid right now. Every other outcome is an
 * error envelope (`PASSPORT_EXPIRED`, `PASSPORT_REVOKED`, ...), never
 * `valid: false`.
 */
export const VerifyPassportResult = z.object({
  valid: z.literal(true),
  jti: z.string(),
  agent_id: z.string(),
  expires_at: z.string(),
  claims: PassportClaims,
});
export type VerifyPassportResult = z.infer<typeof VerifyPassportResult>;

/**
 * What is published on the revocation channel (`stack:revoked`) when
 * Passports are revoked. The channel is a notification: the revocation flag
 * on each Passport, not this message, is what verification reads.
 */
export const RevocationEvent = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('single'),
    operator_id: z.string(),
    jti: z.string(),
    cascaded: z.array(z.string()),
    reason: z.string(),
    at: z.number(),
  }),
  z.object({
    type: z.literal('bulk_agent'),
    operator_id: z.string(),
    agent_id: z.string(),
    revoked_count: z.number(),
    cascaded_count: z.number(),
    reason: z.string(),
    at: z.number(),
  }),
  z.object({
    type: z.literal('bulk_session'),
    operator_id: z.string(),
    session_id: z.string(),
    revoked_count: z.number(),
    reason: z.string(),
    at: z.number(),
  }),
  z.object({
    type: z.literal('bulk_operator'),
    operator_id: z.string(),
    revoked_count: z.number(),
    reason: z.string(),
    at: z.number(),
  }),
  z.object({
    type: z.literal('bulk_claim'),
    operator_id: z.string(),
    claim_id: z.string(),
    revoked_count: z.number(),
    reason: z.string(),
    at: z.number(),
  }),
  z.object({
    type: z.literal('bulk_mission'),
    operator_id: z.string(),
    mission_id: z.string(),
    revoke_reason: z.string(),
    cascaded_passport_jtis: z.array(z.string()),
    at: z.number(),
  }),
]);
export type RevocationEvent = z.infer<typeof RevocationEvent>;

export const PassportIntentInput = z.object({
  summary: z.string().min(1).max(500),
  services: z.array(z.string()),
  will_delegate: z.boolean().optional(),
  estimated_duration_seconds: z.number().int().min(60).max(86400).optional(),
  // Optional full intent references (name + params). When provided,
  // these are preserved on the passport's JWT claims and DB row so
  // downstream telemetry (e.g. proxy upstream_not_found) can surface
  // the specific intent responsible instead of only the service list.
  // Additive: existing callers that only send summary + services
  // continue to work unchanged.
  refs: z.array(IntentRef).max(64).optional(),
  // (auth refactor): platform-intent. When set, the passport
  // becomes inbound-auth for STACK's own API at platform-staff or
  // platform-monitor scope. Issuance gated by issuer.is_platform_staff
  // = true (and issuer = op_stack_system for 'monitor'). Never survives
  // delegation. Will-delegate must NOT be true when platform_intent is
  // set — passport-service.issue rejects the combination.
  platform_intent: PlatformIntent.optional(),
});
export type PassportIntentInput = z.infer<typeof PassportIntentInput>;

/** Field shape of IssuePassportInput for consumers that inspect keys. Parse with IssuePassportInput. */
export const IssuePassportInputObject = z.object({
  agent_id: z.string(),
  scopes: z
    .array(
      z.object({
        service_connection_id: z.string(),
        scopes: z.array(z.string()),
        // Optional per-scope tightening. These are ADDED on top of the
        // grant's baseline constraints — together they must still form a
        // superset of the baseline (i.e., never loosen what the operator
        // set at grant time).
        constraints: z.array(Constraint).max(32).refine(withinAnyOfBudget, { message: ANY_OF_BUDGET_MESSAGE }).optional(),
        intents: z.array(IntentRef).max(32).optional(),
        // Optional per-scope data-flow declaration. Names the services whose
        // content may flow INTO this one (enforced by the scope wall's
        // data-flow rule; see ServiceScope.allow_data_from). Unlike
        // `constraints`, this GRANTS a movement — so it narrows the OTHER
        // way: the grant's `allow_data_from` is the CEILING, and this may
        // only declare a subset of it (never a flow the grant did not
        // permit). Omitted grant authority means no cross-service movement.
        // Wildcards are grant-only and are resolved before signing.
        allow_data_from: z
          .array(z.string().min(1).max(128).refine((value) => value !== '*', {
            message: 'allow_data_from on a Passport must name exact services',
          }))
          .max(32)
          .optional(),
      }),
    )
    .optional(), // if omitted, use all granted scopes
  ttl_seconds: z.number().int().min(60).max(3600).optional(), // default 900 (15 min)
  // Opt-in identity claims — when provided, only these claims are embedded
  identity_claim_ids: z.array(z.string()).optional(),
  // Accountability fields
  intent: PassportIntentInput.optional(),
  checkpoint_interval_seconds: z.number().int().min(60).max(3600).optional(),
  // every agent Passport is issued for exactly one Mission.
  // The list shape is kept for wire and index compatibility; it must
  // hold exactly one ms_* id. The Mission must exist, belong to the
  // issuing operator, be live (not completed, revoked or expired), and
  // the agent's granted services must cover the Mission's
  // intent_services. PassportService re-checks all of this. The single
  // exemption is a STACK platform staff/monitor Passport
  // (intent.platform_intent), which authenticates STACK's own admin
  // surface and is never bound to a Mission.
  mission_ids: z.array(z.string().regex(/^ms_[\w-]+$/)).optional(),
  /** Exact authority bindings to attach. Omitted for legacy Passports. */
  authority_binding_ids: z.array(z.string().regex(/^abn_[\w-]+$/)).max(8).optional(),
});
export const IssuePassportInput = IssuePassportInputObject.superRefine((input, ctx) => {
  if (input.intent?.platform_intent) {
    if ((input.mission_ids?.length ?? 0) > 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['mission_ids'],
        message: 'A platform Passport is not bound to a Mission; omit mission_ids',
      });
    }
    return;
  }
  if (input.mission_ids?.length !== 1) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['mission_ids'],
      message: 'A Passport must be issued for exactly one Mission: pass mission_ids with one ms_* id (open one with POST /v1/missions or POST /v1/missions/start)',
    });
  }
});
export type IssuePassportInput = z.infer<typeof IssuePassportInput>;

export const DelegatePassportInput = z.object({
  parent_passport_token: z.string(),
  child_agent_id: z.string(),
  scopes: z.array(
    z.object({
      service_connection_id: z.string(),
      scopes: z.array(z.string()), // must be subset of parent
      // Child can tighten with additional constraints; the effective set
      // must be a superset of the parent passport's constraints for the
      // same service (never loosen).
      constraints: z.array(Constraint).max(32).refine(withinAnyOfBudget, { message: ANY_OF_BUDGET_MESSAGE }).optional(),
      intents: z.array(IntentRef).max(32).optional(),
      // Optional per-scope data-flow declaration for the child. Because
      // `allow_data_from` GRANTS a movement, a child may only declare a
      // SUBSET of the parent scope's `allow_data_from` for the same service
      // — never a flow the parent lacked. Widening is a scope escalation and
      // is rejected (fail closed) by passport-service.delegate. When omitted,
      // the child inherits the parent scope's declaration unchanged.
      allow_data_from: z
        .array(z.string().min(1).max(128).refine((value) => value !== '*', {
          message: 'allow_data_from on a Passport must name exact services',
        }))
        .max(32)
        .optional(),
    }),
  ),
  ttl_seconds: z.number().int().min(60).max(3600).optional(),
});
export type DelegatePassportInput = z.infer<typeof DelegatePassportInput>;

export const RefreshPassportInput = z.object({
  token: z.string(), // expired passport token
  ttl_seconds: z.number().int().min(60).max(3600).optional(), // default 900 (15 min)
});
export type RefreshPassportInput = z.infer<typeof RefreshPassportInput>;

export const RevokeAllInput = z.object({
  confirm: z.literal(true),
  reason: z.string().optional(),
});
export type RevokeAllInput = z.infer<typeof RevokeAllInput>;

// Stored passport record (DB)
export const PassportRecord = z.object({
  jti: z.string(),
  operator_id: z.string(),
  agent_id: z.string(),
  session_id: z.string(),
  delegation_depth: z.number().int(),
  parent_passport_id: z.string().nullable(),
  issued_at: z.date(),
  expires_at: z.date(),
  revoked_at: z.date().nullable(),
  revoked_reason: z.string().nullable(),
  // Accountability
  intent_summary: z.string().nullable().optional(),
  intent_services: z.array(z.string()).nullable().optional(),
  // Full intent refs (name + params). NULL for pre-migration rows.
  intent_refs: z.array(IntentRef).nullable().optional(),
  intent_delegates: z.boolean().optional(),
  estimated_duration_seconds: z.number().nullable().optional(),
  checkpoint_interval_seconds: z.number().nullable().optional(),
  last_checkpoint_at: z.date().nullable().optional(),
  checkpoint_count: z.number().optional(),
  checked_out_at: z.date().nullable().optional(),
  checkout_status: z.string().nullable().optional(),
  checkout_flags: z.array(z.object({ type: z.string(), severity: z.string(), message: z.string() })).nullable().optional(),
  // denormalized list of mission_ids this
  // passport is bound to (mirrors the JWT's mission_ids claim).
  // Indexed via GIN for revokeMissionPassportChain (a Mission's end
  // revokes every Passport carrying it. NULL on pre-migration rows.
  mission_ids: z.array(z.string()).nullable().optional(),
});
export type PassportRecord = z.infer<typeof PassportRecord>;

// ─── Accountability Schemas ──────────────────────────────────────────

/**
 * Signals that land on a passport's checkout flags without being detectors.
 * Each is recorded against a passport as a security event, and checkout merges
 * every security event on the passport into its flags. They are absent from the
 * detector catalog on purpose (see `SignalType` in the vault's security-event
 * service). Operator-scoped signals (oauth_*, partner_connect_burst) never
 * reach a passport and are not listed.
 */
export const NON_DETECTOR_FLAG_TYPES = [
  'unconstrained_scope',
  'pii_below_threshold',
  'audit_claim_binding_failure',
] as const;

/** Every flag type: the detector catalog is the source, so a new detector needs no edit here. */
const REVIEW_FLAG_TYPES = [...DETECTOR_KEYS, ...NON_DETECTOR_FLAG_TYPES] as const;

export const ReviewFlag = z.object({
  type: z.enum(REVIEW_FLAG_TYPES),
  severity: z.enum(['info', 'warning', 'critical']),
  message: z.string(),
});
export type ReviewFlag = z.infer<typeof ReviewFlag>;

export const ToolCallEntry = z.object({
  service: z.string(),
  method: z.string(),
  target: z.string().optional(),
});
export type ToolCallEntry = z.infer<typeof ToolCallEntry>;

export const CheckpointInput = z.object({
  services_used: z.array(z.string()),
  tool_calls: z.array(ToolCallEntry).optional(),
  actions_count: z.number().int().min(0),
  delegated_to: z.array(z.string()).optional(),
  summary: z.string().max(1000).optional(),
});
export type CheckpointInput = z.infer<typeof CheckpointInput>;

export const CheckoutInput = z.object({
  services_used: z.array(z.string()),
  tool_calls: z.array(ToolCallEntry).optional(),
  actions_count: z.number().int().min(0),
  delegated_to: z.array(z.string()).optional(),
  summary: z.string().max(2000).optional(),
});
export type CheckoutInput = z.infer<typeof CheckoutInput>;

export const ReviewDecisionInput = z.object({
  decision: z.enum(['approved', 'blocked']),
  notes: z.string().max(1000).optional(),
  block_future: z.boolean().optional(),
});
export type ReviewDecisionInput = z.infer<typeof ReviewDecisionInput>;

export const NotificationChannelInput = z.object({
  channel_type: z.enum(['email', 'sms', 'webhook']),
  destination: z.string().min(1),
  events: z.array(z.string()).optional(),
  min_severity: z.enum(['info', 'warning', 'critical']).optional(),
  destination_id: z.string().optional(),
});
export type NotificationChannelInput = z.infer<typeof NotificationChannelInput>;

export const AddDeliveryMethodInput = z.object({
  channel_type: z.enum(['email', 'sms', 'webhook']),
  destination: z.string().min(1),
});
export type AddDeliveryMethodInput = z.infer<typeof AddDeliveryMethodInput>;

export const CreateNotificationRuleInput = z.object({
  destination_id: z.string().min(1).optional(),
  destination_ids: z.array(z.string().min(1)).min(1).optional(),
  events: z.array(z.string()).min(1),
  min_severity: z.enum(['info', 'warning', 'critical']).optional(),
}).refine((d) => d.destination_id || (d.destination_ids && d.destination_ids.length > 0), {
  message: 'At least one delivery method is required',
});
export type CreateNotificationRuleInput = z.infer<typeof CreateNotificationRuleInput>;

export const UpdateNotificationRuleInput = z.object({
  destination_ids: z.array(z.string().min(1)).min(1).optional(),
  events: z.array(z.string()).min(1).optional(),
  min_severity: z.enum(['info', 'warning', 'critical']).optional(),
  /** Pause a rule without deleting it. The column has always existed on
   * notification_channels; it had no way in, so the console rendered a
   * switch that could not move. Silencing a rule is a governance action —
   * denyAgentContexts on the route keeps agents out of it. */
  active: z.boolean().optional(),
});
export type UpdateNotificationRuleInput = z.infer<typeof UpdateNotificationRuleInput>;
