import { z } from 'zod';
import { ActionType } from './types.js';

/**
 * intent_claim — pre-execution declaration of an agent action.
 *
 * of the Signed Primitive epic. ADR at
 * the intent claims design (Design Decision 4).
 *
 * Every external-world action an agent performs emits an Intent claim
 * BEFORE execution. The Intent declares: what action, why (free-text),
 * what prerequisites must be met, who is acting (agent + user), and the
 * projected cost. The paired `intent_outcome` claim records the actual
 * outcome post-execution; the pair lives in the claims registry as a
 * verifiable record of the action.
 *
 * Wire shape: rides the existing ClaimEnvelope (COSE_Sign1
 * EdDSA, additive-only versioning). Subject is the passport JTI per
 * the canonical `stack://operator/{op_id}/passport/{ppt_jti}` scheme.
 *
 * Cryptographic agent attribution lives in the envelope's signing key
 * (kid resolves to agent's pubkey in operator's JWKS), NOT in the
 * payload. `agent_id` is denormalised onto the payload for query
 * performance only.
 *
 * Three semantic fields carry the intent as signed primitives:
 *
 * - `reason`: natural-language justification, kept as a signed-primitive
 *   field rather than a runtime LLM check. The detector grid runs over it
 *   (Aho-Corasick + Output Injection patterns), and an optional LLM
 *   coherence check (opt-in per operator) compares it against operator
 *   policy. Max 2048 chars.
 *
 * - `requires`: array of prior intent_outcome claim_ids. Constraints live
 *   in the signed history, so a third-party verifier can replay the
 *   chain and confirm each prerequisite was met (claim exists,
 *   produced by the same agent or its delegation chain, status =
 *   'succeeded'). The constraint checker runs in the simulation service.
 *
 * - `user_subject`: authenticated user the agent is acting for.
 *   Derived from the delegation chain's identity claims at issue time.
 *   Policy decisions can consider (user X, agent Y, resource Z) jointly.
 *   Cryptographically attested through the delegation chain rather than
 *   evaluated at policy-decision time.
 *
 * `mission_ref` is the Mission Layer future-proofing field
 * nullable today, populated when Mission Layer ships. ClaimRef is
 * generic so this doesn't bind to a specific Mission shape.
 */
export const IntentClaim = z.object({
  type: z.literal('intent_claim'),
  policy_decision: z.object({
    origin: z.literal('fleet_policy'),
    policy_id: z.string().min(1),
    policy_revision: z.number().int().positive(),
    mission_id: z.string().regex(/^ms_[\w-]+$/),
    rule_id: z.string().min(1),
    request_hash: z.string().regex(/^[0-9a-f]{64}$/),
    effect: z.enum(['allow', 'review']),
  }).strict().optional(),

  /**
   * The action shape the agent is performing. References the shared
   * `ActionType` enum (in `./types.ts`) so Intent and Outcome can
   * never drift. See ActionType's docstring for per-value semantics.
   *
   * `task_complete` is informational only — no external action, no
   * constraint check, no cost. Used for multi-step workflows where
   * "I finished the analysis" is itself worth recording.
   */
  intent_type: ActionType,

  /**
   * The agent submitting the intent. Denormalised for query
   * performance — without it, "all Intents by agent X" requires
   * joining through passport. The cryptographic agent attribution
   * lives in `envelope.kid` (resolves to agent's pubkey via JWKS);
   * this field is for fast lookup only. Per ADR D4: agent_pubkey is
   * NOT in the payload — that's redundant with the envelope's
   * signature metadata.
   */
  // Accepts the production `agt_*` id shape produced by ids.agent()
  // and the legacy `ag_*` shape used by older smoke fixtures + a
  // handful of seed rows. The field is informational (auth lives on
  // the passport JWT, not here), so a permissive format check is
  // sufficient.
  agent_id: z.string().regex(/^(ag|agt)_[\w-]+$/, 'agent_id must be an agent id'),

  /**
   * Reference into the named-intent catalog (provider:resource:action).
   * Examples: 'stripe:charges:create', 'github:repos:create_pull_request'.
   *
   * Schema validates shape only. Catalog membership is verified
   * producer-side via expandIntents() — same reasoning as the
   * detector_key field in detector_signal: the catalog (2,199 entries
   * across 115 providers) grows freely; binding the schema to runtime
   * catalog state would make every catalog addition a schema-version
   * event.
   */
  named_intent: z.string().regex(
    /^[a-z][\w-]*:[a-z][\w-]*:[a-z][\w-]*$/,
    'named_intent must match provider:resource:action shape',
  ),

  /**
   * Where the action is going. For http_call this is the granted SERVICE
   * SLUG (e.g. 'stripe', 'slack'), NOT a URL or hostname — the enforced-mode
   * scope check string-equals `target` against your granted provider slugs.
   * The full request URL goes in `parameters.url`. For other intent types:
   * tool URI for mcp_tool, skill_id for skill_invocation, contract address
   * for onchain_tx, free-form label for task_complete.
   */
  target: z
    .string()
    .min(1)
    .describe(
      "For http_call: the granted service SLUG (e.g. 'stripe'), NOT a URL — put the URL in parameters.url. For mcp_tool: tool URI. For skill_invocation: skill_id. For onchain_tx: contract address.",
    ),

  /**
   * What is being done. Method+path for http_call ('POST /v1/charges'),
   * tool method for mcp_tool ('search'), function selector for
   * onchain_tx ('transfer(address,uint256)'), free-form for the rest.
   */
  action: z.string().min(1),

  /**
   * Action-specific parameters. Validated by the producer-side
   * constraint expansion against the named_intent, not by the claim
   * payload schema. The claim records what was attempted.
   */
  parameters: z.record(z.string(), z.unknown()),

  /**
   * Pre-execution cost estimate. Three nullable fields so the envelope
   * shape is constant across intent_types:
   *
   * - `wallet_cents` (sub-cent precision, like the action bands):
   *   used by http_call, mcp_tool, skill_invocation, and the protocol
   *   fee portion of onchain_tx.
   * - `tokens`: integer LLM tokens (input + output combined). Used by
   *   skill_invocation (if the skill calls an LLM) and by http_call
   *   when the target is an LLM provider (Shroud-LITE producer in
   * - `gas_gwei`: EVM gas estimate. Used only by onchain_tx.
   *
   * task_complete leaves all three null.
   *
   * Negative values rejected. Zero accepted (free actions should be
   * recordable for audit even when they cost nothing).
   *
   * Same shape reused by intent_outcome.cost_actual for direct
   * comparison at audit time.
   */
  estimated_cost: z.object({
    wallet_cents: z.number().nonnegative().nullable(),
    tokens: z.number().int().nonnegative().nullable(),
    gas_gwei: z.number().nonnegative().nullable(),
  }),

  /**
   * Accountability tier declared at submit time. Matches the existing
   * accountability monotonicity rule: enforced > logged > standard.
   * `enforced` Intents pause for operator approval at submission;
   * `logged` emit to the operator's event stream in real time;
   * `standard` execute and record post-hoc.
   *
   * Default 'standard' to match the existing passport-default
   * behaviour.
   */
  accountability: z
    .enum(['enforced', 'logged', 'standard'])
    .default('standard'),

  /**
   * Natural-language justification. Optional (nullable, not omitted —
   * the field is always present in the payload, but its value can be
   * null when no justification is provided).
   *
   * The purpose of the action, as a signed primitive. Consumption:
   * - Output Injection detector runs over reason for credential-shape
   *   strings and assistant-compliance language.
   * - Aho-Corasick scan.
   * - Optional LLM coherence check (opt-in per operator) against
   *   operator-set policy (mission alignment, etc.).
   *
   * Capped at 2048 chars to bound storage + LLM context size.
   */
  reason: z.string().max(2048).nullable(),

  /**
   * Prior intent_outcome claim IDs this Intent depends on. Producer
   * must verify each referenced outcome exists in the registry, was
   * produced by the same agent or a member of the delegation chain,
   * and has status='succeeded' before signing the Intent envelope.
   *
   * The dependency graph lives in the signed history. A third party
   * with access to the claim registry can replay the chain and verify
   * every prerequisite was met before each action.
   *
   * Empty array (default) means no prerequisites — most actions today.
   */
  requires: z.array(z.string().regex(/^pc_[\w-]+$/, 'requires entries must be passport-claim ids (pc_*)')).default([]),

  /**
   * Authenticated user the agent is acting for. Derived from the
   * delegation chain's identity claims at issue time. Policy decisions can
   * consider (user X, agent Y, resource Z) jointly. Cryptographically
   * attested through the delegation chain rather than evaluated at
   * policy-decision time.
   *
   * Format depends on the auth path:
   * - Member OAuth/session: 'mem_*' (the member's id).
   * - OAuth-bound passport: the OIDC `sub` claim (e.g.
   *   'user:google:117...').
   * - Operator-only auth: null (no user-level identity available).
   *
   * Combined with member-scoped MCP auth, this field
   * is the per-user attribution primitive — without member-scoped
   * MCP, user_subject would always be the operator.
   */
  user_subject: z.string().nullable(),

  /**
   * mission binding. References the stable
   * mission_id (ms_*) the intent was emitted under. Nullable when the
   * passport isn't bound to any mission (or is bound to multiple and
   * the caller didn't pick one explicitly).
   *
   * Wire-shape change from pre-5.0.4 placeholder (which expected pc_*
   * the mission_open claim_id): the stable ms_* identifier is the
   * right shape because (a) it survives mission lifecycle transitions
   * transparently, (b) it removes a per-producer DB lookup that would
   * be required to resolve mission_id → claim_id on every action, and
   * (c) the audit chain at the time of emission cryptographically
   * anchors the mission via passport_claims_at_event hashing — the
   * mission's signed envelope is verifiable through the chain, not
   * through this payload field. Change is wire-shape but safe: no
   * production code populated this field before 5.0.4 (the field
   * was reserved nullable-only at original publish 2026-05-17).
   */
  mission_ref: z.string().regex(/^ms_[\w-]+$/, 'mission_ref must be a mission_id (ms_*)').nullable(),

  /**
   * unix ms — when the agent (or producer-on-behalf-of-agent) emitted
   * the intent. Separate from `envelope.issued_at` (which is when
   * STACK signed the envelope wrapping it). The two timestamps can
   * differ when the agent signed locally (customer_managed mode) and
   * submitted later, or when STACK delays signing.
   */
  submitted_at: z.number().int(),
});

export type IntentClaim = z.infer<typeof IntentClaim>;
