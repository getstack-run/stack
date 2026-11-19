import { z } from 'zod';
import { CredentialAccess } from './proxy.js';

export const AgentStatus = z.enum(['active', 'suspended', 'revoked', 'blocked']);
export type AgentStatus = z.infer<typeof AgentStatus>;

export const AccountabilityMode = z.enum(['enforced', 'logged', 'standard']);
export type AccountabilityMode = z.infer<typeof AccountabilityMode>;

export const EscalationAction = z.enum(['notify', 'block']);
export type EscalationAction = z.infer<typeof EscalationAction>;

// Skill access control.
// Mode: 'none' blocks all skill invocation (default). 'custom' uses allowed_skills. 'all' allows any active skill.
// allowed_skills is an array the backend always stores; it is only enforced when mode = 'custom'. The list
// persists through mode changes so flipping to 'none' or 'all' and back to 'custom' preserves the selection.
export const SkillAccessMode = z.enum(['none', 'custom', 'all']);
export type SkillAccessMode = z.infer<typeof SkillAccessMode>;

export const AllowedSkills = z.array(z.string());
export type AllowedSkills = z.infer<typeof AllowedSkills>;

// agent signing model selector. ADR Design
// Decision 10. Three modes:
//   stack_managed   — STACK generates + KMS-wraps the agent's keypair;
//                     AgentSigner signs claim envelopes on the agent's
//                     behalf. Default for new agents.
//   customer_managed — Customer holds the private key on their own infra;
//                     enrolls only the pubkey via the existing
//                     /v1/agents/:id/enroll proof-of-possession flow;
//                     submits pre-signed envelopes which AgentSigner
//                     verifies against the stored pubkey before persist.
//   co_signed       — Same primary signature as stack_managed, plus an
//                     operator co-signature in the envelope's
//                     co_signatures array.
export const AgentKeyMode = z.enum(['stack_managed', 'customer_managed', 'co_signed']);
export type AgentKeyMode = z.infer<typeof AgentKeyMode>;

// twin runtime opt-in policy. The twin runs every
// mission's actions a SECOND time against a different model/provider
// in parallel; divergence between real + twin chains at mission close
// becomes a signed TwinDivergenceClaim.
//   'always' — every mission spawns a twin
//   'never' — twin runtime disabled for this agent
//   'high_stakes_only' — twin only when mission has coverage_cap_cents
//     OR any cap_behavior value is 'auto_revoke' (operator self-flags
//     high stakes by setting either a wallet cap or an auto-revoke cap
//     behavior on the mission)
//   'per_mission' (default) — twin only when POST /v1/missions body
//     carries run_twin=true (explicit per-call opt-in)
export const TwinPolicy = z.enum(['always', 'high_stakes_only', 'never', 'per_mission']);
export type TwinPolicy = z.infer<typeof TwinPolicy>;

// registration presets. A profile is a named bundle of
// safe-by-intent defaults for a common agent shape, so a caller doesn't
// have to know the three fields (credential_access + accountability_mode
// + key_mode) that define a posture. The preset expands to field values
// at registration time (see resolveAgentProfile); any field the caller
// ALSO passes explicitly overrides the preset. Omitting the profile leaves
// the base posture (logged + proxy_only): presets are strictly opt-in and
// never change behavior for callers who do not ask for one.
//
//   proxied-llm-bot — "a bot that just runs": calls an LLM through the
//     STACK gateway, holds no provider key on the box. Expands to
//     credential_access: proxy_only (never sees the raw key) +
//     accountability_mode: logged (records every call, no per-call
//     approval gate) + key_mode: stack_managed (zero-enroll). This is
//     the posture the LLM-gateway paved road (proxy serve / quickstart)
//     provisions.
export const AgentProfile = z.enum(['proxied-llm-bot']);
export type AgentProfile = z.infer<typeof AgentProfile>;

/**
 * Expand a registration `profile` to the partial field defaults it
 * implies. Pure + total; the caller layers this UNDER any explicitly-
 * passed fields and OVER the base logged/proxy_only defaults. Returns an
 * empty object for an undefined profile so the caller can spread
 * unconditionally.
 */
export function resolveAgentProfile(profile: AgentProfile | undefined): {
  credential_access?: CredentialAccess;
  accountability_mode?: AccountabilityMode;
  key_mode?: AgentKeyMode;
} {
  switch (profile) {
    case 'proxied-llm-bot':
      return {
        credential_access: 'proxy_only',
        accountability_mode: 'logged',
        key_mode: 'stack_managed',
      };
    case undefined:
      return {};
  }
}

/** A model id as a provider names it: letters, digits and . _ : / @ + -, at most 128 characters, never a space or a line break. */
export const TwinLlmModel = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/, 'A model id is letters, digits and . _ : / @ + - only');

/**
 * An icon: an address of at most 2048 characters, or an image as a data URL (up to 100,000), and never a control
 * character, so an icon is one line wherever it is shown.
 */
export const AgentIconUrl = z
  .string()
  .max(100_000)
  // eslint-disable-next-line no-control-regex
  .refine((value) => !/[\u0000-\u001f\u007f\u2028\u2029]/.test(value), 'An icon address holds no control or line-break character')
  .refine((value) => value.startsWith('data:image/') || value.length <= 2048, 'An icon address is at most 2048 characters; only an image as a data URL may be longer');

export const RegisterAgentInput = z.object({
  name: z
    .string()
    .min(1)
    .max(64)
    .regex(
      /^[a-z0-9_][a-z0-9_-]*[a-z0-9_]$/,
      'Agent name must be lowercase. Letters, digits, hyphens, or underscores only. Examples: my-agent, my_agent, research-pipeline.',
    ),
  description: z.string().max(256).optional(),
  // registration preset. Expands to a bundle of posture
  // defaults (see resolveAgentProfile) BEFORE the per-field defaults
  // below apply. Any field also passed explicitly wins over the preset.
  // Omitted → the base posture (logged + proxy_only): start loose, the owner tightens.
  // A strict mode (enforced) is the owner's choice at registration or later.
  profile: AgentProfile.optional(),
  accountability_mode: AccountabilityMode.optional(), // default: logged (or per `profile`)
  on_warning: EscalationAction.optional(),
  on_critical: EscalationAction.optional(),
  // default: proxy_only (or per `profile`). `direct` is the one
  // posture that lets an agent take the credential out of STACK's hands and
  // call the provider itself, past every check on the proxy path. It stays
  // available; it is no longer what you get by saying nothing.
  credential_access: CredentialAccess.optional(),
  icon_url: AgentIconUrl.nullable().optional(), // data URL or external URL
  skill_access_mode: SkillAccessMode.optional(), // default: 'none' (safe-by-default)
  allowed_skills: AllowedSkills.optional(),
  // Signing model selector. Defaults to 'stack_managed' at the DB layer;
  // callers wanting customer_managed (BYO keypair) or co_signed declare
  // it at registration. Post-registration mutation is intentionally NOT
  // in UpdateAgentInput — changing key_mode after enrollment would
  // invalidate every claim signed under the prior mode.
  key_mode: AgentKeyMode.optional(),
  // twin runtime opt-in. Default 'per_mission' at the DB
  // layer; callers wanting 'always' / 'high_stakes_only' / 'never'
  // declare it at registration. Post-registration mutation is
  // available via UpdateAgentInput.
  twin_policy: TwinPolicy.optional(),
  // optional twin LLM model override. Free-text; when set
  // sealed-skill twin invocations swap the skill's published model with
  // this value (e.g. 'openai/gpt-5'). Null = "twin uses same model as
  // real" (lower divergence signal). Validated by OpenRouter at
  // invocation time, not config time.
  twin_llm_model: TwinLlmModel.nullable().optional(),
  // 2026-05-25 — durable synthetic flag. Smoke tests + close-gate
  // verification scripts set this true at registration; events tied to
  // synthetic agents are excluded from the daily digest, admin view, and
  // operator-facing /v1/security-events list. Defaults to false at the DB.
  is_synthetic: z.boolean().optional(),
  // Test and benchmark traffic. Detection stays fully on and events stay visible, but warning-and-below events
  // insert pre-resolved with no notification (criticals stay live). Set at registration it rides inside the one
  // register approval: the person sees it on the same card and is never asked a second time.
  eval_traffic: z.boolean().optional(),
  // LLM gateway per-agent toggles. llm_inject_system_prompt is accepted and
  // ignored: STACK adds no system prompt to any call, so it has no effect.
  // llm_redact_pii defaults true at the DB (fail-closed): scan user-role
  // message content and replace PII before forwarding — off means user
  // PII flows to the LLM provider unredacted (explicit operator choice).
  llm_inject_system_prompt: z.boolean().optional(),
  llm_redact_pii: z.boolean().optional(),
});
export type RegisterAgentInput = z.infer<typeof RegisterAgentInput>;

export const UpdateAgentInput = z.object({
  status: z.enum(['active', 'suspended']).optional(),
  accountability_mode: AccountabilityMode.optional(),
  on_warning: EscalationAction.optional(),
  on_critical: EscalationAction.optional(),
  credential_access: CredentialAccess.optional(),
  icon_url: AgentIconUrl.nullable().optional(), // data URL or external URL
  skill_access_mode: SkillAccessMode.optional(),
  allowed_skills: AllowedSkills.optional(),
  identity_claim_ids: z.array(z.string()).optional(), // per-agent claims when operator is in opt_in mode
  // mutable twin runtime opt-in (post-registration).
  twin_policy: TwinPolicy.optional(),
  // mutable twin LLM model override (post-registration).
  // Null clears the override; undefined leaves the field untouched.
  twin_llm_model: TwinLlmModel.nullable().optional(),
  // 2026-05-25 — mutable synthetic flag (post-registration). Lets existing
  // smoke-test agents flag themselves on reuse without re-registration.
  is_synthetic: z.boolean().optional(),
  // mutable eval-traffic valve (operator/dashboard only; agent
  // contexts can't PATCH, partner grants are explicitly denied this field).
  eval_traffic: z.boolean().optional(),
  // mutable LLM gateway toggles (post-registration). See
  // RegisterAgentInput for semantics (llm_inject_system_prompt has no effect).
  llm_inject_system_prompt: z.boolean().optional(),
  llm_redact_pii: z.boolean().optional(),
});
export type UpdateAgentInput = z.infer<typeof UpdateAgentInput>;

export const Agent = z.object({
  id: z.string(),
  operator_id: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  status: AgentStatus,
  accountability_mode: AccountabilityMode,
  on_warning: EscalationAction,
  on_critical: EscalationAction,
  credential_access: CredentialAccess,
  // Signing-key model — surfaced on the response (244 Finding 4) so
  // an operator can see whether an agent is stack_managed (STACK holds the
  // key; the box authenticates with the operator credential) or
  // customer_managed (an on-box agent keypair) BEFORE building on it.
  // Immutable post-registration.
  key_mode: AgentKeyMode.default('stack_managed'),
  passport_blocked: z.boolean(),
  passport_blocked_reason: z.string().nullable(),
  passport_blocked_at: z.date().nullable(),
  icon_url: z.string().nullable().optional(),
  skill_access_mode: SkillAccessMode,
  allowed_skills: AllowedSkills,
  identity_claim_ids: z.array(z.string()).nullable(),
  enrolled_at: z.date().nullable(),
  twin_policy: TwinPolicy.default('per_mission'),
  twin_llm_model: z.string().nullable().optional(),
  is_synthetic: z.boolean().default(false),
  // LLM gateway toggles surfaced on the response. Defaults mirror the DB
  // columns. llm_inject_system_prompt has no effect: STACK adds no system prompt.
  llm_inject_system_prompt: z.boolean().default(true),
  llm_redact_pii: z.boolean().default(true),
  created_at: z.date(),
  updated_at: z.date(),
});
export type Agent = z.infer<typeof Agent>;
