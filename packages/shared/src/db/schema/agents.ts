// Agent identities.

import { pgTable, text, timestamp, jsonb, boolean, uniqueIndex, check } from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { operators } from './operators.js';

// ─── Agents ──────────────────────────────────────────────────────────

export const agents = pgTable(
  'agents',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    name: text('name').notNull(),
    description: text('description'),
    status: text('status').notNull().default('active'), // active | suspended | revoked
    // both defaults fail closed (migration 0033). 'standard' skips
    // the approval gate and emits no claims; 'direct' lets the agent fetch the
    // raw secret and call the provider itself, outside every wall the proxy
    // path enforces. Neither is a posture to hand someone who did not ask for
    // it. Loosening is an explicit operator act.
    accountability_mode: text('accountability_mode').notNull().default('enforced'), // enforced | logged | standard
    on_warning: text('on_warning').notNull().default('notify'), // notify | block
    on_critical: text('on_critical').notNull().default('notify'), // notify | block
    credential_access: text('credential_access').notNull().default('proxy_only'), // direct | proxy_preferred | proxy_only
    passport_blocked: boolean('passport_blocked').notNull().default(false),
    passport_blocked_reason: text('passport_blocked_reason'),
    passport_blocked_at: timestamp('passport_blocked_at', { withTimezone: true }),
    // Accepted and ignored: STACK adds no system prompt to /v1/llm/<provider>/*
    // calls, so this flag has no effect. The column stays so stored values and
    // old clients keep working.
    llm_inject_system_prompt: boolean('llm_inject_system_prompt').notNull().default(true),
    // per-agent toggle for gateway PII redaction on
    // /v1/llm/<provider>/* routes. Default true (fail-closed): user-role
    // message content is scanned and PII replaced with [REDACTED:<cat>]
    // before forwarding. Off means user-supplied PII flows to the LLM
    // provider unredacted — an explicit operator decision (e.g. apps whose
    // prompts legitimately carry contact data, or message-level caching).
    llm_redact_pii: boolean('llm_redact_pii').notNull().default(true),
    // twin runtime opt-in policy. Enum text:
    //   'always' — every mission spawns a twin
    //   'never' — twin runtime disabled for this agent
    //   'high_stakes_only' — twin only when mission has coverage_cap_cents
    //     OR any cap_behavior value is 'auto_revoke'
    //   'per_mission' (default) — twin only when caller sets
    //     run_twin=true on POST /v1/missions
    twin_policy: text('twin_policy').notNull().default('per_mission'),
    // optional twin LLM model override. When set, sealed
    // skill twin invocations under this agent's missions swap the skill's
    // published llm_model with this value (e.g. 'openai/gpt-5'). Null =
    // "twin runs the same model as real" (lower divergence signal but
    // still surfaces non-deterministic-output divergence at temperature
    // > 0). Free-text — validated by OpenRouter at invocation time, not
    // at config time, so the model catalog can drift without breaking
    // config.
    twin_llm_model: text('twin_llm_model'),
    // resource provenance for partner grants. Set when the agent
    // was registered by a grant-authenticated request. A grant context may
    // only mutate / issue passports for agents it created (multi-homing
    // isolation); enforced by assertGrantOwnsResource in the API layer.
    created_via_grant_id: text('created_via_grant_id'),
    // 2026-05-25 — durable synthetic-agent flag for smoke tests + close-gate
    // verification agents. When true, the agent's events are excluded from
    // the daily digest + admin view + operator-facing /v1/security-events
    // counts. Operator-controlled; safe in that flagging your own agents
    // synthetic only hides them from your own surfaces. Sandbox-prefix +
    // 'oauth' literal exclusions remain (covers agents that have no row).
    is_synthetic: boolean('is_synthetic').notNull().default(false),
    // eval-traffic valve. Distinct from is_synthetic (which
    // HIDES the agent's events everywhere): eval_traffic keeps detection
    // fully ON and events fully VISIBLE, but (a) severity ≤ warning
    // events insert pre-resolved (resolved_by='auto:eval_traffic') and
    // skip notification dispatch, (b) the L3 LLM classification is
    // skipped (L1/L2 still run — evals still get verdicts), (c) digest
    // noise is excluded. OPERATOR-SET ONLY: agent contexts can't PATCH
    // at all and partner-grant contexts are explicitly denied
    // this field + is_synthetic (see agents.ts PATCH guard).
    eval_traffic: boolean('eval_traffic').notNull().default(false),
    icon_url: text('icon_url'), // data URL or external URL for agent icon
    // Skill access control. The mode drives enforcement; the list is persistent memory
    // that survives mode changes so a user switching custom→none→custom keeps their list.
    // mode: 'none' (deny-all, default) | 'custom' (list-driven) | 'all' (allow-all)
    skill_access_mode: text('skill_access_mode').notNull().default('none'),
    allowed_skills: jsonb('allowed_skills').$type<string[]>().notNull().default([]),
    // Per-agent opt-in identity claims, used when the operator's
    // identity_claim_inheritance is 'opt_in'. NULL means inherit-default
    // (no per-agent override). Set at passport-issue time on
    // services.passport.issue to constrain which of the operator's
    // verified claims this agent presents.
    identity_claim_ids: jsonb('identity_claim_ids').$type<string[]>(),
    // (auth modernization): per-agent Ed25519 keypair. The SDK
    // generates the keypair locally and sends only the public half here
    // at enrollment. NULL until the SDK first runs + completes proof-
    // of-possession at POST /v1/agents/:id/enroll. Once set, the agent's
    // SDK signs request JWTs (iss=stack-sdk, aud=stack:agent, 60s TTL)
    // and the API auth middleware's 4th resolver verifies against this
    // pubkey instead of accepting the operator API key.
    pubkey: jsonb('pubkey').$type<{ kty: string; crv: string; x: string }>(),
    enrolled_at: timestamp('enrolled_at', { withTimezone: true }),
    // signing-mode selector. ADR
    // Design Decision 10. Three modes:
    //   stack_managed   — STACK generates + holds (KMS-wrapped) the
    //                     keypair; signs envelopes on agent's behalf
    //   customer_managed — Customer holds private key; STACK only
    //                     stores pubkey (existing 0026 enrolment flow)
    //   co_signed       — Both agent AND STACK sign; uses agent's key
    //                     (stack_managed OR customer_managed pathway)
    //                     plus operator's key for the co-signature
    // Defaults to stack_managed for new agents; existing agents get
    // the default via the migration's `DEFAULT 'stack_managed'`.
    key_mode: text('key_mode').notNull().default('stack_managed'),
    // KMS-wrapped private-key bytes (base64 ciphertext). Populated
    // for stack_managed + co_signed (after AgentSigner provisioning
    // ; null for customer_managed (customer holds
    // the private key on their own infra). Mirrors the existing
    // service_connections.credential_encrypted pattern — text column
    // holding base64 ciphertext, not an ARN. KMS Decrypt derives the
    // key id from the ciphertext envelope, so no separate ARN
    // pointer is needed.
    signing_key_encrypted: text('signing_key_encrypted'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    // A retired (revoked) agent does not hold its name: the name is unique among the agents that are not revoked.
    uniqueIndex('agents_operator_name_idx').on(table.operator_id, table.name).where(sql`${table.status} <> 'revoked'`),
    uniqueIndex('agents_id_operator_idx').on(table.id, table.operator_id),
    check('agents_status_check', sql`${table.status} IN ('active', 'suspended', 'revoked', 'blocked')`),
  ],
);
