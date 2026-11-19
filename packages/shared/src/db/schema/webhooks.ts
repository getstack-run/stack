// Inbound webhooks and their receipts.

import {
  pgTable,
  text,
  timestamp,
  integer,
  jsonb,
  index,
  uniqueIndex,
  primaryKey,
  check,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { agents } from './agents.js';
import { operators } from './operators.js';

// ─── Twin runs ─────────────────────────────────────────
//
// One row per mission with an active twin run. The twin is a parallel
// passport that mirrors the real agent's actions against a different
// model or provider; divergence between the two chains at mission
// close becomes a signed TwinDivergenceClaim (5.3.1 schema).
//
// 5.3.2 ships the substrate: TwinOrchestrationService.startTwinForMission
// inserts; mirrorIntent/mirrorOutcome append to claim_pairs; evaluateDivergence
// stub-emits a TwinDivergenceClaim and marks status='evaluated'.
//
// 5.3.3 wires the call sites (agent.twin_policy + per-mission override).
// 5.3.4 replaces the divergence-eval stub with real per-dimension math.
// 5.3.5 wires the actual twin EXECUTION runtime (sealed-exec variant).
//
// Indexes:
//   - twin_runs_mission_idx — one twin run per mission lookup
//   - twin_runs_real_passport_idx — find the twin by real passport jti
//     (used by the ClaimRegistryService post-persist hook in 5.3.3)
//   - twin_runs_status_idx — find running twins for the close-mission sweep
// ─── Inbound webhooks (5.5 hosted-receiver surface) ──────────────────
//
// AgentMail-shaped inbound endpoints hosted at api.getstack.run. A
// customer creates a row, copies the returned URL + HMAC secret into
// their provider's webhook config, and STACK becomes the inbound path:
// HMAC verify → DetectorService scan → security_event claim on block →
// forward to operator-configured downstream URL on clean. No customer
// infrastructure beyond a forward URL.
//
// Auth shape on the public receiver path:
//   - Slug is opaque + URL-routed (32-char nanoid behind `iwh_`).
//   - HMAC secret stored KMS-encrypted; decrypted per-request for
//     signature verification. AAD: {operator_id, webhook_id, purpose:
//     'inbound_webhook_secret'}.
//   - revoked_at is the soft-delete; receiver returns 404 when set.
//
// Indexes:
//   - inbound_webhooks_lookup_idx — (provider, slug) covering index for
//     the public receiver path; unique because (provider, slug) IS the
//     route.
//   - inbound_webhooks_operator_idx — partial idx on active rows for
//     the operator's list view.
export const inboundWebhooks = pgTable(
  'inbound_webhooks',
  {
    id: text('id').primaryKey(), // iwh_*
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    provider: text('provider').notNull(), // agentmail | (future)
    slug: text('slug').notNull(), // opaque URL segment
    forward_url: text('forward_url'), // nullable — null = log-only mode (security_event still written)
    generic_config: jsonb('generic_config').$type<{
      signature_header: string;
      signature_algorithm: 'hmac-sha256' | 'hmac-sha1';
      dedupe_key_path: string;
      content_paths: string[];
    }>(),
    webhook_secret_encrypted: text('webhook_secret_encrypted').notNull(), // downstream STACK signing key, KMS envelope
    provider_signing_secret_encrypted: text('provider_signing_secret_encrypted'), // incoming provider authentication key, KMS envelope
    // The downstream secret a rotation replaced: it keeps signing beside the new one for 24 hours.
    webhook_secret_previous_encrypted: text('webhook_secret_previous_encrypted'),
    webhook_secret_rotated_at: timestamp('webhook_secret_rotated_at', { withTimezone: true }),
    agent_id: text('agent_id').references(() => agents.id, { onDelete: 'set null' }), // optional — for security_event attribution
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
    last_used_at: timestamp('last_used_at', { withTimezone: true }),
    last_block_at: timestamp('last_block_at', { withTimezone: true }), // telemetry — most recent block decision
    total_calls: integer('total_calls').notNull().default(0),
    total_blocked: integer('total_blocked').notNull().default(0),
    // resource provenance for partner grants (see agents table).
    created_via_grant_id: text('created_via_grant_id'),
  },
  (table) => [
    uniqueIndex('inbound_webhooks_lookup_idx').on(table.provider, table.slug),
    index('inbound_webhooks_operator_idx').on(table.operator_id),
  ],
);

// ─── Inbound webhook receipts (5.5 idempotency dedupe) ───────────────
//
// One durable receipt per logical delivery. Only completed receipts acknowledge
// retries; processing leases are fenced by an attempt ID and can be recovered.
//
// TTL: 48h. A daily worker sweep removes older rows so the table stays
// bounded under high-volume inbound traffic.
//
// Operator-scoped via the inbound_webhooks FK; deleting the webhook
// cascades.
export const inboundWebhookReceipts = pgTable(
  'inbound_webhook_receipts',
  {
    webhook_id: text('webhook_id')
      .notNull()
      .references(() => inboundWebhooks.id, { onDelete: 'cascade' }),
    provider_message_id: text('provider_message_id').notNull(),
    seen_at: timestamp('seen_at', { withTimezone: true }).notNull().defaultNow(),
    // Existing one-bit receipts predate recovery metadata; preserve their
    // completed interpretation rather than replaying historical deliveries.
    state: text('state').notNull().default('completed'),
    body_hash: text('body_hash'),
    attempt_id: text('attempt_id'),
    lease_expires_at: timestamp('lease_expires_at', { withTimezone: true }),
    metered_at: timestamp('metered_at', { withTimezone: true }),
    scan_verdict: text('scan_verdict'),
    completed_at: timestamp('completed_at', { withTimezone: true }),
  },
  (table) => [
    primaryKey({ columns: [table.webhook_id, table.provider_message_id] }),
    index('inbound_webhook_receipts_seen_at_idx').on(table.seen_at),
    check(
      'inbound_webhook_receipts_state_check',
      sql`${table.state} IN ('pending', 'processing', 'completed')`,
    ),
  ],
);
