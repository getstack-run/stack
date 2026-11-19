// Signed claim records, evidence packs, operator signing keys and external anchors.

import {
  pgTable,
  text,
  timestamp,
  integer,
  jsonb,
  bigint,
  index,
  uniqueIndex,
  check,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { operators } from './operators.js';
import { passports } from './passports.js';

// ─── Passport Claims (typed claim registry) ───────────────────
// Append-only typed claims attached to passports. v1 consumer is the
// SPIFFE consumer which writes svid_attestation rows. Future consumers
// (detector_signal, checkpoint_approval) write the same shape; the
// discriminator is `type` and the body is validated against the
// PASSPORT_CLAIM_SCHEMAS registry at attach time.
//
// Cascade-revoke: revoking a passport marks attached claims
// revoked_at = now() and emits one claim.revoke audit row each.
// Tamper-evidence: every audit entry's `passport_claims_at_event`
// captures the sorted set of claim hashes attached at write time, hashed
// into the chain.

export const passportClaims = pgTable(
  'passport_claims',
  {
    claim_id: text('claim_id').primaryKey(),
    // nullable so operator-scoped claims (e.g.
    // identity_claim) can persist without a passport binding. FK stays;
    // null rows simply don't participate in passport-cascade revoke.
    passport_id: text('passport_id').references(() => passports.jti, { onDelete: 'cascade' }),
    type: text('type').notNull(), // 'svid_attestation' | future types

    // ─── Legacy JWS-style columns (the original SPIFFE consumer) ──
    // Existing rows have these; new envelope-shaped rows leave them
    // null. The SPIFFE consumer's migration will
    // re-sign the one historical row into the envelope shape and
    // these columns become legacy-only thereafter.
    body_json: jsonb('body_json').notNull().$type<Record<string, unknown>>(),
    claim_hash: text('claim_hash').notNull(),
    signature: text('signature').notNull(),
    attached_at: timestamp('attached_at', { withTimezone: true }).notNull().defaultNow(),

    // ─── Envelope columns ──────────────
    // Canonical signed artifact is the COSE_Sign1 message stored in
    // envelope_cose (base64-encoded). The other fields are
    // denormalised query-helpers derived from the envelope at write
    // time: subject for listBySubject lookups, claim_type for tier
    // gating and admin filters, issued_at_ms for chronological scans.
    // receipt is null until transparency-log publishing.
    operator_id: text('operator_id').references(() => operators.id, { onDelete: 'cascade' }),
    subject: text('subject'), // stack://operator/{op_id}/passport/{ppt_jti}
    envelope_version: integer('envelope_version'), // 1 for v1 envelopes, NULL on legacy rows
    claim_version: integer('claim_version'), // version of the claim_type's payload schema
    envelope_cose: text('envelope_cose'), // base64-encoded COSE_Sign1 bytes
    issuer: text('issuer'), // op_* — the operator whose key signed
    issued_at_ms: bigint('issued_at_ms', { mode: 'number' }), // unix ms; matches envelope's issued_at field
    receipt: jsonb('receipt').$type<Record<string, unknown>>(), // see Receipt schema in passport-claims/receipt.ts

    // Optional deterministic producer identity for resumable outbox work.
    // A retry returns the already-written signed claim instead of appending a
    // duplicate after a process dies between persistence and acknowledgement.
    source_operation_id: text('source_operation_id'),
    source_role: text('source_role'),

    revoked_at: timestamp('revoked_at', { withTimezone: true }),
    revoked_reason: text('revoked_reason'),
  },
  (table) => [
    uniqueIndex('pc_claim_id_operator_idx').on(table.claim_id, table.operator_id),
    index('pc_passport_idx').on(table.passport_id),
    index('pc_type_idx').on(table.type),
    index('pc_claim_hash_idx').on(table.claim_hash),
    index('pc_attached_at_idx').on(table.attached_at),
    // indexes for envelope-shaped lookups
    index('pc_operator_type_idx').on(table.operator_id, table.type),
    index('pc_issued_at_idx').on(table.issued_at_ms),
    uniqueIndex('pc_source_operation_role_idx')
      .on(table.operator_id, table.source_operation_id, table.source_role)
      .where(sql`${table.source_operation_id} is not null and ${table.source_role} is not null`),
    // The active-subject partial index (pc_subject_active_idx, WHERE revoked_at IS NULL)
    // is created in the SQL migration only.
  ],
);

/**
 * Immutable download metadata for exact evidence-pack manifest bytes.
 *
 * The manifest itself stays in the existing audit object store. PostgreSQL
 * keeps only the operator boundary, the claim binding, the object key, and
 * the hash needed to reject missing or changed bytes before download.
 * Migration 0053 installs the database trigger that rejects direct UPDATE
 * and DELETE statements. Account deletion can still cascade this metadata.
 */
export const evidencePackArtifacts = pgTable(
  'evidence_pack_artifacts',
  {
    pack_id: text('pack_id').primaryKey(),
    claim_id: text('claim_id')
      .notNull()
      .references(() => passportClaims.claim_id, { onDelete: 'cascade' }),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    object_key: text('object_key').notNull(),
    byte_size: integer('byte_size').notNull(),
    manifest_sha256: text('manifest_sha256').notNull(),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('evidence_pack_artifacts_claim_idx').on(table.claim_id),
    uniqueIndex('evidence_pack_artifacts_object_key_idx').on(table.object_key),
    index('evidence_pack_artifacts_operator_idx').on(table.operator_id),
    check('evidence_pack_artifacts_byte_size_check', sql`${table.byte_size} > 0`),
    check(
      'evidence_pack_artifacts_manifest_sha256_check',
      sql`${table.manifest_sha256} ~ '^[0-9a-f]{64}$'`,
    ),
  ],
);

// ─── Per-operator signing keys ────────────────────────
// EdDSA keypairs used to sign COSE_Sign1 claim envelopes for tenant
// operators. Deployment-key (`stack-passport-v1`) keeps signing passports,
// sessions, OAuth tokens, and op_stack_system claims. History-keyed:
// rotation appends a new row + stamps `retired_at` on the prior so old
// kids stay in the operator's JWKS for verification of historical claims.
// Private key is KMS-wrapped at rest with AAD
// {operator_id, kid, purpose: 'claim_signing'}; stored as base64 text
// (matches the credential_encrypted shape convention: a base64 JSON
// envelope in a TEXT column, never cast to BYTEA).

export const operatorSigningKeys = pgTable(
  'operator_signing_keys',
  {
    kid: text('kid').primaryKey(), // ${operator_id}:claim:v${N}
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    private_key_wrapped: text('private_key_wrapped').notNull(), // base64(KMS-wrapped JWK JSON)
    public_jwk: jsonb('public_jwk').notNull().$type<Record<string, unknown>>(),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    active_from: timestamp('active_from', { withTimezone: true }).notNull().defaultNow(),
    retired_at: timestamp('retired_at', { withTimezone: true }),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
  },
  (table) => [
    index('osk_operator_idx').on(table.operator_id),
    // Partial index on active rows (lookups by operator for sign-time
    // signer selection). Defined in 0002 SQL migration — Drizzle DSL
    // does not support partial indexes, so this Drizzle-side index() is
    // a non-partial fallback and the SQL migration carries the partial.
  ],
);

// ─── External chain-head anchors ─────────────────────
// Daily-cron in-DB mirror of the public chain-head anchor commits to
// `example-org/anchors` (or any other registry the publisher
// targets). Each row records ONE anchor publication for ONE operator
// at ONE point in time. EvidencePackService.export reads from here to
// populate `EvidencePackClaim.external_chain_anchors[]`.
//
// `chain_head_hash` is the audit chain head sampled at anchor time
// (64-hex sha256). `chain_head_at_audit_position` is the operator's
// total audit_log row count at that sample (monotonic). `registry`
// + `permalink` + `commit_sha` identify the public anchor commit
// (e.g. registry=`github:example-org/anchors` + permalink to
// the JSON file in the commit + the commit's sha for tamper-evidence
// against force-push).
//
// Idempotent on same-UTC-day: the worker cron's Redis day-lock
// (`anchor_lock:YYYY-MM-DD`) gates re-runs. When a same-day re-run
// happens (lock released early, machine restart, etc.) the publisher
// overwrites the existing date-keyed file but a new DB row records the
// fresh commit. Old rows stay — the chain of anchor publications is
// itself part of the forensic audit trail.

export const externalAnchors = pgTable(
  'external_anchors',
  {
    id: text('id').primaryKey(), // anc_*
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    anchored_at_ms: bigint('anchored_at_ms', { mode: 'number' }).notNull(), // unix ms
    chain_head_hash: text('chain_head_hash').notNull(), // 64-hex sha256
    chain_head_at_audit_position: integer('chain_head_at_audit_position').notNull(),
    registry: text('registry').notNull(), // e.g. 'github:example-org/anchors'
    permalink: text('permalink').notNull(), // URL to the anchor file in the commit
    commit_sha: text('commit_sha').notNull(), // git commit sha for tamper-evidence
    chain_head_signature: text('chain_head_signature').notNull(), // operator-signed (base64url Ed25519)
    stack_system_attestation: text('stack_system_attestation'), // STACK-system co-sig (optional)
  },
  (table) => [
    // "anchor in effect at time T" — most-recent anchor for an operator
    // at or before T is a single index seek.
    index('ext_anchors_op_time_idx').on(table.operator_id, table.anchored_at_ms),
  ],
);
