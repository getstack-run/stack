/**
 * Claim type discriminator + reserved-name registry.
 *
 * Every entry here is a name STACK MIGHT EVER USE for a claim type
 * attached to a passport via the claims-registry. Reserved names
 * prevent collisions across phases — if reserves
 * `behavioral_genome` here, no future engineer can repurpose the
 * name for something incompatible without explicit ADR review.
 *
 * Active vs reserved: a name appears here as soon as the architecture
 * commits to it; it appears in `PASSPORT_CLAIM_SCHEMAS` (passport-
 * claims/index.ts) only when its payload schema is implemented.
 * Trying to register a claim with a name that is reserved but not
 * yet implemented fails at attach time with a clear error.
 *
 * Source of truth for which phase each name unlocks:
 * the claims registry design, "Design decision 6 —
 * Claim-type slots reserved for future phases".
 */
import { z } from 'zod';

/**
 * ActionType — the shared vocabulary for "what kind of action an agent
 * is performing" referenced by BOTH Intent claims (intent_type) and
 * Outcome claims (outcome_type).
 *
 * One source of truth for action shapes. Adding a new action_type
 * here adds it to both Intent and Outcome schemas simultaneously,
 * eliminating the parallel-enum drift risk where you could add a
 * value to one schema and forget the other.
 *
 * Each action_type has paired semantics:
 * - `http_call`: STACK proxied an HTTP request to an external API.
 *   Cost field: wallet_cents. Constraint: named-intent URL+method.
 * - `mcp_tool`: STACK invoked an MCP tool against a downstream MCP
 *   server. Cost field: wallet_cents. Constraint: tool allowlist +
 *   tool-arg schema.
 * - `skill_invocation`: STACK ran a sealed skill in an isolated container or
 *   node:vm fallback. Cost field: wallet_cents. Constraint: skill
 *   trust tier + sealed input schema.
 * - `onchain_tx`: STACK submitted a blockchain transaction (EVM
 *   today, other chains add additively). Cost field: gas_gwei plus
 *   protocol fee in wallet_cents. Constraint: named-intent on
 *   contract+function.
 * - `task_complete`: Agent declared step completion without an
 *   external action. Informational only. No cost. No constraint.
 * - `a2a_dispatch`: Peer-to-peer agent message dispatch via A2A
 *   protocol (JSON-RPC over HTTP). Different semantic surface than
 *   mcp_tool — A2A is agent-to-agent, MCP is agent-to-tool-server.
 *   Cost field: wallet_cents.
 *
 * Adding a new action_type is additive (no envelope_version bump
 * needed); existing claims under prior action_types remain valid
 * forever.
 */
export const ActionType = z.enum([
  'http_call',
  'mcp_tool',
  'skill_invocation',
  'onchain_tx',
  'task_complete',
  'a2a_dispatch',
]);
export type ActionType = z.infer<typeof ActionType>;

export const ClaimType = z.enum([
  // ── Active ──
  'svid_attestation',

  // ── Active (standards push) ──
  'workload_attestation',  // WIMSE WIT + future non-SPIFFE workload-identity formats

  // ── Reserved (standards push) ──
  'rats_evidence',         // RATS Remote Attestation evidence (RFC 9334 + EAT)
  'slsa_provenance',       // in-toto / SLSA build provenance
  'c2pa_assertion',        // C2PA Content Credentials (ISO/IEC 22144)
  'ai_bom_ref',            // CycloneDX AI-BOM reference

  // ── Active (action layer) ──
  'intent_claim',          // pre-execution action declaration with reason/requires/user_subject
  'intent_outcome',        // post-execution outcome paired with each Intent
  'intent_denial',         // every denial (constraint, scope, monotonicity, detector) leaves a signed claim
  'intent_simulation',     // signed pre-execution dry-run result
  'entity_observation',    // entity references extracted from outcomes

  // ── Promoted → Active ──
  'detector_signal',       // canonical detector-fire record (replaces security_events writes after cutover)
  'skill_invocation',      // sealed-skill invocation record (migrated to ride intent_claim/intent_outcome)
  'sandbox_run',           // agent-account sandbox run record (code, input and output hashes)
  'workspace_action',      // agent-account workspace action record (command hash and clipped preview, file hashes)

  // ── Reserved (remaining observation migration) ──
  'checkpoint_approval',   // existing checkpoints row
  'identity_claim',        // non-SVID identity claims (Stripe Identity, Cloudflare Turnstile)

  // ── Active (Mission Layer) ──
  'mission',               // sealed mission binding (Mission Layer Pillar 1)
  'behavioral_genome',     // passport-scoped behavioral fingerprint (Pillar 2)
  'twin_divergence',       // real-vs-twin mission-close divergence (Pillar 2 ground truth)

  // ── Active (Mission Layer — evidence pack) ──
  'evidence_pack',         // portable cryptographic bundle (mission/session/incident/period scope)
  'operator_decision',     // mission-bound human decision from the Console Home queue
  'operator_review',       // immutable operator-organization post-mission assessment

  // â”€â”€ Active authority binding and proof rails â”€â”€
  'external_proof_verification',
  'authority_binding',
  'authority_approval',
  'authority_use',
  'receiver_transaction_receipt',
  'authority_erasure_tombstone',

  // ── Reserved (Mission Layer R&D) ──
  'passport_color',        // computed color view; may not need persistence
  'dossier',               // end-of-life forensic post-mortem

  // ── Reserved ──
  'chain_anchor',          // Bitcoin OP_RETURN anchor (reserved; not issued yet)
]);
export type ClaimType = z.infer<typeof ClaimType>;
