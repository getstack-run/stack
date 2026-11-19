import { z } from 'zod';

/**
 * entity_observation — extracted entity references from an Intent
 * outcome.
 *
 * . Producers emit this claim alongside
 * an `intent_outcome` claim when they have raw runtime data in scope
 * (response body, skill output, A2A task result). The producer walks
 * the JSON-like payload with deterministic regex patterns (URLs,
 * emails, well-known IDs, file paths) and records the distinct entity
 * strings against the passport's claim chain.
 *
 * **Why a separate claim type instead of stuffing entities into
 * `intent_outcome.metadata`.** Entity observations have their own
 * retrieval pattern (fact-set lookup at simulation time) and their
 * own retention concerns (broader than per-outcome). Carving them off
 * means the `undeclared_target` detector can query a passport's
 * observed-entity-set via a single subject + type filter rather than
 * walking every outcome's metadata.
 *
 * **Consumed by `undeclared_target`** at
 * `IntentSimulationService.simulate()` time. The simulator extracts
 * entities from the candidate Intent's `parameters` and target,
 * compares against the union of all `entity_observation.entities` on
 * the same passport, and fires when any candidate entity is absent
 * from the observed set.
 *
 * **Permitted at every tier** (free → enterprise) — this is
 * action-layer substrate, not a tier-gated feature.
 */
export const EntityObservationClaim = z.object({
  type: z.literal('entity_observation'),

  /**
   * The outcome claim that produced this observation. Optional —
   * background re-scans of past outcomes can emit observations
   * without a single direct parent.
   */
  intent_outcome_ref: z
    .string()
    .regex(/^pc_[\w-]+$/, 'intent_outcome_ref must be a passport-claim id (pc_*)')
    .optional(),

  /**
   * Distinct entity references extracted from the runtime data.
   * Normalized to lowercase, trimmed, deduplicated by the producer.
   * Capped at 256 per claim to bound storage.
   */
  entities: z.array(z.string().min(1).max(512)).max(256).default([]),

  /**
   * Classification of each entity, aligned 1:1 with `entities` when
   * the producer can distinguish. Empty when classification was
   * skipped. Closed set so consumers can query reliably; `other` is
   * the escape hatch.
   */
  entity_types: z
    .array(
      z.enum([
        'url_host',
        'url_path',
        'email',
        'account_id',
        'file_path',
        'arn',
        'gcp_resource',
        'azure_resource',
        'phone',
        'ip_address',
        // Recorded only from financial providers, as one-way digests
        // (`money:<hex>`, `acct:<hex>`), never the figure itself.
        'money_amount',
        'account_number',
        'other',
      ]),
    )
    .default([]),

  /**
   * The entities (a subset of `entities`, in the same form) that are the
   * request's own URL and nothing the call read: its host, path and query,
   * which the agent SENT. They stay in `entities` because the
   * undeclared-counterparty check counts them as dealt with, but they are not
   * content read from `source_service`, so the data-flow rule leaves them out.
   * An entity the answer or the request body also carried is read content and
   * is not listed. Optional, and absent from an observation that has none, so
   * observations recorded before it existed keep the bytes they were signed
   * with and are read as they always were (every entity counted as read).
   */
  request_entities: z.array(z.string().min(1).max(512)).max(256).optional(),

  /**
   * Agent that produced the outcome this observation derived from.
   * Required — entity observation only happens within an agent's
   * execution context.
   */
  agent_id: z.string().regex(/^(ag|agt)_[\w-]+$/, 'agent_id must be an agent id'),

  /**
   * The service this content was read from.
   *
   * Provenance used to live in `metadata.service`, inside a
   * `z.record(z.string(), z.unknown())` the schema explicitly does not
   * validate, and no consumer read it. A data-flow rule depends on knowing
   * where content came from, so origin gets a typed, validated field of its
   * own rather than an untyped blob that nothing guarantees.
   *
   * Optional for backward compatibility with observations recorded before
   * this field existed; those simply cannot participate in a flow decision,
   * which is the safe direction (they are treated as having no known origin
   * rather than as coming from anywhere).
   */
  source_service: z.string().min(1).max(128).optional(),

  /**
   * Content fingerprints of what was read — hashed overlapping word runs.
   *
   * The entity catalogue recognises emails, URLs, account ids and paths. It
   * does not recognise `Alice Johnson`, so an entity-only record cannot
   * support the case this exists for: an agent mailing a list of ordinary
   * names it read somewhere else. These are one-way hashes, never the text.
   *
   * Capped so a large response cannot bloat the claim.
   */
  content_fingerprints: z.array(z.string().min(1).max(64)).max(512).default([]),

  /**
   * Free-form producer-specific metadata (extraction method,
   * confidence scores, regex patterns matched, source field).
   * Schema does NOT validate; producers stamp what makes sense.
   */
  metadata: z.record(z.string(), z.unknown()).default({}),

  /** unix ms — when STACK recorded this observation. */
  observed_at: z.number().int(),

  /**
   * mission binding (additive nullable
   * retrofit). Auto-resolved from the passport's mission_ids when
   * exactly one is bound. Provenance tag.
   *
   * The `undeclared_target` detector fires off the passport's observed-entity
   * set (prior entity_observation claims) UNION the bound mission's
   * `expected_counterparties` ( #6 — pre-declaration is honoured by the
   * intent simulator), so a mission-declared counterparty is not flagged on
   * first touch.
   */
  mission_ref: z.string().regex(/^ms_[\w-]+$/, 'mission_ref must be a mission_id (ms_*)').nullable().optional(),
});

export type EntityObservationClaim = z.infer<typeof EntityObservationClaim>;
