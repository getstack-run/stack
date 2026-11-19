// Evidence-pack export, receipt, list, and immutable artifact routes.
//
// The read surface has three distinct contracts:
//
//   GET /v1/evidence-packs/:pack_id     — fetch one EvidencePackClaim envelope
//   GET /v1/evidence-packs?scope=...    — list packs for a scope
//   GET /v1/evidence-packs/:pack_id/download — exact stored manifest bytes
//
// The existing GET-by-id route remains the claim receipt route. The list
// reports receipt_only for rows that predate immutable artifact storage.

import type { FastifyInstance } from 'fastify';
import { and, desc, eq, isNull, sql } from 'drizzle-orm';
import { passportClaims, type EvidencePackClaim } from '@stack/shared';
import { z } from 'zod';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { auditCtx } from '../middleware/audit.js';
import { requireControls } from '../middleware/require-controls.js';

const ListQuery = z.object({
  /**
   * Scope filter. Pass either:
   *   - `mission:<ms_id>`  — packs for a specific mission
   *   - `session:<ses_id>` — packs for a specific session
   *   - `period:<ref>`     — packs covering a calendar period
   *   - `incident:<ref>`   — packs tied to an incident
   * Format must match `<kind>:<ref>`. The two halves are checked
   * independently against the pack claim's `scope.kind` + `scope.ref`.
   */
  scope: z.string().optional(),
});

const PackId = z.string().regex(/^pck_[\w-]+$/);

// POST /v1/evidence-packs body. Mirrors
// EvidencePackService.export's signature: scope (kind + ref) +
// supersedes + air_gap. The service handles the heavy lifting.
const ExportBody = z.object({
  scope: z.object({
    kind: z.enum(['mission', 'session', 'incident', 'period']),
    ref: z.string().min(1).max(256),
  }),
  supersedes: z.string().regex(/^pck_[\w-]+$/).optional(),
  /**
   * v1 hint to the verifier downstream. Producer always emits inline
   * JWKS + inline schemas (when the resolver returns them) so air-gap
   * verification works regardless. The flag rides on the pack claim
   * for the consumer's record.
   */
  air_gap: z.boolean().optional(),
});

interface PackListItem {
  pack_id: string;
  claim_id: string;
  content_hash: string;
  scope: EvidencePackClaim['scope'];
  time_bounds: EvidencePackClaim['time_bounds'];
  claim_count: number;
  supersedes: string | null;
  issued_at_ms: number | null;
  artifact_state: 'stored_manifest' | 'receipt_only';
}

export function registerEvidencePacksRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);
  // Signed records are a controls feature: without controls every route here answers 402 CONTROLS_REQUIRED.
  const controls = requireControls(services);

  // POST /v1/evidence-packs.
  //
  // Export an evidence pack for a scope. Returns the pack_id, the
  // signed pack_claim, and the full canonical manifest JSON (the
  // bytes a downstream verifier consumes). Operator-scope auth.
  // A controls feature; on a self-managed install also a licensed one
  // (`evidence_exports`).
  app.post('/v1/evidence-packs', { preHandler: [auth, controls] }, async (request, reply) => {
    const body = ExportBody.parse(request.body);
    const start = Date.now();
    // Signed evidence exports are an enterprise feature of a self-managed install.
    services.features.require('evidence_exports');

    try {
      const result = await services.evidencePack.export(
        request.operatorId,
        body.scope,
        {
          ...(body.supersedes !== undefined ? { supersedes: body.supersedes } : {}),
          ...(body.air_gap !== undefined ? { airGap: body.air_gap } : {}),
        },
      );
      await services.audit.write({
        ctx: auditCtx(request, {}),
        layer: 'vault',
        action: 'evidence_pack.export',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });
      return reply.status(201).send({
        pack_id: result.pack_id,
        claim_id: result.claim_id,
        pack_claim: result.pack_claim,
        manifest: result.manifest,
      });
    } catch (err) {
      // Tier-gate ForbiddenError, scope-shape SchemaValidationError, and
      // scope-resolution NotImplemented all surface as the StackError
      // shape via the global error handler. We catch only for the
      // audit-write outcome flip; the error class itself bubbles up.
      await services.audit.write({
        ctx: auditCtx(request, {}),
        layer: 'vault',
        action: 'evidence_pack.export',
        outcome: 'failure',
        duration_ms: Date.now() - start,
      });
      throw err;
    }
  });

  // GET /v1/evidence-packs?scope=mission:<id>
  app.get('/v1/evidence-packs', { preHandler: [auth, controls] }, async (request, reply) => {
    const query = ListQuery.parse(request.query ?? {});

    const conditions = [
      eq(passportClaims.operator_id, request.operatorId),
      eq(passportClaims.type, 'evidence_pack'),
      isNull(passportClaims.revoked_at),
    ];

    if (query.scope) {
      const sepIdx = query.scope.indexOf(':');
      if (sepIdx === -1) {
        return reply.status(400).send({
          error: {
            code: 'INVALID_QUERY',
            message: "scope filter must match '<kind>:<ref>' (e.g. 'mission:ms_abc')",
          },
        });
      }
      const kind = query.scope.slice(0, sepIdx);
      const ref = query.scope.slice(sepIdx + 1);
      conditions.push(sql`${passportClaims.body_json}->'scope'->>'kind' = ${kind}`);
      conditions.push(sql`${passportClaims.body_json}->'scope'->>'ref' = ${ref}`);
    }

    const rows = await services.db
      .select({
        claim_id: passportClaims.claim_id,
        body_json: passportClaims.body_json,
        issued_at_ms: passportClaims.issued_at_ms,
      })
      .from(passportClaims)
      .where(and(...conditions))
      .orderBy(desc(passportClaims.issued_at_ms));

    const parsedRows: Array<Omit<PackListItem, 'artifact_state'>> = rows.map((row) => {
      const body = row.body_json as Partial<EvidencePackClaim> & Record<string, unknown>;
      return {
        pack_id: typeof body.pack_id === 'string' ? body.pack_id : '',
        claim_id: row.claim_id,
        content_hash: typeof body.content_hash === 'string' ? body.content_hash : '',
        scope:
          body.scope && typeof body.scope === 'object'
            ? (body.scope as EvidencePackClaim['scope'])
            : { kind: 'mission', ref: '' },
        time_bounds:
          body.time_bounds && typeof body.time_bounds === 'object'
            ? (body.time_bounds as EvidencePackClaim['time_bounds'])
            : { t0_ms: 0, t1_ms: 0 },
        claim_count: typeof body.claim_count === 'number' ? body.claim_count : 0,
        supersedes: typeof body.supersedes === 'string' ? body.supersedes : null,
        issued_at_ms: row.issued_at_ms,
      };
    });
    const artifactStates = await services.evidencePack.getArtifactStates(
      request.operatorId,
      parsedRows.map((row) => row.pack_id).filter(Boolean),
    );
    const items: PackListItem[] = parsedRows.map((row) => ({
      ...row,
      artifact_state: artifactStates.has(row.pack_id) ? 'stored_manifest' : 'receipt_only',
    }));

    return reply.send({ items });
  });

  // Exact immutable manifest bytes. The existing GET-by-id route below stays
  // the claim receipt route for backward compatibility.
  app.get<{ Params: { pack_id: string } }>(
    '/v1/evidence-packs/:pack_id/download',
    { preHandler: [auth, controls] },
    async (request, reply) => {
      const packId = PackId.parse(request.params.pack_id);
      const artifact = await services.evidencePack.getStoredManifest(
        request.operatorId,
        packId,
      );
      const digest = Buffer.from(artifact.manifest_sha256, 'hex').toString('base64');
      return reply
        .header('Content-Type', 'application/json')
        .header('Content-Length', String(artifact.byte_size))
        .header('Content-Disposition', `attachment; filename="${packId}.json"`)
        .header('Digest', `sha-256=${digest}`)
        .send(artifact.body);
    },
  );

  // GET /v1/evidence-packs/:pack_id
  app.get<{ Params: { pack_id: string } }>(
    '/v1/evidence-packs/:pack_id',
    { preHandler: [auth, controls] },
    async (request, reply) => {
      const row = await services.db.query.passportClaims.findFirst({
        where: and(
          eq(passportClaims.operator_id, request.operatorId),
          eq(passportClaims.type, 'evidence_pack'),
          sql`${passportClaims.body_json}->>'pack_id' = ${request.params.pack_id}`,
        ),
      });
      if (!row) {
        return reply.status(404).send({
          error: { code: 'NOT_FOUND', message: `pack ${request.params.pack_id} not found` },
        });
      }
      const body = row.body_json as EvidencePackClaim;
      return reply.send({
        claim_id: row.claim_id,
        envelope_cose: row.envelope_cose,
        revoked_at: row.revoked_at,
        pack_claim: body,
      });
    },
  );
}
