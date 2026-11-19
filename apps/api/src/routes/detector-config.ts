import type { FastifyInstance } from 'fastify';
import { denyAgentContexts } from '../middleware/require-platform.js';
import { z } from 'zod';
import {
  StackError,
  ForbiddenError,
  NotFoundError,
  DETECTORS,
} from '@stack/shared';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { auditCtx } from '../middleware/audit.js';
import { requireControls } from '../middleware/require-controls.js';

/**
 * L7 — per-operator detector customization.
 *
 * Operators can override the default detector behavior:
 *   - add custom regex patterns ("ignore the rules of our employee handbook")
 *   - whitelist false-positive matched_text values ("DAN" when DAN is a
 *     real customer name)
 *   - override built-in pattern severities
 *   - master-disable a detector entirely
 *
 * Changing the settings is a controls feature: a customer with controls changes
 * them directly, with no plan check and no approval; without controls a write
 * answers 402 CONTROLS_REQUIRED (an install has every controls feature). Reads
 * are open so anyone can see what is configured, an empty list included.
 *
 * Detector keys are validated against the central DETECTORS catalog so
 * operators cannot accumulate config rows for detector_keys that don't
 * exist or have been removed.
 */

const PatternId = z.string().min(1).max(64);
const PatternRegex = z.string().min(1).max(512);
const PatternDescription = z.string().max(256);
const Severity = z.enum(['warning', 'critical']);

const CustomPattern = z.object({
  id: PatternId,
  regex: PatternRegex,
  severity: Severity,
  description: PatternDescription,
});

const WhitelistPattern = z.object({
  id: PatternId,
  regex: PatternRegex,
  description: PatternDescription,
});

const UpsertInput = z
  .object({
    custom_patterns: z.array(CustomPattern).max(50).optional(),
    whitelist_patterns: z.array(WhitelistPattern).max(50).optional(),
    severity_overrides: z.record(z.string(), Severity).optional(),
    enabled: z.boolean().optional(),
  })
  .refine(
    (data) =>
      data.custom_patterns !== undefined ||
      data.whitelist_patterns !== undefined ||
      data.severity_overrides !== undefined ||
      data.enabled !== undefined,
    { message: 'at least one field must be provided' },
  );

function assertKnownDetector(detectorKey: string) {
  if (!DETECTORS[detectorKey]) {
    throw new NotFoundError('Detector', detectorKey);
  }
}

export function registerDetectorConfigRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);
  const readsNeedControls = requireControls(services, 'detector_reads');

  // List every detector_config row this operator has set. Read-open
  // to all tiers so the dashboard shows an empty state cleanly.
  app.get('/v1/detectors/config', { preHandler: [auth, denyAgentContexts, readsNeedControls] }, async (request) => {
    if (request.memberId) {
      throw new ForbiddenError('Detector customization requires operator access');
    }
    const rows = await services.operatorDetectorConfig.getAllForOperator(request.operatorId);
    return { configs: rows };
  });

  // Get one detector's config. Returns 404 if no row exists for this
  // (operator, detector_key) pair — caller treats absence as "running
  // on built-in defaults". 404 is intentional here, not an error
  // condition for the dashboard.
  app.get<{ Params: { detector_key: string } }>(
    '/v1/detectors/:detector_key/config',
    { preHandler: [auth, denyAgentContexts, readsNeedControls] },
    async (request) => {
      if (request.memberId) {
        throw new ForbiddenError('Detector customization requires operator access');
      }
      assertKnownDetector(request.params.detector_key);
      const row = await services.operatorDetectorConfig.getForDetector(
        request.operatorId,
        request.params.detector_key,
      );
      if (!row) {
        throw new NotFoundError('DetectorConfig', request.params.detector_key);
      }
      return row;
    },
  );

  // Upsert. A customer with controls writes directly; an agent context
  // may write only a STRICTLY TIGHTENING delta (safety-increasing
  // automation; anything else 403s). The audit row records the delta
  // classification.
  app.put<{ Params: { detector_key: string } }>(
    '/v1/detectors/:detector_key/config',
    { preHandler: [auth, requireControls(services, 'detector_settings')] },
    async (request, reply) => {
      if (request.memberId) {
        throw new ForbiddenError('Detector customization requires operator access');
      }
      assertKnownDetector(request.params.detector_key);

      const parsed = UpsertInput.safeParse(request.body);
      if (!parsed.success) {
        throw new StackError(
          parsed.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('; '),
          'INVALID_REQUEST',
          400,
        );
      }

      const { delta } = await services.operatorDetectorConfig.classifyUpsert({
        operator_id: request.operatorId,
        detector_key: request.params.detector_key,
        ...parsed.data,
      });

      if (request.agentId) {
        // direction gate: agents automate tightening ONLY.
        // 'unchanged' is also refused — an agent no-op write on a
        // governance surface has no legitimate purpose.
        if (delta.direction !== 'tightening') {
          throw new ForbiddenError(
            `agent contexts may only TIGHTEN detector config (this change is ${delta.direction}); loosening requires a human`,
          );
        }
      }

      const start = Date.now();
      const row = await services.operatorDetectorConfig.upsert({
        operator_id: request.operatorId,
        detector_key: request.params.detector_key,
        ...parsed.data,
      });

      // Direction-suffixed action keeps 'detector.config.upsert' prefix
      // queries working while making the delta class chain-bound; the
      // full change narrative rides the response (and the approval row
      // when one was consumed).
      await services.audit.write({
        ctx: auditCtx(request, request.agentId ? { agent_id: request.agentId } : undefined),
        layer: 'system',
        action: `detector.config.upsert.${delta.direction}`,
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return reply.status(200).send({ ...row, delta });
    },
  );

  // Reset to defaults — deletes the row so the next detector run reads
  // built-in patterns only. A reset's direction depends on what the row
  // contained (dropping custom patterns loosens; dropping a whitelist
  // tightens), so agent contexts are denied it outright; a customer with
  // controls resets directly.
  app.delete<{ Params: { detector_key: string } }>(
    '/v1/detectors/:detector_key/config',
    { preHandler: [auth, denyAgentContexts, requireControls(services, 'detector_settings')] },
    async (request, reply) => {
      if (request.memberId) {
        throw new ForbiddenError('Detector customization requires operator access');
      }
      assertKnownDetector(request.params.detector_key);

      const start = Date.now();
      const deleted = await services.operatorDetectorConfig.reset(
        request.operatorId,
        request.params.detector_key,
      );
      if (!deleted) {
        throw new NotFoundError('DetectorConfig', request.params.detector_key);
      }

      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'system',
        action: 'detector.config.reset',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return reply.send({ success: true, detector_key: request.params.detector_key });
    },
  );
}
