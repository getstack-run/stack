import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { StackError, ForbiddenError, PII_DEFAULT_THRESHOLD } from '@stack/shared';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { requireControls } from '../middleware/require-controls.js';
import { denyAgentContexts } from '../middleware/require-platform.js';
import { auditCtx } from '../middleware/audit.js';

/**
 * Per-operator PII redaction config — `/v1/pii/config`.
 *
 * Two dials over the scored PII scanner: how much confidence to demand
 * before redacting, and which countries' identifier schemes to run at all.
 * Together they are how an operator gets both halves of the trade — scope to
 * the countries you actually work in, then lower the threshold, and bare
 * formats redact without eating every order number in your traffic.
 *
 * NO TIER GATE, unlike /v1/detectors/:key/config. This costs no LLM call and
 * no model spend: regex and arithmetic in-process behind a cached config
 * read. Gating it would leave a free-tier Swedish customer with a false-
 * positive rate they cannot fix, which reads as our defect rather than their
 * plan limit.
 *
 * Writes deny agent contexts outright. An agent weakening the
 * redaction applied to its own prompts is self-authorization. The owner's own
 * change, by session, key or chat, applies at once and asks no one, loosening
 * included: turning redaction off, RAISING the threshold (a higher number
 * redacts less), or narrowing the country list. `direction` in the answer and
 * the audit action say which way it went.
 *
 * Never metered. Configuration is not an action — see the never-metered list
 * in metering-invariants.test.ts.
 */

/**
 * Both nullable fields accept an explicit null to mean "clear back to the
 * built-in", which is different from omitting them (leave untouched). The
 * distinction has to survive the wire, so `.nullable().optional()` rather
 * than `.optional()`.
 */
const UpsertInput = z
  .object({
    enabled: z.boolean().optional(),
    threshold: z.number().min(0).max(1).nullable().optional(),
    countries: z
      .array(z.string().regex(/^[A-Za-z]{2}$/, 'must be an ISO 3166-1 alpha-2 code, e.g. SE'))
      .max(64)
      .nullable()
      .optional(),
  })
  .refine(
    (d) => d.enabled !== undefined || d.threshold !== undefined || d.countries !== undefined,
    { message: 'at least one of enabled, threshold or countries must be provided' },
  );

/** What the caller gets when they have no row: the built-ins, labelled as
 *  defaults rather than a 404. A 404 here would be technically honest and
 *  practically useless — every caller's next question is "so what IS it". */
function defaultsResponse() {
  return {
    configured: false,
    enabled: true,
    threshold: PII_DEFAULT_THRESHOLD,
    countries: null,
  };
}

export function registerPiiConfigRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);
  const needsControls = requireControls(services, 'pii_settings');

  app.get('/v1/pii/config', { preHandler: [auth, denyAgentContexts, needsControls] }, async (request) => {
    if (request.memberId) {
      throw new ForbiddenError('PII redaction config requires operator access');
    }
    const row = await services.operatorPiiConfig.getForOperator(request.operatorId);
    if (!row) return defaultsResponse();
    return {
      configured: true,
      enabled: row.enabled,
      threshold: row.threshold ?? PII_DEFAULT_THRESHOLD,
      countries: row.countries,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  });

  app.put('/v1/pii/config', { preHandler: [auth, denyAgentContexts, needsControls] }, async (request, reply) => {
    if (request.memberId) {
      throw new ForbiddenError('PII redaction config requires operator access');
    }
    const parsed = UpsertInput.safeParse(request.body);
    if (!parsed.success) {
      throw new StackError(
        parsed.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('; '),
        'INVALID_REQUEST',
        400,
      );
    }

    const prior = await services.operatorPiiConfig.getForOperator(request.operatorId);
    const loosening = services.operatorPiiConfig.isLoosening(prior, parsed.data);
    const start = Date.now();
    const row = await services.operatorPiiConfig.upsert({
      operator_id: request.operatorId,
      ...parsed.data,
    });

    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'system',
      action: `pii.config.upsert.${loosening ? 'loosening' : 'tightening'}`,
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    return reply.status(200).send({
      configured: true,
      enabled: row.enabled,
      threshold: row.threshold ?? PII_DEFAULT_THRESHOLD,
      countries: row.countries,
      created_at: row.created_at,
      updated_at: row.updated_at,
      direction: loosening ? 'loosening' : 'tightening',
    });
  });

  // Reset asks no one either; it deletes the row and the built-ins apply.
  app.delete('/v1/pii/config', { preHandler: [auth, denyAgentContexts, needsControls] }, async (request, reply) => {
    if (request.memberId) {
      throw new ForbiddenError('PII redaction config requires operator access');
    }
    const start = Date.now();
    const deleted = await services.operatorPiiConfig.reset(request.operatorId);

    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'system',
      action: 'pii.config.reset',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    return reply.status(200).send({ success: true, deleted, ...defaultsResponse() });
  });
}
