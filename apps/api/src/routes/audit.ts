import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { ForbiddenError, StackError } from '@stack/shared';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { denyAgentContexts } from '../middleware/require-platform.js';
import { requireControls } from '../middleware/require-controls.js';

const ExportQuery = z.object({
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
  format: z.enum(['json', 'ndjson', 'csv']).default('json'),
  limit: z.coerce.number().int().min(1).max(50_000).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

const VerifyQuery = z.object({
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
  limit: z.coerce.number().int().min(1).max(100_000).optional(),
});

const ListQuery = z.object({
  limit: z.coerce.number().int().min(1).max(100).optional(),
  since: z.coerce.number().int().min(0).optional(),
  agent_id: z.string().min(1).max(128).optional(),
  passport_jti: z.string().min(1).max(128).optional(),
});

/**
 * Agent-bearing credentials may inspect the evidence produced by that agent,
 * but must never widen the query to another agent or the whole operator. The
 * principal comes from verified auth context, never from the query string.
 */
export function resolveAuditAgentScope(
  authenticatedAgentId: string | undefined,
  requestedAgentId: string | undefined,
): string | undefined {
  if (!authenticatedAgentId) return requestedAgentId;
  if (requestedAgentId && requestedAgentId !== authenticatedAgentId) {
    throw new ForbiddenError('Agent audit access is limited to its own entries');
  }
  return authenticatedAgentId;
}

/**
 * Audit log routes under /v1/audit.
 *
 *   GET /v1/audit              — tail of recent entries (newest-first), optional `since` watermark.
 *   GET /v1/audit/export       — paginated export for date-range exports.
 *   GET /v1/audit/chain-head   — current chain head hash + entry count (external proof anchor).
 *   GET /v1/audit/verify-chain — re-walks hashes and reports tamper status.
 *
 * Reading the record is a controls feature: without controls every route here answers 402 CONTROLS_REQUIRED. The
 * record is written for every account all the same, so switching controls on shows all of it, from before too.
 */
export function registerAuditRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);
  const controls = requireControls(services);

  app.get('/v1/audit', { preHandler: [auth, controls] }, async (request) => {
    const parsed = ListQuery.safeParse(request.query);
    if (!parsed.success) {
      throw new StackError(
        parsed.error.errors.map((e) => e.message).join(', '),
        'INVALID_REQUEST',
        400,
      );
    }
    const rows = await services.audit.listRecent({
      operatorId: request.operatorId,
      limit: parsed.data.limit,
      sinceMs: parsed.data.since,
      agentId: resolveAuditAgentScope(request.agentId, parsed.data.agent_id),
      passportJti: parsed.data.passport_jti,
    });
    const entries = rows.map((r) => ({
      ...r,
      timestamp: typeof r.timestamp === 'string' ? Number(r.timestamp) : r.timestamp,
    }));
    return {
      entries,
      max_timestamp: entries.length > 0 ? Number(entries[0]!.timestamp) : (parsed.data.since ?? null),
    };
  });

  // Never metered. A 50,000-row page and no cap on calls is a bulk-egress
  // endpoint, so the ceiling here is abuse control: 30/min still exports a large
  // account in minutes while stopping a loop from reading the table forever.
  app.get(
    '/v1/audit/export',
    {
      preHandler: [auth, denyAgentContexts, controls],
      config: { rateLimit: { max: 30, timeWindow: '1 minute' } },
    },
    async (request, reply) => {
    const parsed = ExportQuery.safeParse(request.query);
    if (!parsed.success) {
      throw new StackError(
        parsed.error.errors.map((e) => e.message).join(', '),
        'INVALID_REQUEST',
        400,
      );
    }
    const { from, to, format, limit, offset } = parsed.data;

    const rows = await services.audit.listForExport({
      operatorId: request.operatorId,
      from: from ? new Date(from) : undefined,
      to: to ? new Date(to) : undefined,
      limit,
      offset,
    });

    const filename = `stack-audit-${new Date().toISOString().slice(0, 10)}`;

    if (format === 'ndjson') {
      reply.header('Content-Type', 'application/x-ndjson');
      reply.header('Content-Disposition', `attachment; filename="${filename}.ndjson"`);
      return rows.map((r) => JSON.stringify(r)).join('\n');
    }

    if (format === 'csv') {
      const headers = [
        'entry_id', 'timestamp', 'trace_id', 'operator_id', 'agent_id',
        'passport_jti', 'layer', 'action', 'outcome', 'duration_ms',
        'error_code', 'error_message', 'entry_hash',
      ];
      const rowsCsv = rows.map((r) => headers.map((h) => {
        const val = (r as Record<string, unknown>)[h];
        if (val == null) return '';
        const s = typeof val === 'string' ? val : String(val);
        // Minimal CSV escaping: quote if contains comma/quote/newline, escape quotes.
        return /[,"\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
      }).join(','));
      reply.header('Content-Type', 'text/csv');
      reply.header('Content-Disposition', `attachment; filename="${filename}.csv"`);
      return [headers.join(','), ...rowsCsv].join('\n');
    }

    // Default JSON response — array wrapped in metadata.
    return {
      operator_id: request.operatorId,
      count: rows.length,
      from: from ?? null,
      to: to ?? null,
        rows,
      };
    },
  );

  app.get('/v1/audit/chain-head', { preHandler: [auth, denyAgentContexts, controls] }, async (request) => {
    const head = await services.audit.getChainHead(request.operatorId);
    return {
      operator_id: request.operatorId,
      ...head,
      observed_at: new Date().toISOString(),
    };
  });

  app.get('/v1/audit/verify-chain', { preHandler: [auth, denyAgentContexts, controls] }, async (request) => {
    const parsed = VerifyQuery.safeParse(request.query);
    if (!parsed.success) {
      throw new StackError(
        parsed.error.errors.map((e) => e.message).join(', '),
        'INVALID_REQUEST',
        400,
      );
    }
    const { from, to, limit } = parsed.data;

    const result = await services.audit.verifyChain(request.operatorId, {
      from: from ? new Date(from) : undefined,
      to: to ? new Date(to) : undefined,
      limit,
    });

    return {
      operator_id: request.operatorId,
      verified_at: new Date().toISOString(),
      ...result,
    };
  });
}
