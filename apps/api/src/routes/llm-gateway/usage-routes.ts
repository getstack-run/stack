// Handlers for the two read-only usage routes. The registrations (and their
// auth) live in routes/llm.ts.
//
// Observability surface for the llm_usage rows written on every successful
// POST. Operator-scoped (the route auth middleware sets request.operatorId
// from any of the five auth paths; the repo layer always filters by
// operator_id). No audit middleware (read-only). No overage meter
// (observability is free for the operator paying for the rollup).

import type { FastifyReply, FastifyRequest } from 'fastify';
import { ListLlmUsageQuery, StackError, SummaryLlmUsageQuery } from '@stack/shared';
import type { Services } from '../../config/services.js';

export async function listLlmUsage(
  services: Services,
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<FastifyReply> {
  const parsed = ListLlmUsageQuery.safeParse(request.query);
  if (!parsed.success) {
    throw new StackError(
      parsed.error.errors.map((e: { message: string }) => e.message).join(', '),
      'INVALID_REQUEST',
      400,
    );
  }
  const { items, nextCursor } = await services.llmUsage.list({
    operatorId: request.operatorId!,
    limit: parsed.data.limit,
    ...(parsed.data.cursor ? { cursor: parsed.data.cursor } : {}),
    ...(parsed.data.provider ? { provider: parsed.data.provider } : {}),
    ...(parsed.data.passport_jti ? { passportJti: parsed.data.passport_jti } : {}),
    ...(parsed.data.mission_id ? { missionId: parsed.data.mission_id } : {}),
    ...(parsed.data.agent_id ? { agentId: parsed.data.agent_id } : {}),
    ...(parsed.data.surface ? { surface: parsed.data.surface } : {}),
    ...(parsed.data.provider_payer ? { providerPayer: parsed.data.provider_payer } : {}),
    ...(parsed.data.stack_fee_payer ? { stackFeePayer: parsed.data.stack_fee_payer } : {}),
    ...(parsed.data.since ? { since: parsed.data.since } : {}),
    ...(parsed.data.until ? { until: parsed.data.until } : {}),
  });
  return reply.send({
    items: items.map((r) => ({
      ...r,
      // Serialize the timestamptz column as ISO string (Date → ISO).
      created_at: r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at,
    })),
    next_cursor: nextCursor,
  });
}

export async function summarizeLlmUsage(
  services: Services,
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<FastifyReply> {
  const parsed = SummaryLlmUsageQuery.safeParse(request.query);
  if (!parsed.success) {
    throw new StackError(
      parsed.error.errors.map((e: { message: string }) => e.message).join(', '),
      'INVALID_REQUEST',
      400,
    );
  }
  const buckets = await services.llmUsage.summary({
    operatorId: request.operatorId!,
    groupByModel: parsed.data.group_by_model,
    ...(parsed.data.provider ? { provider: parsed.data.provider } : {}),
    ...(parsed.data.passport_jti ? { passportJti: parsed.data.passport_jti } : {}),
    ...(parsed.data.mission_id ? { missionId: parsed.data.mission_id } : {}),
    ...(parsed.data.agent_id ? { agentId: parsed.data.agent_id } : {}),
    ...(parsed.data.surface ? { surface: parsed.data.surface } : {}),
    ...(parsed.data.provider_payer ? { providerPayer: parsed.data.provider_payer } : {}),
    ...(parsed.data.stack_fee_payer ? { stackFeePayer: parsed.data.stack_fee_payer } : {}),
    ...(parsed.data.since ? { since: parsed.data.since } : {}),
    ...(parsed.data.until ? { until: parsed.data.until } : {}),
  });
  return reply.send({ buckets });
}
