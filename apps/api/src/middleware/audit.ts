import type { FastifyRequest } from 'fastify';
import type { AuditContext } from '@stack/vault';
import { ids } from '@stack/shared';

/**
 * Build an AuditContext from a Fastify request.
 * For operator-level operations where no agent or passport exists,
 * sentinel values are used to keep the audit chain intact.
 */
export function auditCtx(
  request: FastifyRequest,
  overrides?: { agent_id?: string; passport_jti?: string },
): AuditContext {
  return {
    trace_id: request.id ?? ids.session(),
    span_id: ids.session(),
    operator_id: request.operatorId ?? 'anonymous',
    agent_id: overrides?.agent_id ?? 'system',
    passport_jti: overrides?.passport_jti ?? 'none',
  };
}

