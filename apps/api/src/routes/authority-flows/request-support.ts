import { StackError } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { auditCtx } from '../../middleware/audit.js';

/** The header every authority mutation requires; a missing or malformed value is a 400. */
export function idempotencyKey(request: { headers: Record<string, unknown> }): string {
  const value = request.headers['idempotency-key'];
  if (typeof value !== 'string' || !/^[\x21-\x7e]{1,128}$/.test(value)) {
    throw new StackError(
      'A valid Idempotency-Key header is required',
      'VALIDATION_ERROR',
      400,
    );
  }
  return value;
}

/** Audit row for a successful operator-authenticated authority mutation. */
export async function writeAudit(
  services: Services,
  request: Parameters<typeof auditCtx>[0],
  action: string,
): Promise<void> {
  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action,
    outcome: 'success',
    duration_ms: 0,
  });
}
