import { describe, expect, it, vi } from 'vitest';
import type { Database } from '@stack/shared';
import { AuditClaimBindingError, AuditService } from './audit-service.js';

const input = {
  ctx: {
    trace_id: 'tr_synthetic',
    span_id: 'sp_synthetic',
    operator_id: 'op_synthetic',
    agent_id: 'agt_synthetic',
    passport_jti: 'pas_synthetic',
  },
  layer: 'vault' as const,
  action: 'synthetic.evidence',
  outcome: 'success' as const,
};

describe('AuditService passport claim binding', () => {
  it('fails closed and emits a stable signal when the resolver is not wired', async () => {
    const transaction = vi.fn();
    const audit = new AuditService({ transaction } as unknown as Database);
    const report = vi.fn();
    audit.onClaimBindingFailure(report);

    await expect(audit.write(input)).rejects.toMatchObject({
      name: 'AuditClaimBindingError',
      code: 'AUDIT_CLAIM_BINDING_UNAVAILABLE',
      reason: 'resolver_unavailable',
    });
    expect(report).toHaveBeenCalledWith({
      operatorId: 'op_synthetic',
      agentId: 'agt_synthetic',
      passportJti: 'pas_synthetic',
      reason: 'resolver_unavailable',
    });
    expect(transaction).not.toHaveBeenCalled();
  });

  it('does not expose resolver errors and still fails if the event sink fails', async () => {
    const transaction = vi.fn();
    const audit = new AuditService({ transaction } as unknown as Database);
    const resolverError = new Error('synthetic resolver detail that must not escape');
    audit.setPassportClaimHashResolver({
      findActiveHashesByPassportId: vi.fn(async () => { throw resolverError; }),
    });
    audit.onClaimBindingFailure(vi.fn(async () => { throw new Error('synthetic sink failure'); }));

    const rejection = await audit.write(input).catch((error: unknown) => error);
    expect(rejection).toBeInstanceOf(AuditClaimBindingError);
    expect((rejection as Error).message).toBe('Audit evidence claim binding is unavailable');
    expect((rejection as Error).message).not.toContain(resolverError.message);
    expect(transaction).not.toHaveBeenCalled();
  });
});
