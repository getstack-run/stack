import { describe, expect, it, vi } from 'vitest';
import type { Services } from '../../config/services.js';
import { recordProxyEvaluation } from './allowance-accounting.js';
import type { ParsedProxyRequest, ProxyHttpRequest, ResolvedProxyTarget, VerifiedProxyPassport } from './types.js';

function build(opts: { overage: 'block' | 'wallet'; actionsPerMonth: number; used: number }) {
  const recordEvaluation = vi.fn(async () => ({ state: 'recorded', receipt: { period_sequence: 1 } }));
  const pool = vi.fn(async () => ({ limit: opts.actionsPerMonth, used: opts.used }));
  const services = {
    entitlements: {
      resolve: vi.fn(async () => ({
        billingOperatorId: 'op_partner', planOperatorId: 'op_partner', pooled: false, isTenant: false, tier: 'enterprise',
        limits: { actionsPerMonth: opts.actionsPerMonth, overage: opts.overage },
      })),
    },
    actionMeter: { pool },
    proxyOperation: { recordEvaluation },
  } as unknown as Services;
  const call = () => recordProxyEvaluation(
    services,
    { headers: {} } as unknown as ProxyHttpRequest,
    { isMutation: true, operationKey: 'op-handle' } as unknown as ParsedProxyRequest,
    { operatorId: 'op_partner', agentId: 'agt_1', jti: 'jti_1' } as unknown as VerifiedProxyPassport,
    { normalizedRequest: {}, conn: { connection_id: 'svc_1', credential_version: 1 } } as unknown as ResolvedProxyTarget,
  );
  return { call, pool, recordEvaluation };
}

describe('the allowance a proxy receipt is fenced against', () => {
  it('reads a hard-capped partner\'s used actions from the meter that counted them', async () => {
    const t = build({ overage: 'block', actionsPerMonth: 100, used: 98 });
    await t.call();
    expect(t.pool).toHaveBeenCalledOnce();
    expect(t.recordEvaluation).toHaveBeenCalledWith(expect.objectContaining({ allowanceLimit: 2 }));
  });

  it('asks the meter for nothing on an account that pays by band', async () => {
    const t = build({ overage: 'wallet', actionsPerMonth: 100, used: 98 });
    await t.call();
    expect(t.pool).not.toHaveBeenCalled();
    expect(t.recordEvaluation).toHaveBeenCalledWith(expect.objectContaining({ allowanceLimit: null }));
  });

  it('fails closed when the pool cannot be read as a count', async () => {
    const t = build({ overage: 'block', actionsPerMonth: 100, used: Number.NaN });
    await expect(t.call()).rejects.toMatchObject({ code: 'SERVICE_UNAVAILABLE', statusCode: 503 });
    expect(t.recordEvaluation).not.toHaveBeenCalled();
  });
});
