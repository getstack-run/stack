import { describe, expect, it, vi } from 'vitest';
import type { SetServiceRequirementInput } from '../types.js';
import { IdentityService } from './identity.js';

const requirement: SetServiceRequirementInput = {
  layer: 'identity',
  requires_claim: 'verified_identity',
  minimum_assurance: 'substantial',
  accepted_providers: ['stripe_identity'],
  requires_pii: true,
  lawful_basis: 'contract',
};

describe('IdentityService requirement replacement', () => {
  it('wraps one canonical requirement for the atomic PUT route', async () => {
    const response = { requirements: [{ id: 'sir_one', ...requirement }] };
    const put = vi.fn(async () => response);
    const service = new IdentityService({ put } as never);

    const result = await service.replaceServiceRequirement('svc_agent/mail', requirement);

    expect(result).toEqual(response);
    expect(put).toHaveBeenCalledWith(
      '/v1/services/svc_agent%2Fmail/requirements',
      { requirement },
      undefined,
    );
  });

  it('sends an explicit null to remove all requirements', async () => {
    const response = { requirements: [] };
    const put = vi.fn(async () => response);
    const service = new IdentityService({ put } as never);

    const result = await service.replaceServiceRequirement('svc_agentmail', null);

    expect(result).toEqual(response);
    expect(put).toHaveBeenCalledWith(
      '/v1/services/svc_agentmail/requirements',
      { requirement: null },
      undefined,
    );
  });

  it('carries the approval a person gave to a removal as the governance header', async () => {
    const put = vi.fn(async () => ({ requirements: [] }));
    const service = new IdentityService({ put } as never);
    await service.replaceServiceRequirement('svc_agentmail', null, { governanceApprovalId: 'gvr_ok' });
    expect(put).toHaveBeenCalledWith(
      '/v1/services/svc_agentmail/requirements',
      { requirement: null },
      { headers: { 'X-Governance-Approval': 'gvr_ok' } },
    );
  });
});

describe('IdentityService single sign-on domains', () => {
  const domain = {
    id: 'ssod_1',
    domain: 'corp.example.com',
    status: 'pending',
    record: { type: 'TXT', name: '_stack-sso.corp.example.com', value: 'stack-sso-verification=abc' },
    verified_at: null,
    last_checked_at: null,
    last_check: null,
    missing_since: null,
    created_at: '2026-10-26T10:00:00.000Z',
  };

  it('lists the domains of the account', async () => {
    const get = vi.fn(async () => ({ domains: [domain] }));
    const result = await new IdentityService({ get } as never).listSsoDomains();
    expect(result).toEqual([domain]);
    expect(get).toHaveBeenCalledWith('/v1/identity/sso-domains');
  });

  it('claims a domain, and sends the approval on the retry only', async () => {
    const post = vi.fn(async () => domain);
    const service = new IdentityService({ post } as never);
    await service.addSsoDomain('corp.example.com');
    await service.addSsoDomain('corp.example.com', { governanceApprovalId: 'gvr_1' });
    expect(post).toHaveBeenNthCalledWith(1, '/v1/identity/sso-domains', { domain: 'corp.example.com' }, undefined);
    expect(post).toHaveBeenNthCalledWith(2, '/v1/identity/sso-domains', { domain: 'corp.example.com' }, { headers: { 'X-Governance-Approval': 'gvr_1' } });
  });

  it('checks and removes a domain by its id, encoded in the path', async () => {
    const post = vi.fn(async () => ({ domain, check: 'missing' }));
    const del = vi.fn(async () => undefined);
    const service = new IdentityService({ post, delete: del } as never);
    expect((await service.verifySsoDomain('ssod/1')).check).toBe('missing');
    await service.removeSsoDomain('ssod/1');
    expect(post).toHaveBeenCalledWith('/v1/identity/sso-domains/ssod%2F1/verify', {});
    expect(del).toHaveBeenCalledWith('/v1/identity/sso-domains/ssod%2F1');
  });
});
