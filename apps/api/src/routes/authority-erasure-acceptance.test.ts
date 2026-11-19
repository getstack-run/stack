import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { ForbiddenError, NotFoundError } from '@stack/shared';
import { errorHandler } from '../middleware/error-handler.js';
import { registerAuthorityRoutes } from './authority.js';
import { fakeEntitlements } from '../test/entitlements.js';

const TOMBSTONE_HASH = `sha256:${'a'.repeat(64)}`;

function makeServices(authority: Record<string, unknown>, governance?: Record<string, unknown>) {
  return {
    entitlements: fakeEntitlements(), operator: {
      authenticateByApiKey: vi.fn(async () => ({
        id: 'op_one', tier: 'pro', status: 'active', is_admin: true,
        is_platform_staff: false, is_partner: false, stripe_customer_id: null,
      })),
    },
    governanceApprovals: governance ?? {
      consumeAuthorityIdempotently: vi.fn(async () => undefined),
      requireApproval: vi.fn(async () => { throw new ForbiddenError('Human approval required'); }),
    },
    authority,
    audit: { write: vi.fn(async () => undefined) },
  };
}

function appWithAuthorityRoutes(services: ReturnType<typeof makeServices>) {
  const app = Fastify();
  app.setErrorHandler(errorHandler);
  registerAuthorityRoutes(app, services as never);
  return app;
}

const cases = [
  {
    kind: 'principal', id: 'prn_one', method: 'erasePrincipal', action: 'authority_principal_erase',
    url: '/v1/authority/principals/prn_one/erase', audit: 'authority.principal.erase',
  },
  {
    kind: 'binding', id: 'abn_one', method: 'eraseBinding', action: 'authority_binding_erase',
    url: '/v1/authority/bindings/abn_one/erase', audit: 'authority.binding.erase',
  },
  {
    kind: 'presentation', id: 'prs_one', method: 'erasePresentation', action: 'authority_presentation_erase',
    url: '/v1/authority/presentations/prs_one/erase', audit: 'authority.presentation.erase',
  },
] as const;

describe('authority erasure acceptance', () => {
  it.each(cases)('erases a $kind only after operator-admin auth, step-up, and durable idempotency', async (testCase) => {
    const erase = vi.fn(async () => ({
      target_kind: testCase.kind,
      target_id: testCase.id,
      target_version: 1,
      erased_at: '2026-08-21T12:00:00.000Z',
      tombstone_hash: TOMBSTONE_HASH,
      tombstone_claim_id: 'pc_tombstone_one',
    }));
    const consumeAuthorityIdempotently = vi.fn(async () => undefined);
    const audit = vi.fn(async () => undefined);
    const services = makeServices({ [testCase.method]: erase }, { consumeAuthorityIdempotently });
    services.audit.write = audit;
    const app = appWithAuthorityRoutes(services);

    const response = await app.inject({
      method: 'POST', url: testCase.url,
      headers: {
        authorization: 'Bearer sk_live_test',
        'idempotency-key': `erase-${testCase.kind}-one`,
        'x-governance-approval': `gov_erase_${testCase.kind}`,
      },
      payload: {},
    });
    const replay = await app.inject({
      method: 'POST', url: testCase.url,
      headers: {
        authorization: 'Bearer sk_live_test',
        'idempotency-key': `erase-${testCase.kind}-one`,
        'x-governance-approval': `gov_erase_${testCase.kind}`,
      },
      payload: {},
    });
    await app.close();

    expect(response.statusCode).toBe(200);
    expect(replay.statusCode).toBe(200);
    expect(replay.json()).toEqual(response.json());
    expect(erase).toHaveBeenCalledTimes(2);
    expect(erase).toHaveBeenCalledWith('op_one', testCase.id, `erase-${testCase.kind}-one`);
    expect(consumeAuthorityIdempotently).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: 'op_one', action: testCase.action, resourceId: testCase.id, payload: {},
      idempotencyKey: `erase-${testCase.kind}-one`,
    }));
    expect(audit).toHaveBeenCalledWith(expect.objectContaining({ action: testCase.audit }));
    expect(response.json()).toEqual({ tombstone: expect.objectContaining({
      target_kind: testCase.kind,
      target_id: testCase.id,
      tombstone_hash: TOMBSTONE_HASH,
      tombstone_claim_id: 'pc_tombstone_one',
    }) });
    expect(response.body).not.toMatch(/personal_number|native_evidence|normalized_request|ciphertext/i);
  });

  it('does not reuse an authority governance approval with a different mutation key', async () => {
    let acceptedKey: string | null = null;
    const consumeAuthorityIdempotently = vi.fn(async (input: { idempotencyKey: string }) => {
      if (acceptedKey === null) acceptedKey = input.idempotencyKey;
      else if (acceptedKey !== input.idempotencyKey) throw new ForbiddenError('Governance approval replay mismatch');
    });
    const erasePrincipal = vi.fn(async () => ({
      target_kind: 'principal', target_id: 'prn_one', target_version: 1,
      erased_at: '2026-08-21T12:00:00.000Z', tombstone_hash: TOMBSTONE_HASH,
      tombstone_claim_id: 'pc_tombstone_one',
    }));
    const app = appWithAuthorityRoutes(makeServices({ erasePrincipal }, { consumeAuthorityIdempotently }));
    const base = {
      method: 'POST' as const, url: '/v1/authority/principals/prn_one/erase',
      headers: {
        authorization: 'Bearer sk_live_test', 'x-governance-approval': 'gov_erase_principal',
        'idempotency-key': 'erase-principal-one',
      },
      payload: {},
    };

    const first = await app.inject(base);
    const changedKey = await app.inject({
      ...base, headers: { ...base.headers, 'idempotency-key': 'erase-principal-two' },
    });
    await app.close();

    expect(first.statusCode).toBe(200);
    expect(changedKey.statusCode).toBe(403);
    expect(erasePrincipal).toHaveBeenCalledTimes(1);
  });

  it('does not reuse an authority governance approval for another action or resource', async () => {
    let accepted: { action: string; resourceId: string } | null = null;
    const consumeAuthorityIdempotently = vi.fn(async (input: { action: string; resourceId: string }) => {
      if (accepted === null) accepted = input;
      else if (accepted.action !== input.action || accepted.resourceId !== input.resourceId) {
        throw new ForbiddenError('Governance approval replay mismatch');
      }
    });
    const tombstone = async (kind: string, id: string) => ({
      target_kind: kind, target_id: id, target_version: 1,
      erased_at: '2026-08-21T12:00:00.000Z', tombstone_hash: TOMBSTONE_HASH,
      tombstone_claim_id: 'pc_tombstone_one',
    });
    const erasePrincipal = vi.fn(() => tombstone('principal', 'prn_one'));
    const eraseBinding = vi.fn(() => tombstone('binding', 'abn_one'));
    const app = appWithAuthorityRoutes(makeServices(
      { erasePrincipal, eraseBinding }, { consumeAuthorityIdempotently },
    ));
    const headers = {
      authorization: 'Bearer sk_live_test', 'x-governance-approval': 'gov_erase_shared',
      'idempotency-key': 'erase-shared-one',
    };

    const first = await app.inject({
      method: 'POST', url: '/v1/authority/principals/prn_one/erase', headers, payload: {},
    });
    const changedActionAndResource = await app.inject({
      method: 'POST', url: '/v1/authority/bindings/abn_one/erase', headers, payload: {},
    });
    await app.close();

    expect(first.statusCode).toBe(200);
    expect(changedActionAndResource.statusCode).toBe(403);
    expect(erasePrincipal).toHaveBeenCalledTimes(1);
    expect(eraseBinding).not.toHaveBeenCalled();
  });

  it.each(cases)('rejects $kind erasure before mutation without an idempotency key', async (testCase) => {
    const erase = vi.fn();
    const app = appWithAuthorityRoutes(makeServices({ [testCase.method]: erase }));

    const response = await app.inject({
      method: 'POST', url: testCase.url,
      headers: { authorization: 'Bearer sk_live_test', 'x-governance-approval': 'gov_erase_one' },
      payload: {},
    });
    await app.close();

    expect(response.statusCode).toBe(400);
    expect(erase).not.toHaveBeenCalled();
  });

  it.each(cases)('requires human governance step-up for API-key $kind erasure', async (testCase) => {
    const erase = vi.fn();
    const requireApproval = vi.fn(async () => { throw new ForbiddenError('Human approval required'); });
    const app = appWithAuthorityRoutes(makeServices({ [testCase.method]: erase }, {
      consumeAuthorityIdempotently: vi.fn(), requireApproval,
    }));

    const response = await app.inject({
      method: 'POST', url: testCase.url,
      headers: { authorization: 'Bearer sk_live_test', 'idempotency-key': `erase-${testCase.kind}-one` },
      payload: {},
    });
    await app.close();

    expect(response.statusCode).toBe(403);
    expect(requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: 'op_one', action: testCase.action, resourceId: testCase.id,
    }));
    expect(erase).not.toHaveBeenCalled();
  });

  it.each(cases)('keeps a foreign $kind identifier enumeration-safe as 404', async (testCase) => {
    const erase = vi.fn(async () => { throw new NotFoundError('AuthorityTarget', testCase.id); });
    const app = appWithAuthorityRoutes(makeServices({ [testCase.method]: erase }));

    const response = await app.inject({
      method: 'POST', url: testCase.url,
      headers: {
        authorization: 'Bearer sk_live_test',
        'idempotency-key': `erase-${testCase.kind}-foreign`,
        'x-governance-approval': 'gov_erase_foreign',
      },
      payload: {},
    });
    await app.close();

    expect(response.statusCode).toBe(404);
    expect(response.body).not.toContain('op_foreign');
  });

  it.each(cases)('rejects caller-supplied $kind erasure detail', async (testCase) => {
    const erase = vi.fn();
    const app = appWithAuthorityRoutes(makeServices({ [testCase.method]: erase }));

    const response = await app.inject({
      method: 'POST', url: testCase.url,
      headers: {
        authorization: 'Bearer sk_live_test',
        'idempotency-key': `erase-${testCase.kind}-body`,
        'x-governance-approval': 'gov_erase_body',
      },
      payload: { reason: 'contains untrusted personal detail' },
    });
    await app.close();

    expect(response.statusCode).toBe(400);
    expect(erase).not.toHaveBeenCalled();
  });
});
