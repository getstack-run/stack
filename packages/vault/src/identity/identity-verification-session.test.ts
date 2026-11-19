import { describe, expect, it, vi } from 'vitest';
import { IdentityVerificationService } from './identity-verification-service.js';
import { IdentityProviderRegistry } from './provider-registry.js';
import type { IdentityVerificationProvider } from './types.js';

const now = Date.now();

type SessionRow = {
  id: string;
  operator_id: string;
  provider_key: string;
  session_ref: string;
  status: string;
  expires_at: Date;
};

function session(overrides: Partial<SessionRow> = {}): SessionRow {
  return {
    id: 'ivs_one',
    operator_id: 'op_one',
    provider_key: 'test_provider',
    session_ref: 'provider_session_one',
    status: 'pending',
    expires_at: new Date(now + 60_000),
    ...overrides,
  };
}

function database(row: SessionRow | null) {
  const limit = vi.fn(async () => row ? [row] : []);
  const returning = vi.fn(async () => row ? [{ id: row.id }] : []);
  return {
    select: vi.fn(() => ({
      from: vi.fn(() => ({
        where: vi.fn(() => ({ limit })),
      })),
    })),
    update: vi.fn(() => ({
      set: vi.fn(() => ({
        where: vi.fn(() => ({ returning })),
      })),
    })),
  };
}

function service(row: SessionRow | null) {
  const registry = new IdentityProviderRegistry();
  const complete = vi.fn(async () => ({ success: false, claims: [] }));
  registry.register({
    providerKey: 'test_provider',
    displayName: 'Test provider',
    claimTypes: ['verified_human'],
    supportedLayers: ['humanity'],
    assuranceLevel: 'low',
    initiate: vi.fn(),
    complete,
  } as IdentityVerificationProvider);

  const verification = new IdentityVerificationService(
    database(row) as never,
    registry,
    { findProviderByKey: vi.fn(async () => ({ id: 'idp_test' })) } as never,
    {} as never,
  );
  return { verification, complete };
}

describe('owned live pending identity verification sessions', () => {
  it.each([
    ['missing', null],
    ['foreign', session({ operator_id: 'op_foreign' })],
    ['wrong provider', session({ provider_key: 'other_provider' })],
    ['completed', session({ status: 'completed' })],
    ['expired', session({ expires_at: new Date(now - 1) })],
  ] as const)('rejects a %s session before normal completion', async (_name, row) => {
    const { verification, complete } = service(row);

    await expect(verification.complete(
      'op_one',
      'test_provider',
      'provider_session_one',
    )).rejects.toThrow('IdentityVerificationSession');
    expect(complete).not.toHaveBeenCalled();
  });

  it.each([
    ['missing', null],
    ['foreign', session({ operator_id: 'op_foreign' })],
    ['completed', session({ status: 'completed' })],
    ['expired', session({ expires_at: new Date(now - 1) })],
  ] as const)('rejects a %s session before token completion', async (_name, row) => {
    const { verification, complete } = service(row);

    await expect(verification.completeWithToken(
      'op_one',
      'test_provider',
      'provider_session_one',
      'provider-token',
    )).rejects.toThrow('IdentityVerificationSession');
    expect(complete).not.toHaveBeenCalled();
  });

  it('allows a matching live pending session for both completion paths', async () => {
    const normal = service(session());
    const token = service(session());

    await expect(normal.verification.complete(
      'op_one',
      'test_provider',
      'provider_session_one',
    )).resolves.toEqual({ success: false, claims: [] });
    await expect(token.verification.completeWithToken(
      'op_one',
      'test_provider',
      'provider_session_one',
      'provider-token',
    )).resolves.toEqual({ success: false, claims: [] });
    expect(normal.complete).toHaveBeenCalledWith('op_one', 'provider_session_one');
    expect(token.complete).toHaveBeenCalledWith('op_one', 'provider-token');
  });
});
