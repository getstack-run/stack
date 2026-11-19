import { describe, expect, it, vi } from 'vitest';
import { OauthAppService } from './oauth-app-service.js';

/** A KMS that keeps what it is given, bound to its context, and a repository over one row. */
function harness() {
  const rows: Array<Record<string, unknown>> = [];
  const kms = {
    encrypt: vi.fn(async (plaintext: string, context: Record<string, unknown>) =>
      ({ ciphertext: `enc:${JSON.stringify(context)}:${plaintext}`, keyRef: 'k' })),
    decrypt: vi.fn(async (ciphertext: string, context: Record<string, unknown>) => {
      const prefix = `enc:${JSON.stringify(context)}:`;
      if (!ciphertext.startsWith(prefix)) throw new Error('context mismatch');
      return ciphertext.slice(prefix.length);
    }),
  };
  const repo = {
    findByOperatorAndProvider: vi.fn(async (operator: string, provider: string) =>
      rows.find((row) => row['operator_id'] === operator && row['provider'] === provider)),
    findByOperator: vi.fn(async (operator: string) => rows.filter((row) => row['operator_id'] === operator)),
    create: vi.fn(async (data: Record<string, unknown>) => {
      const row = { created_at: new Date(), updated_at: new Date(), ...data };
      rows.push(row);
      return row;
    }),
    deleteByOperatorAndProvider: vi.fn(),
  };
  return { service: new OauthAppService(repo as never, kms as never), kms, rows };
}

describe('OauthAppService tenant', () => {
  it('keeps a single-tenant app\'s tenant inside the secret\'s envelope and reads it back', async () => {
    const h = harness();
    const created = await h.service.create('op_a', {
      provider: 'microsoft', client_id: 'cid', client_secret: 'synthetic-secret', tenant: 'contoso.onmicrosoft.com',
    });
    expect(created).not.toHaveProperty('tenant');
    expect(h.rows[0]).not.toHaveProperty('tenant');
    expect(String(h.rows[0]?.['client_secret_encrypted'])).toContain('contoso.onmicrosoft.com');
    expect(await h.service.getDecrypted('op_a', 'microsoft')).toMatchObject({
      client_id: 'cid', client_secret: 'synthetic-secret', tenant: 'contoso.onmicrosoft.com',
    });
  });

  it('reads an app made without a tenant, or before tenants existed, as the bare secret', async () => {
    const h = harness();
    await h.service.create('op_a', { provider: 'google', client_id: 'cid', client_secret: 'plain-secret' });
    const app = await h.service.getDecrypted('op_a', 'google');
    expect(app).toMatchObject({ client_secret: 'plain-secret' });
    expect(app).not.toHaveProperty('tenant');
  });

  it('treats a secret that merely starts with the marker as a secret', async () => {
    const h = harness();
    await h.service.create('op_a', { provider: 'google', client_id: 'cid', client_secret: 'stack-oauth-app/v1:not-json' });
    expect(await h.service.getDecrypted('op_a', 'google')).toMatchObject({ client_secret: 'stack-oauth-app/v1:not-json' });
  });

  it('refuses a tenant that could change the sign-in URL', async () => {
    const h = harness();
    for (const tenant of ['../common', 'a/b', 'a b', '', '-x']) {
      await expect(h.service.create('op_a', { provider: 'microsoft', client_id: 'c', client_secret: 's', tenant }))
        .rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    }
    expect(h.rows).toHaveLength(0);
  });
});
