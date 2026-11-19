import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { LicenceRequiredError } from '@stack/shared';
import { SmtpEmailService } from '@stack/vault';
import { createEmailSenders, resolveEmailTransport } from './email-transport.js';
import {
  LicenceService,
  createFeatureGate,
  hostedFeatureGate,
  licenceKeyReaderFromEnv,
  requireFeatureHook,
} from './licence-service.js';
import { assertSelfManagedBoot } from './self-managed.js';

const quiet = { log: vi.fn(), warn: vi.fn() };

function licenceIssuer(kid = 'test-licence-1') {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64url');
  return {
    trustedKeys: { [kid]: raw },
    issue(overrides: Record<string, unknown> = {}) {
      const claims = {
        v: 1,
        kid,
        customer: 'Example AB',
        issued_at: '2026-01-01T00:00:00.000Z',
        expires_at: '2027-01-01T00:00:00.000Z',
        features: ['sso', 'siem'],
        ...overrides,
      };
      const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
      const signature = sign(null, Buffer.from(`stack-licence-v1\n${payload}`), privateKey).toString('base64url');
      return `STACKLIC1.${payload}.${signature}`;
    },
  };
}

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  vi.clearAllMocks();
});

describe('feature gate', () => {
  it('says yes to everything on STACK\'s hosted deployment, where plans decide', () => {
    expect(hostedFeatureGate.has('sso')).toBe(true);
    expect(() => hostedFeatureGate.require('partners')).not.toThrow();
    expect(createFeatureGate(true)).toBe(hostedFeatureGate);
  });

  it('never gives the engine alone the hosted gate, whatever the environment says', () => {
    // The gate follows the extension: no extension, no hosted gate, in every mode and every NODE_ENV.
    for (const STACK_DEPLOYMENT of [undefined, '', 'hosted', 'self_managed']) {
      for (const NODE_ENV of [undefined, 'production', 'staging', 'development', 'test']) {
        const gate = createFeatureGate(false, { STACK_DEPLOYMENT, NODE_ENV });
        expect(gate, `${STACK_DEPLOYMENT} ${NODE_ENV}`).not.toBe(hostedFeatureGate);
        expect(gate.has('sso')).toBe(false);
        expect(() => gate.require('partners')).toThrow(LicenceRequiredError);
        expect(gate.snapshot()).toMatchObject({ mode: 'self_managed', licence: 'none', features: [] });
      }
    }
  });

  it('runs a self-managed install with no key, every enterprise feature off', () => {
    const gate = new LicenceService({ readKey: () => undefined, log: quiet });
    gate.check();
    expect(gate.has('sso')).toBe(false);
    expect(gate.snapshot()).toMatchObject({ mode: 'self_managed', licence: 'none', features: [] });
    try {
      gate.require('roles');
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(LicenceRequiredError);
      expect((err as LicenceRequiredError).statusCode).toBe(402);
      expect((err as LicenceRequiredError).code).toBe('LICENCE_REQUIRED');
      expect((err as LicenceRequiredError).details).toEqual({ feature: 'roles', licence: 'none' });
    }
  });

  it('turns on exactly the features the key covers', () => {
    const { issue, trustedKeys } = licenceIssuer();
    const gate = new LicenceService({
      readKey: () => issue(),
      trustedKeys,
      now: () => new Date('2026-10-21T00:00:00Z'),
      log: quiet,
    });
    gate.check();
    expect(gate.has('sso')).toBe(true);
    expect(gate.has('siem')).toBe(true);
    expect(gate.has('evidence_exports')).toBe(false);
    expect(gate.snapshot()).toMatchObject({ licence: 'valid', customer: 'Example AB', features: ['sso', 'siem'] });
    expect(JSON.stringify(gate.snapshot())).not.toContain('STACKLIC1');
  });

  it('stops granting at the expiry instant without waiting for the daily check', () => {
    const { issue, trustedKeys } = licenceIssuer();
    let now = new Date('2026-12-31T23:59:00Z');
    const gate = new LicenceService({ readKey: () => issue(), trustedKeys, now: () => now, log: quiet });
    gate.check();
    expect(gate.has('sso')).toBe(true);
    now = new Date('2027-01-01T00:00:01Z');
    expect(gate.has('sso')).toBe(false);
    expect(gate.snapshot().licence).toBe('expired');
    expect(() => gate.require('sso')).toThrow(LicenceRequiredError);
  });

  it('picks up a renewed key on the next check and keeps running when the key file disappears', () => {
    const { issue, trustedKeys } = licenceIssuer();
    const dir = mkdtempSync(join(tmpdir(), 'stack-licence-'));
    dirs.push(dir);
    const file = join(dir, 'licence');
    const gate = new LicenceService({
      readKey: licenceKeyReaderFromEnv({ STACK_LICENCE_KEY_FILE: file }),
      trustedKeys,
      now: () => new Date('2026-10-21T00:00:00Z'),
      log: quiet,
    });
    gate.check();
    expect(gate.snapshot().licence).toBe('none');
    writeFileSync(file, `${issue()}\n`);
    gate.check();
    expect(gate.has('sso')).toBe(true);
    rmSync(file);
    gate.check();
    expect(gate.has('sso')).toBe(false);
    expect(quiet.warn).toHaveBeenCalled();
  });

  it('refuses a key that was tampered with, and says why, without the key', () => {
    const { issue, trustedKeys } = licenceIssuer();
    const [prefix, , signature] = issue().split('.');
    const forged = Buffer.from(
      JSON.stringify({ v: 1, kid: 'test-licence-1', customer: 'X', issued_at: '2026-01-01T00:00:00.000Z', expires_at: '2099-01-01T00:00:00.000Z', features: ['sso'] }),
    ).toString('base64url');
    const gate = new LicenceService({ readKey: () => `${prefix}.${forged}.${signature}`, trustedKeys, log: quiet });
    gate.check();
    expect(gate.has('sso')).toBe(false);
    expect(gate.snapshot()).toMatchObject({ licence: 'invalid', reason: 'bad_signature' });
    expect(JSON.stringify(quiet.warn.mock.calls)).not.toContain(forged);
  });

  it('refuses both an inline key and a key file', () => {
    expect(() => licenceKeyReaderFromEnv({ STACK_LICENCE_KEY: 'a', STACK_LICENCE_KEY_FILE: '/x' })).toThrow(/not both/);
  });

  it('answers a request to a gated route with 402 before anything else runs', async () => {
    const gate = new LicenceService({ readKey: () => undefined, log: quiet });
    gate.check();
    await expect(requireFeatureHook(gate, 'partners')()).rejects.toBeInstanceOf(LicenceRequiredError);
    await expect(requireFeatureHook(hostedFeatureGate, 'partners')()).resolves.toBeUndefined();
  });
});

describe('email transport', () => {
  it('keeps Resend for STACK\'s hosted deployment and never reads SMTP there', () => {
    expect(resolveEmailTransport({ selfManaged: false, resendKey: 're_x', smtpHost: 'mail.example' })).toEqual({
      kind: 'resend',
      apiKey: 're_x',
    });
    expect(resolveEmailTransport({ selfManaged: false })).toEqual({ kind: 'none' });
  });

  it('lets a self-managed install pick SMTP, Resend or no email', () => {
    expect(resolveEmailTransport({ selfManaged: true })).toEqual({ kind: 'none' });
    const smtp = resolveEmailTransport({
      selfManaged: true,
      smtpUrl: 'smtps://u:p@mail.example',
      emailFrom: 'stack@corp.example',
    });
    expect(smtp).toMatchObject({ kind: 'smtp', config: { host: 'mail.example', port: 465, secure: true } });
    expect(resolveEmailTransport({ selfManaged: true, resendKey: 're_x' }).kind).toBe('resend');
    expect(resolveEmailTransport({ selfManaged: true, resendKey: 're_x', transport: 'none' }).kind).toBe('none');
  });

  it('refuses SMTP without a sender, an unknown transport and a transport without its settings', () => {
    expect(() => resolveEmailTransport({ selfManaged: true, smtpHost: 'mail.example' })).toThrow(/EMAIL_FROM/);
    expect(() => resolveEmailTransport({ selfManaged: true, transport: 'carrier-pigeon' })).toThrow(/STACK_EMAIL_TRANSPORT/);
    expect(() => resolveEmailTransport({ selfManaged: true, transport: 'smtp' })).toThrow(/SMTP_URL/);
    expect(() => resolveEmailTransport({ selfManaged: true, transport: 'resend' })).toThrow(/RESEND_API_KEY/);
  });

  it('builds no sender for no email, and one SMTP sender for every purpose', () => {
    const resend = { fromNotifications: 'n', fromAuth: 'a', replyTo: '', listUnsubscribe: '' };
    expect(createEmailSenders({ kind: 'none' }, resend)).toEqual({ notifications: null, auth: null, account: null });
    const senders = createEmailSenders(
      { kind: 'smtp', config: { host: 'mail.example', port: 587, secure: false, from: 'stack@corp.example' } },
      resend,
    );
    expect(senders.auth).toBeInstanceOf(SmtpEmailService);
    expect(senders.auth).toBe(senders.notifications);
  });
});

describe('self-managed boot checks', () => {
  it('needs a real API key pepper in production and nothing elsewhere', () => {
    expect(() => assertSelfManagedBoot({ NODE_ENV: 'production', API_KEY_PEPPER: 'short' })).toThrow(/API_KEY_PEPPER/);
    expect(() => assertSelfManagedBoot({ NODE_ENV: 'production' })).toThrow(/API_KEY_PEPPER/);
    expect(() => assertSelfManagedBoot({ NODE_ENV: 'production', API_KEY_PEPPER: 'p'.repeat(32) })).not.toThrow();
    expect(() => assertSelfManagedBoot({ NODE_ENV: 'development' })).not.toThrow();
  });
});
