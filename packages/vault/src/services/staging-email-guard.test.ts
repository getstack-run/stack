import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import nodemailer from 'nodemailer';
import { STAGING_SKIPPED_EMAIL_ID } from '@stack/shared';
import { ResendEmailService } from './resend-email-service.js';
import { SmtpEmailService } from './smtp-email-service.js';
import { EmailChangeService } from './email-change-service.js';
import { skipStagingRecipient } from './staging-email-guard.js';

const ENV = { staging: process.env['STACK_STAGING'], list: process.env['STAGING_SIGNIN_ALLOWLIST'] };

function restoreEnv(): void {
  for (const [name, value] of [['STACK_STAGING', ENV.staging], ['STAGING_SIGNIN_ALLOWLIST', ENV.list]] as const) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
}

function onStaging(): void {
  process.env['STACK_STAGING'] = 'true';
  process.env['STAGING_SIGNIN_ALLOWLIST'] = 'tester@example.com';
}

describe('the staging email guard', () => {
  afterEach(() => {
    restoreEnv();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('changes nothing outside staging', async () => {
    delete process.env['STACK_STAGING'];
    expect(skipStagingRecipient('stranger@example.org')).toBeNull();
    const fetch = vi.fn(async () => new Response(JSON.stringify({ id: 'email_1' }), { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    const service = new ResendEmailService({ apiKey: 're_test', fromEmail: 'STACK <n@example.com>' });
    await expect(service.sendEmail('stranger@example.org', 's', 't')).resolves.toEqual({ id: 'email_1' });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('on staging, Resend sends to an allowed address and skips anyone else, logging it without the address', async () => {
    onStaging();
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const fetch = vi.fn(async () => new Response(JSON.stringify({ id: 'email_2' }), { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    const service = new ResendEmailService({ apiKey: 're_test', fromEmail: 'STACK <n@example.com>' });

    await expect(service.sendEmail('stranger@example.org', 'Your digest', 'body')).resolves.toEqual({ id: STAGING_SKIPPED_EMAIL_ID });
    expect(fetch).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0]?.[0])).toMatch(/\[STAGING\] Skipped an email/);
    expect(JSON.stringify(warn.mock.calls)).not.toContain('stranger@example.org');

    await expect(service.sendEmail('Tester@Example.com', 'Your digest', 'body')).resolves.toEqual({ id: 'email_2' });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('on staging, SMTP skips anyone outside the allow-list too', async () => {
    onStaging();
    vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const transport = nodemailer.createTransport({ jsonTransport: true });
    const sendMail = vi.spyOn(transport, 'sendMail');
    const service = new SmtpEmailService({ host: 'relay.corp.example', port: 587, secure: false, from: 'stack@corp.example' }, transport);
    await expect(service.sendEmail('stranger@example.org', 's', 't')).resolves.toEqual({ id: STAGING_SKIPPED_EMAIL_ID });
    expect(sendMail).not.toHaveBeenCalled();
    await service.sendEmail('tester@example.com', 's', 't');
    expect(sendMail).toHaveBeenCalledTimes(1);
  });
});

describe('an email change on staging', () => {
  beforeEach(onStaging);
  afterEach(restoreEnv);

  it('refuses a new address outside the allow-list before anything is read, written or sent', async () => {
    const touched: string[] = [];
    const trap = new Proxy({}, { get: (_t, key) => { touched.push(String(key)); throw new Error('touched'); } });
    const service = new EmailChangeService({
      db: trap as never,
      email: trap as never,
      rateLimitStore: trap as never,
      audit: trap as never,
      dashboardUrl: 'https://staging-site.example.test',
    } as never);
    await expect(
      service.request({ operatorId: 'op_x', newEmail: 'stranger@example.org' }, { traceId: 't', spanId: 's', startedAtMs: 0 } as never),
    ).rejects.toMatchObject({ code: 'INVALID_EMAIL' });
    expect(touched).toEqual([]);
  });
});
