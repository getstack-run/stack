import { emailChrome, neutralEmailChrome, setEmailChrome } from '@stack/shared';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ResendEmailService } from './resend-email-service.js';

describe('ResendEmailService error hygiene', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('does not put provider response content in the thrown error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response('owner@example.invalid token=secret-token code=123456', { status: 400 }),
      ),
    );
    const service = new ResendEmailService({
      apiKey: 're_test',
      fromEmail: 'Install <notifications@install.example>',
    });

    await expect(
      service.sendEmail('owner@example.invalid', 'Secret subject', 'Secret body'),
    ).rejects.toThrow(/^Resend email failed \(400\)$/);
  });

  it('passes an idempotency key without exposing it in the body', async () => {
    const fetch = vi.fn(async (_url: string, options: RequestInit) => {
      expect((options.headers as Record<string, string>)['Idempotency-Key']).toBe('welcome/op_123');
      expect(String(options.body)).not.toContain('welcome/op_123');
      return new Response(JSON.stringify({ id: 'email_123' }), { status: 200 });
    });
    vi.stubGlobal('fetch', fetch);
    const service = new ResendEmailService({
      apiKey: 're_test',
      fromEmail: 'Install <hello@install.example>',
    });
    await expect(
      service.sendEmail('owner@example.invalid', 'Welcome', 'body', undefined, {
        idempotencyKey: 'welcome/op_123',
      }),
    ).resolves.toEqual({ id: 'email_123' });
  });
});

describe('ResendEmailService signature', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    setEmailChrome(null);
  });

  function sentBody(): { calls: () => Record<string, unknown> } {
    const fetch = vi.fn(async (_url: string, _options: RequestInit) => new Response(JSON.stringify({ id: 'email_1' }), { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    return { calls: () => JSON.parse(String(fetch.mock.calls[0]![1].body)) as Record<string, unknown> };
  }
  const service = () => new ResendEmailService({ apiKey: 're_test', fromEmail: 'Install <hello@install.example>' });

  it('appends no footer unless the deployment registered one', async () => {
    expect(emailChrome().signature()).toBeNull();
    const sent = sentBody();
    await service().sendEmail('a@example.invalid', 'Subject', 'body', '<p>body</p>');
    expect(sent.calls()).toMatchObject({ text: 'body', html: '<p>body</p>' });
  });

  it("appends the deployment's footer to text and html, and skips it when asked", async () => {
    setEmailChrome({ ...neutralEmailChrome, signature: () => ({ text: '\n-- footer', html: '<i>footer</i>' }) });
    const sent = sentBody();
    await service().sendEmail('a@example.invalid', 'Subject', 'body', '<p>body</p>');
    expect(sent.calls()).toMatchObject({ text: 'body\n-- footer', html: '<p>body</p><i>footer</i>' });
    const skipped = sentBody();
    await service().sendEmail('a@example.invalid', 'Subject', 'body', '<p>body</p>', { skipSignature: true });
    expect(skipped.calls()).toMatchObject({ text: 'body', html: '<p>body</p>' });
  });
});
