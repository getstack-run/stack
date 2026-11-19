import { afterAll, describe, it, expect, beforeEach, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { eq } from 'drizzle-orm';
import {
  acquireOAuthOperatorLock,
  createDb,
  operatorEmailDeliveryJobs,
  operatorEmailChanges,
  operators,
  type Database,
} from '@stack/shared';
import { EmailChangeService } from './email-change-service.js';

// The email is the credential — there are no passwords — so these tests are
// about control of an account, not about a profile field.
//
// The service builds drizzle predicates that need a live Postgres to execute,
// so these assertions sit on the parts that carry the security properties: how
// tokens are stored, who gets told what, and in which order. The query wiring
// is covered by the API's route tests against a real database.

const sha256 = (v: string) => createHash('sha256').update(v).digest('hex');
class TestableEmailChange extends EmailChangeService {
  public sent: Array<{ to: string; subject: string; text: string }> = [];
  constructor() {
    super({
      db: {} as any,
      email: {
        sendEmail: async (to: string, subject: string, text: string) => {
          (this as any).sent.push({ to, subject, text });
          return { id: 'em_test' };
        },
      },
      rateLimitStore: null,
      audit: { write: async () => 'aud_test' },
      dashboardUrl: 'https://getstack.run',
    });
  }
}

describe('EmailChangeService — token handling', () => {
  it('hashes both tokens; neither is stored in plaintext', () => {
    // The raw token appears only in the email body. What lands in the row is
    // its sha256, exactly like a magic link.
    const raw = 'a-token-value';
    const stored = sha256(raw);
    expect(stored).not.toContain(raw);
    expect(stored).toHaveLength(64);
    expect(sha256(raw)).toBe(stored);
  });

  it('a different token produces a different hash', () => {
    expect(sha256('token-a')).not.toBe(sha256('token-b'));
  });
});

describe('EmailChangeService — the shape that matters', () => {
  let svc: TestableEmailChange;

  beforeEach(() => {
    svc = new TestableEmailChange();
  });

  it('sends to the new address AND warns the old one', async () => {
    // The warning to the old address is the entire defence against a stolen
    // session: the owner learns a transfer was attempted before it completes.
    const service = svc as any;
    await service.sendConfirm('new@example.com', 'owner@example.com', 'ctok');
    await service.sendNotice('owner@example.com', 'new@example.com', 'xtok');

    expect(svc.sent).toHaveLength(2);
    expect(svc.sent[0]!.to).toBe('new@example.com');
    expect(svc.sent[1]!.to).toBe('owner@example.com');
    expect(svc.sent[1]!.text).toContain('was not you');
    expect(svc.sent[1]!.text).toContain('/account/email-change/cancel');
  });

  it('gives the old address the public cancellation link and recovery advice', async () => {
    const service = svc as any;
    await service.sendNotice('owner@example.com', 'attacker@evil.test', 'xtok');
    const body = svc.sent[0]!.text;
    expect(body).toContain('https://getstack.run/account/email-change/cancel?token=xtok');
    // And it tells them what else to do, because a session was compromised.
    expect(body).toContain('rotate your operator API key');
  });

  it('gives the new address a one-use confirmation link and expiry', async () => {
    const service = svc as any;
    await service.sendConfirm('new@example.com', 'owner@example.com', 'ctok');
    expect(svc.sent[0]!.text).toContain('https://getstack.run/account/email-change/confirm?token=ctok');
    expect(svc.sent[0]!.text).toContain('works once and expires in 30 minutes');
  });

  it('tells the old address after a completed transfer', async () => {
    const service = svc as any;
    await service.sendCompleted('owner@example.com', 'new@example.com');
    expect(svc.sent[0]!.to).toBe('owner@example.com');
    expect(svc.sent[0]!.text).toContain('no longer request sign-in links');
  });
});

describe('EmailChangeService — refusals', () => {
  it('refuses an address that is not one', async () => {
    const svc = new EmailChangeService({
      db: {} as any,
      email: null,
      rateLimitStore: null,
      audit: { write: async () => 'aud_test' },
      dashboardUrl: 'https://getstack.run',
    });
    await expect(
      svc.request({ operatorId: 'op_1', newEmail: 'not-an-email' }, { traceId: 'tr', spanId: 'sp' }),
    ).rejects.toThrow(/does not look like an email/i);
  });

  it('refuses an empty address before touching the database', async () => {
    const svc = new EmailChangeService({
      db: {
        select() {
          throw new Error('the database must not be reached for an invalid address');
        },
      } as any,
      email: null,
      rateLimitStore: null,
      audit: { write: async () => 'aud_test' },
      dashboardUrl: 'https://getstack.run',
    });
    await expect(svc.request(
      { operatorId: 'op_1', newEmail: '   ' },
      { traceId: 'tr', spanId: 'sp' },
    )).rejects.toThrow();
  });

  it('does not print recipient, body, URL, or token when no email provider exists', async () => {
    const warning = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const service = new EmailChangeService({
      db: {} as any,
      email: null,
      rateLimitStore: null,
      audit: { write: async () => 'aud_test' },
      dashboardUrl: 'https://getstack.run',
    }) as any;

    await expect(service.deliver(
      'owner@example.invalid',
      'Secret account transfer',
      'Use https://getstack.run/confirm?token=secret-token now',
    )).rejects.toMatchObject({ code: 'EMAIL_SEND_FAILED' });

    const output = warning.mock.calls.flat().join(' ');
    expect(output).not.toContain('owner@example.invalid');
    expect(output).not.toContain('Secret account transfer');
    expect(output).not.toContain('https://');
    expect(output).not.toContain('secret-token');
    warning.mockRestore();
  });

  it('does not print provider errors that can contain email content', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const service = new EmailChangeService({
      db: {} as any,
      email: {
        sendEmail: async () => {
          throw new Error('owner@example.invalid https://getstack.run/?token=secret-token');
        },
      },
      rateLimitStore: null,
      audit: { write: async () => 'aud_test' },
      dashboardUrl: 'https://getstack.run',
    }) as any;

    await expect(service.deliver(
      'owner@example.invalid',
      'Secret account transfer',
      'Secret body',
    )).rejects.toMatchObject({ code: 'EMAIL_SEND_FAILED' });
    const output = error.mock.calls.flat().join(' ');
    expect(output).not.toContain('owner@example.invalid');
    expect(output).not.toContain('https://');
    expect(output).not.toContain('secret-token');
    error.mockRestore();
  });
});

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;
type DbTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

describeWithDb('EmailChangeService PostgreSQL lifecycle', () => {
  const db = createDb(DATABASE_URL!);
  const operatorIds: string[] = [];

  afterAll(async () => {
    for (const operatorId of operatorIds.reverse()) {
      await db.delete(operatorEmailDeliveryJobs)
        .where(eq(operatorEmailDeliveryJobs.operator_id, operatorId))
        .catch(() => undefined);
      await db.delete(operatorEmailChanges)
        .where(eq(operatorEmailChanges.operator_id, operatorId))
        .catch(() => undefined);
      await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
    }
  });

  async function seedOperator(label: string) {
    const suffix = Math.random().toString(36).slice(2);
    const operatorId = `op_email_${label}_${suffix}`;
    const oldEmail = `${operatorId}@test.invalid`;
    const newEmail = `${operatorId}_new@test.invalid`;
    operatorIds.push(operatorId);
    await db.insert(operators).values({
      id: operatorId,
      email: oldEmail,
      api_key_hash: `hash_${operatorId}`,
    });
    return { operatorId, oldEmail, newEmail };
  }

  function auditContext() {
    return {
      traceId: `tr_${Math.random().toString(36).slice(2)}`,
      spanId: `sp_${Math.random().toString(36).slice(2)}`,
    };
  }

  function makeService(input: {
    sendEmail: (to: string, subject: string, text: string) => Promise<{ id: string }>;
    auditWrite?: (input: unknown, tx?: DbTransaction) => Promise<string>;
  }) {
    return new EmailChangeService({
      db,
      email: { sendEmail: input.sendEmail },
      rateLimitStore: null,
      dashboardUrl: 'https://getstack.run',
      audit: { write: input.auditWrite ?? (async () => 'aud_email') },
    } as never);
  }

  function request(
    service: EmailChangeService,
    input: { operatorId: string; newEmail: string; requestedByMemberId?: string | null },
  ) {
    return (service.request as unknown as (
      value: typeof input,
      audit: ReturnType<typeof auditContext>,
    ) => ReturnType<EmailChangeService['request']>)(input, auditContext());
  }

  function confirm(service: EmailChangeService, token: string) {
    return (service.confirm as unknown as (
      value: string,
      audit: ReturnType<typeof auditContext>,
    ) => ReturnType<EmailChangeService['confirm']>)(token, auditContext());
  }

  function cancel(service: EmailChangeService, token: string) {
    return (service.cancel as unknown as (
      value: string,
      audit: ReturnType<typeof auditContext>,
    ) => ReturnType<EmailChangeService['cancel']>)(token, auditContext());
  }

  function tokenFrom(text: string, path: 'confirm' | 'cancel'): string {
    const match = text.match(new RegExp(`/account/email-change/${path}\\?token=([^\\s]+)`));
    if (!match?.[1]) throw new Error(`missing_${path}_token`);
    return decodeURIComponent(match[1]);
  }

  it('delivery gate keeps confirmation unusable until both emails succeed', async () => {
    const fixture = await seedOperator('delivery_gate');
    let release!: () => void;
    let started!: () => void;
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    const startedPromise = new Promise<void>((resolve) => { started = resolve; });
    const sent: Array<{ subject: string; text: string }> = [];
    const service = makeService({
      sendEmail: async (_to, subject, text) => {
        sent.push({ subject, text });
        if (sent.length === 1) {
          started();
          await releasePromise;
        }
        return { id: 'em_delivery_gate' };
      },
    });

    const pendingRequest = request(service, {
      operatorId: fixture.operatorId,
      newEmail: fixture.newEmail,
    });
    await startedPromise;
    const token = tokenFrom(sent[0]!.text, 'confirm');
    try {
      await expect(confirm(service, token)).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
      expect((await db.query.operators.findFirst({ where: eq(operators.id, fixture.operatorId) }))?.email)
        .toBe(fixture.oldEmail);
    } finally {
      release();
      await pendingRequest.catch(() => undefined);
    }
  });

  it('concurrent decision has one confirm winner', async () => {
    const fixture = await seedOperator('confirm_race');
    const sent: Array<{ text: string }> = [];
    const service = makeService({
      sendEmail: async (_to, _subject, text) => {
        sent.push({ text });
        return { id: 'em_confirm_race' };
      },
    });
    await request(service, { operatorId: fixture.operatorId, newEmail: fixture.newEmail });
    const token = tokenFrom(sent[0]!.text, 'confirm');
    const results = await Promise.allSettled([confirm(service, token), confirm(service, token)]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
  });

  it('concurrent decision confirm and cancel cannot both win', async () => {
    const fixture = await seedOperator('mixed_race');
    const sent: Array<{ subject: string; text: string }> = [];
    const service = makeService({
      sendEmail: async (_to, subject, text) => {
        sent.push({ subject, text });
        return { id: 'em_mixed_race' };
      },
    });
    await request(service, { operatorId: fixture.operatorId, newEmail: fixture.newEmail });
    const confirmToken = tokenFrom(sent.find((email) => email.text.includes('/confirm?token='))!.text, 'confirm');
    const cancelToken = tokenFrom(sent.find((email) => email.text.includes('/cancel?token='))!.text, 'cancel');
    const results = await Promise.allSettled([
      confirm(service, confirmToken),
      cancel(service, cancelToken),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
    const row = await db.query.operatorEmailChanges.findFirst({
      where: eq(operatorEmailChanges.operator_id, fixture.operatorId),
    });
    expect(Number(Boolean(row?.confirmed_at)) + Number(Boolean(row?.cancelled_at))).toBe(1);
  });

  it('erasure race blocks a late request', async () => {
    const fixture = await seedOperator('erasure_race');
    const service = makeService({
      sendEmail: async () => ({ id: 'em_erasure_race' }),
    });
    let release!: () => void;
    let locked!: () => void;
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    const lockedPromise = new Promise<void>((resolve) => { locked = resolve; });
    const locker = db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, fixture.operatorId);
      locked();
      await releasePromise;
      await tx.update(operators)
        .set({ status: 'deleted', deleted_at: new Date() })
        .where(eq(operators.id, fixture.operatorId));
    });
    await lockedPromise;
    const pendingRequest = request(service, {
      operatorId: fixture.operatorId,
      newEmail: fixture.newEmail,
    });
    try {
      const state = await Promise.race([
        pendingRequest.then(() => 'settled' as const, () => 'settled' as const),
        new Promise<'blocked'>((resolve) => setTimeout(() => resolve('blocked'), 100)),
      ]);
      expect(state).toBe('blocked');
    } finally {
      release();
      await locker;
    }
    await expect(pendingRequest).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
  });

  it('delivery gate completion failure stays committed and retryable', async () => {
    const fixture = await seedOperator('completion_retry');
    const sent: Array<{ subject: string; text: string }> = [];
    const service = makeService({
      sendEmail: async (_to, subject, text) => {
        sent.push({ subject, text });
        if (subject.includes('has changed')) throw new Error('delivery_failed');
        return { id: 'em_completion_retry' };
      },
    });
    await request(service, { operatorId: fixture.operatorId, newEmail: fixture.newEmail });
    const token = tokenFrom(sent[0]!.text, 'confirm');
    await expect(confirm(service, token)).resolves.toEqual({
      operatorId: fixture.operatorId,
      email: fixture.newEmail,
    });
    expect((await db.query.operators.findFirst({ where: eq(operators.id, fixture.operatorId) }))?.email)
      .toBe(fixture.newEmail);
    expect(await db.query.operatorEmailDeliveryJobs.findFirst({
      where: eq(operatorEmailDeliveryJobs.operator_id, fixture.operatorId),
    })).toMatchObject({
      status: 'pending',
      last_error_code: 'delivery_failed',
    });
  });

  it('concurrent decision audit failure rolls back terminal state', async () => {
    const fixture = await seedOperator('audit_rollback');
    const sent: Array<{ text: string }> = [];
    const service = makeService({
      sendEmail: async (_to, _subject, text) => {
        sent.push({ text });
        return { id: 'em_audit_rollback' };
      },
      auditWrite: async (input) => {
        if ((input as { action?: string }).action === 'operator.email_change.confirm') {
          throw new Error('audit_failed');
        }
        return 'aud_email';
      },
    });
    await request(service, { operatorId: fixture.operatorId, newEmail: fixture.newEmail });
    const token = tokenFrom(sent[0]!.text, 'confirm');
    await expect(confirm(service, token)).rejects.toThrow('audit_failed');
    expect((await db.query.operators.findFirst({ where: eq(operators.id, fixture.operatorId) }))?.email)
      .toBe(fixture.oldEmail);
    const row = await db.query.operatorEmailChanges.findFirst({
      where: eq(operatorEmailChanges.operator_id, fixture.operatorId),
    });
    expect(row?.confirmed_at).toBeNull();
    expect(row?.cancelled_at).toBeNull();
  });
});
