import { describe, it, expect, vi } from 'vitest';
import { NotificationService, type NotificationSendMeter } from './notification-service.js';

// mailOwner: the one mail to the account owner for an event no delivery method received. The recipient is the
// account's own sign-in address, read from its row; the ordinary mail service and send cap apply.

const EVENT = {
  operatorId: 'op_1',
  eventType: 'governance.approval_pending',
  severity: 'warning' as const,
  payload: {
    approval_id: 'gva_1',
    action: 'service_grant_expand',
    resource_id: 'agt_1',
    requested_via: 'oauth',
    expires_at: '2026-11-12T10:00:00.000Z',
    approval_url: 'https://getstack.run/app/approve/gva_1',
    summary: 'Give agent "bot" access to anthropic',
  },
};

function makeService(ownerEmail: string | null) {
  const db = {
    select: () => ({ from: () => ({ where: () => ({ limit: async () => (ownerEmail === null ? [] : [{ email: ownerEmail }]) }) }) }),
  } as never;
  const sendEmail = vi.fn(async (_to: string, _subject: string, _text: string, _html?: string, _options?: { skipSignature?: boolean }) => ({ id: "msg_1" }));
  const svc = new NotificationService(db, { findByOperator: vi.fn(async () => []) } as never, null);
  svc.setEmailService({ sendEmail });
  return { svc, sendEmail };
}

describe('NotificationService.mailOwner', () => {
  it("mails the approval to the account's own sign-in address, with its link, through the mail service", async () => {
    const { svc, sendEmail } = makeService('owner@example.com');
    expect(await svc.mailOwner(EVENT)).toBe(true);
    expect(sendEmail).toHaveBeenCalledTimes(1);
    const [to, subject, text, html] = sendEmail.mock.calls[0]!;
    expect(to).toBe('owner@example.com');
    expect(subject).toContain('Approval required');
    expect(text).toContain('https://getstack.run/app/approve/gva_1');
    expect(html).toContain('https://getstack.run/app/approve/gva_1');
  });

  it('is under the same send cap as every notification email: a refusal sends nothing', async () => {
    const { svc, sendEmail } = makeService('owner@example.com');
    const meter: NotificationSendMeter = { authorizeSend: vi.fn(async () => ({ allowed: false, reason: 'monthly email allowance reached' })) };
    svc.setSendMeter(meter);
    expect(await svc.mailOwner(EVENT)).toBe(false);
    expect(meter.authorizeSend).toHaveBeenCalledWith('op_1', 'email', expect.objectContaining({ to: 'owner@example.com' }));
    expect(sendEmail).not.toHaveBeenCalled();
  });

  it("sends nothing to a white-label tenant's placeholder address", async () => {
    const { svc, sendEmail } = makeService('tenant-op_x@op_partner.stack-tenant.local');
    expect(await svc.mailOwner(EVENT)).toBe(false);
    expect(sendEmail).not.toHaveBeenCalled();
  });

  it('sends nothing without a mail service, or for an account that does not exist', async () => {
    const { svc, sendEmail } = makeService(null);
    expect(await svc.mailOwner(EVENT)).toBe(false);
    const noMail = new NotificationService({} as never, { findByOperator: vi.fn(async () => []) } as never, null);
    expect(await noMail.mailOwner(EVENT)).toBe(false);
    expect(sendEmail).not.toHaveBeenCalled();
  });

  it('lets a mail service failure reach the caller, which logs it without the address', async () => {
    const { svc, sendEmail } = makeService('owner@example.com');
    sendEmail.mockRejectedValueOnce(new Error('provider refused'));
    await expect(svc.mailOwner(EVENT)).rejects.toThrow('provider refused');
  });
});
