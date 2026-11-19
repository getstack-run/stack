// A new pending approval that no delivery method of the account received is mailed once to the account owner.

import { describe, it, expect } from 'vitest';
import { OP, baseReq, makeService } from './governance-approval-service.test-support.js';

const settle = () => new Promise((resolve) => setTimeout(resolve, 5));

describe('GovernanceApprovalService: the owner mail for an approval nobody was told of', () => {
  it('mails the owner once when the event reached no channel, with the approval link and no request payload', async () => {
    const { svc, ownerMails } = makeService({ dispatched: 0 });
    const { row } = await svc.createPending(baseReq);
    await settle();
    expect(ownerMails).toHaveLength(1);
    const mail = ownerMails[0]!;
    expect(mail.operatorId).toBe(OP);
    expect(mail.eventType).toBe('governance.approval_pending');
    expect(mail.payload['approval_url']).toBe(`https://getstack.run/app/approve/${row.id}`);
    // The mail carries the facts the template shows and nothing of the request's own values.
    expect(Object.keys(mail.payload).sort()).toEqual(
      ['action', 'approval_id', 'approval_url', 'expires_at', 'requested_via', 'resource_id', 'summary'],
    );
    expect(JSON.stringify(mail.payload)).not.toContain('prompt_injection_secret_value');
  });

  it('sends nothing when a channel of the account received the event', async () => {
    const { svc, ownerMails } = makeService({ dispatched: 1 });
    await svc.createPending(baseReq);
    await settle();
    expect(ownerMails).toHaveLength(0);
  });

  it('mails once per approval: an identical pending request returns the same approval and sends none', async () => {
    const { svc, ownerMails } = makeService({ dispatched: 0 });
    const req = { ...baseReq, action: 'service_grant_expand' as const, resourceId: 'r', payload: { a: 1 } };
    const first = await svc.createPending(req);
    const again = await svc.createPending(req);
    await settle();
    expect(again.row.id).toBe(first.row.id);
    expect(ownerMails).toHaveLength(1);
  });

  it("a member's request mails only the owner: the recipient is never read from the requester", async () => {
    const { svc, ownerMails } = makeService({ dispatched: 0 });
    await svc.createPending({ ...baseReq, memberId: 'mem_a', requestedVia: 'member_session' });
    await settle();
    expect(ownerMails).toHaveLength(1);
    // The service names the account only; where the mail goes is resolved from the account's own owner row.
    expect(ownerMails[0]!.operatorId).toBe(OP);
    expect(ownerMails[0]!.payload['requested_via']).toBe('member_session');
  });

  it("a partner-managed tenant's owner is not mailed: its sign-in address is a placeholder, the partner decides", async () => {
    const { svc, ownerMails } = makeService({
      dispatched: 0,
      partnerOf: async () => ({ partner_operator_id: 'op_partner', external_customer_id: 'acme' }),
    });
    await svc.createPending(baseReq);
    await settle();
    expect(ownerMails).toHaveLength(0);
  });

  it('a failing mail service never fails the request, and the failure is logged without the address', async () => {
    const lines: string[] = [];
    const spy = (await import('vitest')).vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => { lines.push(args.join(' ')); });
    try {
      const { svc } = makeService({ dispatched: 0, mailOwnerFails: true });
      await expect(svc.requireApproval(baseReq)).rejects.toThrow(/approve/i);
      await settle();
    } finally {
      spy.mockRestore();
    }
    expect(lines.some((line) => line.includes('owner approval mail failed'))).toBe(true);
    expect(lines.join('\n')).not.toContain('owner@example.com');
  });

  it('does not wait for the mail: the request returns before a slow mail service answers', async () => {
    const { svc } = makeService({ dispatched: 0 });
    // createPending resolves with the row at once; the notification is fire and forget as before.
    const started = Date.now();
    await svc.createPending(baseReq);
    expect(Date.now() - started).toBeLessThan(500);
  });
});
