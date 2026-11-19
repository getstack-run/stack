// GovernanceApprovalService state machine + fail-closed matrix.

import { describe, it, expect, beforeEach } from 'vitest';
import { ForbiddenError, NotFoundError, GovernanceApprovalRequiredError } from '@stack/shared';
import {
  type GovernanceApprovalService,
  hashGovernancePayload,
} from './governance-approval-service.js';
import type { GovernanceApprovalRow } from '../repositories/governance-approval-repo.js';
import { OP, baseReq, createPending, makeService, payload } from './governance-approval-service.test-support.js';

describe('GovernanceApprovalService', () => {
  let svc: GovernanceApprovalService;
  let rows: Map<string, GovernanceApprovalRow>;
  let notifications: Array<{ operatorId: string; eventType: string; payload: Record<string, unknown> }>;
  beforeEach(() => {
    ({ svc, rows, notifications } = makeService());
  });

  it('requireApproval creates a pending row, pushes a notification with the URL, and throws the 403', async () => {
    const id = await createPending(svc);
    const row = rows.get(id)!;
    expect(row.status).toBe('pending');
    expect(row.payload_hash).toBe(hashGovernancePayload(payload));
    expect(notifications[0]!.eventType).toBe('governance.approval_pending');
    expect(notifications[0]!.payload['approval_url']).toBe(`https://getstack.run/app/approve/${id}`);
    expect(notifications[0]!.payload['summary']).toBe('Disable prompt_injection detector');
  });

  it("a normal operator's approval goes to its own channels only", async () => {
    await createPending(svc);
    await new Promise((r) => setTimeout(r, 0));
    expect(notifications.map((n) => n.operatorId)).toEqual([OP]);
  });

  it("a tenant's pending approval also reaches its partner's channels, tenant named", async () => {
    const partnered = makeService({
      partnerOf: async (operatorId) => operatorId === OP
        ? { partner_operator_id: 'op_partner', external_customer_id: 'acme' }
        : undefined,
    });
    const id = await createPending(partnered.svc);
    await new Promise((r) => setTimeout(r, 0));
    expect(partnered.notifications.map((n) => n.operatorId)).toEqual([OP, 'op_partner']);
    const toPartner = partnered.notifications[1]!;
    expect(toPartner.eventType).toBe('governance.approval_pending');
    expect(toPartner.payload['approval_id']).toBe(id);
    expect(toPartner.payload['tenant_operator_id']).toBe(OP);
    expect(toPartner.payload['tenant_external_customer_id']).toBe('acme');
    expect(toPartner.payload['summary']).toBe('Tenant acme: Disable prompt_injection detector');
  });

  it("a normal operator's approval lasts 24 hours, names the operator and links its own page", async () => {
    const err = await svc.requireApproval(baseReq).catch((e: unknown) => e as Error);
    const row = [...rows.values()][0]!;
    const ttl = (row.expires_at.getTime() - Date.now()) / 1000;
    expect(ttl).toBeGreaterThan(23 * 3600);
    expect(ttl).toBeLessThanOrEqual(24 * 3600);
    expect(err.message).toContain('Ask the operator to approve request');
    expect(err.message).toContain(`https://getstack.run/app/approve/${row.id}`);
  });

  it('reads one approval with its payload hash and own link, refusing another operator', async () => {
    const id = await createPending(svc);
    const detail = await svc.getDetailForOperator(id, OP);
    expect(detail.payload_hash).toBe(hashGovernancePayload(payload));
    expect(detail.approval_url).toBe(`https://getstack.run/app/approve/${id}`);
    expect(detail.approval.id).toBe(id);
    expect(detail.approval.status).toBe('pending');
    await expect(svc.getDetailForOperator(id, 'op_other')).rejects.toBeInstanceOf(NotFoundError);
  });

  it('reports a stale pending approval as expired when it is read', async () => {
    const id = await createPending(svc);
    rows.get(id)!.expires_at = new Date(Date.now() - 1000);
    expect((await svc.getDetailForOperator(id, OP)).approval.status).toBe('expired');
  });

  it("a tenant's approval lasts 24 hours and tells the tenant to ask its partner", async () => {
    const partnered = makeService({
      partnerOf: async () => ({ partner_operator_id: 'op_partner', external_customer_id: 'acme' }),
    });
    const err = await partnered.svc.requireApproval(baseReq).catch((e: unknown) => e as Error);
    expect(err).toBeInstanceOf(GovernanceApprovalRequiredError);
    const row = [...partnered.rows.values()][0]!;
    const ttl = (row.expires_at.getTime() - Date.now()) / 1000;
    expect(ttl).toBeGreaterThan(23 * 3600);
    expect(ttl).toBeLessThanOrEqual(24 * 3600);
    expect(err.message).toContain(`Ask your partner to approve request ${row.id} in their STACK console`);
    expect(err.message).not.toContain('Ask the operator');
  });

  it('a failed partner lookup still notifies the tenant and still returns the 403', async () => {
    const failing = makeService({ partnerOf: async () => { throw new Error('db down'); } });
    await createPending(failing.svc);
    await new Promise((r) => setTimeout(r, 0));
    expect(failing.notifications.map((n) => n.operatorId)).toEqual([OP]);
  });

  it('consume before approval fails closed with "still pending"', async () => {
    const id = await createPending(svc);
    await expect(
      svc.consume({
        approvalId: id,
        operatorId: OP,
        action: baseReq.action,
        resourceId: baseReq.resourceId,
        payload,
      }),
    ).rejects.toThrow(/still pending/);
  });

  it('happy path: approve then consume exactly once; replay dies', async () => {
    const id = await createPending(svc);
    const view = await svc.decide(id, OP, 'approve');
    expect(view.status).toBe('approved');
    await expect(
      svc.consume({
        approvalId: id,
        operatorId: OP,
        action: baseReq.action,
        resourceId: baseReq.resourceId,
        payload,
      }),
    ).resolves.toBeUndefined();
    await expect(
      svc.consume({
        approvalId: id,
        operatorId: OP,
        action: baseReq.action,
        resourceId: baseReq.resourceId,
        payload,
      }),
    ).rejects.toThrow(/consumed|request a new one/);
  });

  it('authority consumption permits only an exact idempotent replay', async () => {
    const request = {
      ...baseReq,
      action: 'authority_proof_erase' as const,
      resourceId: 'prf_one',
      payload: { version: 1, reason_code: 'principal_request' },
      summary: 'Erase authority proof',
    };
    let id = '';
    try {
      await svc.requireApproval(request);
    } catch (error) {
      expect(error).toBeInstanceOf(GovernanceApprovalRequiredError);
      id = (error as Error).message.match(/gvr_[A-Za-z0-9_-]+/)![0];
    }
    await svc.decide(id, OP, 'approve');
    const exact = {
      approvalId: id,
      operatorId: OP,
      action: request.action,
      resourceId: request.resourceId,
      payload: request.payload,
      idempotencyKey: 'erase-proof-attempt-one',
    };
    await expect(svc.consumeAuthorityIdempotently(exact)).resolves.toBeUndefined();
    await expect(svc.consumeAuthorityIdempotently(exact)).resolves.toBeUndefined();
    await expect(
      svc.consumeAuthorityIdempotently({
        ...exact,
        idempotencyKey: 'erase-proof-attempt-two',
      }),
    ).rejects.toThrow(/another authority operation/);
    await expect(
      svc.consumeAuthorityIdempotently({
        ...exact,
        payload: { version: 2, reason_code: 'principal_request' },
      }),
    ).rejects.toThrow(/exact change/);
    await expect(
      svc.consumeAuthorityIdempotently({
        ...exact,
        action: 'authority_binding_erase',
      }),
    ).rejects.toThrow(/does not match this action/);
    await expect(
      svc.consumeAuthorityIdempotently({
        ...exact,
        resourceId: 'prf_other',
      }),
    ).rejects.toThrow(/does not match this action/);
  });

  it('non-authority actions cannot opt into idempotent governance consumption', async () => {
    const id = await createPending(svc);
    await svc.decide(id, OP, 'approve');
    await expect(
      svc.consumeAuthorityIdempotently({
        approvalId: id,
        operatorId: OP,
        action: baseReq.action,
        resourceId: baseReq.resourceId,
        payload,
        idempotencyKey: 'not-allowed',
      }),
    ).rejects.toThrow(/does not permit/);
  });

  it('payload tamper: retried body differing from what the human saw is refused', async () => {
    const id = await createPending(svc);
    await svc.decide(id, OP, 'approve');
    await expect(
      svc.consume({
        approvalId: id,
        operatorId: OP,
        action: baseReq.action,
        resourceId: baseReq.resourceId,
        payload: {
          detector_key: 'prompt_injection',
          enabled: false,
          whitelist_patterns: [{ id: 'sneak', regex: '.*', description: '' }],
        },
      }),
    ).rejects.toThrow(/exact change/);
  });

  it('is for the member who asked: another member, or a key, replaying the same request does not use it', async () => {
    const asked = (member: string | null) => ({ ...baseReq, memberId: member, requestedVia: member ? ('member_session' as const) : ('operator_key' as const) });
    const idOf = async (member: string | null) => {
      const e = await svc.requireApproval(asked(member)).catch((err: unknown) => err as Error);
      return e.message.match(/gvr_[A-Za-z0-9_-]+/)![0];
    };
    const consume = (id: string, memberId?: string | null) =>
      svc.consume({ approvalId: id, operatorId: OP, action: baseReq.action, resourceId: baseReq.resourceId, payload, ...(memberId !== undefined ? { memberId } : {}) });

    const id = await idOf('mem_a');
    await svc.decide(id, OP, 'approve');
    await expect(consume(id, 'mem_b')).rejects.toThrow(/requested by someone else/);
    await expect(consume(id, null)).rejects.toThrow(/requested by someone else/);
    // Still unused: the one who asked can.
    await expect(consume(id, 'mem_a')).resolves.toBeUndefined();

    // A key's approval is a key's: no member uses it.
    const keyed = await idOf(null);
    await svc.decide(keyed, OP, 'approve');
    await expect(consume(keyed, 'mem_a')).rejects.toThrow(/requested by someone else/);
    await expect(consume(keyed, null)).resolves.toBeUndefined();
  });

  it('action/resource mismatch is refused', async () => {
    const id = await createPending(svc);
    await svc.decide(id, OP, 'approve');
    await expect(
      svc.consume({
        approvalId: id,
        operatorId: OP,
        action: 'agent_unblock',
        resourceId: 'agt_x',
        payload,
      }),
    ).rejects.toThrow(/does not match this action/);
  });

  it('foreign operator sees NotFound (no enumeration)', async () => {
    const id = await createPending(svc);
    await expect(
      svc.consume({
        approvalId: id,
        operatorId: 'op_other',
        action: baseReq.action,
        resourceId: baseReq.resourceId,
        payload,
      }),
    ).rejects.toBeInstanceOf(NotFoundError);
    await expect(svc.decide(id, 'op_other', 'approve')).rejects.toBeInstanceOf(NotFoundError);
  });

  it('reject is terminal; double-decide refused', async () => {
    const id = await createPending(svc);
    const view = await svc.decide(id, OP, 'reject');
    expect(view.status).toBe('rejected');
    await expect(svc.decide(id, OP, 'approve')).rejects.toBeInstanceOf(ForbiddenError);
    await expect(
      svc.consume({
        approvalId: id,
        operatorId: OP,
        action: baseReq.action,
        resourceId: baseReq.resourceId,
        payload,
      }),
    ).rejects.toThrow(/rejected/);
  });

  it('expiry: pending past TTL lazily expires on consume and on decide', async () => {
    const id = await createPending(svc);
    rows.get(id)!.expires_at = new Date(Date.now() - 1000);
    await expect(
      svc.consume({
        approvalId: id,
        operatorId: OP,
        action: baseReq.action,
        resourceId: baseReq.resourceId,
        payload,
      }),
    ).rejects.toThrow(/expired/);
    expect(rows.get(id)!.status).toBe('expired');
    const id2 = await createPending(svc);
    rows.get(id2)!.expires_at = new Date(Date.now() - 1000);
    await expect(svc.decide(id2, OP, 'approve')).rejects.toBeInstanceOf(NotFoundError);
  });

  it('approved-but-expired at consume time is refused', async () => {
    const id = await createPending(svc);
    await svc.decide(id, OP, 'approve');
    rows.get(id)!.expires_at = new Date(Date.now() - 1000);
    await expect(
      svc.consume({
        approvalId: id,
        operatorId: OP,
        action: baseReq.action,
        resourceId: baseReq.resourceId,
        payload,
      }),
    ).rejects.toThrow(/expired/);
  });

  describe('an identical request is one prompt, not two', () => {
    const SINGLE_PROMPT = [
      'service_grant_expand',
      'account_control_loosen',
      'agent_register',
      'agent_setup',
      'agent_authority_expand',
      'service_allowed_hosts_expand',
    ] as const;

    it.each(SINGLE_PROMPT)('%s: the same requester, resource and payload gets the same approval back', async (action) => {
      const ask = () => svc.createPending({ ...baseReq, action, resourceId: 'agt_1:scon_1', payload: { a: 1 } });
      const first = await ask();
      const second = await ask();
      expect(second.row.id).toBe(first.row.id);
      expect([...rows.values()].filter((r) => r.action === action)).toHaveLength(1);
      // One notification, not one per retry.
      expect(notifications.filter((n) => n.eventType === 'governance.approval_pending')).toHaveLength(1);
    });

    it('an approved request that was not used yet is returned, not asked again', async () => {
      const first = await svc.createPending({ ...baseReq, action: 'service_grant_expand', resourceId: 'r', payload: { a: 1 } });
      await svc.decide(first.row.id, OP, 'approve');
      const again = await svc.createPending({ ...baseReq, action: 'service_grant_expand', resourceId: 'r', payload: { a: 1 } });
      expect(again.row.id).toBe(first.row.id);
      expect(again.row.status).toBe('approved');
    });

    it('a different payload, resource, requester or action is a different approval', async () => {
      const base = { ...baseReq, action: 'service_grant_expand' as const, resourceId: 'r', payload: { a: 1 } };
      const ids = new Set<string>();
      for (const variant of [
        base,
        { ...base, payload: { a: 2 } },
        { ...base, resourceId: 'other' },
        { ...base, memberId: 'mem_a', requestedVia: 'member_session' as const },
        { ...base, action: 'agent_setup' as const },
      ]) ids.add((await svc.createPending(variant)).row.id);
      expect(ids.size).toBe(5);
    });

    it('a consumed approval is spent: the same request asks again', async () => {
      const req = { ...baseReq, action: 'service_grant_expand' as const, resourceId: 'r', payload: { a: 1 } };
      const first = await svc.createPending(req);
      await svc.decide(first.row.id, OP, 'approve');
      await svc.consume({ approvalId: first.row.id, operatorId: OP, action: req.action, resourceId: req.resourceId, payload: req.payload });
      const again = await svc.createPending(req);
      expect(again.row.id).not.toBe(first.row.id);
    });

    it('a rejected request asks again when it is made again', async () => {
      const req = { ...baseReq, action: 'service_grant_expand' as const, resourceId: 'r', payload: { a: 1 } };
      const first = await svc.createPending(req);
      await svc.decide(first.row.id, OP, 'reject');
      expect((await svc.createPending(req)).row.id).not.toBe(first.row.id);
    });

    it('an approval someone else asked for is not used by a colleague who asks for the same thing', async () => {
      const mine = await svc.createPending({ ...baseReq, action: 'service_grant_expand', resourceId: 'r', payload: { a: 1 }, memberId: 'mem_a', requestedVia: 'member_session' });
      const theirs = await svc.createPending({ ...baseReq, action: 'service_grant_expand', resourceId: 'r', payload: { a: 1 }, memberId: 'mem_b', requestedVia: 'member_session' });
      expect(theirs.row.id).not.toBe(mine.row.id);
    });

    it('an action that is not coalesced still creates a row for every request', async () => {
      const a = await svc.createPending({ ...baseReq, action: 'detector_config_upsert' });
      const b = await svc.createPending({ ...baseReq, action: 'detector_config_upsert' });
      expect(b.row.id).not.toBe(a.row.id);
    });
  });

  it('an agent setup keeps the preview the card lists, and hands it back on the view', async () => {
    const preview = { agent: { name: 'bot' }, grants: [], allowed_hosts: [] };
    const { row } = await svc.createPending({ ...baseReq, action: 'agent_setup', resourceId: 'bot', payload: { agent: { name: 'bot' } }, preview });
    const detail = await svc.getDetailForOperator(row.id, OP);
    expect(detail.approval.setup_preview).toEqual(preview);
  });

  it('hashGovernancePayload is canonical: key order does not matter', () => {
    expect(hashGovernancePayload({ a: 1, b: 2 })).toBe(hashGovernancePayload({ b: 2, a: 1 }));
    expect(hashGovernancePayload({ a: 1 })).not.toBe(hashGovernancePayload({ a: 2 }));
  });
});
