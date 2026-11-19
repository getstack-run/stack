import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { createDb, operators, teamMembers, sha256 } from '@stack/shared';
import { MemberRepository } from '../repositories/member-repo.js';
import { AuditService, type AuditInput } from './audit-service.js';
import { MemberService } from './member-service.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('MemberService invite redemption lifecycle', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_member_invite_${suffix}`;
  const memberId = `mem_invite_${suffix}`;
  const inviteToken = `inv_${'a'.repeat(64)}`;
  const auditInput: AuditInput = {
    ctx: {
      trace_id: `tr_member_${suffix}`,
      span_id: `sp_member_${suffix}`,
      operator_id: operatorId,
      agent_id: 'system',
      passport_jti: 'none',
    },
    layer: 'vault',
    action: 'member.accept',
    outcome: 'success',
  };

  afterAll(async () => {
    await db
      .delete(teamMembers)
      .where(eq(teamMembers.operator_id, operatorId))
      .catch(() => undefined);
    await db
      .delete(operators)
      .where(eq(operators.id, operatorId))
      .catch(() => undefined);
  });

  beforeEach(async () => {
    await db
      .delete(teamMembers)
      .where(eq(teamMembers.operator_id, operatorId))
      .catch(() => undefined);
    await db
      .delete(operators)
      .where(eq(operators.id, operatorId))
      .catch(() => undefined);
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@test.invalid`,
      api_key_hash: `hash_${operatorId}`,
    });
    await db.insert(teamMembers).values({
      id: memberId,
      operator_id: operatorId,
      email: `${memberId}@test.invalid`,
      name: 'Invite Test',
      status: 'invited',
      invite_token_hash: sha256(inviteToken),
      invite_expires_at: new Date(Date.now() + 60_000),
    });
  });

  function makeService(audit: Pick<AuditService, 'write'> = new AuditService(db)) {
    const service = new MemberService(new MemberRepository(db));
    service.setDb(db);
    (
      service as unknown as { setAuditService?: (value: Pick<AuditService, 'write'>) => void }
    ).setAuditService?.(audit);
    return service;
  }

  function redeem(service: MemberService) {
    return (
      service.acceptInvite as unknown as (
        id: string,
        input: AuditInput,
      ) => ReturnType<MemberService['acceptInvite']>
    )(inviteToken, {
      trace_id: auditInput.ctx.trace_id,
      span_id: auditInput.ctx.span_id,
    } as never);
  }

  it('concurrent invite redemption creates one keyless member session identity', async () => {
    const service = makeService();
    const results = await Promise.allSettled([redeem(service), redeem(service)]);

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
    const accepted = results.find((result) => result.status === 'fulfilled');
    if (accepted?.status === 'fulfilled') {
      expect(accepted.value.member.api_key_hash).toBeNull();
      expect(accepted.value.member.invite_token_hash).toBeNull();
    }
  });

  it('concurrent invite redemption rejects a closed owner opaquely', async () => {
    await db.update(operators).set({ status: 'deleted' }).where(eq(operators.id, operatorId));
    const service = makeService();

    await expect(redeem(service)).rejects.toMatchObject({
      code: 'INVALID_INVITE',
    });
    expect(
      (await db.query.teamMembers.findFirst({ where: eq(teamMembers.id, memberId) }))?.status,
    ).toBe('invited');
  });

  it('rejects an expired invitation without activating the member', async () => {
    await db
      .update(teamMembers)
      .set({ invite_expires_at: new Date(Date.now() - 1_000) })
      .where(eq(teamMembers.id, memberId));
    const service = makeService();

    await expect(redeem(service)).rejects.toMatchObject({ code: 'INVALID_INVITE' });
    expect(
      (await db.query.teamMembers.findFirst({ where: eq(teamMembers.id, memberId) }))?.status,
    ).toBe('invited');
  });

  it('concurrent invite audit failure leaves the invite redeemable', async () => {
    const service = makeService({
      write: async () => {
        throw new Error('audit_failed');
      },
    });

    await expect(redeem(service)).rejects.toThrow('audit_failed');
    expect(
      (await db.query.teamMembers.findFirst({ where: eq(teamMembers.id, memberId) }))?.status,
    ).toBe('invited');
  });
});
