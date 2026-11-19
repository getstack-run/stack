import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { createDb, operators, sha256, teamMembers } from '@stack/shared';
import { MemberRepository } from '../repositories/member-repo.js';
import { MemberService } from './member-service.js';
import { isDedicatedVaultTestDatabase } from '../test/dedicated-test-database.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = isDedicatedVaultTestDatabase(DATABASE_URL) ? describe : describe.skip;

// A staging deployment (STACK_STAGING=true) gives a membership only to an address on STAGING_SIGNIN_ALLOWLIST: an
// invitation, the redemption of one and a single sign-on all refuse anyone else, and nothing is written for them.
describeWithDb('MemberService on a staging deployment', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_stg_member_${suffix}`;
  const allowed = `allowed-${suffix}@example.com`;
  const outsider = `outsider-${suffix}@example.com`;
  const service = new MemberService(new MemberRepository(db));
  service.setDb(db);
  service.setAuditService({ write: async () => undefined } as never);
  const env = { staging: process.env['STACK_STAGING'], list: process.env['STAGING_SIGNIN_ALLOWLIST'] };

  const members = () => db.select().from(teamMembers).where(eq(teamMembers.operator_id, operatorId));

  beforeAll(async () => {
    await db.insert(operators).values({ id: operatorId, email: `${operatorId}@test.invalid`, api_key_hash: `hash_${operatorId}` });
    process.env['STACK_STAGING'] = 'true';
    process.env['STAGING_SIGNIN_ALLOWLIST'] = `${allowed.toUpperCase()}, someone-else@example.com`;
  });

  afterEach(async () => {
    await db.delete(teamMembers).where(eq(teamMembers.operator_id, operatorId));
  });

  afterAll(async () => {
    for (const [name, value] of [['STACK_STAGING', env.staging], ['STAGING_SIGNIN_ALLOWLIST', env.list]] as const) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    await db.delete(teamMembers).where(eq(teamMembers.operator_id, operatorId)).catch(() => undefined);
    await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
    await db.$client.end({ timeout: 5 });
  });

  it('invites an address on the allow-list', async () => {
    const { member, inviteToken } = await service.invite(operatorId, { email: allowed, name: 'Allowed', role: 'standard' } as never);
    expect(member.email).toBe(allowed);
    expect(inviteToken).toMatch(/^inv_/);
  });

  it('refuses to invite an address outside the allow-list, with the answer of an address that cannot be invited, and writes nothing', async () => {
    await expect(service.invite(operatorId, { email: outsider, name: 'Outsider', role: 'standard' } as never)).rejects.toMatchObject({
      code: 'FORBIDDEN',
      message: 'This address cannot be invited to an account.',
    });
    expect(await members()).toHaveLength(0);
  });

  it('opens nothing for an invitation to an outsider made before sign-in was limited', async () => {
    const token = `inv_${'b'.repeat(32)}`;
    await db.insert(teamMembers).values({
      id: `mem_stg_${suffix}`,
      operator_id: operatorId,
      email: outsider,
      name: 'Outsider',
      status: 'invited',
      invite_token_hash: sha256(token),
      invite_expires_at: new Date(Date.now() + 60_000),
    });
    await expect(service.acceptInvite(token, { trace_id: 't', span_id: 's', started_at_ms: Date.now() })).rejects.toMatchObject({
      code: 'INVALID_INVITE',
    });
    const [row] = await members();
    expect(row?.status).toBe('invited');
  });

  it('provisions an allowed person through single sign-on and refuses an outsider before anything is written', async () => {
    const sso = (email: string, subject: string) =>
      service.findOrProvisionForSso({
        operatorId,
        email,
        emailVerified: true,
        issuer: 'https://idp.example',
        subject,
        name: null,
        defaultRole: 'standard',
        allowProvision: true,
      });
    await expect(sso(outsider, 'sub-outsider')).rejects.toMatchObject({
      code: 'FORBIDDEN',
      message: 'This organisation has no account for you. Ask an admin to invite you.',
    });
    expect(await members()).toHaveLength(0);
    const provisioned = await sso(allowed, 'sub-allowed');
    expect(provisioned.provisioned).toBe(true);
    expect((await members()).map((m) => m.email)).toEqual([allowed]);
  });
});
