import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { createDb, operators, teamMembers } from '@stack/shared';
import { MemberRepository } from '../repositories/member-repo.js';
import { MemberService } from './member-service.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

// Single sign-on finds a person by the identity provider's subject, and binds the subject to the
// member the first time that person signs in (spec/sso-login/SPEC.md, section 9). The email claim
// is only a way to find the member to bind, and only when the provider says it is verified.
describeWithDb('MemberService single sign-on identity binding', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_sso_bind_${suffix}`;
  const otherOperatorId = `op_sso_bind_other_${suffix}`;
  const issuer = 'https://idp.corp.example';
  const alice = `alice-${suffix}@corp.example`;
  const bob = `bob-${suffix}@corp.example`;

  const service = new MemberService(new MemberRepository(db));
  service.setDb(db);

  const signIn = (over: Partial<Parameters<MemberService['findOrProvisionForSso']>[0]> = {}) =>
    service.findOrProvisionForSso({
      operatorId,
      email: alice,
      emailVerified: true,
      issuer,
      subject: 'sub-alice',
      name: 'Alice',
      defaultRole: 'standard',
      allowProvision: true,
      ...over,
    });

  const row = async (email: string, id = operatorId) =>
    (await db.select().from(teamMembers).where(eq(teamMembers.operator_id, id))).find((m) => m.email === email);

  async function clean() {
    for (const id of [operatorId, otherOperatorId]) {
      await db.delete(teamMembers).where(eq(teamMembers.operator_id, id)).catch(() => undefined);
      await db.delete(operators).where(eq(operators.id, id)).catch(() => undefined);
    }
  }

  afterAll(clean);

  beforeEach(async () => {
    await clean();
    for (const id of [operatorId, otherOperatorId]) {
      await db.insert(operators).values({ id, email: `${id}@test.invalid`, api_key_hash: `hash_${id}` });
    }
    await db.insert(teamMembers).values([
      { id: `mem_alice_${suffix}`, operator_id: operatorId, email: alice, name: 'Alice', role: 'admin', status: 'invited' },
      { id: `mem_bob_${suffix}`, operator_id: operatorId, email: bob, name: 'Bob', role: 'standard', status: 'active', joined_at: new Date() },
    ]);
  });

  it('binds the issuer and subject to the member on the first sign-in and signs the same member in again by subject', async () => {
    const first = await signIn();
    expect(first).toMatchObject({ provisioned: false, member: { id: `mem_alice_${suffix}`, role: 'admin' } });
    expect(await row(alice)).toMatchObject({ status: 'active', sso_issuer: issuer, sso_subject: 'sub-alice' });

    // The provider now says another address: the subject, not the address, is who signs in.
    const again = await signIn({ email: `renamed-${suffix}@corp.example`, subject: 'sub-alice', emailVerified: false });
    expect(again.member.id).toBe(`mem_alice_${suffix}`);
    expect(await row(`renamed-${suffix}@corp.example`)).toBeUndefined();
  });

  it('refuses a token whose email is a colleague\'s when its subject is not the one bound to that colleague', async () => {
    await signIn({ email: bob, subject: 'sub-bob' });
    // A user of the identity provider who changed their own email claim to bob's address.
    await expect(signIn({ email: bob, subject: 'sub-mallory' })).rejects.toMatchObject({ code: 'SSO_LOGIN_FAILED', statusCode: 400 });
    expect(await row(bob)).toMatchObject({ sso_subject: 'sub-bob' });
    expect(await row(`mallory-${suffix}@corp.example`)).toBeUndefined();
  });

  it('treats the same subject at another issuer as another person', async () => {
    await signIn({ email: bob, subject: 'sub-bob' });
    await expect(signIn({ email: bob, subject: 'sub-bob', issuer: 'https://other-idp.corp.example' })).rejects.toMatchObject({ code: 'SSO_LOGIN_FAILED' });
    expect(await row(bob)).toMatchObject({ sso_issuer: issuer });
  });

  it('requires a verified email to link an existing member: false and missing are refused and nothing is bound', async () => {
    for (const emailVerified of [false, undefined, 'true' as unknown as boolean]) {
      await expect(signIn({ emailVerified })).rejects.toMatchObject({ code: 'SSO_LOGIN_FAILED', statusCode: 400 });
    }
    expect(await row(alice)).toMatchObject({ status: 'invited', sso_issuer: null, sso_subject: null });
  });

  it('requires a verified email to provision a new member, and binds the new member', async () => {
    const carol = `carol-${suffix}@corp.example`;
    await expect(signIn({ email: carol, subject: 'sub-carol', emailVerified: false })).rejects.toMatchObject({ code: 'SSO_LOGIN_FAILED' });
    expect(await row(carol)).toBeUndefined();

    const created = await signIn({ email: carol, subject: 'sub-carol' });
    expect(created.provisioned).toBe(true);
    expect(await row(carol)).toMatchObject({ status: 'active', sso_issuer: issuer, sso_subject: 'sub-carol' });
  });

  describe('an address the provider did not verify but the account can vouch for (a verified domain, the issuer own claim)', () => {
    const carol = `carol-${suffix}@corp.example`;

    it('links an existing member on a first sign-in the account vouches for, and says what vouched', async () => {
      const result = await signIn({ emailVerified: undefined, vouchForEmail: async () => 'verified_domain' });
      expect(result).toMatchObject({ provisioned: false, linked: true, vouchedBy: 'verified_domain', member: { id: `mem_alice_${suffix}` } });
      expect(await row(alice)).toMatchObject({ status: 'active', sso_issuer: issuer, sso_subject: 'sub-alice' });
    });

    it('provisions a new member on it, bound at once', async () => {
      const created = await signIn({ email: carol, subject: 'sub-carol', emailVerified: undefined, vouchForEmail: async () => 'issuer_domain_claim' });
      expect(created).toMatchObject({ provisioned: true, linked: true, vouchedBy: 'issuer_domain_claim' });
      expect(await row(carol)).toMatchObject({ status: 'active', sso_issuer: issuer, sso_subject: 'sub-carol' });
    });

    it('still refuses when nothing vouches, and binds nothing', async () => {
      await expect(signIn({ emailVerified: undefined, vouchForEmail: async () => undefined })).rejects.toMatchObject({ code: 'SSO_LOGIN_FAILED', statusCode: 400 });
      expect(await row(alice)).toMatchObject({ status: 'invited', sso_issuer: null, sso_subject: null });
    });

    it('never asks when the provider verified the address, or when a member is already linked to the subject', async () => {
      let asked = 0;
      const vouchForEmail = async () => { asked += 1; return 'verified_domain' as const; };
      const first = await signIn({ vouchForEmail });
      expect(first).toMatchObject({ linked: true });
      expect(first.vouchedBy).toBeUndefined();
      const again = await signIn({ emailVerified: undefined, vouchForEmail });
      expect(again).toMatchObject({ linked: false, member: { id: `mem_alice_${suffix}` } });
      expect(again.vouchedBy).toBeUndefined();
      expect(asked).toBe(0);
    });

    it('does not let it re-link a member bound to another subject, nor bring back a removed one', async () => {
      await signIn({ email: bob, subject: 'sub-bob' });
      await expect(signIn({ email: bob, subject: 'sub-mallory', emailVerified: undefined, vouchForEmail: async () => 'verified_domain' })).rejects.toMatchObject({ code: 'SSO_LOGIN_FAILED' });
      expect(await row(bob)).toMatchObject({ sso_subject: 'sub-bob' });
      await db.update(teamMembers).set({ status: 'revoked', revoked_at: new Date() }).where(eq(teamMembers.id, `mem_alice_${suffix}`));
      await expect(signIn({ emailVerified: undefined, vouchForEmail: async () => 'verified_domain' })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    });

    it('still does not provision when the account does not provision', async () => {
      await expect(signIn({ email: carol, subject: 'sub-carol', emailVerified: undefined, vouchForEmail: async () => 'verified_domain', allowProvision: false })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    });
  });

  it('does not provision when the account does not provision, even for a verified email', async () => {
    await expect(signIn({ email: `dave-${suffix}@corp.example`, subject: 'sub-dave', allowProvision: false })).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('refuses a removed member by subject and by email, and a sign-in does not bring them back', async () => {
    await signIn({ email: bob, subject: 'sub-bob' });
    await db.update(teamMembers).set({ status: 'revoked', revoked_at: new Date() }).where(eq(teamMembers.id, `mem_bob_${suffix}`));
    await expect(signIn({ email: bob, subject: 'sub-bob' })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(signIn({ email: alice, subject: 'sub-bob' })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    expect(await row(bob)).toMatchObject({ status: 'revoked' });
  });

  it('refuses an unverified email for a removed member without saying the member was removed', async () => {
    await db.update(teamMembers).set({ status: 'revoked', revoked_at: new Date() }).where(eq(teamMembers.id, `mem_bob_${suffix}`));
    await expect(signIn({ email: bob, subject: 'sub-x', emailVerified: false })).rejects.toMatchObject({ code: 'SSO_LOGIN_FAILED' });
  });

  it('keeps the bindings of two accounts apart: one subject can be a member of two organisations', async () => {
    await signIn();
    await db.insert(teamMembers).values({ id: `mem_alice2_${suffix}`, operator_id: otherOperatorId, email: alice, name: 'Alice', status: 'invited' });
    const other = await signIn({ operatorId: otherOperatorId });
    expect(other.member.id).toBe(`mem_alice2_${suffix}`);
  });

  it('keeps a subject on at most one member of an account', async () => {
    await signIn();
    await expect(
      db.update(teamMembers).set({ sso_issuer: issuer, sso_subject: 'sub-alice' }).where(eq(teamMembers.id, `mem_bob_${suffix}`)),
    ).rejects.toThrow();
  });

  it('lets only one of two concurrent first sign-ins bind a member', async () => {
    const results = await Promise.allSettled([
      signIn({ subject: 'sub-first' }),
      signIn({ subject: 'sub-second' }),
    ]);
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    const bound = (await row(alice))!.sso_subject;
    expect(['sub-first', 'sub-second']).toContain(bound);
  });

  it('forgets the binding when an administrator invites the person again, so a new provider identity can be linked', async () => {
    await signIn({ email: bob, subject: 'sub-bob' });
    await db.update(teamMembers).set({ status: 'revoked', revoked_at: new Date() }).where(eq(teamMembers.id, `mem_bob_${suffix}`));
    await service.invite(operatorId, { email: bob, name: 'Bob', role: 'standard' } as never);
    expect(await row(bob)).toMatchObject({ status: 'invited', sso_issuer: null, sso_subject: null });
    const relinked = await signIn({ email: bob, subject: 'sub-bob-new' });
    expect(relinked.member.id).toBe(`mem_bob_${suffix}`);
    expect(await row(bob)).toMatchObject({ sso_subject: 'sub-bob-new' });
  });

  describe('clearing a binding after the identity provider was replaced', () => {
    const oldIssuer = 'https://old-idp.corp.example';
    const newIssuer = 'https://new-idp.corp.example';
    const aliceId = `mem_alice_${suffix}`;
    const bobId = `mem_bob_${suffix}`;
    const carol = `carol-${suffix}@corp.example`;

    async function bindBoth() {
      await signIn({ issuer: oldIssuer, subject: 'old-alice' });
      await signIn({ email: bob, issuer: oldIssuer, subject: 'old-bob' });
    }

    it('locks a member out of the new provider until the binding is cleared, and clearing one member lets that member bind again', async () => {
      await bindBoth();
      await expect(signIn({ issuer: newIssuer, subject: 'new-alice' })).rejects.toMatchObject({ code: 'SSO_LOGIN_FAILED' });

      const cleared = await service.clearSsoBindings(operatorId, { memberId: aliceId });
      expect(cleared).toEqual([{ id: aliceId, email: alice, sso_issuer: oldIssuer }]);
      expect(await row(alice)).toMatchObject({ status: 'active', role: 'admin', sso_issuer: null, sso_subject: null });
      // Bob is untouched.
      expect(await row(bob)).toMatchObject({ sso_issuer: oldIssuer, sso_subject: 'old-bob' });

      const relinked = await signIn({ issuer: newIssuer, subject: 'new-alice' });
      expect(relinked.member.id).toBe(aliceId);
      expect(await row(alice)).toMatchObject({ sso_issuer: newIssuer, sso_subject: 'new-alice' });
    });

    it('clears every member bound to one issuer and no one bound to another, or in another account', async () => {
      await bindBoth();
      await signIn({ email: carol, issuer: newIssuer, subject: 'new-carol' });
      await db.insert(teamMembers).values({
        id: `mem_other_${suffix}`, operator_id: otherOperatorId, email: alice, name: 'Alice', role: 'standard', status: 'active',
        joined_at: new Date(), sso_issuer: oldIssuer, sso_subject: 'old-alice',
      });
      const cleared = await service.clearSsoBindings(operatorId, { issuer: oldIssuer });
      expect(cleared.map((m) => m.email).sort()).toEqual([alice, bob].sort());
      expect(await row(alice)).toMatchObject({ sso_issuer: null, sso_subject: null });
      expect(await row(bob)).toMatchObject({ sso_issuer: null, sso_subject: null });
      expect(await row(carol)).toMatchObject({ sso_issuer: newIssuer });
      expect(await row(alice, otherOperatorId)).toMatchObject({ sso_issuer: oldIssuer, sso_subject: 'old-alice' });
    });

    it('does not reach another account\'s member by id, and says nothing about whether one exists', async () => {
      await db.insert(teamMembers).values({
        id: `mem_other_${suffix}`, operator_id: otherOperatorId, email: bob, name: 'Bob', role: 'standard', status: 'active',
        joined_at: new Date(), sso_issuer: oldIssuer, sso_subject: 'old-bob',
      });
      await expect(service.clearSsoBindings(operatorId, { memberId: `mem_other_${suffix}` })).rejects.toMatchObject({ code: 'NOT_FOUND' });
      await expect(service.clearSsoBindings(operatorId, { memberId: 'mem_nobody' })).rejects.toMatchObject({ code: 'NOT_FOUND' });
      expect(await row(bob, otherOperatorId)).toMatchObject({ sso_subject: 'old-bob' });
    });

    it('is idempotent: a member with no binding, or an issuer nobody is bound to, clears nothing', async () => {
      expect(await service.clearSsoBindings(operatorId, { memberId: aliceId })).toEqual([]);
      expect(await service.clearSsoBindings(operatorId, { issuer: oldIssuer })).toEqual([]);
    });

    it('keeps a removed member removed: only the binding goes, and a sign-in does not bring them back', async () => {
      await bindBoth();
      await db.update(teamMembers).set({ status: 'revoked', revoked_at: new Date() }).where(eq(teamMembers.id, bobId));
      await service.clearSsoBindings(operatorId, { issuer: oldIssuer });
      await expect(signIn({ email: bob, issuer: newIssuer, subject: 'new-bob' })).rejects.toMatchObject({ statusCode: 403 });
      expect(await row(bob)).toMatchObject({ status: 'revoked', sso_subject: null });
    });
  });
});
