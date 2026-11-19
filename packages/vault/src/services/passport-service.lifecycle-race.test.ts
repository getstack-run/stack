import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import {
  agents,
  acquireOAuthOperatorLock,
  createDb,
  operatorErasureJobs,
  operators,
  passports,
  PassportRevokedError,
  PassportExpiredError,
} from '@stack/shared';
import { AgentRepository } from '../repositories/agent-repo.js';
import { OperatorRepository } from '../repositories/operator-repo.js';
import { PassportRepository } from '../repositories/passport-repo.js';
import { ServiceRepository } from '../repositories/service-repo.js';
import { PassportSigner, type PassportPayload } from '../crypto/passport-signer.js';
import { OperatorErasureService } from './operator-erasure-service.js';
import { PassportService } from './passport-service.js';
import { passportTestWiring } from './passport-service.test-support.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('PassportService operator lifecycle races', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorIds: string[] = [];
  let signer: PassportSigner;

  beforeAll(async () => {
    signer = new PassportSigner();
    await signer.init();
  });

  afterAll(async () => {
    for (const operatorId of operatorIds.reverse()) {
      await db.delete(passports).where(eq(passports.operator_id, operatorId)).catch(() => undefined);
      await db.delete(agents).where(eq(agents.operator_id, operatorId)).catch(() => undefined);
      await db.delete(operatorErasureJobs)
        .where(eq(operatorErasureJobs.operator_id, operatorId))
        .catch(() => undefined);
      await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
    }
  });

  async function makeFixture(label: string) {
    const operatorId = `op_passport_lifecycle_${label}_${suffix}`;
    const parentAgentId = `agt_passport_parent_${label}_${suffix}`;
    const childAgentId = `agt_passport_child_${label}_${suffix}`;
    const parentJti = `ppt_passport_parent_${label}_${suffix}`;
    const sessionId = `ses_passport_${label}_${suffix}`;
    operatorIds.push(operatorId);
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@test.invalid`,
      api_key_hash: `hash_${operatorId}`,
    });
    await db.insert(agents).values([
      {
        id: parentAgentId,
        operator_id: operatorId,
        name: `parent-${label}-${suffix}`,
        accountability_mode: 'standard',
      },
      {
        id: childAgentId,
        operator_id: operatorId,
        name: `child-${label}-${suffix}`,
        accountability_mode: 'standard',
      },
    ]);

    // every agent Passport is bound to exactly one live Mission.
    const missionId = `ms_passport_${label}_${suffix}`;
    const parentPayload: PassportPayload = {
      operator_id: operatorId,
      agent_id: parentAgentId,
      agent_name: `parent-${label}`,
      services: [],
      identity_claims: [],
      delegation_depth: 0,
      session_id: sessionId,
      accountability: 'standard',
      mission_ids: [missionId],
    };
    const parent = await signer.sign(parentJti, parentPayload, 900);
    const passportRepo = new PassportRepository(db);
    await passportRepo.create({
      jti: parentJti,
      operator_id: operatorId,
      agent_id: parentAgentId,
      session_id: sessionId,
      delegation_depth: 0,
      parent_passport_id: null,
      expires_at: parent.expires_at,
      intent_delegates: true,
      mission_ids: [missionId],
    });

    const operatorRepo = new OperatorRepository(db);
    const service = Reflect.construct(PassportService, [
      passportRepo,
      new AgentRepository(db),
      new ServiceRepository(db),
      signer,
      {
        get: async () => null,
        set: async () => 'OK',
        publish: async () => 1,
        pipeline: () => ({ set: () => undefined, exec: async () => [] }),
      },
      operatorRepo,
      '',
      db,
      passportTestWiring({
        missionLookup: {
          findById: async (id: string) => ({
            mission_id: id, operator_id: operatorId, intent_services: [],
            expires_at: new Date(Date.now() + 3_600_000), completed_at: null, revoked_at: null,
          }),
        },
      }).dependencies,
    ]) as PassportService;
    const erasure = new OperatorErasureService({
      db,
      operatorRepo,
      archive: { eraseOperatorArchive: async () => undefined },
    });
    return {
      operatorId,
      parentAgentId,
      childAgentId,
      parent,
      service,
      erasure,
    };
  }

  async function expectErasureWins(
    fixture: Awaited<ReturnType<typeof makeFixture>>,
    operation: () => Promise<unknown>,
  ) {
    let lockHeld!: () => void;
    let releaseLock!: () => void;
    const lockHeldPromise = new Promise<void>((resolve) => { lockHeld = resolve; });
    const releaseLockPromise = new Promise<void>((resolve) => { releaseLock = resolve; });
    const erase = db.transaction((tx) => fixture.erasure.beginErasureInTransaction(
      fixture.operatorId,
      tx,
      {
        afterLock: async () => {
          lockHeld();
          await releaseLockPromise;
        },
      },
    ));
    await lockHeldPromise;

    const credential = operation();
    const stateBeforeRelease = await Promise.race([
      credential.then(() => 'settled' as const, () => 'settled' as const),
      new Promise<'blocked'>((resolve) => setTimeout(() => resolve('blocked'), 100)),
    ]);

    releaseLock();
    await expect(erase).resolves.toBeUndefined();
    await expect(credential).rejects.toBeInstanceOf(PassportRevokedError);
    expect(stateBeforeRelease).toBe('blocked');
    expect(await db.select().from(passports)
      .where(eq(passports.operator_id, fixture.operatorId))).toHaveLength(1);
  }

  it('serializes issue behind erasure and issues no passport', async () => {
    const fixture = await makeFixture('issue');
    await expectErasureWins(fixture, () => fixture.service.issue(fixture.operatorId, {
      agent_id: fixture.parentAgentId,
      mission_ids: [`ms_passport_issue_${suffix}`],
    }));
  });

  it('serializes delegation behind erasure and issues no child passport', async () => {
    const fixture = await makeFixture('delegate');
    await expectErasureWins(fixture, () => fixture.service.delegate(fixture.operatorId, {
      parent_passport_token: fixture.parent.token,
      child_agent_id: fixture.childAgentId,
      scopes: [],
    }));
  });

  it('serializes refresh behind erasure and issues no replacement passport', async () => {
    const fixture = await makeFixture('refresh');
    await expectErasureWins(fixture, () => fixture.service.refresh(
      fixture.operatorId,
      fixture.parent.token,
    ));
  });

  it('online verification rejects a passport whose owner has pending erasure', async () => {
    const fixture = await makeFixture('verify');
    await db.transaction((tx) => fixture.erasure.beginErasureInTransaction(
      fixture.operatorId,
      tx,
    ));

    await expect(fixture.service.verify(fixture.parent.token))
      .rejects.toBeInstanceOf(PassportRevokedError);
  });

  for (const operation of ['refresh', 'delegate'] as const) {
    it(`rejects ${operation} when revocation commits while admission waits on the operator lock`, async () => {
      const fixture = await makeFixture(`revoke_${operation}`);
      let lockHeld!: () => void;
      let releaseLock!: () => void;
      const held = new Promise<void>((resolve) => { lockHeld = resolve; });
      const release = new Promise<void>((resolve) => { releaseLock = resolve; });
      const revoke = db.transaction(async (tx) => {
        await acquireOAuthOperatorLock(tx, fixture.operatorId);
        lockHeld();
        await release;
        await tx.update(passports).set({ revoked_at: new Date(), revoked_reason: 'race fixture' })
          .where(eq(passports.jti, fixture.parent.jti));
      });
      await held;
      const pending = operation === 'refresh'
        ? fixture.service.refresh(fixture.operatorId, fixture.parent.token)
        : fixture.service.delegate(fixture.operatorId, {
            parent_passport_token: fixture.parent.token,
            child_agent_id: fixture.childAgentId,
            scopes: [],
          });
      const result = pending.then(() => false, (error: unknown) => error instanceof PassportRevokedError);
      const beforeRelease = await Promise.race([
        result.then(() => 'settled'),
        new Promise<string>((resolve) => setTimeout(() => resolve('waiting'), 100)),
      ]);
      releaseLock();
      await revoke;
      expect(beforeRelease).toBe('waiting');
      expect(await result).toBe(true);
      expect(await db.select().from(passports)
        .where(eq(passports.operator_id, fixture.operatorId))).toHaveLength(1);
    });
  }

  async function expiredRoot(fixture: Awaited<ReturnType<typeof makeFixture>>) {
    const payload = (await signer.verify(fixture.parent.token)).stk;
    const expired = await signer.sign(fixture.parent.jti, payload, -30);
    await db.update(passports).set({ expires_at: expired.expires_at })
      .where(eq(passports.jti, expired.jti));
    return expired;
  }

  it('keeps the documented grace period for an expired root Passport', async () => {
    const fixture = await makeFixture('root_grace');
    const expired = await expiredRoot(fixture);
    const renewed = await fixture.service.refresh(fixture.operatorId, expired.token);
    expect((await fixture.service.verify(renewed.token)).stk.agent_id).toBe(fixture.parentAgentId);
  });

  for (const control of ['agent', 'session', 'operator', 'block', 'claim'] as const) {
    it(`${control} revocation covers expired Passports still inside the refresh grace period`, async () => {
      const fixture = await makeFixture(`expired_${control}`);
      const expired = await expiredRoot(fixture);
      if (control === 'agent') await fixture.service.revokeAllForAgent(fixture.parentAgentId, 'fixture');
      if (control === 'session') {
        const claims = await signer.verify(expired.token, { ignoreExpiration: true });
        await fixture.service.revokeBySession(fixture.operatorId, claims.stk.session_id, 'fixture');
      }
      if (control === 'operator') await fixture.service.revokeAllForOperator(fixture.operatorId, 'fixture');
      if (control === 'claim') {
        await db.update(passports).set({ identity_claim_ids: ['clm_expired_fixture'] })
          .where(eq(passports.jti, expired.jti));
        expect(await fixture.service.revokeByCarriedClaim(fixture.operatorId, 'clm_expired_fixture', 'fixture'))
          .toEqual({ revoked_count: 1 });
      }
      if (control === 'block') {
        await fixture.service.blockAgent(fixture.operatorId, fixture.parentAgentId, 'fixture');
        await db.update(agents).set({ passport_blocked: false }).where(eq(agents.id, fixture.parentAgentId));
      }
      await expect(fixture.service.refresh(fixture.operatorId, expired.token))
        .rejects.toBeInstanceOf(PassportRevokedError);
    });
  }

  for (const state of ['revoked', 'expired', 'blocked', 'missing'] as const) {
    it(`rejects a delegated Passport with a ${state} ancestor during refresh and inbound verification`, async () => {
      const fixture = await makeFixture(`ancestor_${state}`);
      const child = await fixture.service.delegate(fixture.operatorId, {
        parent_passport_token: fixture.parent.token, child_agent_id: fixture.childAgentId, scopes: [],
      });
      if (state === 'revoked') await db.update(passports).set({ revoked_at: new Date() })
        .where(eq(passports.jti, fixture.parent.jti));
      if (state === 'expired') await db.update(passports).set({ expires_at: new Date(Date.now() - 1000) })
        .where(eq(passports.jti, fixture.parent.jti));
      if (state === 'blocked') await db.update(agents).set({ passport_blocked: true })
        .where(eq(agents.id, fixture.parentAgentId));
      if (state === 'missing') await db.delete(passports).where(eq(passports.jti, fixture.parent.jti));
      const error = state === 'expired' ? PassportExpiredError : PassportRevokedError;
      await expect(fixture.service.refresh(fixture.operatorId, child.token)).rejects.toBeInstanceOf(error);
      await expect(fixture.service.verify(child.token, { check_freshness: false })).rejects.toBeInstanceOf(error);
    });
  }

  it('requires fresh parent authorization after the signed child lifetime ends', async () => {
    const fixture = await makeFixture('expired_child');
    const child = await fixture.service.delegate(fixture.operatorId, {
      parent_passport_token: fixture.parent.token, child_agent_id: fixture.childAgentId, scopes: [],
    });
    const expired = await signer.sign(child.jti, (await signer.verify(child.token)).stk, -30);
    await db.update(passports).set({ expires_at: expired.expires_at }).where(eq(passports.jti, child.jti));
    await expect(fixture.service.refresh(fixture.operatorId, expired.token)).rejects.toBeInstanceOf(PassportExpiredError);
  });

  it('does not renew completed work by dropping checkout state', async () => {
    const fixture = await makeFixture('checked_out');
    await db.update(passports).set({ checked_out_at: new Date() }).where(eq(passports.jti, fixture.parent.jti));
    await expect(fixture.service.refresh(fixture.operatorId, fixture.parent.token)).rejects.toBeInstanceOf(PassportRevokedError);
  });

  for (const operation of ['refresh', 'delegate'] as const) {
    it(`session revocation waits for admitted ${operation} and revokes the newly committed Passport`, async () => {
      const fixture = await makeFixture(`admitted_${operation}`);
      let signing!: () => void;
      let release!: () => void;
      const entered = new Promise<void>((resolve) => { signing = resolve; });
      const resume = new Promise<void>((resolve) => { release = resolve; });
      const originalSign = signer.sign.bind(signer);
      const sign = vi.spyOn(signer, 'sign').mockImplementation(async (...args) => {
        signing();
        await resume;
        return originalSign(...args);
      });
      try {
        const pending = operation === 'refresh'
          ? fixture.service.refresh(fixture.operatorId, fixture.parent.token)
          : fixture.service.delegate(fixture.operatorId, {
              parent_passport_token: fixture.parent.token, child_agent_id: fixture.childAgentId, scopes: [],
            });
        await entered;
        const session = (await signer.verify(fixture.parent.token)).stk.session_id;
        const revoke = fixture.service.revokeBySession(fixture.operatorId, session, 'fixture');
        const waiting = await Promise.race([
          revoke.then(() => false), new Promise<boolean>((resolve) => setTimeout(() => resolve(true), 100)),
        ]);
        release();
        const issued = await pending;
        expect(waiting).toBe(true);
        expect((await revoke).revoked_count).toBe(2);
        await expect(fixture.service.verify(issued.token)).rejects.toBeInstanceOf(PassportRevokedError);
      } finally {
        release();
        sign.mockRestore();
      }
    });
  }

  it('revokes every Passport of an operator inside the transaction of the caller, and the whole chain stops verifying once it commits', async () => {
    const fixture = await makeFixture('operator_in');
    const child = await fixture.service.delegate(fixture.operatorId, {
      parent_passport_token: fixture.parent.token, child_agent_id: fixture.childAgentId, scopes: [],
    });
    // A rolled-back transaction revokes nothing; a committed one revokes the parent and the delegated child together.
    const aborted = new Error('rolled back');
    await expect(db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, fixture.operatorId);
      await fixture.service.revokeAllForOperatorIn(fixture.operatorId, 'claimed', tx);
      throw aborted;
    })).rejects.toBe(aborted);
    await expect(fixture.service.verify(child.token)).resolves.toBeDefined();

    const revoked = await db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, fixture.operatorId);
      return fixture.service.revokeAllForOperatorIn(fixture.operatorId, 'claimed', tx);
    });
    expect(revoked.revoked_count).toBe(2);
    await revoked.publish();
    const rows = await db.select().from(passports).where(eq(passports.operator_id, fixture.operatorId));
    expect(rows.map((row) => [row.revoked_at !== null, row.revoked_reason])).toEqual([[true, 'claimed'], [true, 'claimed']]);
    await expect(fixture.service.verify(fixture.parent.token)).rejects.toBeInstanceOf(PassportRevokedError);
    await expect(fixture.service.verify(child.token)).rejects.toBeInstanceOf(PassportRevokedError);
    // Repeating finds nothing left to revoke.
    expect((await fixture.service.revokeAllForOperator(fixture.operatorId, 'again')).revoked_count).toBe(0);
  });
});
