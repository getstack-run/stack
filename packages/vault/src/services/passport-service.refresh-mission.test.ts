import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { eq } from 'drizzle-orm';
import {
  agents,
  createDb,
  ForbiddenError,
  missions,
  operators,
  passportClaims,
  passports,
  PassportRevokedError,
} from '@stack/shared';
import { AgentRepository } from '../repositories/agent-repo.js';
import { MissionRepository } from '../repositories/mission-repo.js';
import { OperatorRepository } from '../repositories/operator-repo.js';
import { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';
import { PassportRepository } from '../repositories/passport-repo.js';
import { ServiceRepository } from '../repositories/service-repo.js';
import { PassportSigner, type PassportPayload } from '../crypto/passport-signer.js';
import { MissionService } from './mission-service.js';
import { createMissionPassportRevoker, PassportService } from './passport-service.js';
import { passportTestWiring } from './passport-service.test-support.js';

/**
 * a Passport lives and dies with its one Mission. PostgreSQL-backed
 * (skipped without DATABASE_URL) so the transaction, the GIN mission_ids
 * query and verify()'s database fallback are the real ones.
 *
 * Refresh / delegation:
 *   F1: refresh refuses a Passport with no Mission
 *   F2: refresh refuses a Passport whose Mission expired (before the sweep)
 *   F3: refresh refuses a Passport whose Mission was revoked
 *   F4: refresh of a live-Mission Passport keeps the one Mission, leaves the
 *       old Passport and the Mission alone
 *   F5: delegation from a Passport whose Mission is dead is refused
 *
 * Mission end:
 *   E1: complete() revokes the Passport and its delegated child; verify()
 *       rejects both; the Redis flags are written
 *   E2: every revoke reason revokes the bound Passports; verify() rejects
 *   E3: no loop — a Passport revoke leaves its Mission live and a fresh
 *       Passport can be issued for it; ending the Mission then kills that one
 *   E4: a Passport cannot be issued for a Mission that has ended
 */

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('Passport ↔ Mission lifecycle', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = randomUUID().replaceAll('-', '').slice(0, 16);
  const operatorId = `op_mission_life_${suffix}`;
  const parentAgentId = `agt_mission_parent_${suffix}`;
  const childAgentId = `agt_mission_child_${suffix}`;
  const redisStore = new Map<string, string>();
  const redis = {
    get: async (key: string) => redisStore.get(key) ?? null,
    set: async (key: string, value: string) => { redisStore.set(key, value); return 'OK'; },
    publish: async () => 1,
    pipeline: () => {
      const ops: Array<[string, string]> = [];
      return {
        set: (key: string, value: string) => { ops.push([key, value]); },
        exec: async () => { for (const [k, v] of ops) redisStore.set(k, v); return []; },
      };
    },
  };
  let claimSeq = 0;
  const claimRegistry = {
    async registerClaim(
      input: { operatorId: string; payload: Record<string, unknown> },
      options: { persistence?: Pick<PassportClaimsRepository, 'insert'> } = {},
    ) {
      claimSeq += 1;
      const claimId = `pc_mission_life_${suffix}_${claimSeq}`;
      await options.persistence!.insert({
        claim_id: claimId, operator_id: input.operatorId, type: 'mission', body_json: input.payload,
        claim_hash: `hash_${claimSeq}`, signature: 'fixture', envelope_cose: 'fixture',
      });
      return { claimId };
    },
  };
  const wiring = passportTestWiring();
  let signer: PassportSigner;
  let passport: PassportService;
  let mission: MissionService;

  beforeAll(async () => {
    signer = new PassportSigner();
    await signer.init();
    await db.insert(operators).values({ id: operatorId, email: `${operatorId}@test.invalid`, api_key_hash: `hash_${operatorId}` });
    await db.insert(agents).values([
      { id: parentAgentId, operator_id: operatorId, name: `parent-${suffix}`, accountability_mode: 'standard' },
      { id: childAgentId, operator_id: operatorId, name: `child-${suffix}`, accountability_mode: 'standard' },
    ]);
    passport = new PassportService(
      new PassportRepository(db), new AgentRepository(db), new ServiceRepository(db), signer,
      redis as never, new OperatorRepository(db), '', db, wiring.dependencies,
    );
    mission = new MissionService({
      repo: new MissionRepository(db),
      claimRegistry: claimRegistry as never,
      passportRevoker: createMissionPassportRevoker({ redis: redis as never, passportClaimsRepo: new PassportClaimsRepository(db) }),
    });
    // The Mission service is built from the repository below; the Passport reads it through the accessor.
    wiring.missionLookup = { findById: (id) => mission.findById(id) };
  });

  afterAll(async () => {
    await db.delete(missions).where(eq(missions.operator_id, operatorId)).catch(() => undefined);
    await db.delete(passportClaims).where(eq(passportClaims.operator_id, operatorId)).catch(() => undefined);
    await db.delete(passports).where(eq(passports.operator_id, operatorId)).catch(() => undefined);
    await db.delete(agents).where(eq(agents.operator_id, operatorId)).catch(() => undefined);
    await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
  });

  async function openMission(ttlSeconds = 900) {
    return (await mission.open({ operatorId, intent_summary: 'lifecycle fixture', expiresInSeconds: ttlSeconds })).mission_id;
  }

  async function issueFor(missionId: string, willDelegate = false) {
    return passport.issue(operatorId, {
      agent_id: parentAgentId,
      mission_ids: [missionId],
      ...(willDelegate ? { intent: { summary: 'delegating', services: [], will_delegate: true } } : {}),
    });
  }

  async function delegateFrom(token: string) {
    return passport.delegate(operatorId, { parent_passport_token: token, child_agent_id: childAgentId, scopes: [] });
  }

  it('F1: refresh refuses a Passport with no Mission', async () => {
    // A legacy Passport, minted before, signed and stored directly.
    const jti = `ppt_legacy_${suffix}`;
    const sessionId = `ses_legacy_${suffix}`;
    const payload: PassportPayload = {
      operator_id: operatorId, agent_id: parentAgentId, agent_name: 'parent', services: [],
      identity_claims: [], delegation_depth: 0, session_id: sessionId, accountability: 'standard',
    };
    const legacy = await signer.sign(jti, payload, 900);
    await new PassportRepository(db).create({
      jti, operator_id: operatorId, agent_id: parentAgentId, session_id: sessionId,
      delegation_depth: 0, parent_passport_id: null, expires_at: legacy.expires_at,
    });
    await expect(passport.refresh(operatorId, legacy.token)).rejects.toThrow(/exactly one Mission/);
    await expect(passport.refresh(operatorId, legacy.token)).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('F2: refresh refuses a Passport whose Mission expired before the sweep', async () => {
    const missionId = await openMission();
    const issued = await issueFor(missionId);
    await db.update(missions).set({ expires_at: new Date(Date.now() - 1000) }).where(eq(missions.mission_id, missionId));
    await expect(passport.refresh(operatorId, issued.token)).rejects.toThrow(/has expired/);
  });

  it('F3: refresh refuses a Passport whose Mission was revoked', async () => {
    const missionId = await openMission();
    const issued = await issueFor(missionId);
    // Revoked out of band, so the refresh check is exercised on its own
    // rather than through the Passport revoke that a Mission end performs.
    await db.update(missions).set({ revoked_at: new Date(), revoked_reason: 'operator_initiated_clean' })
      .where(eq(missions.mission_id, missionId));
    await expect(passport.refresh(operatorId, issued.token)).rejects.toThrow(/is revoked/);
  });

  it('F4: refresh under a live Mission keeps that one Mission and leaves the Mission live', async () => {
    const missionId = await openMission();
    const issued = await issueFor(missionId);
    const refreshed = await passport.refresh(operatorId, issued.token);
    expect((await signer.verify(refreshed.token)).stk.mission_ids).toEqual([missionId]);
    const row = await mission.findById(missionId);
    expect(row!.completed_at).toBeNull();
    expect(row!.revoked_at).toBeNull();
    // Refresh does not revoke the source Passport, so it cannot trip any cascade.
    await expect(passport.verify(issued.token)).resolves.toBeDefined();
  });

  it('F5: delegation from a Passport whose Mission is dead is refused', async () => {
    const missionId = await openMission();
    const issued = await issueFor(missionId, true);
    await db.update(missions).set({ expires_at: new Date(Date.now() - 1000) }).where(eq(missions.mission_id, missionId));
    await expect(delegateFrom(issued.token)).rejects.toThrow(/has expired/);
  });

  it('E1: complete() revokes the Passport and its delegated child; verify() rejects both', async () => {
    const missionId = await openMission();
    const root = await issueFor(missionId, true);
    const child = await delegateFrom(root.token);
    expect((await signer.verify(child.token)).stk.mission_ids).toEqual([missionId]);
    await expect(passport.verify(child.token)).resolves.toBeDefined();

    await mission.complete(missionId);

    await expect(passport.verify(root.token)).rejects.toBeInstanceOf(PassportRevokedError);
    await expect(passport.verify(child.token)).rejects.toBeInstanceOf(PassportRevokedError);
    expect(redisStore.get(`revoked:${root.jti}`)).toBe('1');
    expect(redisStore.get(`revoked:${child.jti}`)).toBe('1');
    // The database is authoritative even with the cache cleared.
    redisStore.delete(`revoked:${root.jti}`);
    await expect(passport.verify(root.token)).rejects.toBeInstanceOf(PassportRevokedError);
    await expect(passport.refresh(operatorId, root.token)).rejects.toBeInstanceOf(PassportRevokedError);
  });

  it('E2: every revoke reason revokes the bound Passports', async () => {
    const ends: Array<[string, (id: string) => Promise<unknown>]> = [
      ['adversarial', (id) => mission.revoke(id, { reason: 'adversarial' })],
      ['operator_initiated_clean', (id) => mission.revoke(id, { reason: 'operator_initiated_clean' })],
      ['cap_breach_hard', (id) => mission.autoRevokeForCapBreach(id, 'coverage_cap_cents')],
      ['cascade_from_passport', (id) => mission.revoke(id, { reason: 'cascade_from_passport' })],
    ];
    for (const [reason, end] of ends) {
      const missionId = await openMission();
      const issued = await issueFor(missionId);
      await end(missionId);
      await expect(passport.verify(issued.token), reason).rejects.toBeInstanceOf(PassportRevokedError);
      const row = await new PassportRepository(db).findByJti(issued.jti);
      expect(row!.revoked_reason, reason).toContain(missionId);
    }
  });

  it('E3: no loop — a Passport revoke leaves the Mission live; the Mission end still kills later Passports', async () => {
    const missionId = await openMission();
    const first = await issueFor(missionId);
    await passport.revoke({ jti: first.jti, operatorId, reason: 'rotated by operator' });
    const afterRevoke = await mission.findById(missionId);
    expect(afterRevoke!.revoked_at).toBeNull();
    expect(afterRevoke!.completed_at).toBeNull();

    const second = await issueFor(missionId);
    await expect(passport.verify(second.token)).resolves.toBeDefined();
    const revoked = await mission.revoke(missionId, { reason: 'operator_initiated_clean' });
    expect(revoked.transitioned).toBe(true);
    await expect(passport.verify(second.token)).rejects.toBeInstanceOf(PassportRevokedError);
    expect((await mission.revoke(missionId, { reason: 'adversarial' })).transitioned).toBe(false);
  });

  it('E4: a Passport cannot be issued for an ended Mission', async () => {
    const missionId = await openMission();
    await mission.complete(missionId);
    await expect(issueFor(missionId)).rejects.toThrow(/is completed/);
  });
});
