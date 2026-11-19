import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { agents, createDb, ForbiddenError, missions, operators, passportClaims, passports } from '@stack/shared';
import { AgentRepository } from '../repositories/agent-repo.js';
import { MissionRepository } from '../repositories/mission-repo.js';
import { OperatorRepository } from '../repositories/operator-repo.js';
import { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';
import { PassportRepository } from '../repositories/passport-repo.js';
import { ServiceRepository } from '../repositories/service-repo.js';
import { PassportSigner } from '../crypto/passport-signer.js';
import { MissionService } from './mission-service.js';
import { createMissionPassportRevoker, PassportService } from './passport-service.js';
import { passportTestWiring } from './passport-service.test-support.js';

/**
 * A Passport made for one workspace command carries a claim that says so. The claim is server-derived (the public
 * issue input has no such field), survives delegation, and a Passport that carries it is never refreshed: it is a
 * credential for the command's own calls to STACK's proxy, not an identity that can keep itself alive.
 */

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('Passport made for a workspace command', { timeout: 30_000 }, () => {
  const db = createDb(DATABASE_URL!);
  const suffix = randomUUID().replaceAll('-', '').slice(0, 16);
  const operatorId = `op_wscmd_${suffix}`;
  const parentAgentId = `agt_wscmd_parent_${suffix}`;
  const childAgentId = `agt_wscmd_child_${suffix}`;
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
      const claimId = `pc_wscmd_${suffix}_${claimSeq}`;
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
    wiring.missionLookup = { findById: (id) => mission.findById(id) };
  });

  afterAll(async () => {
    await db.delete(missions).where(eq(missions.operator_id, operatorId)).catch(() => undefined);
    await db.delete(passportClaims).where(eq(passportClaims.operator_id, operatorId)).catch(() => undefined);
    await db.delete(passports).where(eq(passports.operator_id, operatorId)).catch(() => undefined);
    await db.delete(agents).where(eq(agents.operator_id, operatorId)).catch(() => undefined);
    await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
  });

  async function openMission() {
    return (await mission.open({ operatorId, intent_summary: 'workspace command fixture', expiresInSeconds: 900 })).mission_id;
  }

  it('carries the claim, which the ordinary issue never sets', async () => {
    const missionId = await openMission();
    const marked = await passport.issueWorkspaceCommand(
      operatorId,
      { agent_id: parentAgentId, mission_ids: [missionId], ttl_seconds: 120, intent: { summary: 'Command in workspace ws_1', services: [] } },
      { workspace_id: 'ws_1' },
    );
    expect((await signer.verify(marked.token)).stk.workspace_command).toEqual({ workspace_id: 'ws_1' });
    const plain = await passport.issue(operatorId, { agent_id: parentAgentId, mission_ids: [missionId] });
    expect((await signer.verify(plain.token)).stk.workspace_command).toBeUndefined();
  });

  it('survives delegation, so a child cannot shed it', async () => {
    const missionId = await openMission();
    const marked = await passport.issueWorkspaceCommand(
      operatorId,
      { agent_id: parentAgentId, mission_ids: [missionId], ttl_seconds: 120, intent: { summary: 'Command in workspace ws_2', services: [], will_delegate: true } },
      { workspace_id: 'ws_2' },
    );
    const child = await passport.delegate(operatorId, { parent_passport_token: marked.token, child_agent_id: childAgentId, scopes: [] });
    expect((await signer.verify(child.token)).stk.workspace_command).toEqual({ workspace_id: 'ws_2' });
  });

  it('is never refreshed', async () => {
    const missionId = await openMission();
    const marked = await passport.issueWorkspaceCommand(
      operatorId,
      { agent_id: parentAgentId, mission_ids: [missionId], ttl_seconds: 120 },
      { workspace_id: 'ws_3' },
    );
    await expect(passport.refresh(operatorId, marked.token)).rejects.toBeInstanceOf(ForbiddenError);
    await expect(passport.refresh(operatorId, marked.token)).rejects.toThrow(/workspace command/);
  });
});
