import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { eq, inArray } from 'drizzle-orm';
import {
  acquireOAuthOperatorLock,
  createDb,
  operators,
  teamMembers,
  governanceApprovals,
} from '@stack/shared';
import { OperatorDecisionService } from './operator-decision-service.js';
import { OperatorDecisionRepository } from '../repositories/operator-decision-repo.js';
import { isDedicatedVaultTestDatabase } from '../test/dedicated-test-database.js';

const databaseUrl = process.env['DATABASE_URL'];
const run = isDedicatedVaultTestDatabase(databaseUrl) ? describe : describe.skip;
run('browser decision lifecycle races', () => {
  const cleanups: Array<() => Promise<void>> = [];
  afterEach(async () => {
    while (cleanups.length) await cleanups.pop()!();
  });
  async function fixture() {
    const db = createDb(databaseUrl!);
    const id = randomUUID();
    const owner = `op_decision_${id}`;
    const memberId = `mem_decision_${id}`;
    const email = `${id}@decision.invalid`;
    await db.insert(operators).values({ id: owner, email, api_key_hash: owner });
    await db
      .insert(teamMembers)
      .values({
        id: memberId,
        operator_id: owner,
        email: `member_${email}`,
        name: 'Synthetic',
        status: 'active',
        role: 'admin',
      });
    await db
      .insert(governanceApprovals)
      .values({
        id,
        operator_id: owner,
        action: 'detector_config_change',
        resource_id: 'synthetic',
        payload_hash: id,
        summary: 'Synthetic',
        requested_via: 'operator_key',
        expires_at: new Date(Date.now() + 60000),
      });
    cleanups.push(async () => {
      await db.delete(governanceApprovals).where(eq(governanceApprovals.id, id));
      await db.delete(teamMembers).where(eq(teamMembers.id, memberId));
      await db.delete(operators).where(inArray(operators.id, [owner]));
      await db.$client.end();
    });
    const audit = { write: async () => undefined };
    const governance = new OperatorDecisionService({
      repo: new OperatorDecisionRepository(db),
      audit,
    } as never);
    const decide = (
      actor: 'owner' | 'member',
      expiresAt = Date.now() / 1000 + 60,
    ) => {
      const browserSession = {
        email: actor === 'owner' ? email : `member_${email}`,
        ownerSessionRevision: '0',
        ...(actor === 'member' ? { memberId } : {}),
        expiresAt,
      };
      return governance.decideGovernance({
        operatorId: owner,
        approvalId: id,
        decision: 'approve',
        authoredBy:
          actor === 'owner'
            ? { kind: 'operator_owner', operator_id: owner }
            : { kind: 'team_member', member_id: memberId, role_at_signing: 'admin' },
        browserSession,
      });
    };
    return { db, owner, memberId, id, decide };
  }
  for (const path of ['governance'] as const) {
    for (const change of ['transfer', 'demotion'] as const) {
      it(`${path} waits for ${change} and rejects the stale decision without mutation`, async () => {
        const f = await fixture();
        let release!: () => void;
        let held!: () => void;
        const ready = new Promise<void>((resolve) => {
          held = resolve;
        });
        const gate = new Promise<void>((resolve) => {
          release = resolve;
        });
        const mutation = f.db.transaction(async (tx) => {
          await acquireOAuthOperatorLock(tx, f.owner);
          if (change === 'transfer')
            await tx
              .update(operators)
              .set({ owner_session_revision: 'transferred' })
              .where(eq(operators.id, f.owner));
          else
            await tx
              .update(teamMembers)
              .set({ role: 'readonly' })
              .where(eq(teamMembers.id, f.memberId));
          held();
          await gate;
        });
        await ready;
        const decision = f.decide(change === 'transfer' ? 'owner' : 'member').then(
          () => 'approved',
          () => 'rejected',
        );
        const state = await Promise.race([
          decision,
          new Promise((resolve) => setTimeout(() => resolve('blocked'), 75)),
        ]);
        release();
        await mutation;
        expect(state).toBe('blocked');
        expect(await decision).toBe('rejected');
        const row = await f.db.query.governanceApprovals.findFirst({ where: eq(governanceApprovals.id, f.id) });
        expect(row?.status).toBe('pending');
      });
    }
    for (const actor of ['owner', 'member'] as const) {
      it(`${path} permits a current ${actor}`, async () => {
        const f = await fixture();
        await expect(f.decide(actor)).resolves.toBeTruthy();
      });
    }
    it(`${path} rejects an expired session under its mutation lock`, async () => {
      const f = await fixture();
      await expect(f.decide('owner', 1)).rejects.toThrow();
    });
  }
});
