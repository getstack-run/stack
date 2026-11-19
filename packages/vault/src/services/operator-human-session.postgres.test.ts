import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import { createDb, operators, teamMembers } from '@stack/shared';
import { OperatorDecisionService } from './operator-decision-service.js';
import { OperatorReviewService } from './operator-review-service.js';
import { isDedicatedVaultTestDatabase } from '../test/dedicated-test-database.js';

const databaseUrl = process.env['DATABASE_URL'];
const run = isDedicatedVaultTestDatabase(databaseUrl) ? describe : describe.skip;
run('signed human writes retain browser identity under the transaction', () => {
  const cleanups: Array<() => Promise<void>> = [];
  afterEach(async () => {
    while (cleanups.length) await cleanups.pop()!();
  });
  for (const path of ['decision', 'create', 'revise'] as const) {
    for (const state of [
      'transferred',
      'demoted',
      'role_changed',
      'expired',
      'owner',
      'member',
    ] as const) {
      it(`${path}: ${state} session`, async () => {
        const db = createDb(databaseUrl!);
        const id = randomUUID();
        const operatorId = `op_human_${id}`;
        const memberId = `mem_human_${id}`;
        const email = `${id}@test.invalid`;
        await db.insert(operators).values({ id: operatorId, email, api_key_hash: id });
        const originalRole = state === 'role_changed' ? ('admin' as const) : ('standard' as const);
        await db
          .insert(teamMembers)
          .values({
            id: memberId,
            operator_id: operatorId,
            email: `member_${email}`,
            name: 'Fixture',
            status: 'active',
            role: originalRole,
          });
        cleanups.push(async () => {
          await db.delete(teamMembers).where(eq(teamMembers.id, memberId));
          await db.delete(operators).where(eq(operators.id, operatorId));
          await db.$client.end();
        });
        const isMember = state === 'member' || state === 'demoted' || state === 'role_changed';
        const author = isMember
          ? { kind: 'team_member' as const, member_id: memberId, role_at_signing: originalRole }
          : { kind: 'operator_owner' as const, operator_id: operatorId };
        const browserSession = {
          email: isMember ? `member_${email}` : email,
          ownerSessionRevision: '0',
          ...(isMember ? { memberId } : {}),
          expiresAt: state === 'expired' ? 1 : Date.now() / 1000 + 60,
        };
        if (state === 'transferred')
          await db
            .update(operators)
            .set({ owner_session_revision: 'changed' })
            .where(eq(operators.id, operatorId));
        if (state === 'demoted')
          await db
            .update(teamMembers)
            .set({ role: 'readonly' })
            .where(eq(teamMembers.id, memberId));
        if (state === 'role_changed')
          await db
            .update(teamMembers)
            .set({ role: 'standard' })
            .where(eq(teamMembers.id, memberId));
        const effect = vi.fn(async () => []);
        const registerClaim = vi.fn(async () => ({
          claimId: 'pc_result',
          envelopeCose: 'fixture',
          subject: 'operator',
        }));
        const audit = { write: vi.fn(async () => undefined) };
        let operation: Promise<unknown>;
        if (path === 'decision') {
          const decisions = {
            findByIdempotencyKey: async () => undefined,
            findCheckoutSources: async () => [
              {
                id: 'cout_fixture',
                operator_id: operatorId,
                mission_id: 'ms_fixture',
                agent_id: 'agt_fixture',
                review_status: 'flagged',
              },
            ],
            applyCheckoutEffect: effect,
            create: async (row: unknown) => row,
            createSources: async () => undefined,
          };
          const service = new OperatorDecisionService({
            repo: {
              findByIdempotencyKey: async () => undefined,
              transaction: (fn: (value: unknown) => Promise<unknown>) =>
                db.transaction((tx) => fn({ decisions, claimPersistence: {}, transaction: tx })),
            },
            claimRegistry: { registerClaim },
            audit,
          } as never);
          operation = service.decide({
            operatorId,
            authoredBy: author,
            action: 'checkout_approved',
            sourceIds: ['cout_fixture'],
            browserSession,
          } as never);
        } else {
          const input = {
            overall_judgment: 'Synthetic assessment.',
            checkpoint_notes: [],
            decision_rationales: [],
            alert_explanations: [],
            incident_classification: 'no_incident' as const,
            lessons_learned: 'Synthetic fixture.',
          };
          const previous = {
            type: 'operator_review',
            mission_ref: 'ms_fixture',
            operator_id: operatorId,
            authored_by: author,
            authored_at_ms: 1,
            ...input,
            prior_review_ref: null,
            assessment_basis: 'operator_organization_assessment',
          };
          const service = new OperatorReviewService({
            missionRepo: {
              findById: async () => ({
                mission_id: 'ms_fixture',
                operator_id: operatorId,
                completed_at: new Date(),
                revoked_at: null,
              }),
            },
            memberRepo: {
              findById: async () => ({
                id: memberId,
                operator_id: operatorId,
                status: 'active',
                role: originalRole,
              }),
            },
            reviewRepo: {
              transaction: (
                _op: string,
                _mission: string,
                fn: (claims: unknown, tx: unknown) => Promise<unknown>,
              ) =>
                db.transaction((tx) =>
                  fn(
                    {
                      findActiveByTypeAndMissionRef: async (type: string) =>
                        path === 'revise' && type === 'operator_review'
                          ? [{ claim_id: 'pc_previous', type, issued_at_ms: 1 }]
                          : [],
                    },
                    tx,
                  ),
                ),
            },
            claimVerifier: {
              verifyClaim: async () => ({
                valid: true,
                envelope: {
                  issuer: operatorId,
                  claim_type: 'operator_review',
                  issued_at: 1,
                  payload: previous,
                },
              }),
            },
            claimRegistry: { registerClaim },
            audit,
          } as never);
          operation =
            path === 'create'
              ? service.create('ms_fixture', operatorId, input, author, undefined, browserSession)
              : service.revise(
                  'ms_fixture',
                  'pc_previous',
                  operatorId,
                  input,
                  author,
                  undefined,
                  browserSession,
                );
        }
        if (['transferred', 'demoted', 'role_changed', 'expired'].includes(state)) {
          await expect(operation).rejects.toThrow();
          expect(effect).not.toHaveBeenCalled();
          expect(registerClaim).not.toHaveBeenCalled();
        } else {
          await expect(operation).resolves.toBeTruthy();
          expect(registerClaim).toHaveBeenCalledOnce();
        }
      });
    }
  }
});
