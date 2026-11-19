import { randomUUID } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { describe, expect, it, vi } from 'vitest';
import { createDb, operators, teamMembers } from '@stack/shared';
import {
  AuthorityService,
  type AuthorityServiceDeps,
  type AuthorityRepositoryPort,
} from './authority-service.js';
import { ApprovalService } from './authority/approvals.js';
import { AuthorityGuards } from './authority/guards.js';
import { isDedicatedVaultTestDatabase } from '../test/dedicated-test-database.js';

// The binding digest has its own suite; this fixture only needs a stable value.
vi.mock('./authority/digest.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./authority/digest.js')>()),
  bindingDigest: () => 'synthetic-digest',
}));

const databaseUrl = process.env['DATABASE_URL'];
const suite = isDedicatedVaultTestDatabase(databaseUrl) ? describe : describe.skip;
suite('Authority browser decision lifecycle', () => {
  it.each([
    'transferred-owner',
    'demoted-member',
    'expired-session',
    'active-owner',
    'active-standard',
  ])('checks %s inside the decision transaction before ceremony or signing', async (kind) => {
    const url = databaseUrl!;
    const db = createDb(url);
    const id = `op_browser_${randomUUID()}`;
    const memberId = `mem_browser_${randomUUID()}`;
    const ownerEmail = `${id}@test.invalid`;
    const memberEmail = `${memberId}@test.invalid`;
    await db
      .insert(operators)
      .values({
        id,
        email: ownerEmail,
        api_key_hash: randomUUID(),
        owner_session_revision: 'new-owner',
      });
    const member = kind.includes('member') || kind === 'active-standard';
    if (member)
      await db
        .insert(teamMembers)
        .values({
          id: memberId,
          operator_id: id,
          email: memberEmail,
          name: 'Synthetic member',
          status: 'active',
          role: kind === 'demoted-member' ? 'readonly' : 'standard',
        });
    const verify = vi.fn(async () => ({}));
    const sign = vi.fn(async () => ({ claimId: 'synthetic-claim', claimHash: 'synthetic-hash' }));
    const mutate = vi.fn(async () => ({ id: 'synthetic-decision' }));
    const repo = {
      idempotent: async (
        _input: unknown,
        mutation: (r: AuthorityRepositoryPort) => Promise<unknown>,
      ) =>
        db.transaction((tx) =>
          mutation({
            currentTransaction: () => tx,
            validateApprovalDecision: async () => ({}),
            decideApproval: mutate,
          } as unknown as AuthorityRepositoryPort),
        ),
    } as unknown as AuthorityRepositoryPort;
    const service = new AuthorityService({
      repo,
      kms: { encrypt: async () => ({ ciphertext: 'synthetic-ciphertext' }) },
      approvalDecisionVerifier: { verify },
      claimIssuer: { registerApprovalClaim: sign },
    } as unknown as AuthorityServiceDeps);
    try {
      const operation = service.decideApproval(
        id,
        'apr_synthetic',
        member
          ? { kind: 'team_member', member_id: memberId, role_at_signing: 'standard' }
          : { kind: 'operator_owner', operator_id: id },
        {
          request_id: 'apr_synthetic',
          decision: 'approve',
          request_hash: `sha256:${'a'.repeat(64)}`,
          signed_decision: 'synthetic-proof',
        },
        randomUUID(),
        {
          email: member ? memberEmail : ownerEmail,
          ownerSessionRevision: kind === 'transferred-owner' ? 'old-owner' : 'new-owner',
          ...(member ? { memberId } : {}),
          expiresAt: Math.floor(Date.now() / 1000) + (kind === 'expired-session' ? -1 : 60),
        },
      );
      if (kind.startsWith('active')) {
        await expect(operation).resolves.toEqual({ id: 'synthetic-decision' });
        expect(mutate).toHaveBeenCalledOnce();
      } else {
        await expect(operation).rejects.toThrow();
        expect(verify).not.toHaveBeenCalled();
        expect(sign).not.toHaveBeenCalled();
        expect(mutate).not.toHaveBeenCalled();
      }
    } finally {
      if (member) await db.delete(teamMembers).where(eq(teamMembers.id, memberId));
      await db.delete(operators).where(eq(operators.id, id));
      await db.$client.end();
    }
  });
});

suite('Authority browser activation lifecycle', () => {
  it.each([
    'transferred-owner',
    'demoted-member',
    'expired-session',
    'active-owner',
    'active-admin',
  ])('checks %s inside final activation before consuming approvals or signing', async (kind) => {
    const db = createDb(databaseUrl!);
    const id = `op_activation_${randomUUID()}`;
    const memberId = `mem_activation_${randomUUID()}`;
    const email = `${id}@test.invalid`;
    const member = kind.includes('member') || kind === 'active-admin';
    await db
      .insert(operators)
      .values({ id, email, api_key_hash: randomUUID(), owner_session_revision: 'current' });
    if (member)
      await db
        .insert(teamMembers)
        .values({
          id: memberId,
          operator_id: id,
          email: `member_${email}`,
          name: 'Synthetic',
          status: 'active',
          role: kind === 'demoted-member' ? 'standard' : 'admin',
        });
    const row = {
      id: 'abn_synthetic',
      version: 1,
      status: 'draft',
      valid_from: new Date(),
      expires_at: new Date(Date.now() + 60000),
      created_at: new Date(),
    };
    const consume = vi.fn(async () => {});
    const sign = vi.fn(async () => ({ claimId: 'synthetic', claimHash: 'synthetic' }));
    const mutate = vi.fn(async () => ({ ...row, status: 'active' }));
    const repo = {
      idempotent: async (
        _input: unknown,
        mutation: (r: AuthorityRepositoryPort) => Promise<unknown>,
      ) =>
        db.transaction((tx) =>
          mutation({
            currentTransaction: () => tx,
            findBinding: async () => row,
            listBindingProofs: async () => [],
            hasUnsatisfiedApprovals: async () => false,
            consumeSatisfiedApprovals: consume,
            activateBinding: mutate,
          } as unknown as AuthorityRepositoryPort),
        ),
    } as unknown as AuthorityRepositoryPort;
    const service = new AuthorityService({
      repo,
      kms: { encrypt: async () => ({ ciphertext: 'synthetic' }) },
      claimIssuer: { registerBindingClaim: sign },
    } as unknown as AuthorityServiceDeps);
    // Binding proof-policy evaluation has its own suite. This fixture tests
    // the real database session gate immediately before the mutation path.
    const assertUsable = vi
      .spyOn(AuthorityGuards.prototype, 'assertBindingUsable')
      .mockResolvedValue(undefined);
    const ensureApprovals = vi
      .spyOn(ApprovalService.prototype, 'ensureApprovalRequests')
      .mockResolvedValue(undefined);
    try {
      const operation = service.activateBinding(id, row.id, 1, randomUUID(), {
        email: member ? `member_${email}` : email,
        ownerSessionRevision: kind === 'transferred-owner' ? 'old' : 'current',
        ...(member ? { memberId } : {}),
        expiresAt: Math.floor(Date.now() / 1000) + (kind === 'expired-session' ? -1 : 60),
      });
      if (kind.startsWith('active')) {
        await expect(operation).resolves.toMatchObject({ id: row.id, status: 'active' });
        expect(mutate).toHaveBeenCalledOnce();
      } else {
        await expect(operation).rejects.toThrow();
        expect(consume).not.toHaveBeenCalled();
        expect(sign).not.toHaveBeenCalled();
        expect(mutate).not.toHaveBeenCalled();
      }
    } finally {
      assertUsable.mockRestore();
      ensureApprovals.mockRestore();
      if (member) await db.delete(teamMembers).where(eq(teamMembers.id, memberId));
      await db.delete(operators).where(eq(operators.id, id));
      await db.$client.end();
    }
  });
});
