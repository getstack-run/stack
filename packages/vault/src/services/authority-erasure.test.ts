import { afterAll, describe, expect, it, vi } from 'vitest';
import { authorityPrincipals, createDb, operators } from '@stack/shared';
import { eq } from 'drizzle-orm';
import { AuthorityRepository } from '../repositories/authority-repo.js';
import {
  AuthorityService,
  type AuthorityDbTransaction,
  type AuthorityErasureTarget,
  type AuthorityErasureTombstone,
  type AuthorityRepositoryPort,
  type AuthorityServiceDeps,
} from './authority-service.js';

const now = new Date('2026-08-21T17:00:00.000Z');
const digest = `sha256:${'a'.repeat(64)}`;

function makeService(repo: AuthorityRepositoryPort, overrides: Partial<AuthorityServiceDeps> = {}) {
  return new AuthorityService({
    repo,
    kms: {
      encrypt: vi.fn(async (plaintext: string) => ({ ciphertext: `encrypted:${plaintext}`, keyRef: 'test' })),
      decrypt: vi.fn(async (ciphertext: string) => ciphertext.replace(/^encrypted:/, '')),
    },
    claimIssuer: {} as AuthorityServiceDeps['claimIssuer'],
    receiverRequestAudience: 'https://api.test',
    passportVerifier: {} as AuthorityServiceDeps['passportVerifier'],
    approvalDecisionVerifier: {} as AuthorityServiceDeps['approvalDecisionVerifier'],
    receiverOriginVerifier: {} as AuthorityServiceDeps['receiverOriginVerifier'],
    passportRevocationPublisher: { publishAuthorityRevocations: vi.fn() },
    legacyIdentityResolver: {} as AuthorityServiceDeps['legacyIdentityResolver'],
    now: () => now,
    ...overrides,
  });
}

describe('authority graph erasure', () => {
  it('signs every graph tombstone and applies the scrub atomically', async () => {
    const tx = {} as AuthorityDbTransaction;
    const targets: AuthorityErasureTarget[] = [
      { target_kind: 'receiver_transaction_receipt', target_id: 'rtr_one', target_version: null,
        prior_artifact_digest: digest, prior_claim_digest: digest },
      { target_kind: 'presentation', target_id: 'prs_one', target_version: null,
        prior_artifact_digest: digest, prior_claim_digest: null },
      { target_kind: 'binding', target_id: 'abn_one', target_version: 1,
        prior_artifact_digest: digest, prior_claim_digest: digest },
      { target_kind: 'proof', target_id: 'prf_derived', target_version: 1,
        prior_artifact_digest: digest, prior_claim_digest: digest },
      { target_kind: 'proof', target_id: 'prf_source', target_version: 1,
        prior_artifact_digest: digest, prior_claim_digest: digest },
    ];
    let appliedTombstones: AuthorityErasureTombstone[] = [];
    const applyErasureGraph = vi.fn(async (input: { tombstones: AuthorityErasureTombstone[] }) => {
      appliedTombstones = input.tombstones;
      return { passportJtis: ['passport-jti'] };
    });
    const repo = {
      idempotent: async (_input: unknown, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
      currentTransaction: () => tx,
      lockErasureGraph: vi.fn(async () => targets),
      applyErasureGraph,
    } as unknown as AuthorityRepositoryPort;
    const issued: AuthorityErasureTarget[] = [];
    const publish = vi.fn(async () => undefined);
    const sut = makeService(repo, {
      claimIssuer: {
        registerAuthorityErasureTombstone: async (
          { tombstone }: { tombstone: Omit<AuthorityErasureTombstone, 'tombstone_claim_id'> },
          transaction?: AuthorityDbTransaction,
        ) => {
          expect(transaction).toBe(tx);
          issued.push(tombstone);
          return { claimId: `pc_tombstone_${issued.length}`, claimHash: digest };
        },
      } as unknown as AuthorityServiceDeps['claimIssuer'],
      passportRevocationPublisher: { publishAuthorityRevocations: publish },
    });

    await expect(sut.eraseProof('op_test', 'prf_source', 'idem-key')).resolves.toMatchObject({
      target_kind: 'proof', target_id: 'prf_source', target_version: 1,
      erased_at: now.toISOString(), tombstone_claim_id: 'pc_tombstone_5',
    });
    expect(issued).toHaveLength(targets.length);
    expect(issued.map((target) => target.target_id)).toEqual(targets.map((target) => target.target_id));
    expect(applyErasureGraph).toHaveBeenCalledTimes(1);
    expect(appliedTombstones).toHaveLength(targets.length);
    expect(publish).toHaveBeenCalledWith(['passport-jti'], 'authority_proof_erased');
  });

  it('rolls back before scrubbing when any tombstone cannot be signed', async () => {
    const applyErasureGraph = vi.fn();
    const repo = {
      idempotent: async (_input: unknown, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
      currentTransaction: () => ({} as AuthorityDbTransaction),
      lockErasureGraph: async () => [{ target_kind: 'presentation', target_id: 'prs_one', target_version: null,
        prior_artifact_digest: digest, prior_claim_digest: null }],
      applyErasureGraph,
    } as unknown as AuthorityRepositoryPort;
    const sut = makeService(repo, {
      claimIssuer: {
        registerAuthorityErasureTombstone: vi.fn(async () => { throw new Error('signer offline'); }),
      } as unknown as AuthorityServiceDeps['claimIssuer'],
    });

    await expect(sut.erasePresentation('op_test', 'prs_one', 'idem-key'))
      .rejects.toThrow('tombstone signing is unavailable');
    expect(applyErasureGraph).not.toHaveBeenCalled();
  });
});

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('authority graph erasure PostgreSQL locking', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_authority_erase_${suffix}`;
  const principalId = `prn_authority_erase_${suffix}`;

  afterAll(async () => {
    await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
  });

  it('locks and discovers an isolated principal without widening the graph', async () => {
    await db.insert(operators).values({ id: operatorId, email: `${operatorId}@test.invalid`, api_key_hash: `hash_${suffix}` });
    await db.insert(authorityPrincipals).values({
      id: principalId, operator_id: operatorId, kind: 'person', label_encrypted: 'encrypted-label', status: 'active',
    });
    const repo = new AuthorityRepository(db);
    const targets = await repo.atomic((transactional) => transactional.lockErasureGraph({
      operatorId, targetKind: 'principal', targetId: principalId,
    }));
    expect(targets).toEqual([expect.objectContaining({
      target_kind: 'principal', target_id: principalId, target_version: null, prior_claim_digest: null,
    })]);
  });
});
