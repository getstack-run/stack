import { describe, it, expect, beforeEach } from 'vitest';
import { type JWK } from 'jose';
import { OperatorSigningKeyService } from './operator-signing-key-service.js';
import type { OperatorSigningKeyRepository } from '../repositories/operator-signing-key-repo.js';
import type { KmsService } from '../crypto/kms.js';

/**
 * Service-layer invariants for the per-operator signing-key service:
 *
 *  T1: ensureKeyForOperator for a fresh operator inserts one row,
 *      kid format ${operator_id}:claim:v1.
 *  T2: ensureKeyForOperator idempotent — second call returns same kid.
 *  T3: getSigner returns a ClaimSigner whose kid matches the active row.
 *  T4: getSigner is cached — second call hits cache (zero KMS Decrypt).
 *  T5: rotate inserts v+1, marks prior retired, evicts cache, returns
 *      both kids.
 *  T6: getPublicJwksForOperator returns active + retired-not-revoked.
 *  T7: System-operator carve-out — ensureKeyForOperator and getSigner
 *      throw for the dogfood operator id; rotate also throws.
 *  T8: evictSigner clears the cache entry.
 */

function makeStubRepo() {
  const rows = new Map<string, ReturnType<typeof makeRow>>();
  let kmsDecryptCount = 0;

  function makeRow(data: { kid: string; operator_id: string; private_key_wrapped: string; public_jwk: Record<string, unknown> }) {
    return {
      ...data,
      created_at: new Date(),
      active_from: new Date(),
      retired_at: null as Date | null,
      revoked_at: null as Date | null,
    };
  }

  const repo = {
    insert: async (data: { kid: string; operator_id: string; private_key_wrapped: string; public_jwk: Record<string, unknown> }) => {
      const row = makeRow(data);
      rows.set(data.kid, row);
      return row;
    },
    findActiveByOperator: async (operatorId: string) => {
      for (const row of rows.values()) {
        if (row.operator_id === operatorId && row.retired_at === null && row.revoked_at === null) {
          return row;
        }
      }
      return undefined;
    },
    findAllByOperatorForJwks: async (operatorId: string) => {
      return [...rows.values()]
        .filter((r) => r.operator_id === operatorId && r.revoked_at === null)
        .sort((a, b) => a.created_at.getTime() - b.created_at.getTime());
    },
    findByKid: async (kid: string) => rows.get(kid),
    findMaxVersion: async (operatorId: string) => {
      let max = 0;
      for (const row of rows.values()) {
        if (row.operator_id !== operatorId) continue;
        const m = /:claim:v(\d+)$/.exec(row.kid);
        if (m) max = Math.max(max, parseInt(m[1]!, 10));
      }
      return max;
    },
    markRetired: async (kid: string, when: Date = new Date()) => {
      const row = rows.get(kid);
      if (row && row.retired_at === null) row.retired_at = when;
    },
    markRevoked: async (kid: string, when: Date = new Date()) => {
      const row = rows.get(kid);
      if (row) row.revoked_at = when;
    },
  } as unknown as OperatorSigningKeyRepository;

  return { repo, rows, get kmsDecryptCount() { return kmsDecryptCount; }, incrementKmsDecryptCount() { kmsDecryptCount += 1; } };
}

function makeStubKms(handle: { incrementKmsDecryptCount(): void }) {
  // Dev-mock KMS: base64 codec, ignores AAD. Fine for unit tests; real
  // AAD enforcement happens in integration against AWS KMS or the real
  // dev mock with EncryptionContext support.
  const kms = {
    encryptDirect: async (plaintext: Buffer) => Buffer.from(plaintext.toString('base64'), 'utf8'),
    decryptDirect: async (ciphertext: Buffer) => {
      handle.incrementKmsDecryptCount();
      return Buffer.from(ciphertext.toString('utf8'), 'base64');
    },
  } as unknown as KmsService;
  return kms;
}

describe('OperatorSigningKeyService', () => {
  const SYSTEM_OP = 'op_stack_system';
  const TENANT_OP = 'op_tenant_abc';

  let stubRepo: ReturnType<typeof makeStubRepo>;
  let svc: OperatorSigningKeyService;

  beforeEach(() => {
    stubRepo = makeStubRepo();
    const kms = makeStubKms(stubRepo);
    svc = new OperatorSigningKeyService({
      repo: stubRepo.repo,
      kms,
      systemOperatorId: SYSTEM_OP,
    });
  });

  it('T1: ensureKeyForOperator inserts one row with kid v1', async () => {
    const kid = await svc.ensureKeyForOperator(TENANT_OP);
    expect(kid).toBe(`${TENANT_OP}:claim:v1`);
    expect(stubRepo.rows.size).toBe(1);
  });

  it('T2: ensureKeyForOperator is idempotent', async () => {
    const kid1 = await svc.ensureKeyForOperator(TENANT_OP);
    const kid2 = await svc.ensureKeyForOperator(TENANT_OP);
    expect(kid1).toBe(kid2);
    expect(stubRepo.rows.size).toBe(1);
  });

  it('T3: getSigner returns a ClaimSigner with matching kid', async () => {
    const signer = await svc.getSigner(TENANT_OP);
    expect(signer.getKid()).toBe(`${TENANT_OP}:claim:v1`);
  });

  it('T4: getSigner is cached — second call hits zero KMS Decrypt', async () => {
    await svc.getSigner(TENANT_OP);
    const beforeCount = stubRepo.kmsDecryptCount;
    await svc.getSigner(TENANT_OP);
    expect(stubRepo.kmsDecryptCount).toBe(beforeCount);
  });

  it('T5: rotate inserts v2, retires v1, evicts cache', async () => {
    const oldSigner = await svc.getSigner(TENANT_OP);
    const oldKid = oldSigner.getKid();

    const { newKid, retiredKid } = await svc.rotate(TENANT_OP);
    expect(newKid).toBe(`${TENANT_OP}:claim:v2`);
    expect(retiredKid).toBe(oldKid);

    // Prior row stamped retired_at.
    const prior = stubRepo.rows.get(oldKid)!;
    expect(prior.retired_at).toBeInstanceOf(Date);

    // Cache evicted — next getSigner returns the new kid.
    const freshSigner = await svc.getSigner(TENANT_OP);
    expect(freshSigner.getKid()).toBe(newKid);
  });

  it('T6: getPublicJwksForOperator returns active + retired', async () => {
    await svc.ensureKeyForOperator(TENANT_OP);
    await svc.rotate(TENANT_OP);

    const jwks = await svc.getPublicJwksForOperator(TENANT_OP);
    expect(jwks).toHaveLength(2);
    expect(jwks[0]!.kid).toBe(`${TENANT_OP}:claim:v1`);
    expect(jwks[0]!.not_after).not.toBeNull();
    expect(jwks[1]!.kid).toBe(`${TENANT_OP}:claim:v2`);
    expect(jwks[1]!.not_after).toBeNull();
  });

  it('T7: system-operator carve-out blocks all writes', async () => {
    await expect(svc.ensureKeyForOperator(SYSTEM_OP)).rejects.toThrow(/system operator/);
    await expect(svc.getSigner(SYSTEM_OP)).rejects.toThrow(/system operator/);
    await expect(svc.rotate(SYSTEM_OP)).rejects.toThrow(/system operator/);
  });

  it('T8: evictSigner clears the cache entry', async () => {
    await svc.getSigner(TENANT_OP);
    const beforeCount = stubRepo.kmsDecryptCount;
    svc.evictSigner(TENANT_OP);
    await svc.getSigner(TENANT_OP);
    expect(stubRepo.kmsDecryptCount).toBe(beforeCount + 1);
  });

  it('end-to-end: sign + verify round-trip with the operator key', async () => {
    const signer = await svc.getSigner(TENANT_OP);
    const envelope = {
      envelope_version: 1 as const,
      issuer: TENANT_OP,
      subject: `stack://operator/${TENANT_OP}/passport/pas_test`,
      issued_at: Date.now(),
      claim_type: 'svid_attestation' as const,
      claim_version: 1,
      payload: { dummy: true },
      receipt: null,
    };
    const cose = await signer.sign(envelope as Parameters<typeof signer.sign>[0]);

    // Resolve pubkey via the JWKS endpoint shape.
    const jwks = await svc.getPublicJwksForOperator(TENANT_OP);
    const pub = jwks.find((j) => j.kid === signer.getKid())!;

    const { ClaimSigner } = await import('../crypto/claim-signer.js');
    const result = await ClaimSigner.verify(cose, async (kid) => {
      const match = jwks.find((j) => j.kid === kid);
      return (match as JWK) ?? null;
    });
    expect(result.valid).toBe(true);
    expect(result.kid).toBe(pub.kid);
  });
});
