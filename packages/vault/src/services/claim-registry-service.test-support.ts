// The signer and the stub repository the claim registry tests share.

import { generateKeyPair, exportJWK, type JWK } from 'jose';
import { SchemaValidationError } from '@stack/shared';
import { ClaimRegistryService } from './claim-registry-service.js';
import { ClaimSigner } from '../crypto/claim-signer.js';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';

let signerKidSequence = 0;

export async function makeSigner(): Promise<{
  signer: ClaimSigner;
  publicJwk: JWK;
  kid: string;
}> {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', {
    crv: 'Ed25519',
    extractable: true,
  });
  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);
  const kid = `test-key-${++signerKidSequence}`;
  return { signer: new ClaimSigner({ privateKeyJwk: privateJwk, kid }), publicJwk, kid };
}

export function makeStubRepo(initialRows: Record<string, Record<string, unknown>> = {}): {
  repo: PassportClaimsRepository;
  inserted: Array<Record<string, unknown>>;
  cascadeRevokeCalls: Array<{ passportId: string; reason: string }>;
  store: Map<string, Record<string, unknown>>;
} {
  const store = new Map<string, Record<string, unknown>>(Object.entries(initialRows));
  const inserted: Array<Record<string, unknown>> = [];
  const cascadeRevokeCalls: Array<{ passportId: string; reason: string }> = [];

  const repo = {
    insert: async (data: Record<string, unknown>) => {
      inserted.push(data);
      store.set(data['claim_id'] as string, data);
      return data;
    },
    findByClaimId: async (claimId: string) => store.get(claimId) ?? null,
    findActiveByPassportId: async (passportId: string) =>
      Array.from(store.values()).filter(
        (r) => r['passport_id'] === passportId && r['revoked_at'] == null,
      ),
    findActiveBySubject: async (subject: string) =>
      Array.from(store.values()).filter((r) => r['subject'] === subject && r['revoked_at'] == null),
    findActiveHashesByPassportId: async () => [],
    findActiveHashesByPassportIds: async () => [],
    markRevoked: async () => undefined,
    markAllRevokedByPassportId: async (passportId: string, reason: string) => {
      cascadeRevokeCalls.push({ passportId, reason });
      const revoked: Array<{ claim_id: string; claim_hash: string }> = [];
      for (const [id, row] of store.entries()) {
        if (row['passport_id'] === passportId && row['revoked_at'] == null) {
          row['revoked_at'] = new Date();
          row['revoked_reason'] = reason;
          revoked.push({ claim_id: id, claim_hash: row['claim_hash'] as string });
        }
      }
      return revoked;
    },
  } as unknown as PassportClaimsRepository;

  return { repo, inserted, cascadeRevokeCalls, store };
}

export function registryWithSigner(signer: ClaimSigner, publicJwk: JWK) {
  const { repo } = makeStubRepo();
  return new ClaimRegistryService({
    repo,
    signerForOperator: async () => signer,
    resolvePublicJwk: async () => publicJwk,
  });
}

/**
 * Whether a claim type reaches payload validation. An empty payload never
 * registers, so SchemaValidationError means nothing refused the type before
 * its payload was read; any other error is a refusal of the type itself.
 */
export async function reachesValidation(service: ClaimRegistryService, claimType: string): Promise<boolean> {
  try {
    await service.registerClaim({ operatorId: 'op_test', subjectOverride: 'operator', claimType: claimType as never, payload: {} });
  } catch (err) {
    if (err instanceof SchemaValidationError) return true;
    return false;
  }
  throw new Error('an empty payload must never register');
}
