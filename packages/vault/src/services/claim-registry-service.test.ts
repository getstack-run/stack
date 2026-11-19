import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import type { JWK } from 'jose';
import {
  ClaimType,
  SchemaValidationError,
  type ClaimEnvelope,
} from '@stack/shared';
import { ClaimRegistryService } from './claim-registry-service.js';
import type { ClaimSigner } from '../crypto/claim-signer.js';
import { makeSigner, makeStubRepo, reachesValidation, registryWithSigner } from './claim-registry-service.test-support.js';

/**
 * Service-layer invariants for the claim registry:
 *
 *  T1: every claim type reaches payload validation: no plan gate
 *  T2: svid_attestation registers                            → ok
 *  T3: reserved-but-unimplemented claim type → SchemaValidationError
 *  T4: payload fails Zod schema → SchemaValidationError
 *  T5: register + verify round-trip via the signer
 *  T6: cascadeRevoke calls through to repo.markAllRevokedByPassportId
 *
 * Tests stub the repo (only insert / findByClaimId / markAllRevokedByPassportId
 * are exercised) and exercise the service-level gates. Persistence is
 * NOT exercised here — that ships in the end-to-end verification
 * script.
 */


describe('ClaimRegistryService', () => {
  let svid: { signer: ClaimSigner; publicJwk: JWK; kid: string };

  beforeAll(async () => {
    svid = await makeSigner();
  });

  function makeService(
    opts: {
      publicJwk?: JWK;
    } = {},
  ) {
    const { repo, inserted, cascadeRevokeCalls, store } = makeStubRepo();
    const service = new ClaimRegistryService({
      repo,
      signerForOperator: async () => svid.signer,
      resolvePublicJwk: async () => opts.publicJwk ?? svid.publicJwk,
    });
    return { service, repo, inserted, cascadeRevokeCalls, store };
  }

  it('T1: no claim type is refused before its payload is read', async () => {
    const { service } = makeService();
    for (const claimType of ClaimType.options) {
      expect(await reachesValidation(service, claimType), claimType).toBe(true);
    }
  });

  it('T2: svid_attestation registers', async () => {
    const { service, inserted } = makeService();
    const result = await service.registerClaim({
      operatorId: 'op_test',
      passportJti: 'pas_test',
      claimType: 'svid_attestation',
      payload: {
        type: 'svid_attestation',
        spiffe_id: 'spiffe://acme/workload',
        trust_domain: 'acme',
        not_after_svid: 1778600000,
        issuer: 'spire-server',
        attested_at: 1778600000,
        svid_format: 'jwt-svid',
      },
    });
    expect(result.claimId).toMatch(/^pc_/);
    expect(result.envelopeCose).toBeTruthy();
    expect(result.subject).toBe('stack://operator/op_test/passport/pas_test');
    expect(inserted).toHaveLength(1);
    expect(inserted[0]?.['operator_id']).toBe('op_test');
    expect(inserted[0]?.['envelope_cose']).toBe(result.envelopeCose);
  });

  it('T3: reserved-but-unimplemented claim type rejects with SchemaValidationError', async () => {
    const { service } = makeService();
    await expect(
      service.registerClaim({
        operatorId: 'op_test',
        passportJti: 'pas_test',
        claimType: 'mission',
        payload: {},
      }),
    ).rejects.toBeInstanceOf(SchemaValidationError);
  });

  it('T4: payload failing the Zod schema rejects with SchemaValidationError', async () => {
    const { service } = makeService();
    await expect(
      service.registerClaim({
        operatorId: 'op_test',
        passportJti: 'pas_test',
        claimType: 'svid_attestation',
        payload: { type: 'svid_attestation' /* missing required fields */ },
      }),
    ).rejects.toBeInstanceOf(SchemaValidationError);
  });

  it('T5: register + verifyClaim round-trips an envelope', async () => {
    const { service } = makeService();
    const payload = {
      type: 'svid_attestation' as const,
      spiffe_id: 'spiffe://acme/workload',
      trust_domain: 'acme',
      not_after_svid: 1778600000,
      issuer: 'spire-server',
      attested_at: 1778600000,
      svid_format: 'jwt-svid' as const,
    };
    const { claimId } = await service.registerClaim({
      operatorId: 'op_test',
      passportJti: 'pas_test',
      claimType: 'svid_attestation',
      payload,
    });
    const verified = await service.verifyClaim(claimId);
    expect(verified.valid).toBe(true);
    expect(verified.envelope?.claim_type).toBe('svid_attestation');
    expect(verified.envelope?.subject).toBe('stack://operator/op_test/passport/pas_test');
    expect(verified.envelope?.payload).toEqual(payload);
  });

  it.each([
    [
      'claim_hash',
      (row: Record<string, unknown>) => {
        row['claim_hash'] = '0'.repeat(64);
      },
    ],
    [
      'issuer',
      (row: Record<string, unknown>) => {
        row['issuer'] = 'op_other';
      },
    ],
    [
      'operator_id',
      (row: Record<string, unknown>) => {
        row['operator_id'] = 'op_other';
      },
    ],
    [
      'subject',
      (row: Record<string, unknown>) => {
        row['subject'] = 'stack://operator/op_test/passport/pas_other';
      },
    ],
    [
      'passport_id',
      (row: Record<string, unknown>) => {
        row['passport_id'] = 'pas_other';
      },
    ],
    [
      'type',
      (row: Record<string, unknown>) => {
        row['type'] = 'workload_attestation';
      },
    ],
    [
      'envelope_version',
      (row: Record<string, unknown>) => {
        row['envelope_version'] = 2;
      },
    ],
    [
      'claim_version',
      (row: Record<string, unknown>) => {
        row['claim_version'] = 2;
      },
    ],
    [
      'issued_at_ms',
      (row: Record<string, unknown>) => {
        row['issued_at_ms'] = Number(row['issued_at_ms']) + 1;
      },
    ],
  ])(
    'T5-integrity: rejects a %s mismatch between the row and signed envelope',
    async (field, mutate) => {
      const { service, store } = makeService();
      const { claimId } = await service.registerClaim({
        operatorId: 'op_test',
        passportJti: 'pas_test',
        claimType: 'svid_attestation',
        payload: {
          type: 'svid_attestation',
          spiffe_id: 'spiffe://acme/workload',
          trust_domain: 'acme',
          not_after_svid: 1778600000,
          issuer: 'spire-server',
          attested_at: 1778600000,
          svid_format: 'jwt-svid',
        },
      });
      mutate(store.get(claimId)!);

      const verified = await service.verifyClaim(claimId);

      expect(verified.valid).toBe(false);
      expect(verified.error).toContain(field);
    },
  );

  it('T5-schema: rejects a signed envelope whose typed payload is invalid', async () => {
    const { service, store } = makeService();
    const { claimId } = await service.registerClaim({
      operatorId: 'op_test',
      passportJti: 'pas_test',
      claimType: 'svid_attestation',
      payload: {
        type: 'svid_attestation',
        spiffe_id: 'spiffe://acme/workload',
        trust_domain: 'acme',
        not_after_svid: 1778600000,
        issuer: 'spire-server',
        attested_at: 1778600000,
        svid_format: 'jwt-svid',
      },
    });
    const row = store.get(claimId)!;
    const current = await service.verifyClaim(claimId);
    const invalidEnvelope = {
      ...current.envelope!,
      payload: { type: 'svid_attestation' },
    } as ClaimEnvelope;
    const invalidCose = await svid.signer.sign(invalidEnvelope);
    row['envelope_cose'] = invalidCose;
    row['claim_hash'] = createHash('sha256')
      .update(Buffer.from(invalidCose, 'base64url'))
      .digest('hex');

    const verified = await service.verifyClaim(claimId);

    expect(verified.valid).toBe(false);
    expect(verified.error).toMatch(/payload schema validation failed/);
  });

  it('T5-list: listBySubject drops a row whose signed bytes do not match claim_hash', async () => {
    const { service, store } = makeService();
    const { claimId, subject } = await service.registerClaim({
      operatorId: 'op_test',
      passportJti: 'pas_test',
      claimType: 'svid_attestation',
      payload: {
        type: 'svid_attestation',
        spiffe_id: 'spiffe://acme/workload',
        trust_domain: 'acme',
        not_after_svid: 1778600000,
        issuer: 'spire-server',
        attested_at: 1778600000,
        svid_format: 'jwt-svid',
      },
    });
    store.get(claimId)!['claim_hash'] = '0'.repeat(64);

    await expect(service.listBySubject(subject)).resolves.toEqual([]);
  });

  it('T6: cascadeRevoke walks the registry + returns claim_ids', async () => {
    const { service, cascadeRevokeCalls } = makeService();
    const payload = {
      type: 'svid_attestation' as const,
      spiffe_id: 'spiffe://acme/workload',
      trust_domain: 'acme',
      not_after_svid: 1778600000,
      issuer: 'spire-server',
      attested_at: 1778600000,
      svid_format: 'jwt-svid' as const,
    };
    const r1 = await service.registerClaim({
      operatorId: 'op_test',
      passportJti: 'pas_test',
      claimType: 'svid_attestation',
      payload,
    });
    const result = await service.cascadeRevoke('pas_test', 'passport_revoked');
    expect(result.revokedCount).toBe(1);
    expect(result.claimIds).toContain(r1.claimId);
    expect(cascadeRevokeCalls).toHaveLength(1);
    expect(cascadeRevokeCalls[0]).toEqual({ passportId: 'pas_test', reason: 'passport_revoked' });
  });

  // ─── twin intent-claim mirror hook ──────────────────

  const SAMPLE_INTENT_CLAIM = {
    type: 'intent_claim' as const,
    intent_type: 'http_call' as const,
    agent_id: 'agt_test',
    named_intent: 'slack:read:channel',
    target: 'slack',
    action: 'read',
    parameters: {},
    estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
    accountability: 'logged' as const,
    reason: null,
    requires: [],
    user_subject: null,
    mission_ref: 'ms_test',
    submitted_at: 0,
  };

  it('CR-twin-1: setTwinMirrorHook fires on intent_claim with all args populated', async () => {
    const { service } = makeService();
    const calls: Array<{ realClaimId: string; passportJti: string; operatorId: string }> = [];
    service.setTwinMirrorHook({
      async fire(args) {
        calls.push({
          realClaimId: args.realClaimId,
          passportJti: args.passportJti,
          operatorId: args.operatorId,
        });
      },
    });
    const { claimId } = await service.registerClaim({
      operatorId: 'op_test',
      passportJti: 'pas_real',
      claimType: 'intent_claim',
      payload: SAMPLE_INTENT_CLAIM,
    });
    // Hook is fire-and-forget; wait a tick for the .catch chain.
    await new Promise((r) => setImmediate(r));
    expect(calls).toHaveLength(1);
    expect(calls[0]!.realClaimId).toBe(claimId);
    expect(calls[0]!.passportJti).toBe('pas_real');
    expect(calls[0]!.operatorId).toBe('op_test');
  });

  it('CR-twin-2: hook does NOT fire on non-intent_claim types', async () => {
    const { service } = makeService();
    const calls: Array<unknown> = [];
    service.setTwinMirrorHook({
      async fire(args) {
        calls.push(args);
      },
    });
    await service.registerClaim({
      operatorId: 'op_test',
      passportJti: 'pas_test',
      claimType: 'svid_attestation',
      payload: {
        type: 'svid_attestation',
        spiffe_id: 'spiffe://acme/workload',
        trust_domain: 'acme',
        not_after_svid: 1778600000,
        issuer: 'spire-server',
        attested_at: 1778600000,
        svid_format: 'jwt-svid',
      },
    });
    await new Promise((r) => setImmediate(r));
    expect(calls).toHaveLength(0);
  });

  it('CR-twin-3: hook failure is swallowed (best-effort) — registerClaim still succeeds', async () => {
    const { service } = makeService();
    service.setTwinMirrorHook({
      async fire() {
        throw new Error('twin mirror kaboom');
      },
    });
    // Should NOT throw — registry insists registerClaim succeeds even
    // if the hook fails (matches the simulation_divergence + behavioral_drift
    // patterns).
    const result = await service.registerClaim({
      operatorId: 'op_test',
      passportJti: 'pas_real',
      claimType: 'intent_claim',
      payload: SAMPLE_INTENT_CLAIM,
    });
    expect(result.claimId).toMatch(/^pc_/);
  });

  it('CR-twin-4: no hook wired → registerClaim works normally', async () => {
    const { service } = makeService();
    // No setTwinMirrorHook called
    const result = await service.registerClaim({
      operatorId: 'op_test',
      passportJti: 'pas_real',
      claimType: 'intent_claim',
      payload: SAMPLE_INTENT_CLAIM,
    });
    expect(result.claimId).toMatch(/^pc_/);
  });
});

// ─── Every claim type on every account ───

const SAMPLE_MISSION_CLAIM = {
  type: 'mission' as const,
  mission_id: 'ms_test',
  operator_id: 'op_any',
  intent_summary: 'send the weekly report',
  started_at: 1_700_000_000_000,
  expires_at: 1_700_003_600_000,
};

describe('ClaimRegistryService — no plan gate', () => {
  let key: { signer: ClaimSigner; publicJwk: JWK };
  beforeAll(async () => {
    key = await makeSigner();
  });

  it('evidence packs, behavioural genomes, dossiers and workload attestations reach validation for any account', async () => {
    const service = registryWithSigner(key.signer, key.publicJwk);
    for (const claimType of ['evidence_pack', 'behavioral_genome', 'dossier', 'svid_attestation', 'workload_attestation']) {
      expect(await reachesValidation(service, claimType), claimType).toBe(true);
    }
  });

  it('a mission claim registers end to end', async () => {
    const service = registryWithSigner(key.signer, key.publicJwk);
    await expect(service.registerClaim({
      operatorId: 'op_any',
      subjectOverride: 'operator',
      claimType: 'mission',
      payload: SAMPLE_MISSION_CLAIM,
    })).resolves.toMatchObject({ claimId: expect.stringMatching(/^pc_/) });
  });
});
