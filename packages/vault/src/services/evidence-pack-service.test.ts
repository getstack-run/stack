import { describe, it, expect, vi } from 'vitest';
import { createHash } from 'node:crypto';
import {
  canonicalize,
  EvidencePackManifest,
  ServiceUnavailableError,
  type ManifestInlineSchemaEntry,
} from '@stack/shared';
import {
  EvidencePackService,
  type EvidencePackServiceDeps,
  type InlineJwksMaterial,
} from './evidence-pack-service.js';
import type { ClaimRegistryService, RegisterClaimInput, RegisterClaimResult } from './claim-registry-service.js';
import type { AuditService } from './audit-service.js';
import { ObjectStoreUnavailableError } from './object-store.js';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';
import type { ClaimSigner } from '../crypto/claim-signer.js';

/**
 * EvidencePackService.export invariants.
 *
 *   E1: mission scope resolves to claim set, manifest builds, pack registered
 *   E2: session scope routes to findInSessionScope
 *   E3: period scope routes to findInTimeWindow with parsed ranges
 *   E4: incident scope throws SchemaValidationError (v1 deferral)
 *   E5: empty claim set still produces a valid pack (claim_count = 0, empty Merkle root)
 *   E6: merkle_root deterministically over ordered claim_hashes
 *   E7: content_hash = sha256:<hex> over manifest minus claim + co_signatures
 *   E8: STACK system co-sig appended when stackSystemSigner is wired
 *   E9: STACK system co-sig absent when not wired (graceful v1 fallback)
 *   E10: supersedes option propagates to pack_claim
 *   E11: head_signature returned by operator signer.signBytes
 *   E12: claim_count matches included envelope rows (skips rows missing envelope_cose)
 *   E13: revocation_snapshot_at_ms is the export time; per-claim revoked_at_ms preserved
 *   E14: registerClaim invoked with subjectOverride='operator' + claimType='evidence_pack'
 *   E15: period scope ref 'period:2026-Q1' parses to Jan-Apr 2026 UTC bounds
 *   E16: period scope ref 'period:2026-05-01/2026-06-01' parses to explicit range
 *   E17: malformed period ref → SchemaValidationError
 *   E18: schema_versions.by_claim_type populated for every claim_type in pack
 *   E18b-e: every pin is the real hash of its inline schema; a missing,
 *           partial or inconsistent schema catalog refuses the export (503)
 *   E19: manifest parses against EvidencePackManifest schema
 *   E20: operator JWKS + STACK system JWKS embedded inline in manifest
 *   E21: cross_tenant_refs always [] in v1
 *   E22: external_chain_anchors always [] in v1
 */

type ClaimRow = {
  claim_id: string;
  passport_id: string | null;
  claim_hash: string;
  type: string;
  envelope_cose: string | null;
  issued_at_ms: number | null;
  revoked_at: Date | null;
};

const SAMPLE_CLAIM_ROWS: ClaimRow[] = [
  {
    claim_id: 'pc_a',
    passport_id: 'pas_a',
    claim_hash: 'a'.repeat(64),
    type: 'intent_claim',
    envelope_cose: 'envelope_bytes_a',
    issued_at_ms: 1000,
    revoked_at: null,
  },
  {
    claim_id: 'pc_b',
    passport_id: 'pas_b',
    claim_hash: 'b'.repeat(64),
    type: 'intent_outcome',
    envelope_cose: 'envelope_bytes_b',
    issued_at_ms: 2000,
    revoked_at: new Date(2500),
  },
];

/** An inline schema entry whose content_hash is the real hash of its body. */
function inlineSchemaEntry(jsonSchema: Record<string, unknown>): ManifestInlineSchemaEntry {
  return {
    $schema: 'http://json-schema.org/draft-07/schema#',
    content_hash: `sha256:${createHash('sha256').update(canonicalize(jsonSchema)).digest('hex')}`,
    json_schema: jsonSchema,
  };
}

function makeStubs(): {
  service: EvidencePackService;
  claimRows: { value: ClaimRow[] };
  boundaryRows: { value: ClaimRow[] };
  missionRows: Map<string, {
    mission_id: string;
    operator_id: string;
    started_at: Date;
    completed_at: Date | null;
    revoked_at: Date | null;
  }>;
  packRows: Map<string, { claim_id: string; operator_id: string; scope: { kind: string; ref: string } }>;
  registryCalls: RegisterClaimInput[];
  scopeCalls: Array<{ method: string; args: unknown[] }>;
  signBytesCalls: Array<{ data: string }>;
  coSignCalls: Array<{ primary: string; role: string }>;
  chainHead: { value: { latest_entry_hash: string | null; latest_timestamp: number | null; total_entries: number } };
  withStackSig: (signer: ClaimSigner | undefined) => void;
  deps: EvidencePackServiceDeps;
  storedObjects: Map<string, Buffer>;
  artifactRows: Array<Record<string, unknown>>;
} {
  const claimRows = { value: [...SAMPLE_CLAIM_ROWS] };
  const boundaryRows = { value: [] as ClaimRow[] };
  const missionRows = new Map([
    ['ms_done', {
      mission_id: 'ms_done', operator_id: 'op_abc',
      started_at: new Date(1_000), completed_at: new Date(2_500), revoked_at: null,
    }],
    ['ms_x', {
      mission_id: 'ms_x', operator_id: 'op_abc',
      started_at: new Date(1_000), completed_at: new Date(3_000), revoked_at: null,
    }],
    ['ms_empty', {
      mission_id: 'ms_empty', operator_id: 'op_abc',
      started_at: new Date(1_000), completed_at: new Date(2_000), revoked_at: null,
    }],
  ]);
  const registryCalls: RegisterClaimInput[] = [];
  const packRows = new Map([
    ['pck_prior', {
      claim_id: 'pc_prior_pack',
      operator_id: 'op_abc',
      scope: { kind: 'mission', ref: 'ms_x' },
    }],
  ]);
  const scopeCalls: Array<{ method: string; args: unknown[] }> = [];
  const signBytesCalls: Array<{ data: string }> = [];
  const coSignCalls: Array<{ primary: string; role: string }> = [];
  const chainHead = {
    value: {
      latest_entry_hash: 'c'.repeat(64),
      latest_timestamp: 9999,
      total_entries: 42,
    },
  };

  const claimRegistry = {
    registerClaim: async (input: RegisterClaimInput): Promise<RegisterClaimResult> => {
      registryCalls.push(input);
      return {
        claimId: 'pc_pack_persisted',
        envelopeCose: 'primary_signed_pack_cose_bytes',
      } as unknown as RegisterClaimResult;
    },
    verifyClaim: async (claimId: string) => {
      const pack = [...packRows.values()].find((candidate) => candidate.claim_id === claimId);
      return pack ? {
        valid: true,
        envelope: {
          issuer: pack.operator_id,
          claim_type: 'evidence_pack',
          payload: { type: 'evidence_pack', pack_id: [...packRows.entries()].find(([, value]) => value === pack)?.[0], scope: pack.scope },
        },
      } : { valid: false, error: 'not found' };
    },
  } as unknown as ClaimRegistryService;

  const passportClaimsRepo = {
    findInMissionScope: async (...args: unknown[]) => {
      scopeCalls.push({ method: 'mission', args });
      return claimRows.value as unknown as Array<unknown>;
    },
    findInSessionScope: async (...args: unknown[]) => {
      scopeCalls.push({ method: 'session', args });
      return claimRows.value as unknown as Array<unknown>;
    },
    findInTimeWindow: async (...args: unknown[]) => {
      scopeCalls.push({ method: 'period', args });
      return claimRows.value as unknown as Array<unknown>;
    },
    findPeriodBoundaryClaims: async (...args: unknown[]) => {
      scopeCalls.push({ method: 'period-boundary', args });
      return boundaryRows.value as unknown as Array<unknown>;
    },
    findEvidencePackByPackId: async (packId: string, operatorId: string) => {
      const pack = packRows.get(packId);
      return pack?.operator_id === operatorId ? { claim_id: pack.claim_id } : null;
    },
  } as unknown as PassportClaimsRepository;

  const auditService = {
    getChainHead: async () => chainHead.value,
  } as unknown as AuditService;

  const operatorSigner: ClaimSigner = {
    getKid: () => 'op_abc:claim:v1',
    signBytes: async (data: Buffer) => {
      signBytesCalls.push({ data: data.toString('utf8') });
      return 'base64url_signature_over_head';
    },
  } as unknown as ClaimSigner;

  const stackSystemSignerHolder: { value: ClaimSigner | undefined } = { value: undefined };
  const storedObjects = new Map<string, Buffer>();
  const artifactRows: Array<Record<string, unknown>> = [];

  const artifactRepo = {
    transaction: async <T>(callback: (context: {
      artifacts: { create(input: Record<string, unknown>): Promise<Record<string, unknown>> };
      claimPersistence: { insert(input: Record<string, unknown>): Promise<Record<string, unknown>> };
    }) => Promise<T>) => callback({
      artifacts: {
        create: async (input) => {
          artifactRows.push(input);
          return input;
        },
      },
      claimPersistence: {
        insert: async (input) => input,
      },
    }),
    findByPackIdAndOperator: async (packId: string, operatorId: string) =>
      artifactRows.find((row) => row['pack_id'] === packId && row['operator_id'] === operatorId) ?? null,
  };

  const objectStore = {
    description: 'test store',
    durable: true,
    put: async (key: string, body: Buffer) => { storedObjects.set(key, Buffer.from(body)); },
    get: async (key: string) => storedObjects.get(key) ?? null,
    exists: async (key: string) => storedObjects.has(key),
    list: async () => ({ keys: [...storedObjects.keys()] }),
    delete: async (key: string) => { storedObjects.delete(key); },
  };

  const deps: EvidencePackServiceDeps = {
    claimRegistry,
    passportClaimsRepo,
    missionRepo: {
      findById: async (missionId: string) => missionRows.get(missionId) ?? null,
    },
    auditService,
    operatorSignerResolver: async () => operatorSigner,
    get stackSystemSigner() {
      return stackSystemSignerHolder.value;
    },
    getOperatorJwks: async (): Promise<InlineJwksMaterial> => ({
      keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'op_pub' }],
    }),
    getStackSystemJwks: async (): Promise<InlineJwksMaterial> => ({
      keys: [
        { kty: 'OKP', crv: 'Ed25519', x: 'sys_current', kid: 'stack-passport-v1' },
        { kty: 'OKP', crv: 'Ed25519', x: 'sys_historical', kid: 'stack-passport-v1' },
      ],
    }),
    getOperatorJwksUrl: (operatorId: string) =>
      `https://api.getstack.run/v1/operators/${operatorId}/jwks.json`,
    stackSystemJwksUrl: 'https://api.getstack.run/v1/.well-known/jwks.json',
    canonicalSchemaBaseUrl: 'https://getstack.run/schemas/passport-claims/v1/',
    getInlineSchemas: async (claimTypes: ReadonlySet<string>): Promise<Record<string, ManifestInlineSchemaEntry>> => {
      const out: Record<string, ManifestInlineSchemaEntry> = {
        envelope: inlineSchemaEntry({ type: 'object', title: 'envelope' }),
      };
      for (const t of claimTypes) {
        out[t] = inlineSchemaEntry({ type: 'object', title: t });
      }
      return out;
    },
    artifactRepo,
    objectStore,
  } as unknown as EvidencePackServiceDeps;

  // Patch in the dynamic stackSystemSigner setter via getter
  // (the dep typing requires stackSystemSigner be a static field; we
  //  pre-installed a getter so the closure can mutate it from the
  //  test body).
  const service = new EvidencePackService(deps);

  return {
    service,
    claimRows,
    boundaryRows,
    missionRows,
    packRows,
    registryCalls,
    scopeCalls,
    signBytesCalls,
    coSignCalls,
    chainHead,
    withStackSig: (signer) => {
      stackSystemSignerHolder.value = signer;
    },
    deps,
    storedObjects,
    artifactRows,
  };
}

describe('EvidencePackService.export — scope routing', () => {
  it('E1 mission scope resolves to claim set, manifest builds, pack registered', async () => {
    const { service, scopeCalls, registryCalls } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_done' });
    expect(scopeCalls[0]!.method).toBe('mission');
    expect(scopeCalls[0]!.args).toEqual(['ms_done', 'op_abc', 1_000, 2_500]);
    expect(registryCalls).toHaveLength(1);
    expect(result.pack_id).toMatch(/^pck_/);
    expect(result.claim_id).toBe('pc_pack_persisted');
  });

  it('E2 session scope routes to findInSessionScope', async () => {
    const { service, scopeCalls } = makeStubs();
    await service.export('op_abc', { kind: 'session', ref: 'ses_x' });
    expect(scopeCalls[0]!.method).toBe('session');
    expect(scopeCalls[0]!.args).toEqual(['ses_x', 'op_abc']);
  });

  it('E3 period scope routes to findInTimeWindow with parsed ranges', async () => {
    const { service, scopeCalls } = makeStubs();
    await service.export('op_abc', { kind: 'period', ref: 'period:2026-Q1' });
    expect(scopeCalls[0]!.method).toBe('period');
    // op_abc + (t0_ms, t1_ms)
    expect(scopeCalls[0]!.args[0]).toBe('op_abc');
    expect(scopeCalls[0]!.args[1]).toBe(Date.UTC(2026, 0, 1));
    expect(scopeCalls[0]!.args[2]).toBe(Date.UTC(2026, 3, 1));
  });

  it('E3b period scope requests one pre-period boundary claim per in-window passport', async () => {
    const { service, scopeCalls } = makeStubs();
    await service.export('op_abc', { kind: 'period', ref: 'period:2026-Q1' });
    expect(scopeCalls[1]).toEqual({
      method: 'period-boundary',
      args: ['op_abc', ['pas_a', 'pas_b'], Date.UTC(2026, 0, 1)],
    });
  });

  it('E3c includes a boundary claim before the period', async () => {
    const { service, boundaryRows } = makeStubs();
    boundaryRows.value = [{
      claim_id: 'pc_boundary',
      passport_id: 'pas_a',
      claim_hash: 'd'.repeat(64),
      type: 'checkpoint_approval',
      envelope_cose: 'envelope_boundary',
      issued_at_ms: Date.UTC(2025, 11, 31, 23, 59),
      revoked_at: null,
    }];

    const result = await service.export('op_abc', { kind: 'period', ref: 'period:2026-Q1' });
    expect(result.manifest.claims.map((claim) => claim.claim_hash)).toContain('d'.repeat(64));
    expect(result.pack_claim.time_bounds).toEqual({
      t0_ms: Date.UTC(2026, 0, 1),
      t1_ms: Date.UTC(2026, 3, 1),
    });
  });

  it('E3d fails before claim export for an unknown mission', async () => {
    const { service, scopeCalls, registryCalls } = makeStubs();
    await expect(service.export('op_abc', { kind: 'mission', ref: 'ms_missing' }))
      .rejects.toThrow(/not found/i);
    expect(scopeCalls).toHaveLength(0);
    expect(registryCalls).toHaveLength(0);
  });

  it('E3e hides a mission owned by another operator', async () => {
    const { service, missionRows, scopeCalls, registryCalls } = makeStubs();
    missionRows.set('ms_foreign', {
      mission_id: 'ms_foreign', operator_id: 'op_other',
      started_at: new Date(1_000), completed_at: new Date(2_000), revoked_at: null,
    });
    await expect(service.export('op_abc', { kind: 'mission', ref: 'ms_foreign' }))
      .rejects.toThrow(/not found/i);
    expect(scopeCalls).toHaveLength(0);
    expect(registryCalls).toHaveLength(0);
  });

  it('E3f uses the stored mission start and terminal time as pack bounds', async () => {
    const { service } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_done' });
    expect(result.pack_claim.time_bounds).toEqual({ t0_ms: 1_000, t1_ms: 2_500 });
  });

  it('E4 incident scope throws (v1 deferral)', async () => {
    const { service } = makeStubs();
    const err = await service
      .export('op_abc', { kind: 'incident', ref: 'incident:I-2026-04-15' })
      .catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error & { details?: unknown }).message + JSON.stringify((err as { details?: unknown }).details ?? {})).toMatch(
      /incident.*reserved|not yet wired/i,
    );
  });
});

describe('EvidencePackService.export — payload shape', () => {
  it('E5 empty claim set still produces a valid pack', async () => {
    const { service, claimRows } = makeStubs();
    claimRows.value = [];
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_empty' });
    expect(result.pack_claim.claim_count).toBe(0);
    expect(result.pack_claim.merkle_root).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(result.manifest.claims).toEqual([]);
  });

  it('E6 merkle_root deterministic over ordered claim_hashes', async () => {
    const { service, claimRows } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    const leaves = SAMPLE_CLAIM_ROWS.map((r) => r.claim_hash);
    const expected = createHash('sha256').update(leaves.join('')).digest('hex');
    void claimRows;
    expect(result.pack_claim.merkle_root).toBe(`sha256:${expected}`);
  });

  it('E7 content_hash is sha256:<hex>', async () => {
    const { service } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    expect(result.pack_claim.content_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('E7b content_hash excludes claim + co_signatures (verifier can re-derive)', async () => {
    const { service } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    const skeleton = {
      pack_version: result.manifest.pack_version,
      claims: result.manifest.claims,
      audit_chain_proofs: result.manifest.audit_chain_proofs,
      verification_material: result.manifest.verification_material,
      schemas_inline: result.manifest.schemas_inline,
    };
    const expectedHash = createHash('sha256').update(canonicalize(skeleton)).digest('hex');
    expect(result.pack_claim.content_hash).toBe(`sha256:${expectedHash}`);
  });
});

describe('EvidencePackService.export — co-signature', () => {
  it('E8 STACK system co-sig appended when wired', async () => {
    const { service, withStackSig } = makeStubs();
    const stackSigner: ClaimSigner = {
      coSign: async (primary: string, role: string) => ({
        signer_kid: 'stack-passport-v1',
        signer_role: role as 'operator_attestation',
        cose_sign1: `stack_cosig_over_${primary.slice(0, 8)}`,
      }),
    } as unknown as ClaimSigner;
    withStackSig(stackSigner);
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    expect(result.manifest.co_signatures).toHaveLength(1);
    expect(result.manifest.co_signatures[0]!.signer_kid).toBe('stack-passport-v1');
    expect(result.manifest.co_signatures[0]!.signer_role).toBe('operator_attestation');
  });

  it('E9 STACK system co-sig absent when not wired', async () => {
    const { service } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    expect(result.manifest.co_signatures).toEqual([]);
  });
});

describe('EvidencePackService.export — payload details', () => {
  it('E10 supersedes option propagates', async () => {
    const { service } = makeStubs();
    const result = await service.export(
      'op_abc',
      { kind: 'mission', ref: 'ms_x' },
      { supersedes: 'pck_prior' },
    );
    expect(result.pack_claim.supersedes).toBe('pck_prior');
  });

  it('E10b rejects an unknown or foreign superseded pack before signing', async () => {
    const { service, registryCalls } = makeStubs();
    await expect(service.export(
      'op_abc',
      { kind: 'mission', ref: 'ms_x' },
      { supersedes: 'pck_missing' },
    )).rejects.toThrow(/not found/i);
    expect(registryCalls).toHaveLength(0);
  });

  it('E10c rejects a superseded pack with a different exact scope before signing', async () => {
    const { service, packRows, registryCalls } = makeStubs();
    packRows.set('pck_other_scope', {
      claim_id: 'pc_other_pack', operator_id: 'op_abc',
      scope: { kind: 'mission', ref: 'ms_other' },
    });
    await expect(service.export(
      'op_abc',
      { kind: 'mission', ref: 'ms_x' },
      { supersedes: 'pck_other_scope' },
    )).rejects.toMatchObject({
      details: { message: expect.stringMatching(/same scope/i) },
    });
    expect(registryCalls).toHaveLength(0);
  });

  it('E11 head_signature comes from operator signer.signBytes', async () => {
    const { service, signBytesCalls } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    expect(signBytesCalls).toHaveLength(1);
    expect(result.pack_claim.audit_chain_anchor.head_signature).toBe('base64url_signature_over_head');
    expect(result.pack_claim.audit_chain_anchor.head_hash).toBe('c'.repeat(64));
    expect(result.pack_claim.audit_chain_anchor.head_at_ms).toBe(9999);
  });

  it('E12 claim_count matches envelope-bearing rows (skips missing envelopes)', async () => {
    const { service, claimRows } = makeStubs();
    claimRows.value = [
      ...SAMPLE_CLAIM_ROWS,
      {
        claim_id: 'pc_legacy',
        passport_id: 'pas_a',
        claim_hash: 'f'.repeat(64),
        type: 'intent_claim',
        envelope_cose: null,
        issued_at_ms: 3000,
        revoked_at: null,
      },
    ];
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    expect(result.pack_claim.claim_count).toBe(2); // legacy row skipped
  });

  it('E13 revocation snapshots preserved per claim entry', async () => {
    const { service } = makeStubs();
    const before = Date.now();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    const after = Date.now();
    expect(result.pack_claim.revocation_snapshot_at_ms).toBeGreaterThanOrEqual(before);
    expect(result.pack_claim.revocation_snapshot_at_ms).toBeLessThanOrEqual(after);
    expect(result.manifest.claims[0]!.revoked_at_ms).toBeNull();
    expect(result.manifest.claims[1]!.revoked_at_ms).toBe(2500);
  });

  it('E13b writes exact claim ids into every new manifest entry', async () => {
    const { service } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    expect(result.manifest.claims.map((entry) => entry.claim_id)).toEqual(['pc_a', 'pc_b']);
  });

  it('E13c signs every included review revision by exact claim id', async () => {
    const { service, claimRows } = makeStubs();
    claimRows.value = [
      { ...SAMPLE_CLAIM_ROWS[0]!, claim_id: 'pc_decision', type: 'operator_decision' },
      { ...SAMPLE_CLAIM_ROWS[0]!, claim_id: 'pc_old_review', type: 'dossier' },
      { ...SAMPLE_CLAIM_ROWS[1]!, claim_id: 'pc_review_one', type: 'operator_review' },
      { ...SAMPLE_CLAIM_ROWS[1]!, claim_id: 'pc_review_two', type: 'operator_review' },
    ];
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    expect(result.manifest.claims.map((entry) => entry.claim_id)).toEqual([
      'pc_decision',
      'pc_old_review',
      'pc_review_one',
      'pc_review_two',
    ]);
    expect(result.pack_claim.included_review_claim_ids).toEqual([
      'pc_old_review',
      'pc_review_one',
      'pc_review_two',
    ]);
  });

  it('E14 registerClaim uses subjectOverride=operator + claimType=evidence_pack', async () => {
    const { service, registryCalls } = makeStubs();
    await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    expect(registryCalls[0]!.operatorId).toBe('op_abc');
    expect(registryCalls[0]!.claimType).toBe('evidence_pack');
    expect(registryCalls[0]!.subjectOverride).toBe('operator');
  });
});

describe('EvidencePackService.export — period parsing', () => {
  it('E15 period:YYYY-Qn parses to calendar quarter UTC bounds', async () => {
    const { service, scopeCalls } = makeStubs();
    await service.export('op_abc', { kind: 'period', ref: 'period:2026-Q1' });
    const [, t0, t1] = scopeCalls[0]!.args as [string, number, number];
    expect(t0).toBe(Date.UTC(2026, 0, 1));
    expect(t1).toBe(Date.UTC(2026, 3, 1));
  });

  it('E15b period:YYYY-MM parses to calendar month UTC bounds', async () => {
    const { service, scopeCalls } = makeStubs();
    await service.export('op_abc', { kind: 'period', ref: 'period:2026-05' });
    const [, t0, t1] = scopeCalls[0]!.args as [string, number, number];
    expect(t0).toBe(Date.UTC(2026, 4, 1));
    expect(t1).toBe(Date.UTC(2026, 5, 1));
  });

  it('E16 period:YYYY-MM-DD/YYYY-MM-DD parses to explicit range', async () => {
    const { service, scopeCalls } = makeStubs();
    await service.export('op_abc', { kind: 'period', ref: 'period:2026-05-01/2026-06-01' });
    const [, t0, t1] = scopeCalls[0]!.args as [string, number, number];
    expect(t0).toBe(Date.UTC(2026, 4, 1));
    expect(t1).toBe(Date.UTC(2026, 5, 1));
  });

  it('E17 malformed period ref → throws', async () => {
    const { service } = makeStubs();
    const err = await service
      .export('op_abc', { kind: 'period', ref: 'period:not-a-date' })
      .catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error & { details?: unknown }).message + JSON.stringify((err as { details?: unknown }).details ?? {})).toMatch(
      /period scope ref|does not match any supported shape/i,
    );
  });
});

describe('EvidencePackService.export — manifest material', () => {
  it('E18 schema_versions.by_claim_type populated for every claim_type in pack', async () => {
    const { service } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    expect(result.pack_claim.schema_versions.by_claim_type['intent_claim']).toEqual({
      version: 1,
      content_hash: inlineSchemaEntry({ type: 'object', title: 'intent_claim' }).content_hash,
    });
    expect(result.pack_claim.schema_versions.by_claim_type['intent_outcome']).toBeDefined();
  });

  it('E18b every schema pin is the real hash of the inline schema it names, never a placeholder', async () => {
    const { service } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    const pins = {
      envelope: result.pack_claim.schema_versions.envelope.content_hash,
      ...Object.fromEntries(
        Object.entries(result.pack_claim.schema_versions.by_claim_type).map(
          ([key, entry]) => [key, entry.content_hash],
        ),
      ),
    };
    expect(Object.keys(pins).sort()).toEqual(['envelope', 'intent_claim', 'intent_outcome']);
    for (const [key, pinned] of Object.entries(pins)) {
      const inline = result.manifest.schemas_inline[key]!;
      const recomputed = `sha256:${createHash('sha256').update(canonicalize(inline.json_schema)).digest('hex')}`;
      expect(pinned).toBe(recomputed);
      expect(pinned).toBe(inline.content_hash);
      expect(pinned).not.toBe(`sha256:${'0'.repeat(64)}`);
    }
  });

  it('E18c refuses to export when the schema catalog is unavailable, instead of pinning placeholders', async () => {
    const { service, deps, registryCalls, storedObjects } = makeStubs();
    deps.getInlineSchemas = async () => ({});

    const outcome = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' })
      .catch((error: unknown) => error);

    expect(outcome).toBeInstanceOf(ServiceUnavailableError);
    expect((outcome as ServiceUnavailableError).statusCode).toBe(503);
    expect((outcome as Error).message).toMatch(/schema/i);
    expect(registryCalls).toHaveLength(0);
    expect(storedObjects.size).toBe(0);
  });

  it('E18d refuses to export when one claim type in the pack has no published schema', async () => {
    const { service, deps, registryCalls } = makeStubs();
    deps.getInlineSchemas = async () => ({
      envelope: inlineSchemaEntry({ type: 'object', title: 'envelope' }),
      intent_claim: inlineSchemaEntry({ type: 'object', title: 'intent_claim' }),
    });

    const outcome = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' })
      .catch((error: unknown) => error);

    expect(outcome).toBeInstanceOf(ServiceUnavailableError);
    expect((outcome as Error).message).toContain('intent_outcome');
    expect(registryCalls).toHaveLength(0);
  });

  it('E18e refuses to export when an inline schema body does not hash to its own content_hash', async () => {
    const { service, deps, registryCalls } = makeStubs();
    deps.getInlineSchemas = async (claimTypes) => {
      const out: Record<string, ManifestInlineSchemaEntry> = {
        envelope: inlineSchemaEntry({ type: 'object', title: 'envelope' }),
      };
      for (const claimType of claimTypes) {
        out[claimType] = inlineSchemaEntry({ type: 'object', title: claimType });
      }
      out['intent_claim'] = {
        ...out['intent_claim']!,
        content_hash: `sha256:${'e'.repeat(64)}`,
      };
      return out;
    };

    const outcome = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' })
      .catch((error: unknown) => error);

    expect(outcome).toBeInstanceOf(ServiceUnavailableError);
    expect((outcome as Error).message).toContain('intent_claim');
    expect(registryCalls).toHaveLength(0);
  });

  it('E19 manifest parses against EvidencePackManifest schema', async () => {
    const { service } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    expect(() => EvidencePackManifest.parse(result.manifest)).not.toThrow();
  });

  it('E20 operator + STACK system JWKS embedded inline', async () => {
    const { service } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    expect(result.manifest.verification_material.operator_jwks_inline.keys).toHaveLength(1);
    expect(result.manifest.verification_material.stack_system_jwks_inline.keys).toHaveLength(2);
    expect(result.manifest.verification_material.stack_system_jwks_inline.keys).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ x: 'sys_current', kid: 'stack-passport-v1' }),
        expect.objectContaining({ x: 'sys_historical', kid: 'stack-passport-v1' }),
      ]),
    );
    expect(result.manifest.verification_material.operator_jwks_url).toContain('op_abc');
  });

  it('E21 cross_tenant_refs always [] in v1', async () => {
    const { service } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    expect(result.pack_claim.cross_tenant_refs).toEqual([]);
  });

  it('E22 external_chain_anchors empty when no externalAnchor service wired', async () => {
    const { service } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    expect(result.pack_claim.external_chain_anchors).toEqual([]);
  });

  it('E23 external_chain_anchors populated when externalAnchor returns a row', async () => {
    const { deps } = makeStubs();
    // Inject an externalAnchor service that returns a synthetic row.
    const depsWithAnchor: typeof deps = {
      ...deps,
      externalAnchor: {
        getAnchorAtOrBefore: async (operatorId: string, _tMs: number) => ({
          id: 'anc_1',
          operator_id: operatorId,
          anchored_at_ms: 9000,
          chain_head_hash: 'a'.repeat(64),
          chain_head_at_audit_position: 100,
          registry: 'github:example-org/anchors',
          permalink: 'https://github.com/example-org/anchors/blob/sha/file.json',
          commit_sha: 'sha',
          chain_head_signature: 'sig',
          stack_system_attestation: null,
        }),
        getLatestAnchor: async () => null,
        anchorOperator: async () => null,
      } as unknown as typeof deps.externalAnchor,
    };
    const { EvidencePackService: EPS } = await import('./evidence-pack-service.js');
    const localService = new EPS(depsWithAnchor);
    const result = await localService.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    expect(result.pack_claim.external_chain_anchors).toHaveLength(1);
    expect(result.pack_claim.external_chain_anchors[0]).toEqual({
      registry: 'github:example-org/anchors',
      permalink: 'https://github.com/example-org/anchors/blob/sha/file.json',
      anchored_at_ms: 9000,
      anchored_chain_head_hash: 'a'.repeat(64),
    });
  });

  it('E24 external_chain_anchors empty when externalAnchor returns null (no anchor yet)', async () => {
    const { deps } = makeStubs();
    const depsWithAnchor: typeof deps = {
      ...deps,
      externalAnchor: {
        getAnchorAtOrBefore: async () => null,
        getLatestAnchor: async () => null,
        anchorOperator: async () => null,
      } as unknown as typeof deps.externalAnchor,
    };
    const { EvidencePackService: EPS } = await import('./evidence-pack-service.js');
    const localService = new EPS(depsWithAnchor);
    const result = await localService.export('op_abc', { kind: 'mission', ref: 'ms_x' });
    expect(result.pack_claim.external_chain_anchors).toEqual([]);
  });
});

describe('EvidencePackService immutable artifact', () => {
  it('E25 persists the canonical final manifest bytes with operator-scoped metadata', async () => {
    const { service, storedObjects, artifactRows } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_done' });

    expect(artifactRows).toHaveLength(1);
    expect(artifactRows[0]).toMatchObject({
      pack_id: result.pack_id,
      claim_id: result.claim_id,
      operator_id: 'op_abc',
    });
    const key = artifactRows[0]!['object_key'] as string;
    expect(storedObjects.get(key)).toEqual(Buffer.from(canonicalize(result.manifest), 'utf8'));
  });

  it('E26 returns only a same-operator artifact and verifies its stored hash', async () => {
    const { service } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_done' });

    const stored = await service.getStoredManifest('op_abc', result.pack_id);
    expect(stored.body).toEqual(Buffer.from(canonicalize(result.manifest), 'utf8'));
    await expect(service.getStoredManifest('op_other', result.pack_id)).rejects.toThrow(/not found/i);
  });

  it('E27 deletes an object when metadata persistence fails', async () => {
    const { service, deps, storedObjects } = makeStubs();
    deps.artifactRepo.transaction = (async (callback) => callback({
      artifacts: {
        create: async () => {
          throw new Error('metadata insert failed');
        },
      } as never,
      claimPersistence: { insert: async (input) => input as never },
    })) as typeof deps.artifactRepo.transaction;

    await expect(service.export('op_abc', { kind: 'mission', ref: 'ms_done' }))
      .rejects.toThrow('metadata insert failed');
    expect(storedObjects.size).toBe(0);
  });

  it('E28 cleans up an upload that succeeds before the store reports failure', async () => {
    const { service, deps, storedObjects } = makeStubs();
    deps.objectStore.put = async (key, body) => {
      storedObjects.set(key, Buffer.from(body));
      throw new Error('upload response lost');
    };

    const outcome = await service.export('op_abc', { kind: 'mission', ref: 'ms_done' })
      .catch((error: unknown) => error);
    expect(outcome).toBeInstanceOf(ObjectStoreUnavailableError);
    expect((outcome as Error).message).not.toContain('upload response lost');
    expect(storedObjects.size).toBe(0);
  });

  it('E28b a store outage on export is a retriable 503 with a safe message, whichever store is wired', async () => {
    const { service, deps } = makeStubs();
    deps.objectStore.put = async () => {
      throw new Error('connect ECONNREFUSED arn:aws:s3:::secret-bucket');
    };

    const outcome = await service.export('op_abc', { kind: 'mission', ref: 'ms_done' })
      .catch((error: unknown) => error);
    expect(outcome).toBeInstanceOf(ServiceUnavailableError);
    expect((outcome as ServiceUnavailableError).statusCode).toBe(503);
    expect((outcome as Error).message).toBe('Object storage is temporarily unavailable, please retry');
  });

  it('E28c an export whose object cleanup also fails still answers 503, not an aggregate 500', async () => {
    const { service, deps } = makeStubs();
    deps.objectStore.put = async () => {
      throw new ObjectStoreUnavailableError('put', 'access_denied');
    };
    deps.objectStore.delete = async () => {
      throw new Error('delete refused');
    };
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const outcome = await service.export('op_abc', { kind: 'mission', ref: 'ms_done' })
        .catch((error: unknown) => error);
      expect(outcome).toBeInstanceOf(ObjectStoreUnavailableError);
      expect(outcome).not.toBeInstanceOf(AggregateError);
    } finally {
      errors.mockRestore();
    }
  });

  it('E28d a store outage on download is a 503, not a missing pack', async () => {
    const { service, deps } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_done' });
    deps.objectStore.get = async () => {
      throw new Error('socket hang up');
    };

    const outcome = await service.getStoredManifest('op_abc', result.pack_id).catch((error: unknown) => error);
    expect(outcome).toBeInstanceOf(ObjectStoreUnavailableError);
    expect((outcome as ServiceUnavailableError).statusCode).toBe(503);
  });

  it('E29 fails closed when stored manifest bytes no longer match their hash', async () => {
    const { service, storedObjects, artifactRows } = makeStubs();
    const result = await service.export('op_abc', { kind: 'mission', ref: 'ms_done' });
    const objectKey = artifactRows[0]!['object_key'] as string;
    storedObjects.set(objectKey, Buffer.from('{"changed":true}', 'utf8'));

    await expect(service.getStoredManifest('op_abc', result.pack_id))
      .rejects.toThrow(/missing or failed hash verification/i);
  });
});

