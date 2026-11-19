import { describe, it, expect } from 'vitest';
import {
  EvidencePackClaim,
  EvidencePackScope,
  EvidencePackManifest,
  AuditChainAnchor,
  PackSchemaVersions,
  SchemaVersionEntry,
  CrossTenantRef,
  ExternalChainAnchorRef,
  ManifestClaimEntry,
  ManifestAuditChainProof,
  ManifestVerificationMaterial,
  ManifestInlineSchemaEntry,
  InlineJwks,
  PASSPORT_CLAIM_SCHEMAS,
} from './index.js';

/**
 * EvidencePackClaim + EvidencePackManifest schema invariants.
 *
 *   EP1:  minimal-valid claim parses (no cross-tenant + no external anchors)
 *   EP2:  full-shape claim with all optional arrays populated parses
 *   EP3:  pack_id rejects non-pck_* shape
 *   EP4:  content_hash rejects non-sha256-hex shape
 *   EP5:  scope.kind rejects unknown values
 *   EP6:  time_bounds rejects t1_ms <= t0_ms
 *   EP7:  audit_chain_anchor.head_hash rejects non-hex
 *   EP8:  supersedes accepts null
 *   EP9:  supersedes rejects non-pck_* (when non-null)
 *   EP10: schema_versions.envelope rejects malformed content_hash
 *   EP11: schema_versions.by_claim_type rejects unknown claim_type keys
 *   EP12: cross_tenant_refs rejects unknown relation enum
 *   EP13: cross_tenant_refs rejects non-URL foreign_jwks_url
 *   EP14: external_chain_anchors[].anchored_chain_head_hash rejects non-hex
 *   EP15: cross_tenant_refs + external_chain_anchors default to [] when omitted
 *   EP16: registered in PASSPORT_CLAIM_SCHEMAS map
 *
 *   MA1:  minimal-valid manifest parses
 *   MA2:  pack_version literal rejects non-1
 *   MA3:  claims[i].claim_hash rejects non-hex
 *   MA4:  audit_chain_proofs[i].merkle_path entries reject non-canonical hash
 *   MA5:  verification_material requires all 4 fields
 *   MA6:  schemas_inline[k].content_hash rejects non-sha256-hex shape
 */

const VALID_PACK: ReturnType<typeof EvidencePackClaim.parse> = EvidencePackClaim.parse({
  type: 'evidence_pack',
  pack_id: 'pck_abc',
  content_hash: 'sha256:' + 'a'.repeat(64),
  scope: { kind: 'mission', ref: 'ms_done' },
  time_bounds: { t0_ms: 1000, t1_ms: 2000 },
  claim_count: 0,
  merkle_root: 'sha256:' + 'b'.repeat(64),
  audit_chain_anchor: {
    head_hash: 'c'.repeat(64),
    head_signature: 'base64sig',
    head_at_ms: 1500,
  },
  revocation_snapshot_at_ms: 1500,
  schema_versions: {
    envelope: { version: 1, content_hash: 'sha256:' + 'd'.repeat(64) },
    by_claim_type: {},
  },
  canonical_schema_base_url: 'https://getstack.run/schemas/passport-claims/v1/',
  supersedes: null,
  cross_tenant_refs: [],
  external_chain_anchors: [],
});

const VALID_BASE_INPUT = {
  type: 'evidence_pack' as const,
  pack_id: 'pck_abc',
  content_hash: 'sha256:' + 'a'.repeat(64),
  scope: { kind: 'mission' as const, ref: 'ms_done' },
  time_bounds: { t0_ms: 1000, t1_ms: 2000 },
  claim_count: 0,
  merkle_root: 'sha256:' + 'b'.repeat(64),
  audit_chain_anchor: {
    head_hash: 'c'.repeat(64),
    head_signature: 'base64sig',
    head_at_ms: 1500,
  },
  revocation_snapshot_at_ms: 1500,
  schema_versions: {
    envelope: { version: 1, content_hash: 'sha256:' + 'd'.repeat(64) },
    by_claim_type: {},
  },
  canonical_schema_base_url: 'https://getstack.run/schemas/passport-claims/v1/',
  supersedes: null,
  cross_tenant_refs: [],
  external_chain_anchors: [],
};

describe('EvidencePackClaim — parse positives', () => {
  it('EP1 minimal-valid claim parses', () => {
    const parsed = EvidencePackClaim.parse(VALID_BASE_INPUT);
    expect(parsed.type).toBe('evidence_pack');
    expect(parsed.pack_id).toBe('pck_abc');
    expect(parsed.cross_tenant_refs).toEqual([]);
    expect(parsed.external_chain_anchors).toEqual([]);
    expect(parsed.included_review_claim_ids).toEqual([]);
  });

  it('EP1b carries exact included review claim ids', () => {
    const parsed = EvidencePackClaim.parse({
      ...VALID_BASE_INPUT,
      included_review_claim_ids: ['pc_review_one', 'pc_review_two'],
    });
    expect(parsed.included_review_claim_ids).toEqual(['pc_review_one', 'pc_review_two']);
  });

  it('EP2 full-shape claim with cross-tenant + anchors + by_claim_type populated', () => {
    const parsed = EvidencePackClaim.parse({
      ...VALID_BASE_INPUT,
      claim_count: 3,
      schema_versions: {
        envelope: { version: 1, content_hash: 'sha256:' + 'd'.repeat(64) },
        by_claim_type: {
          intent_claim: { version: 1, content_hash: 'sha256:' + 'e'.repeat(64) },
          intent_outcome: { version: 1, content_hash: 'sha256:' + 'f'.repeat(64) },
        },
      },
      supersedes: 'pck_prior',
      cross_tenant_refs: [
        {
          foreign_claim_hash: '1'.repeat(64),
          foreign_issuer_op_id: 'op_other',
          foreign_jwks_url: 'https://api.getstack.run/v1/operators/op_other/jwks.json',
          relation: 'a2a_dispatch',
        },
      ],
      external_chain_anchors: [
        {
          registry: 'github:example-org/anchors',
          permalink: 'https://github.com/example-org/anchors/blob/main/anchors/op_abc/2026-05-24.json',
          anchored_at_ms: 1700,
          anchored_chain_head_hash: '2'.repeat(64),
        },
      ],
    });
    expect(parsed.claim_count).toBe(3);
    expect(parsed.supersedes).toBe('pck_prior');
    expect(parsed.cross_tenant_refs).toHaveLength(1);
    expect(parsed.external_chain_anchors).toHaveLength(1);
  });
});

describe('EvidencePackClaim — parse negatives', () => {
  it('EP3 rejects pack_id not matching pck_* shape', () => {
    expect(() =>
      EvidencePackClaim.parse({ ...VALID_BASE_INPUT, pack_id: 'pc_wrong' }),
    ).toThrow(/pack_id must be a pack id/);
  });

  it('EP4 rejects content_hash not sha256:<64 hex>', () => {
    expect(() =>
      EvidencePackClaim.parse({ ...VALID_BASE_INPUT, content_hash: 'sha256:short' }),
    ).toThrow(/content_hash must be sha256/);
  });

  it('EP5 rejects unknown scope.kind', () => {
    expect(() =>
      EvidencePackClaim.parse({ ...VALID_BASE_INPUT, scope: { kind: 'fleet', ref: 'fl_x' } }),
    ).toThrow();
  });

  it('EP6 rejects t1_ms <= t0_ms', () => {
    expect(() =>
      EvidencePackClaim.parse({ ...VALID_BASE_INPUT, time_bounds: { t0_ms: 2000, t1_ms: 1000 } }),
    ).toThrow(/t1_ms must be > t0_ms/);
  });

  it('EP6b rejects t1_ms === t0_ms', () => {
    expect(() =>
      EvidencePackClaim.parse({ ...VALID_BASE_INPUT, time_bounds: { t0_ms: 1000, t1_ms: 1000 } }),
    ).toThrow(/t1_ms must be > t0_ms/);
  });

  it('EP7 rejects audit_chain_anchor.head_hash not 64 hex chars', () => {
    expect(() =>
      EvidencePackClaim.parse({
        ...VALID_BASE_INPUT,
        audit_chain_anchor: { ...VALID_BASE_INPUT.audit_chain_anchor, head_hash: 'short' },
      }),
    ).toThrow();
  });

  it('EP8 accepts supersedes null', () => {
    const parsed = EvidencePackClaim.parse({ ...VALID_BASE_INPUT, supersedes: null });
    expect(parsed.supersedes).toBeNull();
  });

  it('EP9 rejects supersedes not matching pck_* (when non-null)', () => {
    expect(() =>
      EvidencePackClaim.parse({ ...VALID_BASE_INPUT, supersedes: 'ms_wrong' }),
    ).toThrow(/supersedes must be a pack id/);
  });

  it('EP10 rejects schema_versions.envelope malformed content_hash', () => {
    expect(() =>
      EvidencePackClaim.parse({
        ...VALID_BASE_INPUT,
        schema_versions: {
          envelope: { version: 1, content_hash: 'wrong' },
          by_claim_type: {},
        },
      }),
    ).toThrow();
  });

  it('EP11 rejects schema_versions.by_claim_type unknown claim_type key', () => {
    expect(() =>
      EvidencePackClaim.parse({
        ...VALID_BASE_INPUT,
        schema_versions: {
          envelope: { version: 1, content_hash: 'sha256:' + 'd'.repeat(64) },
          by_claim_type: {
            invented_claim: { version: 1, content_hash: 'sha256:' + 'e'.repeat(64) },
          },
        },
      }),
    ).toThrow();
  });

  it('EP12 rejects cross_tenant_refs unknown relation', () => {
    expect(() =>
      EvidencePackClaim.parse({
        ...VALID_BASE_INPUT,
        cross_tenant_refs: [
          {
            foreign_claim_hash: '1'.repeat(64),
            foreign_issuer_op_id: 'op_other',
            foreign_jwks_url: 'https://api.getstack.run/v1/operators/op_other/jwks.json',
            relation: 'something_else',
          },
        ],
      }),
    ).toThrow();
  });

  it('EP13 rejects non-URL foreign_jwks_url', () => {
    expect(() =>
      EvidencePackClaim.parse({
        ...VALID_BASE_INPUT,
        cross_tenant_refs: [
          {
            foreign_claim_hash: '1'.repeat(64),
            foreign_issuer_op_id: 'op_other',
            foreign_jwks_url: 'not a url',
            relation: 'delegation_parent',
          },
        ],
      }),
    ).toThrow();
  });

  it('EP14 rejects external_chain_anchors[].anchored_chain_head_hash not hex', () => {
    expect(() =>
      EvidencePackClaim.parse({
        ...VALID_BASE_INPUT,
        external_chain_anchors: [
          {
            registry: 'github:example-org/anchors',
            permalink: 'https://github.com/example-org/anchors/blob/main/file.json',
            anchored_at_ms: 1700,
            anchored_chain_head_hash: 'NOT_HEX',
          },
        ],
      }),
    ).toThrow();
  });
});

describe('EvidencePackClaim — defaults + registry', () => {
  it('EP15 arrays default to empty when omitted', () => {
    const parsed = EvidencePackClaim.parse({
      type: 'evidence_pack',
      pack_id: 'pck_minimal',
      content_hash: 'sha256:' + 'a'.repeat(64),
      scope: { kind: 'period', ref: 'period:2026-Q1' },
      time_bounds: { t0_ms: 1, t1_ms: 2 },
      claim_count: 0,
      merkle_root: 'sha256:' + 'b'.repeat(64),
      audit_chain_anchor: {
        head_hash: 'c'.repeat(64),
        head_signature: 's',
        head_at_ms: 1,
      },
      revocation_snapshot_at_ms: 1,
      schema_versions: {
        envelope: { version: 1, content_hash: 'sha256:' + 'd'.repeat(64) },
        by_claim_type: {},
      },
      canonical_schema_base_url: 'https://getstack.run/schemas/passport-claims/v1/',
      supersedes: null,
    });
    expect(parsed.cross_tenant_refs).toEqual([]);
    expect(parsed.external_chain_anchors).toEqual([]);
  });

  it('EP16 registered in PASSPORT_CLAIM_SCHEMAS', () => {
    expect(PASSPORT_CLAIM_SCHEMAS.evidence_pack).toBe(EvidencePackClaim);
  });
});

describe('EvidencePackClaim — sub-shape standalone parses', () => {
  it('EvidencePackScope', () => {
    const parsed = EvidencePackScope.parse({ kind: 'session', ref: 'ses_x' });
    expect(parsed.kind).toBe('session');
  });

  it('AuditChainAnchor', () => {
    const parsed = AuditChainAnchor.parse({
      head_hash: '0'.repeat(64),
      head_signature: 's',
      head_at_ms: 0,
    });
    expect(parsed.head_at_ms).toBe(0);
  });

  it('SchemaVersionEntry', () => {
    const parsed = SchemaVersionEntry.parse({
      version: 1,
      content_hash: 'sha256:' + 'a'.repeat(64),
    });
    expect(parsed.version).toBe(1);
  });

  it('PackSchemaVersions', () => {
    const parsed = PackSchemaVersions.parse({
      envelope: { version: 1, content_hash: 'sha256:' + 'a'.repeat(64) },
      by_claim_type: {
        mission: { version: 1, content_hash: 'sha256:' + 'b'.repeat(64) },
      },
    });
    expect(parsed.by_claim_type['mission']).toBeDefined();
  });

  it('CrossTenantRef', () => {
    const parsed = CrossTenantRef.parse({
      foreign_claim_hash: '0'.repeat(64),
      foreign_issuer_op_id: 'op_x',
      foreign_jwks_url: 'https://api.getstack.run/v1/operators/op_x/jwks.json',
      relation: 'skill_invocation',
    });
    expect(parsed.relation).toBe('skill_invocation');
  });

  it('ExternalChainAnchorRef', () => {
    const parsed = ExternalChainAnchorRef.parse({
      registry: 'github:example-org/anchors',
      permalink: 'https://github.com/example-org/anchors/blob/main/file.json',
      anchored_at_ms: 1,
      anchored_chain_head_hash: '0'.repeat(64),
    });
    expect(parsed.registry).toBe('github:example-org/anchors');
  });
});

const VALID_MANIFEST = {
  pack_version: 1 as const,
  claim: 'base64url_cose_bytes_for_the_signed_evidence_pack_claim',
  claims: [
    {
      claim_hash: '1'.repeat(64),
      envelope_cose: 'cose_bytes_for_claim_1',
      revoked_at_ms: null,
    },
  ],
  audit_chain_proofs: [
    {
      claim_hash: '1'.repeat(64),
      audit_position: 100,
      merkle_path: ['sha256:' + 'a'.repeat(64), 'sha256:' + 'b'.repeat(64)],
    },
  ],
  verification_material: {
    operator_jwks_url: 'https://api.getstack.run/v1/operators/op_abc/jwks.json',
    operator_jwks_inline: { keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'pub' }] },
    stack_system_jwks_url: 'https://api.getstack.run/v1/.well-known/jwks.json',
    stack_system_jwks_inline: { keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'pub' }] },
  },
  schemas_inline: {
    envelope: {
      $schema: 'http://json-schema.org/draft-07/schema#',
      content_hash: 'sha256:' + 'd'.repeat(64),
      json_schema: { type: 'object', properties: {} },
    },
  },
};

describe('EvidencePackManifest — parse positives + negatives', () => {
  it('MA1 minimal-valid manifest parses', () => {
    const parsed = EvidencePackManifest.parse(VALID_MANIFEST);
    expect(parsed.pack_version).toBe(1);
    expect(parsed.claims).toHaveLength(1);
    expect(parsed.audit_chain_proofs).toHaveLength(1);
  });

  it('MA2 rejects pack_version other than 1', () => {
    expect(() =>
      EvidencePackManifest.parse({ ...VALID_MANIFEST, pack_version: 2 }),
    ).toThrow();
  });

  it('MA3 rejects claims[i].claim_hash not 64 hex chars', () => {
    expect(() =>
      EvidencePackManifest.parse({
        ...VALID_MANIFEST,
        claims: [{ claim_hash: 'short', envelope_cose: 'bytes', revoked_at_ms: null }],
      }),
    ).toThrow();
  });

  it('MA4 rejects audit_chain_proofs merkle_path with non-canonical hash entry', () => {
    expect(() =>
      EvidencePackManifest.parse({
        ...VALID_MANIFEST,
        audit_chain_proofs: [
          {
            claim_hash: '1'.repeat(64),
            audit_position: 1,
            merkle_path: ['not_a_canonical_hash'],
          },
        ],
      }),
    ).toThrow();
  });

  it('MA5 requires all 4 verification_material fields', () => {
    expect(() =>
      EvidencePackManifest.parse({
        ...VALID_MANIFEST,
        verification_material: {
          operator_jwks_url: 'https://api.getstack.run/v1/operators/op_abc/jwks.json',
          operator_jwks_inline: { keys: [] },
          // missing stack_system_jwks_url + stack_system_jwks_inline
        },
      }),
    ).toThrow();
  });

  it('MA6 rejects schemas_inline[k].content_hash not sha256:<64 hex>', () => {
    expect(() =>
      EvidencePackManifest.parse({
        ...VALID_MANIFEST,
        schemas_inline: {
          envelope: {
            $schema: 'x',
            content_hash: 'wrong',
            json_schema: {},
          },
        },
      }),
    ).toThrow();
  });
});

describe('EvidencePackManifest — sub-shape standalone parses', () => {
  it('ManifestClaimEntry with revoked_at_ms set', () => {
    const parsed = ManifestClaimEntry.parse({
      claim_id: 'pc_claim_one',
      claim_hash: '1'.repeat(64),
      envelope_cose: 'bytes',
      revoked_at_ms: 5000,
    });
    expect(parsed.claim_id).toBe('pc_claim_one');
    expect(parsed.revoked_at_ms).toBe(5000);
  });

  it('ManifestClaimEntry keeps old manifests valid when claim_id is absent', () => {
    const parsed = ManifestClaimEntry.parse({
      claim_hash: '1'.repeat(64),
      envelope_cose: 'bytes',
      revoked_at_ms: null,
    });
    expect(parsed.claim_id).toBeUndefined();
  });

  it('ManifestClaimEntry rejects a malformed claim_id', () => {
    expect(() => ManifestClaimEntry.parse({
      claim_id: 'wrong',
      claim_hash: '1'.repeat(64),
      envelope_cose: 'bytes',
      revoked_at_ms: null,
    })).toThrow();
  });

  it('ManifestAuditChainProof with empty merkle_path', () => {
    const parsed = ManifestAuditChainProof.parse({
      claim_hash: '1'.repeat(64),
      audit_position: 0,
      merkle_path: [],
    });
    expect(parsed.merkle_path).toEqual([]);
  });

  it('ManifestInlineSchemaEntry', () => {
    const parsed = ManifestInlineSchemaEntry.parse({
      $schema: 'http://json-schema.org/draft-07/schema#',
      content_hash: 'sha256:' + 'd'.repeat(64),
      json_schema: {},
    });
    expect(parsed.$schema).toBe('http://json-schema.org/draft-07/schema#');
  });

  it('ManifestVerificationMaterial', () => {
    const parsed = ManifestVerificationMaterial.parse(VALID_MANIFEST.verification_material);
    expect(parsed.operator_jwks_inline.keys).toHaveLength(1);
  });

  it('InlineJwks with empty keys', () => {
    const parsed = InlineJwks.parse({ keys: [] });
    expect(parsed.keys).toEqual([]);
  });
});

describe('round-trip', () => {
  it('VALID_PACK fixture round-trips identically', () => {
    expect(EvidencePackClaim.parse(VALID_PACK)).toEqual(VALID_PACK);
  });
});
