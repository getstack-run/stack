import { describe, it, expect } from 'vitest';
import {
  PASSPORT_CLAIM_SCHEMAS,
  RatsEvidenceClaim,
  SlsaProvenanceClaim,
  AiBomRefClaim,
  C2paAssertionClaim,
} from './index.js';

/**
 * Smoke + happy-path coverage for the four chunk C claim
 * schemas. The schemas are pure shape validators; the goal here is
 * to lock the wire shape so a future breaking change fails CI
 * loudly, and to assert each one is registered in
 * PASSPORT_CLAIM_SCHEMAS so ClaimRegistryService.registerClaim() can
 * dispatch by claim_type.
 */

describe('RatsEvidenceClaim', () => {
  const valid = {
    type: 'rats_evidence' as const,
    evidence_format: 'aws-nitro-enclave' as const,
    measurements: { PCR0: 'a'.repeat(96), PCR8: 'b'.repeat(96) },
    pubkey_jwk: { kty: 'EC', crv: 'P-384', x: 'AAA', y: 'BBB' },
    nonce: 'n-1234567890',
    evidence_uri: 'https://attest.example.com/nitro/12345',
    evidence_sha256: 'a'.repeat(64),
    attested_at: 1_726_000_000,
  };

  it('accepts a full valid payload', () => {
    expect(() => RatsEvidenceClaim.parse(valid)).not.toThrow();
  });

  it('accepts minimum required fields only', () => {
    const minimal = {
      type: 'rats_evidence' as const,
      evidence_format: 'generic-eat' as const,
      measurements: { configuration_state: 'baseline' },
      attested_at: 1_726_000_000,
    };
    expect(() => RatsEvidenceClaim.parse(minimal)).not.toThrow();
  });

  it('rejects empty measurements', () => {
    expect(() => RatsEvidenceClaim.parse({ ...valid, measurements: {} })).toThrow();
  });

  it('rejects malformed evidence_sha256', () => {
    expect(() => RatsEvidenceClaim.parse({ ...valid, evidence_sha256: 'not-hex' })).toThrow();
  });

  it('rejects unknown evidence_format', () => {
    expect(() =>
      RatsEvidenceClaim.parse({ ...valid, evidence_format: 'made-up-tee' as never }),
    ).toThrow();
  });

  it('is registered in PASSPORT_CLAIM_SCHEMAS', () => {
    expect(PASSPORT_CLAIM_SCHEMAS.rats_evidence).toBe(RatsEvidenceClaim);
  });
});

describe('SlsaProvenanceClaim', () => {
  const valid = {
    type: 'slsa_provenance' as const,
    predicate_type: 'https://slsa.dev/provenance/v1' as const,
    build_type: 'https://github.com/actions/runner/github-hosted@v1',
    builder: {
      id: 'https://github.com/actions/runner',
      version: { 'github-hosted': 'v1' },
    },
    invocation: {
      config_source: {
        uri: 'git+https://github.com/example/repo@refs/heads/main',
        digest: { sha1: 'abcdef0123456789' },
        entry_point: '.github/workflows/engine-images.yml',
      },
    },
    subject_digest: { sha256: 'c'.repeat(64) },
    slsa_level: 3,
    attested_at: 1_726_000_000,
  };

  it('accepts a full valid payload', () => {
    expect(() => SlsaProvenanceClaim.parse(valid)).not.toThrow();
  });

  it('accepts minimum required fields', () => {
    const minimal = {
      type: 'slsa_provenance' as const,
      predicate_type: 'https://slsa.dev/provenance/v1' as const,
      build_type: 'https://example.com/build/manual',
      builder: { id: 'https://example.com/builder/manual' },
      subject_digest: { sha256: 'd'.repeat(64) },
      attested_at: 1_726_000_000,
    };
    expect(() => SlsaProvenanceClaim.parse(minimal)).not.toThrow();
  });

  it('rejects wrong predicate_type', () => {
    expect(() =>
      SlsaProvenanceClaim.parse({ ...valid, predicate_type: 'https://slsa.dev/provenance/v0.2' }),
    ).toThrow();
  });

  it('rejects empty subject_digest', () => {
    expect(() => SlsaProvenanceClaim.parse({ ...valid, subject_digest: {} })).toThrow();
  });

  it('rejects slsa_level outside 0-4', () => {
    expect(() => SlsaProvenanceClaim.parse({ ...valid, slsa_level: 5 })).toThrow();
    expect(() => SlsaProvenanceClaim.parse({ ...valid, slsa_level: -1 })).toThrow();
  });

  it('is registered in PASSPORT_CLAIM_SCHEMAS', () => {
    expect(PASSPORT_CLAIM_SCHEMAS.slsa_provenance).toBe(SlsaProvenanceClaim);
  });
});

describe('AiBomRefClaim', () => {
  const valid = {
    type: 'ai_bom_ref' as const,
    bom_format: 'CycloneDX' as const,
    spec_version: '1.6',
    bom_uri: 'https://operator.example.com/boms/agent-42.cdx.json',
    bom_sha256: 'e'.repeat(64),
    models: [
      { name: 'gpt-4o', version: '2024-08-06', source: 'https://openai.com', license: 'proprietary' },
    ],
    training_data_summary: 'Proprietary OpenAI training corpus.',
    attested_at: 1_726_000_000,
  };

  it('accepts a full valid payload', () => {
    expect(() => AiBomRefClaim.parse(valid)).not.toThrow();
  });

  it('accepts minimum required fields', () => {
    const minimal = {
      type: 'ai_bom_ref' as const,
      bom_format: 'CycloneDX' as const,
      spec_version: '1.6',
      bom_uri: 'https://example.com/bom.json',
      bom_sha256: 'f'.repeat(64),
      attested_at: 1_726_000_000,
    };
    expect(() => AiBomRefClaim.parse(minimal)).not.toThrow();
  });

  it('rejects malformed bom_sha256', () => {
    expect(() => AiBomRefClaim.parse({ ...valid, bom_sha256: 'short' })).toThrow();
  });

  it('rejects non-CycloneDX bom_format', () => {
    expect(() => AiBomRefClaim.parse({ ...valid, bom_format: 'SPDX' as never })).toThrow();
  });

  it('is registered in PASSPORT_CLAIM_SCHEMAS', () => {
    expect(PASSPORT_CLAIM_SCHEMAS.ai_bom_ref).toBe(AiBomRefClaim);
  });
});

describe('C2paAssertionClaim', () => {
  const valid = {
    type: 'c2pa_assertion' as const,
    manifest_uri: 'https://content.example.com/img/12345.c2pa.json',
    manifest_sha256: '1'.repeat(64),
    claim_generator: 'STACK Proxy/0.5 (c2pa/0.42)',
    signature_info: {
      issuer: 'CN=STACK Content Signer, O=getstack.run',
      cert_thumbprint: '2'.repeat(40),
      signature_alg: 'EdDSA',
    },
    content_digest: { sha256: '3'.repeat(64) },
    content_type: 'image/png',
    attested_at: 1_726_000_000,
  };

  it('accepts a full valid payload', () => {
    expect(() => C2paAssertionClaim.parse(valid)).not.toThrow();
  });

  it('accepts minimum required fields', () => {
    const minimal = {
      type: 'c2pa_assertion' as const,
      content_digest: { sha256: '4'.repeat(64) },
      attested_at: 1_726_000_000,
    };
    expect(() => C2paAssertionClaim.parse(minimal)).not.toThrow();
  });

  it('rejects empty content_digest', () => {
    expect(() => C2paAssertionClaim.parse({ ...valid, content_digest: {} })).toThrow();
  });

  it('rejects malformed cert_thumbprint', () => {
    expect(() =>
      C2paAssertionClaim.parse({ ...valid, signature_info: { cert_thumbprint: 'nope' } }),
    ).toThrow();
  });

  it('is registered in PASSPORT_CLAIM_SCHEMAS', () => {
    expect(PASSPORT_CLAIM_SCHEMAS.c2pa_assertion).toBe(C2paAssertionClaim);
  });
});
