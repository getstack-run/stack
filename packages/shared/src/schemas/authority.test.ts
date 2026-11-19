import { describe, expect, it } from 'vitest';
import { getTableConfig, PgDialect } from 'drizzle-orm/pg-core';
import { authorityBindings, authorityProofs } from '../db/schema/index.js';
import {
  AuthorityBindingStatus,
  AuthorityProofStatus,
  AddAuthorityReceiverKeyInput,
  AttachAuthorityProofInput,
  AuthorityDisclosureMode,
  AuthorityProofCallbackInput,
  AuthorityPresentationRequestInput,
  AuthorityReceiverPresentationPayload,
  AuthorityReference,
  CreateAuthorityApprovalRequestsInput,
  CreateAuthorityProofCollectionSessionInput,
  CreateAuthorityProfileVersionInput,
  CreateEnterpriseOidcAuthoritySetupInput,
  ProxyBridgeReceiverProfileV1,
} from './authority.js';
import { IssuePassportInput, PassportClaims } from './passport.js';

const digest = `sha256:${'a'.repeat(64)}`;
const authorityRef = {
  binding_id: 'abn_tax',
  binding_version: 1,
  binding_claim_id: 'pc_binding',
  binding_digest: digest,
  receiver_id: 'rcv_tax',
  receiver_profile_version_id: 'apv_tax_1',
  expires_at: 1_800_000_000,
};

describe('authority wire contract', () => {
  it('accepts only the exact seven-field PII-free Passport authority reference', () => {
    expect(AuthorityReference.parse(authorityRef)).toEqual(authorityRef);
    expect(() => AuthorityReference.parse({ ...authorityRef, principal_id: 'prn_subject' })).toThrow();
    expect(() => AuthorityReference.parse({ ...authorityRef, binding_digest: 'a'.repeat(64) })).toThrow();
    expect(() => AuthorityReference.parse({ ...authorityRef, receiver_profile_version_id: 'rpv_1' })).toThrow();
  });

  it('keeps Passport authority references plural and capped at eight', () => {
    const parsed = PassportClaims.parse({
      operator_id: 'op_test',
      agent_id: 'agt_test',
      agent_name: 'Tax agent',
      services: [],
      identity_claims: [],
      delegation_depth: 0,
      session_id: 'ses_test',
      authority_refs: [authorityRef],
    });
    expect(parsed.authority_refs).toEqual([authorityRef]);
    expect(() => PassportClaims.parse({
      operator_id: 'op_test',
      agent_id: 'agt_test',
      agent_name: 'Tax agent',
      services: [],
      identity_claims: [],
      delegation_depth: 0,
      session_id: 'ses_test',
      authority_refs: Array.from({ length: 9 }, () => authorityRef),
    })).toThrow();
  });

  it('keeps Passport issue binding selection plural and capped at eight', () => {
    expect(IssuePassportInput.parse({
      agent_id: 'agt_test',
      scopes: [],
      mission_ids: ['ms_test'],
      authority_binding_ids: ['abn_tax'],
    }).authority_binding_ids).toEqual(['abn_tax']);
    expect(() => IssuePassportInput.parse({
      agent_id: 'agt_test',
      scopes: [],
      mission_ids: ['ms_test'],
      authority_binding_ids: Array.from({ length: 9 }, (_, i) => `abn_${i}`),
    })).toThrow();
  });

  it('uses only the approved disclosure modes', () => {
    for (const mode of ['predicate', 'pairwise', 'exact_private', 'issuer_evidence', 'status_only']) {
      expect(AuthorityDisclosureMode.parse(mode)).toBe(mode);
    }
    expect(() => AuthorityDisclosureMode.parse('pairwise_identifier')).toThrow();
  });

  it('requires unified apv profile IDs and exact versioned profile configuration', () => {
    const profile = CreateAuthorityProfileVersionInput.parse({
      profile_kind: 'proof',
      profile_key: 'id-proof-like',
      version: 1,
      schema_uri: 'urn:example:proof',
      schema_version: '1',
      adapter_key: 'id-proof-like',
      adapter_version: 1,
      config_json: {
        proof_kind: 'identity',
        schema: { uri: 'urn:example:proof', version: '1' },
        adapter: { key: 'id-proof-like', version: 1 },
        accepted_native_formats: ['compact'],
        validation: {
          accepted_issuer_ids: ['issuer'],
          accepted_signature_algs: ['ES256'],
          signature_required: true,
          required_claim_paths: ['sub'],
          subject_binding: { method: 'signed-subject' },
          status_method: { method: 'adapter' },
        },
        assurance_mapping: {},
        freshness: { maximum_age_seconds: 300, live_status_required: true },
        disclosable_facts: [{
          fact_id: 'se.personal_number',
          native_path: 'personalNumber',
          allowed_modes: ['exact_private'],
        }],
      },
    });
    expect(profile.profile_kind).toBe('proof');
    if (profile.profile_kind !== 'proof') throw new Error('expected proof profile');
    expect(() => CreateAuthorityProfileVersionInput.parse({ ...profile, profile_kind: 'receiver', receiver_id: 'rpv_old' })).toThrow();
    expect(() => CreateAuthorityProfileVersionInput.parse({
      ...profile,
      config_json: {
        ...profile.config_json,
        validation: {
          ...profile.config_json.validation,
          status_method: { endpoint: 'https://unregistered.example/status' },
        },
      },
    })).toThrow();
    expect(() => CreateAuthorityProfileVersionInput.parse({
      ...profile,
      config_json: {
        ...profile.config_json,
        assurance_mapping: { script: 'return true' },
      },
    })).toThrow();
  });

  it('rejects symmetric or private receiver JWK material', () => {
    const base = {
      key_id: 'request-1',
      use: 'request_signing' as const,
      algorithm: 'EdDSA' as const,
      public_jwk: { kty: 'OKP', crv: 'Ed25519', x: 'public' },
      valid_from: '2026-08-21T00:00:00.000Z',
    };
    expect(AddAuthorityReceiverKeyInput.parse(base).public_jwk.kty).toBe('OKP');
    expect(() => AddAuthorityReceiverKeyInput.parse({ ...base, public_jwk: { ...base.public_jwk, d: 'private' } })).toThrow();
    expect(() => AddAuthorityReceiverKeyInput.parse({ ...base, public_jwk: { kty: 'oct', k: 'secret' } })).toThrow();
  });

  it('keeps proxy-bridge receivers inside STACK without invented receiver keys or delivery endpoints', () => {
    const profile = {
      receiver_id: 'rcv_stripe',
      protocol: { key: 'stack.proxy_bridge', version: '1' },
      audience: 'stack:service-connection:scon_stripe',
      service_connection_id: 'scon_stripe',
      approval_policy: { version: '1', groups: [] },
      live_status_required: true,
    };
    expect(ProxyBridgeReceiverProfileV1.parse(profile)).toEqual(profile);
    expect(() => ProxyBridgeReceiverProfileV1.parse({
      ...profile,
      delivery: { endpoint: 'https://invented.example/authority' },
    })).toThrow();
    expect(() => ProxyBridgeReceiverProfileV1.parse({
      ...profile,
      receiver_keys: [{ kid: 'invented' }],
    })).toThrow();
  });

  it('accepts only safe OIDC role claim paths and a setup expiry within one hour', () => {
    const input = {
      organisation_name: 'Example AB',
      role_name: 'CFO',
      role_claim_path: 'roles.finance',
      role_claim_value: 'cfo',
      agent_id: 'agt_finance',
      mission_id: 'ms_month_end',
      service_connection_id: 'scon_stripe',
      provider: 'stripe',
      purpose: 'Refund duplicate customer charges',
      http_method: 'POST' as const,
      resource_path: '/v1/refunds',
      constraints: [],
      expires_at: new Date(Date.now() + 30 * 60 * 1000),
    };
    expect(CreateEnterpriseOidcAuthoritySetupInput.parse(input).role_claim_path).toBe('roles.finance');
    expect(() => CreateEnterpriseOidcAuthoritySetupInput.parse({
      ...input,
      role_claim_path: '__proto__.role',
    })).toThrow();
    expect(() => CreateEnterpriseOidcAuthoritySetupInput.parse({
      ...input,
      role_claim_path: 'roles[0]',
    })).toThrow();
    expect(() => CreateEnterpriseOidcAuthoritySetupInput.parse({
      ...input,
      expires_at: new Date(Date.now() + 61 * 60 * 1000),
    })).toThrow();
  });

  it('keeps proof collection inputs profile-driven and strict', () => {
    const input = {
      subject_principal_id: 'prn_subject',
      represented_principal_id: 'prn_company',
      profile_version_id: 'apv_bankid_1',
      issuer_identifier: 'id-proof-like-issuer',
      native_format: 'compact-jws',
    };
    expect(CreateAuthorityProofCollectionSessionInput.parse(input)).toEqual(input);
    expect(() => CreateAuthorityProofCollectionSessionInput.parse({
      ...input,
      assurance_level: 'verified-by-caller',
    })).toThrow();
    expect(() => CreateAuthorityProofCollectionSessionInput.parse({
      ...input,
      return_uri: 'https://attacker.example/callback',
    })).toThrow();
  });

  it('keeps imported proof validity and verification facts adapter-derived', () => {
    const input = {
      subject_principal_id: 'prn_subject',
      profile_version_id: 'apv_bankid_1',
      proof_kind: 'identity',
      issuer_identifier: 'id-proof-like-issuer',
      schema_uri: 'urn:example:identity',
      schema_version: '1',
      native_format: 'compact-jws',
      native_evidence: 'provider-native-signed-result',
    };
    expect(AttachAuthorityProofInput.parse(input)).toEqual(input);
    for (const callerFact of [
      { valid_from: '2026-01-01T00:00:00.000Z' },
      { expires_at: '2099-01-01T00:00:00.000Z' },
      { verified_at: '2026-01-01T00:00:00.000Z' },
      { assurance_uri: 'caller:declared' },
      { normalized_facts: { personal_number: '19700101-1234' } },
    ]) {
      expect(() => AttachAuthorityProofInput.parse({ ...input, ...callerFact })).toThrow();
    }
  });

  it('accepts only the write-only, one-session proof callback envelope', () => {
    const callback = {
      session_id: 'pcs_one',
      state_token: 'abcdefghijklmnopqrstuv',
      signed_callback: 'provider-native-signed-result',
    };
    expect(AuthorityProofCallbackInput.parse(callback)).toEqual(callback);
    expect(() => AuthorityProofCallbackInput.parse({
      ...callback,
      issuer_identifier: 'caller-selected-issuer',
    })).toThrow();
  });

  it('does not let approval-request callers choose hashes, slots, proofs or weights', () => {
    expect(CreateAuthorityApprovalRequestsInput.parse({ phase: 'activation' })).toEqual({
      phase: 'activation',
    });
    expect(CreateAuthorityApprovalRequestsInput.parse({
      phase: 'action',
      authority_use_id: 'aus_one',
    })).toEqual({ phase: 'action', authority_use_id: 'aus_one' });
    expect(() => CreateAuthorityApprovalRequestsInput.parse({
      phase: 'activation',
      authority_use_id: 'aus_one',
    })).toThrow();
    expect(() => CreateAuthorityApprovalRequestsInput.parse({
      phase: 'presentation',
      authority_use_id: 'aus_one',
      request_hash: digest,
      authoriser_principal_id: 'prn_subject',
      weight: 100,
    })).toThrow();
  });

  it('requires a signed one-time presentation request with a 120-second maximum window', () => {
    const base = {
      signed_request: 'a.b.c',
      agent_proof: 'd.e.f',
      passport: 'passport.jwt.value',
      authority_ref: authorityRef,
      receiver_profile_version_id: 'apv_tax_1',
      receiver_request_id: 'abcdefghijklmnopqrstuv',
      mission_id: 'ms_tax',
      action_uri: 'tax_return.submit',
      resource_hash: digest,
      request_hash: digest,
      normalized_request: { year: 2026, form: 'annual' },
      requested_facts: [{ fact_id: 'se.personal_number', mode: 'exact_private' }],
      nonce: 'abcdefghijklmnopqrstuv',
      issued_at: 1_700_000_000,
      expires_at: 1_700_000_120,
    };
    expect(AuthorityPresentationRequestInput.parse(base).expires_at).toBe(base.expires_at);
    expect(() => AuthorityPresentationRequestInput.parse({ ...base, agent_proof: undefined })).toThrow();
    expect(() => AuthorityPresentationRequestInput.parse({ ...base, expires_at: base.issued_at + 121 })).toThrow();
    expect(() => AuthorityPresentationRequestInput.parse({ ...base, nonce: 'too-short' })).toThrow();
  });

  it('keeps all five disclosure modes strict and mode-specific', () => {
    const base = {
      iss: 'https://getstack.run' as const,
      aud: 'https://receiver.example',
      jti: 'pjt_modes',
      iat: 1_700_000_000,
      exp: 1_700_000_060,
      authority_use_id: 'aus_modes',
      agent_id: 'agt_modes',
      agent_key_thumbprint: digest,
      binding_ref: authorityRef,
      principal_ref: 'prn_person',
      mission_id: 'ms_tax',
      action_uri: 'tax_return.submit',
      resource_hash: digest,
      request_hash: digest,
      receiver_id: 'rcv_tax',
      receiver_profile_version_id: 'apv_tax_1',
      domain_profile_version_id: 'apv_domain_1',
      proof_profile_version_ids: ['apv_proof_1'],
      live_check_time: 1_700_000_000,
      evidence_refs: [{
        proof_id: 'prf_identity',
        proof_version: 1,
        role: 'principal_identity' as const,
        authoriser_principal_id: null,
        group_key_hash: digest,
        profile_version_id: 'apv_proof_1',
        issuer_identifier: 'issuer.example',
        schema_uri: 'urn:example:identity',
        schema_version: '1',
        assurance_uri: null,
        evidence_digest: digest,
        evidence_modes: ['predicate', 'pairwise', 'exact_private', 'issuer_evidence', 'status_only'] as const,
        status: 'valid' as const,
      }],
      approval_claim_refs: [],
      approval_requirements: [],
      proof_strength: 'native_issuer_evidence' as const,
      nonce: 'abcdefghijklmnopqrstuv',
    };
    const provenance = { profile_version_id: 'apv_proof_1' };
    const facts = [
      { fact_id: 'age_over_18', mode: 'predicate', proof_id: 'prf_identity', value: true, evidence_digest: digest,
        assertion_source: 'adapter_derived', proof_strength: 'native_stack_attestation', provenance },
      { fact_id: 'receiver_subject', mode: 'pairwise', proof_id: 'prf_identity', value: `hmac-sha256:${'a'.repeat(43)}`, evidence_digest: digest,
        assertion_source: 'stack_derived', proof_strength: 'native_stack_attestation',
        provenance: { profile_version_id: 'apv_proof_1', method: 'stack.core.hmac-sha256/v1' } },
      { fact_id: 'personal_number', mode: 'exact_private', proof_id: 'prf_identity', value: 'receiver-only',
        assertion_source: 'stack_derived', proof_strength: 'native_stack_attestation', provenance },
      { fact_id: 'issuer_credential', mode: 'issuer_evidence', proof_id: 'prf_identity', value: 'issuer-evidence', evidence_digest: digest,
        assertion_source: 'issuer_native', proof_strength: 'native_issuer_evidence', provenance },
      { fact_id: 'identity_status', mode: 'status_only', proof_id: 'prf_identity', status: 'valid',
        assertion_source: 'stack_derived', proof_strength: 'native_stack_attestation', provenance },
    ] as const;

    for (const disclosedFact of facts) {
      expect(AuthorityReceiverPresentationPayload.parse({
        ...base,
        disclosed_facts: [disclosedFact],
      }).disclosed_facts).toEqual([disclosedFact]);
    }
    expect(() => AuthorityReceiverPresentationPayload.parse({
      ...base,
      disclosed_facts: [{ ...facts[2], evidence_digest: digest }],
    })).toThrow();
    expect(() => AuthorityReceiverPresentationPayload.parse({
      ...base,
      disclosed_facts: [{ ...facts[4], value: 'leak' }],
    })).toThrow();
    expect(() => AuthorityReceiverPresentationPayload.parse({
      ...base,
      disclosed_facts: [{ ...facts[0], value: '199001011234' }],
    })).toThrow();
    expect(() => AuthorityReceiverPresentationPayload.parse({
      ...base,
      disclosed_facts: [{ ...facts[1], value: '199001011234' }],
    })).toThrow();
  });
});

/** The values a table's `<table>_status_check` constraint allows, read from the live Drizzle definition. */
function statusCheckValues(table: Parameters<typeof getTableConfig>[0], constraintName: string): string[] {
  const check = getTableConfig(table).checks.find((c) => c.name === constraintName);
  if (!check) throw new Error(`check ${constraintName} not found`);
  const { sql } = new PgDialect().sqlToQuery(check.value);
  const list = /in \(([^)]*)\)/.exec(sql);
  if (!list) throw new Error(`no IN list in ${constraintName}: ${sql}`);
  return [...list[1]!.matchAll(/'([^']+)'/g)].map((m) => m[1]!);
}

describe('authority status enums', () => {
  it('lists each proof status once', () => {
    const options: readonly string[] = AuthorityProofStatus.options;
    expect(new Set(options).size).toBe(options.length);
  });

  it('accepts every proof status the database can hold, and nothing else', () => {
    const dbValues = statusCheckValues(authorityProofs, 'authority_proofs_status_check');
    expect([...AuthorityProofStatus.options].sort()).toEqual([...dbValues].sort());
  });

  it('accepts every binding status the database can hold, and nothing else', () => {
    const dbValues = statusCheckValues(authorityBindings, 'authority_bindings_status_check');
    expect([...AuthorityBindingStatus.options].sort()).toEqual([...dbValues].sort());
    expect(AuthorityBindingStatus.parse('erased')).toBe('erased');
  });
});
