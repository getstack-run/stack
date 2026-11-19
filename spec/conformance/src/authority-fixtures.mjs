// The fixed world the authority receiver suite plays in: one receiver, the keys
// of both sides, and builders for the artefacts of the protocol. Everything
// here follows spec/authority-receiver/SPEC.md and nothing else; the keys come
// from fixed seeds, are for these fixtures only and protect nothing.

import { randomBytes } from 'node:crypto';
import { canonicalize } from './canonical.mjs';
import { b64u, digest, ed25519FromSeed, encryptJwe, p256FromSeed, signJws } from './authority-jose.mjs';

export const FIXTURE = Object.freeze({
  /** The origin of the STACK API, as a receiver learns it at registration: the audience of every call. */
  stackOrigin: 'https://api.stack-conformance.test',
  /** `iss` of a presentation. */
  presentationIssuer: 'https://stack-conformance.test',
  receiverId: 'rcv_conformance',
  receiverProfileVersionId: 'apv_conformance_receiver',
  /** `aud` of a presentation: the profile's audience. */
  audience: 'urn:conformance:receiver',
  /** The nonce the receiver under test is told to expect in its delivery checks. */
  nonce: 'conformance-nonce-000000000001',
  receiverRequestId: 'conformance-request-id-0000001',
  actionUri: 'urn:conformance:action:file-return',
  stackKid: 'stack-presentation-1',
  startedAt: 1_790_000_000,
});

/** Every key in the fixed world. */
export function fixtureKeys() {
  return {
    request: ed25519FromSeed(0x41, 'rcv-request-1'),
    requestEs: p256FromSeed(0x47, 'rcv-request-es-1', 'ES256'),
    receipt: ed25519FromSeed(0x42, 'rcv-receipt-1'),
    encryption: p256FromSeed(0x43, 'rcv-enc-1', 'ECDH-ES+A256KW'),
    stack: ed25519FromSeed(0x44, FIXTURE.stackKid),
    /** The same kid as the STACK key and a different key: what an attacker who guesses the kid holds. */
    impostor: ed25519FromSeed(0x45, FIXTURE.stackKid),
    /** A recipient key that is not the receiver's. */
    otherRecipient: p256FromSeed(0x46, 'rcv-enc-1', 'ECDH-ES+A256KW'),
  };
}

export const randomId = (prefix) => `${prefix}_${randomBytes(12).toString('base64url')}`;
export const randomToken = () => randomBytes(18).toString('base64url');

/** `sha256(canonical({ receiver_request_id, normalized_request }))`. */
export const requestHashOf = (receiverRequestId, normalizedRequest) => digest(canonicalize({ receiver_request_id: receiverRequestId, normalized_request: normalizedRequest }));
/** `sha256(canonical({ receiver_request_id, resource_ref }))`. */
export const resourceHashOf = (receiverRequestId, resourceRef) => digest(canonicalize({ receiver_request_id: receiverRequestId, resource_ref: resourceRef }));

export const NORMALIZED_REQUEST = Object.freeze({ resource_type: 'tax_return', resource_ref: 'tax-return:2026', filing_year: 2026 });

/** The request fields the receiver signs into the presentation request and sends in the body. */
export function presentationRequestFields(now, over = {}) {
  const receiverRequestId = over.receiver_request_id ?? FIXTURE.receiverRequestId;
  const normalizedRequest = over.normalized_request ?? NORMALIZED_REQUEST;
  return {
    authority_ref: {
      binding_id: 'abn_conformance', binding_version: 1, binding_claim_id: 'pc_conformance', binding_digest: digest('binding'),
      receiver_id: FIXTURE.receiverId, receiver_profile_version_id: FIXTURE.receiverProfileVersionId, expires_at: now + 3600,
    },
    receiver_profile_version_id: FIXTURE.receiverProfileVersionId,
    receiver_request_id: receiverRequestId,
    mission_id: 'ms_conformance',
    action_uri: FIXTURE.actionUri,
    resource_hash: resourceHashOf(receiverRequestId, normalizedRequest.resource_ref),
    request_hash: requestHashOf(receiverRequestId, normalizedRequest),
    normalized_request: normalizedRequest,
    requested_facts: [{ fact_id: 'person.over_18', mode: 'predicate' }],
    nonce: FIXTURE.nonce,
    issued_at: now,
    expires_at: now + 60,
    passport: signJwtLike({ sub: 'agt_conformance' }),
    agent_proof: signJwtLike({ iss: 'agt_conformance' }),
    ...over,
  };
}

/** A string shaped like a compact JWS, standing in for a Passport or an agent proof the receiver only carries along. */
function signJwtLike(payload) {
  return `${b64u(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' }))}.${b64u(JSON.stringify(payload))}.${b64u(Buffer.alloc(64, 7))}`;
}

/** The plaintext STACK signs and encrypts to the receiver. */
export function presentationPayload(now, over = {}) {
  return {
    iss: FIXTURE.presentationIssuer,
    aud: FIXTURE.audience,
    jti: randomId('pjt'),
    iat: now,
    exp: now + 60,
    authority_use_id: 'aus_conformance',
    agent_id: 'agt_conformance',
    agent_key_thumbprint: digest('agent key'),
    binding_ref: {
      binding_id: 'abn_conformance', binding_version: 1, binding_claim_id: 'pc_conformance', binding_digest: digest('binding'),
      receiver_id: FIXTURE.receiverId, receiver_profile_version_id: FIXTURE.receiverProfileVersionId, expires_at: now + 3600,
    },
    principal_ref: 'prn_conformance',
    mission_id: 'ms_conformance',
    action_uri: FIXTURE.actionUri,
    resource_hash: resourceHashOf(FIXTURE.receiverRequestId, NORMALIZED_REQUEST.resource_ref),
    request_hash: requestHashOf(FIXTURE.receiverRequestId, NORMALIZED_REQUEST),
    receiver_id: FIXTURE.receiverId,
    receiver_profile_version_id: FIXTURE.receiverProfileVersionId,
    domain_profile_version_id: 'apv_conformance_domain',
    proof_profile_version_ids: ['apv_conformance_proof'],
    live_check_time: now,
    evidence_refs: [{
      proof_id: 'prf_conformance', proof_version: 1, role: 'principal_identity', authoriser_principal_id: null,
      group_key_hash: digest('identity'), profile_version_id: 'apv_conformance_proof', issuer_identifier: 'urn:conformance:issuer',
      schema_uri: 'urn:conformance:schema', schema_version: '1', assurance_uri: null, evidence_digest: digest('evidence'),
      evidence_modes: ['predicate'], status: 'active',
    }],
    approval_claim_refs: [],
    approval_requirements: [],
    proof_strength: 'native_stack_attestation',
    nonce: FIXTURE.nonce,
    disclosed_facts: [{
      fact_id: 'person.over_18', mode: 'predicate', proof_id: 'prf_conformance', assertion_source: 'adapter_derived',
      proof_strength: 'native_stack_attestation', provenance: { adapter_key: 'conformance', adapter_version: 1, method: 'conformance' },
      value: true, evidence_digest: digest('evidence'),
    }],
    ...over,
  };
}

/** Sign a presentation payload as STACK does: compact JWS, EdDSA, `typ` JWT. */
export function signPresentation(payload, key = fixtureKeys().stack, headerOver = {}) {
  return signJws({ alg: 'EdDSA', kid: key.kid, typ: 'JWT', ...headerOver }, payload, key.privateKey, 'EdDSA');
}

/** Encrypt a compact JWS to the receiver's encryption key as STACK does. */
export function encryptPresentation(compactJws, recipient = fixtureKeys().encryption, options = {}) {
  return encryptJwe({ plaintext: compactJws, recipientPublicJwk: recipient.publicJwk, kid: recipient.kid, ...options });
}
