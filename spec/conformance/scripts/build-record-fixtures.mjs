#!/usr/bin/env node
// Builds the record-verifier fixtures in fixtures/record/: one pack that
// verifies and a set of tampered variants, each with the outcome a conforming
// verifier must report (spec/record/SPEC.md, sections 8 and 10).
//
// The packs are built independently of any STACK package, from the
// specification alone: node:crypto for Ed25519 and SHA-256, cbor-x for CBOR.
// Keys come from fixed seeds and every timestamp is fixed, and Ed25519 and
// this CBOR encoding are deterministic, so running the script twice writes the
// same bytes. `--check` fails if the files on disk differ from a fresh build.
//
// The keys are for these fixtures only and protect nothing.

import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { encode as cborEncode } from 'cbor-x';
import { canonicalize } from '../src/canonical.mjs';
import { merkleRoot } from '../src/merkle.mjs';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'record');
const sha256Hex = (data) => createHash('sha256').update(data).digest('hex');

const COSE_ALG = 1;
const COSE_KID = 4;
const COSE_TYP = 16;
const EDDSA = -8;
const TYP = 'stack/claim+cose';

function keyFromSeed(seed, kid) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seed)]);
  const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const jwk = { ...createPublicKey(privateKey).export({ format: 'jwk' }), kid };
  return { kid, privateKey, jwk };
}

const OPERATOR = keyFromSeed(0xa1, 'op_conformance:claim:v1');
const SYSTEM = keyFromSeed(0xb2, 'stack-system:v1');
const STRANGER = keyFromSeed(0xc3, 'op_conformance:claim:v1'); // same kid as OPERATOR, a different key

function coseSign1(envelope, key) {
  const payload = cborEncode(envelope);
  const protectedBytes = cborEncode(new Map([[COSE_ALG, EDDSA], [COSE_KID, Buffer.from(key.kid, 'utf8')], [COSE_TYP, TYP]]));
  const toBeSigned = cborEncode(['Signature1', protectedBytes, Buffer.alloc(0), payload]);
  const signature = sign(null, toBeSigned, key.privateKey);
  return Buffer.from(cborEncode([protectedBytes, new Map(), payload, signature])).toString('base64url');
}

function envelope(claimType, payload) {
  return {
    envelope_version: 1,
    issuer: 'op_conformance',
    subject: 'stack://operator/op_conformance',
    issued_at: 1_700_000_000_000,
    claim_type: claimType,
    claim_version: 1,
    payload,
    receipt: null,
    co_signatures: [],
  };
}

const schemaStub = (key) => {
  const stub = { type: 'object', $id: key };
  return { $schema: 'http://json-schema.org/draft-07/schema#', content_hash: `sha256:${sha256Hex(canonicalize(stub))}`, json_schema: stub };
};

/** One pack. `mutate` hooks let a variant damage exactly one thing. */
function buildPack(spec = {}) {
  const {
    claims = [],                // [{ claim_id, type, payload, signer }]
    inlineSchemas = ['envelope'],
    packSigner = OPERATOR,
    cosigner = SYSTEM,          // null for no co-signature
    anchorSigner = OPERATOR,
    packOver = {},              // fields of the pack claim to override after computing
    packVersion = 1,
    packPayloadType = 'evidence_pack',
    pinOver = {},
    manifestOver = {},          // applied to the finished manifest (after signing)
  } = spec;

  const entries = claims.map((c) => {
    const cose = coseSign1(envelope(c.type, c.payload), c.signer ?? OPERATOR);
    return { ...(c.claim_id ? { claim_id: c.claim_id } : {}), claim_hash: sha256Hex(Buffer.from(cose, 'base64url')), envelope_cose: cose, revoked_at_ms: null };
  });

  const schemas = Object.fromEntries(inlineSchemas.map((k) => [k, schemaStub(k)]));
  const pins = { ...Object.fromEntries(Object.entries(schemas).map(([k, v]) => [k, v.content_hash])), ...pinOver };
  const { envelope: envelopePin, ...byType } = pins;

  const headHash = 'a'.repeat(64);
  const headAt = 1_700_000_001_000;
  const headSignature = sign(null, Buffer.from(canonicalize({ head_hash: headHash, head_at_ms: headAt })), anchorSigner.privateKey).toString('base64url');

  const skeleton = {
    pack_version: 1,
    claims: entries,
    audit_chain_proofs: entries.map((e) => ({ claim_hash: e.claim_hash, audit_position: 0, merkle_path: [] })),
    verification_material: {
      operator_jwks_url: 'https://api.getstack.run/v1/operators/op_conformance/jwks.json',
      operator_jwks_inline: { keys: [OPERATOR.jwk] },
      stack_system_jwks_url: 'https://api.getstack.run/v1/.well-known/jwks.json',
      stack_system_jwks_inline: { keys: [SYSTEM.jwk] },
    },
    schemas_inline: schemas,
  };
  const contentHash = `sha256:${sha256Hex(canonicalize(skeleton))}`;

  const pack = {
    type: packPayloadType,
    pack_id: 'pck_conformance',
    content_hash: contentHash,
    scope: { kind: 'mission', ref: 'ms_conformance' },
    time_bounds: { t0_ms: 1_700_000_000_000, t1_ms: 1_700_000_001_000 },
    claim_count: entries.length,
    included_review_claim_ids: [],
    merkle_root: merkleRoot(entries.map((e) => e.claim_hash)),
    audit_chain_anchor: { head_hash: headHash, head_signature: headSignature, head_at_ms: headAt },
    revocation_snapshot_at_ms: 1_700_000_000_500,
    schema_versions: {
      envelope: { version: 1, content_hash: envelopePin ?? `sha256:${'d'.repeat(64)}` },
      by_claim_type: Object.fromEntries(Object.entries(byType).map(([k, hash]) => [k, { version: 1, content_hash: hash }])),
    },
    canonical_schema_base_url: 'https://getstack.run/schemas/passport-claims/v1/',
    supersedes: null,
    cross_tenant_refs: [],
    external_chain_anchors: [],
    ...packOver,
  };

  const packEnvelope = envelope(packPayloadType === 'evidence_pack' ? 'evidence_pack' : packPayloadType, pack);
  const claim = coseSign1(packEnvelope, packSigner);
  const coSignatures = cosigner
    ? [{ signer_kid: cosigner.kid, signer_role: 'operator_attestation', cose_sign1: coseSign1(packEnvelope, cosigner) }]
    : [];

  return {
    pack_version: packVersion,
    claim,
    co_signatures: coSignatures,
    claims: skeleton.claims,
    audit_chain_proofs: skeleton.audit_chain_proofs,
    verification_material: skeleton.verification_material,
    schemas_inline: skeleton.schemas_inline,
    ...manifestOver,
  };
}

const intent = (n) => ({ type: 'intent_claim', value: n });
const TWO = [
  { claim_id: 'pc_conformance_1', type: 'intent_claim', payload: intent(1) },
  { claim_id: 'pc_conformance_2', type: 'intent_claim', payload: intent(2) },
];
const WITH_SCHEMA = ['envelope', 'intent_claim'];

// name, level, options, description, the manifest, the error codes a conforming verifier reports.
const FIXTURES = [
  ['01-valid-empty', 1, {}, 'a pack with no claims verifies', buildPack(), []],
  ['02-valid-two-claims', 1, {}, 'a pack with two signed claims and a system co-signature verifies', buildPack({ claims: TWO, inlineSchemas: WITH_SCHEMA }), []],
  ['03-valid-no-cosignature', 1, {}, 'a pack without a co-signature is valid (a warning, not an error)', buildPack({ claims: TWO, inlineSchemas: WITH_SCHEMA, cosigner: null }), []],
  [
    '04-content-hash-mismatch', 1, {}, 'a manifest member covered by the content hash was changed after signing',
    (() => {
      const pack = buildPack({ claims: TWO, inlineSchemas: WITH_SCHEMA });
      pack.verification_material = { ...pack.verification_material, operator_jwks_url: 'https://elsewhere.example/jwks.json' };
      return pack;
    })(),
    ['CONTENT_HASH_MISMATCH'],
  ],
  ['05-merkle-root-mismatch', 1, {}, 'the signed merkle_root is not the root of the claim hashes', buildPack({ claims: TWO, inlineSchemas: WITH_SCHEMA, packOver: { merkle_root: `sha256:${'e'.repeat(64)}` } }), ['MERKLE_ROOT_MISMATCH']],
  ['06-claim-count-mismatch', 1, {}, 'the signed claim_count is not the number of claims', buildPack({ claims: TWO, inlineSchemas: WITH_SCHEMA, packOver: { claim_count: 3 } }), ['CLAIM_COUNT_MISMATCH']],
  [
    '07-claim-envelope-replaced', 1, {}, 'a claim envelope was replaced by another while its claim_hash was kept',
    (() => {
      const pack = buildPack({ claims: TWO, inlineSchemas: WITH_SCHEMA });
      const other = buildPack({ claims: [{ claim_id: 'pc_conformance_9', type: 'intent_claim', payload: intent(9) }], inlineSchemas: WITH_SCHEMA });
      pack.claims = [{ ...pack.claims[0], envelope_cose: other.claims[0].envelope_cose }, pack.claims[1]];
      return pack;
    })(),
    ['CLAIM_HASH_MISMATCH', 'CONTENT_HASH_MISMATCH'],
  ],
  ['08-pack-signed-by-unknown-key', 1, {}, 'the pack claim is signed by a key that is in neither key set', buildPack({ claims: TWO, inlineSchemas: WITH_SCHEMA, packSigner: STRANGER }), ['PRIMARY_SIG_INVALID']],
  ['09-unsupported-pack-version', 1, {}, 'pack_version is not 1', buildPack({ packVersion: 2 }), ['INVALID_MANIFEST']],
  ['10-pack-claim-undecodable', 1, {}, 'the pack claim is not a COSE_Sign1', { ...buildPack(), claim: 'AAAA' }, ['COSE_DECODE_FAILED']],
  ['11-not-an-evidence-pack', 1, {}, 'the pack claim payload is not an evidence pack', buildPack({ packPayloadType: 'intent_claim' }), ['NOT_EVIDENCE_PACK']],
  ['12-cosignature-by-wrong-key', 1, {}, 'the co-signature was made with the operator key, not the system key', buildPack({ cosigner: OPERATOR }), ['COSIG_SIG_INVALID']],
  [
    '13-claim-signed-by-unknown-key', 1, {}, 'a claim is signed by a key that is in neither key set',
    buildPack({ claims: [{ claim_id: 'pc_conformance_1', type: 'intent_claim', payload: intent(1), signer: STRANGER }], inlineSchemas: WITH_SCHEMA }),
    ['CLAIM_SIG_INVALID'],
  ],
  [
    '14-claim-id-duplicate', 1, {}, 'two claims share a claim_id',
    buildPack({ claims: [{ claim_id: 'pc_conformance_1', type: 'intent_claim', payload: intent(1) }, { claim_id: 'pc_conformance_1', type: 'intent_claim', payload: intent(2) }], inlineSchemas: WITH_SCHEMA }),
    ['CLAIM_ID_DUPLICATE'],
  ],
  [
    '15-schema-pin-mismatch', 1, {}, 'a schema pin in the signed pack claim differs from the inline schema',
    buildPack({ claims: TWO, inlineSchemas: WITH_SCHEMA, pinOver: { intent_claim: `sha256:${'f'.repeat(64)}` } }),
    ['SCHEMA_PIN_MISMATCH'],
  ],
  [
    '16-unknown-claim-type-default', 1, {}, 'a claim type without an inline schema is a warning in the default mode',
    buildPack({ claims: [{ claim_id: 'pc_conformance_1', type: 'mystery_claim', payload: { type: 'mystery_claim' } }], inlineSchemas: ['envelope'] }),
    [],
  ],
  [
    '17-unknown-claim-type-strict', 1, { strict: true }, 'a claim type without an inline schema is an error in strict mode',
    buildPack({ claims: [{ claim_id: 'pc_conformance_1', type: 'mystery_claim', payload: { type: 'mystery_claim' } }], inlineSchemas: ['envelope'] }),
    ['UNKNOWN_CLAIM_TYPE'],
  ],
  ['18-anchor-signature-invalid', 2, {}, 'the signed head of the audit chain was not signed by a key of the pack', buildPack({ claims: TWO, inlineSchemas: WITH_SCHEMA, anchorSigner: STRANGER }), ['ANCHOR_SIG_INVALID']],
];

function render() {
  const files = new Map();
  const expected = [];
  for (const [name, level, options, description, manifest, errors] of FIXTURES) {
    files.set(`${name}.json`, `${JSON.stringify(manifest, null, 2)}\n`);
    expected.push({ file: `${name}.json`, level, options, description, valid: errors.length === 0, complete: false, errors: [...errors].sort() });
  }
  files.set('expected.json', `${JSON.stringify({ spec: 'stack-record', spec_version: '1.0.0', fixtures: expected }, null, 2)}\n`);
  return files;
}

const check = process.argv.includes('--check');
const files = render();
const stale = [];
for (const [name, content] of files) {
  const path = join(OUT, name);
  const current = existsSync(path) ? readFileSync(path, 'utf8').replaceAll('\r\n', '\n') : null;
  if (current !== content) {
    stale.push(name);
    if (!check) {
      mkdirSync(OUT, { recursive: true });
      writeFileSync(path, content, 'utf8');
    }
  }
}
if (check && stale.length > 0) {
  console.error(`record fixtures are out of date: ${stale.join(', ')}. Run node scripts/build-record-fixtures.mjs`);
  process.exit(1);
}
console.log(check ? `record fixtures are current (${files.size} files)` : `wrote ${stale.length} of ${files.size} record fixture files`);
