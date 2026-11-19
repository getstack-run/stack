// A reference verifier of a claim signed with an agent's own key (spec/agent-keys/SPEC.md, section 6), written from
// the specification with cbor-x for CBOR and node:crypto for Ed25519. The kit's own CBOR reader (src/cbor.mjs) is
// deliberately not used here, so that the two are independent readings of the same rules.

import { createPublicKey, verify as edVerify } from 'node:crypto';
import { Decoder, encode } from 'cbor-x';

// Every CBOR map is read as a Map, tagged or not, so that integer labels compare as integers.
const reader = new Decoder({ mapsAsObjects: false });
const decode = (bytes) => reader.decode(bytes);

const untag = (value) => (value && typeof value === 'object' && 'tag' in value && 'value' in value ? value.value : value);

/** The thumbprint of an Ed25519 key (RFC 7638), to count one key listed twice once. */
const thumbprint = (jwk) => `${jwk.crv}:${jwk.x}`;

export function verifyAgentClaim(message, { jwks, agentId }) {
  const fail = (error) => ({ valid: false, error });
  let outer;
  try {
    outer = decode(Buffer.from(message, 'base64url'));
  } catch {
    return fail('not CBOR');
  }
  if (!Array.isArray(outer) || outer.length !== 4) return fail('not a four-element COSE_Sign1');
  const [protectedBytes, , payloadBytes, signature] = outer;
  if (![protectedBytes, payloadBytes, signature].every((part) => part instanceof Uint8Array)) return fail('parts must be byte strings');
  let header;
  try {
    header = untag(decode(protectedBytes));
  } catch {
    return fail('protected header does not decode');
  }
  if (!(header instanceof Map)) return fail('protected header is not a map');
  if (header.get(1) !== -8) return fail('alg is not EdDSA (-8)');
  const rawKid = header.get(4);
  const kid = rawKid instanceof Uint8Array ? Buffer.from(rawKid).toString('utf8') : typeof rawKid === 'string' ? rawKid : '';
  if (!kid) return fail('no kid');
  // The key id must be the agent's own.
  if (kid !== `agent:${agentId}:v1`) return fail('kid is not the agent\'s');
  const candidates = (jwks?.keys ?? []).filter((k) => k && k.kid === kid);
  const distinct = [...new Map(candidates.map((k) => [thumbprint(k), k])).values()];
  if (distinct.length === 0) return fail('no key under the kid');
  const toBeSigned = encode(['Signature1', Buffer.from(protectedBytes), Buffer.alloc(0), Buffer.from(payloadBytes)]);
  let matches = 0;
  for (const key of distinct) {
    if ('d' in key) return fail('the key carries private material');
    if (key.alg !== undefined && key.alg !== 'EdDSA') return fail('the key is not an EdDSA key');
    if (key.use !== undefined && key.use !== 'sig') return fail('the key is not a signing key');
    let publicKey;
    try {
      publicKey = createPublicKey({ key, format: 'jwk' });
    } catch {
      return fail('the key cannot be read');
    }
    if (edVerify(null, toBeSigned, publicKey, Buffer.from(signature))) matches += 1;
  }
  if (matches !== 1) return fail(matches === 0 ? 'signature does not verify' : 'ambiguous');
  try {
    return { valid: true, envelope: decode(Buffer.from(payloadBytes)) };
  } catch {
    return fail('payload does not decode');
  }
}
