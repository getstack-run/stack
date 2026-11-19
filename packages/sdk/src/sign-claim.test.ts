import { describe, it, expect } from 'vitest';
import { generateKeyPair, exportJWK, type JWK } from 'jose';
import { encode as cborEncode, decode as cborDecode } from 'cbor-x';
import { createPublicKey, verify as cryptoVerify, type JsonWebKey } from 'node:crypto';
import { signClaimEnvelope, type ClaimEnvelope } from './sign-claim.js';

/**
 * The SDK's signClaimEnvelope produces a COSE_Sign1 wire format that
 * @stack/vault's ClaimSigner.verify accepts unmodified
 * wire-compat guarantee). We can't import vault here (it's a
 * server-side package), so this test inlines the verification logic
 * using the same primitives (cbor-x + node:crypto). The vault-side
 * test `agent-signer.test.ts > verifyPreSigned` covers the same
 * round-trip in the opposite direction — together they pin the wire
 * format on both sides.
 */

// COSE constants — must match sign-claim.ts.
const COSE_ALG_EDDSA = -8;
const COSE_HEADER_ALG = 1;
const COSE_HEADER_KID = 4;
const COSE_HEADER_TYP = 16;
const STACK_CLAIM_TYP = 'stack/claim+cose';

async function newEd25519KeyPair(): Promise<{ privateJwk: JWK; publicJwk: JWK }> {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', {
    crv: 'Ed25519',
    extractable: true,
  });
  return {
    privateJwk: await exportJWK(privateKey),
    publicJwk: await exportJWK(publicKey),
  };
}

function makeEnvelope(): ClaimEnvelope {
  return {
    envelope_version: 1,
    issuer: 'op_cust',
    subject: 'stack://operator/op_cust/passport/ppt_abc',
    issued_at: 1778600000000,
    claim_type: 'intent_claim',
    claim_version: 1,
    payload: { intent_type: 'http_call', target: 'https://api.example.com' },
    receipt: null,
    co_signatures: [],
  };
}

/**
 * Inline COSE_Sign1 verify — mirrors what @stack/vault's
 * ClaimSigner.verify does, with the kid pinned to the agent's kid.
 * Returns { valid, kid, envelope } or { valid: false, error }.
 */
function verifyCose(base64Cose: string, pubkey: JWK): {
  valid: boolean;
  kid?: string;
  envelope?: ClaimEnvelope;
  error?: string;
} {
  try {
    const coseBytes = Buffer.from(base64Cose, 'base64url');
    const cose = cborDecode(coseBytes) as unknown[];
    if (!Array.isArray(cose) || cose.length !== 4) {
      return { valid: false, error: 'not a 4-element COSE_Sign1 array' };
    }
    const [protectedBytes, , payloadBytes, signatureBytes] = cose as [
      Uint8Array,
      unknown,
      Uint8Array,
      Uint8Array,
    ];
    const protectedMap = cborDecode(protectedBytes) as Map<number, unknown>;
    if (!(protectedMap instanceof Map)) {
      return { valid: false, error: 'protected header is not a CBOR map' };
    }
    const alg = protectedMap.get(COSE_HEADER_ALG);
    if (alg !== COSE_ALG_EDDSA) {
      return { valid: false, error: `unsupported alg ${alg as number}` };
    }
    const typ = protectedMap.get(COSE_HEADER_TYP);
    if (typ !== STACK_CLAIM_TYP) {
      return { valid: false, error: `unexpected typ ${typ as string}` };
    }
    const kidRaw = protectedMap.get(COSE_HEADER_KID);
    const kid =
      kidRaw instanceof Uint8Array
        ? Buffer.from(kidRaw).toString('utf8')
        : typeof kidRaw === 'string'
          ? kidRaw
          : null;
    if (!kid) return { valid: false, error: 'kid missing' };

    const publicKey = createPublicKey({
      key: pubkey as JsonWebKey,
      format: 'jwk',
    });
    const sigStructure = [
      'Signature1',
      protectedBytes,
      Buffer.alloc(0),
      payloadBytes,
    ];
    const sigStructureBytes = cborEncode(sigStructure);
    const valid = cryptoVerify(null, sigStructureBytes, publicKey, signatureBytes);
    if (!valid) return { valid: false, kid, error: 'signature verification failed' };

    const envelope = cborDecode(payloadBytes) as ClaimEnvelope;
    return { valid: true, kid, envelope };
  } catch (err) {
    return { valid: false, error: (err as Error).message };
  }
}

describe('signClaimEnvelope (customer-managed claim signing)', () => {
  it('produces a COSE_Sign1 that round-trips under the customer pubkey', async () => {
    const { privateJwk, publicJwk } = await newEd25519KeyPair();
    const envelope = makeEnvelope();

    const cose = signClaimEnvelope(envelope, {
      privateKey: privateJwk,
      agentId: 'ag_cust',
    });

    expect(cose).toMatch(/^[A-Za-z0-9_-]+$/);

    const result = verifyCose(cose, publicJwk);
    expect(result.valid).toBe(true);
    expect(result.kid).toBe('agent:ag_cust:v1');
    expect(result.envelope?.claim_type).toBe('intent_claim');
    expect((result.envelope?.payload as { intent_type: string })?.intent_type).toBe('http_call');
  });

  it('signs every standard claim_type variant', async () => {
    const { privateJwk, publicJwk } = await newEd25519KeyPair();
    const claimTypes = [
      'intent_claim',
      'intent_outcome',
      'detector_signal',
      'intent_denial',
      'intent_simulation',
    ];

    for (const claim_type of claimTypes) {
      const cose = signClaimEnvelope(
        { ...makeEnvelope(), claim_type },
        { privateKey: privateJwk, agentId: 'ag_cust' },
      );
      const result = verifyCose(cose, publicJwk);
      expect(result.valid, `claim_type=${claim_type}`).toBe(true);
      expect(result.envelope?.claim_type).toBe(claim_type);
    }
  });

  it('does not verify under a different keypair', async () => {
    const { privateJwk } = await newEd25519KeyPair();
    const { publicJwk: otherPubkey } = await newEd25519KeyPair();

    const cose = signClaimEnvelope(makeEnvelope(), {
      privateKey: privateJwk,
      agentId: 'ag_cust',
    });

    const result = verifyCose(cose, otherPubkey);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('signature verification failed');
  });

  it('throws on unsupported algorithm', async () => {
    const { privateJwk } = await newEd25519KeyPair();
    expect(() =>
      signClaimEnvelope(makeEnvelope(), {
        privateKey: privateJwk,
        agentId: 'ag_cust',
        alg: 'ML-DSA-65',
      }),
    ).toThrow(/reserved but not yet implemented/);
  });

  it("embeds kid 'agent:<id>:v1' in the protected header", async () => {
    const { privateJwk } = await newEd25519KeyPair();
    const cose = signClaimEnvelope(makeEnvelope(), {
      privateKey: privateJwk,
      agentId: 'ag_xyz_2',
    });

    // Decode just to inspect the kid — verification uses pubkey above.
    const buf = Buffer.from(cose, 'base64url');
    const cosePieces = cborDecode(buf) as Uint8Array[];
    const headerMap = cborDecode(cosePieces[0]!) as Map<number, unknown>;
    const kidRaw = headerMap.get(COSE_HEADER_KID);
    const kid = kidRaw instanceof Uint8Array ? Buffer.from(kidRaw).toString('utf8') : kidRaw;
    expect(kid).toBe('agent:ag_xyz_2:v1');
  });
});
