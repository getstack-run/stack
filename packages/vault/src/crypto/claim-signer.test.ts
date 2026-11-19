import { describe, it, expect } from 'vitest';
import { generateKeyPair, exportJWK, type JWK } from 'jose';
import {
  ClaimSigner,
  parseTrustedDeploymentJwks,
  publicJwkThumbprint,
} from './claim-signer.js';
import { deploymentJwkCandidates } from './deployment-signing-config.js';
import type { ClaimEnvelope } from '@stack/shared';

async function newEd25519KeyPair(): Promise<{ privateJwk: JWK; publicJwk: JWK }> {
  // `extractable: true` required by jose v6 — default-non-extractable
  // CryptoKey cannot be exported to JWK.
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', {
    crv: 'Ed25519',
    extractable: true,
  });
  return {
    privateJwk: await exportJWK(privateKey),
    publicJwk: await exportJWK(publicKey),
  };
}

function makeEnvelope(overrides: Partial<ClaimEnvelope> = {}): ClaimEnvelope {
  return {
    envelope_version: 1,
    issuer: 'op_test',
    subject: 'stack://operator/op_test/passport/ppt_abc',
    issued_at: 1778600000000,
    claim_type: 'svid_attestation',
    claim_version: 1,
    payload: { hello: 'world', count: 42 },
    receipt: null,
    co_signatures: [],
    ...overrides,
  };
}

describe('ClaimSigner', () => {
  it('round-trips sign + verify', async () => {
    const { privateJwk, publicJwk } = await newEd25519KeyPair();
    const signer = new ClaimSigner({ privateKeyJwk: privateJwk, kid: 'k1' });
    const envelope = makeEnvelope();

    const signed = await signer.sign(envelope);
    expect(signed).toMatch(/^[A-Za-z0-9_-]+$/); // base64url

    const verified = await ClaimSigner.verify(signed, async (kid) => {
      expect(kid).toBe('k1');
      return publicJwk;
    });

    expect(verified.valid).toBe(true);
    expect(verified.kid).toBe('k1');
    expect(verified.alg).toBe(-8);
    expect(verified.envelope).toEqual(envelope);
  });

  it('round-trips an envelope with a populated receipt', async () => {
    const { privateJwk, publicJwk } = await newEd25519KeyPair();
    const signer = new ClaimSigner({ privateKeyJwk: privateJwk, kid: 'k1' });
    const envelope = makeEnvelope({
      receipt: {
        registry: 'stack:transparent-registry',
        registered_at: 1778600001000,
        registry_entry_uri: 'stack://receipts/r_xyz',
        proof: {
          format: 'stack-merkle-v1',
          bytes: 'AQID',
          log_index: 100,
          tree_size: 1000,
          root_hash: 'BAUG',
        },
        witnesses: [],
      },
    });

    const signed = await signer.sign(envelope);
    const verified = await ClaimSigner.verify(signed, async () => publicJwk);

    expect(verified.valid).toBe(true);
    expect(verified.envelope?.receipt).toEqual(envelope.receipt);
  });

  it('detects tampered payload bytes', async () => {
    const { privateJwk, publicJwk } = await newEd25519KeyPair();
    const signer = new ClaimSigner({ privateKeyJwk: privateJwk, kid: 'k1' });
    const signed = await signer.sign(makeEnvelope());

    // Flip a byte in the middle of the base64url-encoded COSE_Sign1.
    // This corrupts either the payload bytes or the signature; either
    // way verify must return valid=false.
    const bytes = Buffer.from(signed, 'base64url');
    const mid = Math.floor(bytes.length / 2);
    bytes[mid] = bytes[mid]! ^ 0xff;
    const tampered = bytes.toString('base64url');

    const verified = await ClaimSigner.verify(tampered, async () => publicJwk);
    expect(verified.valid).toBe(false);
    expect(verified.error).toBeTruthy();
  });

  it('rejects signature with a different operator key', async () => {
    const { privateJwk } = await newEd25519KeyPair();
    const { publicJwk: otherPublicJwk } = await newEd25519KeyPair();

    const signer = new ClaimSigner({ privateKeyJwk: privateJwk, kid: 'k1' });
    const signed = await signer.sign(makeEnvelope());

    const verified = await ClaimSigner.verify(signed, async () => otherPublicJwk);
    expect(verified.valid).toBe(false);
    expect(verified.error).toMatch(/signature verification failed/);
  });

  it('verifies with exactly one matching historical key when candidates share a kid', async () => {
    const legacyKid = 'stack-passport-v1';
    const historical = await newEd25519KeyPair();
    const current = await newEd25519KeyPair();
    const signer = new ClaimSigner({ privateKeyJwk: historical.privateJwk, kid: legacyKid });
    const signed = await signer.sign(makeEnvelope());

    const verified = await ClaimSigner.verify(signed, async () => [
      { ...current.publicJwk, kid: legacyKid },
      { ...historical.publicJwk, kid: legacyKid },
    ]);

    expect(verified.valid).toBe(true);
    expect(verified.verified_key_thumbprint).toBe(
      publicJwkThumbprint(historical.publicJwk),
    );
  });

  it('deduplicates the same public key by thumbprint before verification', async () => {
    const legacyKid = 'stack-passport-v1';
    const historical = await newEd25519KeyPair();
    const signer = new ClaimSigner({ privateKeyJwk: historical.privateJwk, kid: legacyKid });
    const signed = await signer.sign(makeEnvelope());
    const duplicate = { ...historical.publicJwk, kid: legacyKid, alg: 'EdDSA', use: 'sig' };

    const verified = await ClaimSigner.verify(signed, async () => [duplicate, { ...duplicate }]);

    expect(verified.valid).toBe(true);
    expect(verified.verified_key_thumbprint).toBe(publicJwkThumbprint(duplicate));
  });

  it('rejects when no trusted candidate verifies', async () => {
    const legacyKid = 'stack-passport-v1';
    const signing = await newEd25519KeyPair();
    const wrongOne = await newEd25519KeyPair();
    const wrongTwo = await newEd25519KeyPair();
    const signer = new ClaimSigner({ privateKeyJwk: signing.privateJwk, kid: legacyKid });
    const signed = await signer.sign(makeEnvelope());

    const verified = await ClaimSigner.verify(signed, async () => [
      { ...wrongOne.publicJwk, kid: legacyKid },
      { ...wrongTwo.publicJwk, kid: legacyKid },
    ]);

    expect(verified.valid).toBe(false);
    expect(verified.error).toMatch(/no trusted key candidate verified/);
  });

  it('rejects a historical signature after its pinned key is removed', async () => {
    const legacyKid = 'stack-passport-v1';
    const historical = await newEd25519KeyPair();
    const current = await newEd25519KeyPair();
    const signer = new ClaimSigner({ privateKeyJwk: historical.privateJwk, kid: legacyKid });
    const signed = await signer.sign(makeEnvelope());
    const currentJwk = { ...current.publicJwk, kid: legacyKid };

    const verified = await ClaimSigner.verify(signed, async (kid) =>
      deploymentJwkCandidates(kid, currentJwk, []),
    );

    expect(verified.valid).toBe(false);
    expect(verified.error).toMatch(/signature verification failed/);
  });

  it('rejects when the kid is not resolvable in JWKS', async () => {
    const { privateJwk } = await newEd25519KeyPair();
    const signer = new ClaimSigner({ privateKeyJwk: privateJwk, kid: 'unknown-kid' });
    const signed = await signer.sign(makeEnvelope());

    const verified = await ClaimSigner.verify(signed, async () => null);
    expect(verified.valid).toBe(false);
    expect(verified.kid).toBe('unknown-kid');
    expect(verified.error).toMatch(/not found in JWKS/);
  });

  it('parses only pinned public Ed25519 deployment keys', async () => {
    const { publicJwk } = await newEd25519KeyPair();
    const configured = {
      ...publicJwk,
      kid: 'stack-passport-v1',
      alg: 'EdDSA',
      use: 'sig',
    };

    expect(
      parseTrustedDeploymentJwks(JSON.stringify({ keys: [configured, { ...configured }] })),
    ).toEqual([configured]);
  });

  it('rejects private or non-Ed25519 material in the trusted deployment JWKS', async () => {
    const { privateJwk, publicJwk } = await newEd25519KeyPair();
    const base = { kid: 'stack-passport-v1', alg: 'EdDSA', use: 'sig' };

    expect(() =>
      parseTrustedDeploymentJwks(JSON.stringify({ keys: [{ ...privateJwk, ...base }] })),
    ).toThrow(/must not contain private key material/);
    expect(() =>
      parseTrustedDeploymentJwks(
        JSON.stringify({ keys: [{ ...publicJwk, ...base, crv: 'X25519' }] }),
      ),
    ).toThrow(/Ed25519/);
  });

  it('refuses to construct with an unsupported alg', async () => {
    const { privateJwk } = await newEd25519KeyPair();
    expect(
      () =>
        new ClaimSigner({
          privateKeyJwk: privateJwk,
          kid: 'k1',
          alg: 'ML-DSA-65',
        }),
    ).toThrow(/not yet implemented/);
  });

  it('produces stable output for identical inputs', async () => {
    const { privateJwk } = await newEd25519KeyPair();
    const signer = new ClaimSigner({ privateKeyJwk: privateJwk, kid: 'k1' });
    const envelope = makeEnvelope();

    // Two signatures of the same envelope are NOT byte-identical
    // because Ed25519 is deterministic at the signature level but
    // CBOR Map encoding may have stable byte output. What MUST be
    // true is both verify successfully. (For Ed25519 specifically
    // the signatures should be byte-identical — Ed25519 is RFC 8032
    // deterministic.)
    const sig1 = await signer.sign(envelope);
    const sig2 = await signer.sign(envelope);
    expect(sig1).toBe(sig2);
  });
});

// ─── co-signature support ────────────────────────────

describe('ClaimSigner co-signatures', () => {
  it('verifies a primary envelope with zero co-signatures (default empty)', async () => {
    const { privateJwk, publicJwk } = await newEd25519KeyPair();
    const signer = new ClaimSigner({ privateKeyJwk: privateJwk, kid: 'k1' });

    const primaryCose = await signer.sign(makeEnvelope());
    const verified = await ClaimSigner.verify(primaryCose, async () => publicJwk);

    expect(verified.valid).toBe(true);
    expect(verified.co_signature_results).toEqual([]);
  });

  it('round-trips with one co-signature attached', async () => {
    const primary = await newEd25519KeyPair();
    const coSigner = await newEd25519KeyPair();

    const primarySigner = new ClaimSigner({
      privateKeyJwk: primary.privateJwk,
      kid: 'primary-k',
    });
    const coSignerInstance = new ClaimSigner({
      privateKeyJwk: coSigner.privateJwk,
      kid: 'cosigner-k',
    });

    const primaryCose = await primarySigner.sign(makeEnvelope());
    const coSig = await coSignerInstance.coSign(primaryCose, 'operator_attestation');

    expect(coSig.signer_kid).toBe('cosigner-k');
    expect(coSig.signer_role).toBe('operator_attestation');
    expect(coSig.cose_sign1).toMatch(/^[A-Za-z0-9_-]+$/);

    const verified = await ClaimSigner.verify(
      primaryCose,
      async (kid) => {
        if (kid === 'primary-k') return primary.publicJwk;
        if (kid === 'cosigner-k') return coSigner.publicJwk;
        return null;
      },
      [coSig],
    );

    expect(verified.valid).toBe(true);
    expect(verified.co_signature_results).toHaveLength(1);
    expect(verified.co_signature_results![0]!.valid).toBe(true);
    expect(verified.co_signature_results![0]!.signer_kid).toBe('cosigner-k');
    expect(verified.co_signature_results![0]!.signer_role).toBe('operator_attestation');
  });

  it('verifies a co-signature with one matching same-kid historical candidate', async () => {
    const primary = await newEd25519KeyPair();
    const historicalCoSigner = await newEd25519KeyPair();
    const currentWrongKey = await newEd25519KeyPair();
    const primarySigner = new ClaimSigner({
      privateKeyJwk: primary.privateJwk,
      kid: 'primary-k',
    });
    const coSigner = new ClaimSigner({
      privateKeyJwk: historicalCoSigner.privateJwk,
      kid: 'stack-passport-v1',
    });
    const primaryCose = await primarySigner.sign(makeEnvelope());
    const coSignature = await coSigner.coSign(primaryCose, 'operator_attestation');

    const verified = await ClaimSigner.verify(
      primaryCose,
      async (kid) => {
        if (kid === 'primary-k') return primary.publicJwk;
        return [
          { ...currentWrongKey.publicJwk, kid },
          { ...historicalCoSigner.publicJwk, kid },
        ];
      },
      [coSignature],
    );

    expect(verified.valid).toBe(true);
    expect(verified.co_signature_results).toEqual([
      expect.objectContaining({ valid: true, signer_kid: 'stack-passport-v1' }),
    ]);
  });

  it('round-trips with two co-signatures (all three roles tested)', async () => {
    const primary = await newEd25519KeyPair();
    const operatorAttester = await newEd25519KeyPair();
    const witness = await newEd25519KeyPair();

    const primarySigner = new ClaimSigner({ privateKeyJwk: primary.privateJwk, kid: 'primary-k' });
    const opAttSigner = new ClaimSigner({ privateKeyJwk: operatorAttester.privateJwk, kid: 'op-att-k' });
    const witnessSigner = new ClaimSigner({ privateKeyJwk: witness.privateJwk, kid: 'witness-k' });

    const primaryCose = await primarySigner.sign(makeEnvelope());
    const coSig1 = await opAttSigner.coSign(primaryCose, 'operator_attestation');
    const coSig2 = await witnessSigner.coSign(primaryCose, 'witness');

    const verified = await ClaimSigner.verify(
      primaryCose,
      async (kid) => {
        if (kid === 'primary-k') return primary.publicJwk;
        if (kid === 'op-att-k') return operatorAttester.publicJwk;
        if (kid === 'witness-k') return witness.publicJwk;
        return null;
      },
      [coSig1, coSig2],
    );

    expect(verified.valid).toBe(true);
    expect(verified.co_signature_results).toHaveLength(2);
    expect(verified.co_signature_results!.every((r) => r.valid)).toBe(true);
    expect(verified.co_signature_results!.map((r) => r.signer_role)).toEqual([
      'operator_attestation',
      'witness',
    ]);
  });

  it('verifies agent_self co-signature role', async () => {
    const primary = await newEd25519KeyPair();
    const agent = await newEd25519KeyPair();
    const primarySigner = new ClaimSigner({ privateKeyJwk: primary.privateJwk, kid: 'p' });
    const agentSigner = new ClaimSigner({ privateKeyJwk: agent.privateJwk, kid: 'a' });

    const primaryCose = await primarySigner.sign(makeEnvelope());
    const coSig = await agentSigner.coSign(primaryCose, 'agent_self');

    const verified = await ClaimSigner.verify(
      primaryCose,
      async (kid) => (kid === 'p' ? primary.publicJwk : kid === 'a' ? agent.publicJwk : null),
      [coSig],
    );

    expect(verified.valid).toBe(true);
    expect(verified.co_signature_results![0]!.signer_role).toBe('agent_self');
  });

  it('overall valid becomes false when ANY co-signature fails', async () => {
    const primary = await newEd25519KeyPair();
    const cosignerA = await newEd25519KeyPair();
    const cosignerB = await newEd25519KeyPair();

    const primarySigner = new ClaimSigner({ privateKeyJwk: primary.privateJwk, kid: 'p' });
    const aSigner = new ClaimSigner({ privateKeyJwk: cosignerA.privateJwk, kid: 'a' });
    const bSigner = new ClaimSigner({ privateKeyJwk: cosignerB.privateJwk, kid: 'b' });

    const primaryCose = await primarySigner.sign(makeEnvelope());
    const coSigA = await aSigner.coSign(primaryCose, 'witness');
    // Make coSigB invalid: tamper its base64url-encoded COSE_Sign1.
    const coSigBraw = await bSigner.coSign(primaryCose, 'witness');
    const tamperedBytes = Buffer.from(coSigBraw.cose_sign1, 'base64url');
    const tamperIdx = Math.floor(tamperedBytes.length / 2);
    tamperedBytes[tamperIdx] = (tamperedBytes[tamperIdx] ?? 0) ^ 0xff;
    const coSigB = { ...coSigBraw, cose_sign1: tamperedBytes.toString('base64url') };

    const verified = await ClaimSigner.verify(
      primaryCose,
      async (kid) => {
        if (kid === 'p') return primary.publicJwk;
        if (kid === 'a') return cosignerA.publicJwk;
        if (kid === 'b') return cosignerB.publicJwk;
        return null;
      },
      [coSigA, coSigB],
    );

    expect(verified.valid).toBe(false);
    expect(verified.co_signature_results).toHaveLength(2);
    expect(verified.co_signature_results![0]!.valid).toBe(true);
    expect(verified.co_signature_results![1]!.valid).toBe(false);
    expect(verified.co_signature_results![1]!.error).toBeTruthy();
  });

  it('rejects a co-signature whose signer_kid field disagrees with its protected-header kid', async () => {
    const primary = await newEd25519KeyPair();
    const cosigner = await newEd25519KeyPair();

    const primarySigner = new ClaimSigner({ privateKeyJwk: primary.privateJwk, kid: 'p' });
    const cosignerSigner = new ClaimSigner({ privateKeyJwk: cosigner.privateJwk, kid: 'real-kid' });

    const primaryCose = await primarySigner.sign(makeEnvelope());
    const realCoSig = await cosignerSigner.coSign(primaryCose, 'witness');

    // Mutate the surface signer_kid to claim a different identity than
    // what the cryptographic envelope actually signs under.
    const mismatched = { ...realCoSig, signer_kid: 'claimed-different-kid' };

    const verified = await ClaimSigner.verify(
      primaryCose,
      async (kid) =>
        kid === 'p'
          ? primary.publicJwk
          : kid === 'real-kid' || kid === 'claimed-different-kid'
            ? cosigner.publicJwk
            : null,
      [mismatched],
    );

    expect(verified.valid).toBe(false);
    expect(verified.co_signature_results![0]!.valid).toBe(false);
    expect(verified.co_signature_results![0]!.error).toMatch(/kid mismatch/);
  });

  it('rejects a co-signature whose payload differs from primary', async () => {
    // Two primaries, each signed over different envelopes. Take the
    // co-signature of one and try to attach it to the other.
    const primaryA = await newEd25519KeyPair();
    const primaryB = await newEd25519KeyPair();
    const cosigner = await newEd25519KeyPair();

    const sigA = new ClaimSigner({ privateKeyJwk: primaryA.privateJwk, kid: 'A' });
    const sigB = new ClaimSigner({ privateKeyJwk: primaryB.privateJwk, kid: 'B' });
    const co = new ClaimSigner({ privateKeyJwk: cosigner.privateJwk, kid: 'co' });

    const primaryAcose = await sigA.sign(makeEnvelope({ subject: 'stack://operator/op_test/passport/ppt_aaa' }));
    const primaryBcose = await sigB.sign(makeEnvelope({ subject: 'stack://operator/op_test/passport/ppt_bbb' }));

    // co-sign envelope B
    const coSigForB = await co.coSign(primaryBcose, 'witness');

    // Try to verify it against envelope A — should fail with payload mismatch
    const verified = await ClaimSigner.verify(
      primaryAcose,
      async (kid) =>
        kid === 'A' ? primaryA.publicJwk : kid === 'co' ? cosigner.publicJwk : null,
      [coSigForB],
    );

    expect(verified.valid).toBe(false);
    expect(verified.co_signature_results![0]!.valid).toBe(false);
    expect(verified.co_signature_results![0]!.error).toMatch(/payload_bytes differ/);
  });

  it('rejects a co-signature when the verifier cannot resolve its kid', async () => {
    const primary = await newEd25519KeyPair();
    const cosigner = await newEd25519KeyPair();

    const primarySigner = new ClaimSigner({ privateKeyJwk: primary.privateJwk, kid: 'p' });
    const cosignerSigner = new ClaimSigner({ privateKeyJwk: cosigner.privateJwk, kid: 'unknown' });

    const primaryCose = await primarySigner.sign(makeEnvelope());
    const coSig = await cosignerSigner.coSign(primaryCose, 'witness');

    // Resolver returns null for the co-signer's kid
    const verified = await ClaimSigner.verify(
      primaryCose,
      async (kid) => (kid === 'p' ? primary.publicJwk : null),
      [coSig],
    );

    expect(verified.valid).toBe(false);
    expect(verified.co_signature_results![0]!.valid).toBe(false);
    expect(verified.co_signature_results![0]!.error).toMatch(/not found in JWKS/);
  });

  it("coSign() throws when given malformed primary input", async () => {
    const { privateJwk } = await newEd25519KeyPair();
    const signer = new ClaimSigner({ privateKeyJwk: privateJwk, kid: 'k1' });

    await expect(signer.coSign('not-a-valid-base64-cose', 'witness')).rejects.toThrow();
  });

  it('a tampered primary is rejected even when co-signatures are valid', async () => {
    const primary = await newEd25519KeyPair();
    const cosigner = await newEd25519KeyPair();

    const primarySigner = new ClaimSigner({ privateKeyJwk: primary.privateJwk, kid: 'p' });
    const cosignerSigner = new ClaimSigner({ privateKeyJwk: cosigner.privateJwk, kid: 'co' });

    const primaryCose = await primarySigner.sign(makeEnvelope());
    const coSig = await cosignerSigner.coSign(primaryCose, 'witness');

    // Tamper the primary
    const bytes = Buffer.from(primaryCose, 'base64url');
    const ti = Math.floor(bytes.length / 2);
    bytes[ti] = (bytes[ti] ?? 0) ^ 0xff;
    const tamperedPrimary = bytes.toString('base64url');

    const verified = await ClaimSigner.verify(
      tamperedPrimary,
      async (kid) => (kid === 'p' ? primary.publicJwk : kid === 'co' ? cosigner.publicJwk : null),
      [coSig],
    );

    expect(verified.valid).toBe(false);
    // Primary failed; co-sig wasn't even checked because verify returns
    // early when the primary fails. Caller can distinguish via the
    // missing co_signature_results.
  });
});
