// The SDK's network module (`InstallKey` and the `verify*` functions) is the
// reference install client and verifier of spec/network/SPEC.md and must pass the
// `network-verifier` suite; the in-memory reference service (network-service.mjs)
// must pass the `network-service` suite. And, as for every suite, the kit must
// FAIL implementations that each have one deliberate defect: a kit that passes
// everything proves nothing.

import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import * as sdk from '@getstackrun/sdk';
import { formatReport, runNetworkServiceSuite, runNetworkVerifierSuite, buildNetworkVectors, commandNetworkImplementation } from '../src/index.mjs';
import { vectorKeys } from '../src/network-vectors.mjs';
import { startReferenceNetworkService } from './network-service.mjs';

const mustFailedIds = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);

/** The SDK as a network implementation, in the shape the suite takes. */
const sdkImplementation = {
  verify: async (kind, token, { jwks, now, passport, heldRevision }) => {
    const options = { jwks, now: new Date(now * 1000) };
    if (kind === 'countersignature') return sdk.verifyCountersignedPassport({ countersignature: token, passport, ...options });
    if (kind === 'revocation_list') return sdk.verifyRevocationList(token, options);
    if (kind === 'verified') return sdk.verifyVerifiedStatement(token, options);
    return sdk.verifyDetectionRules(token, { ...options, ...(heldRevision !== undefined ? { heldRevision } : {}) });
  },
  revoked: async (token, held, { jwks, now }) => {
    const list = await sdk.verifyRevocationList(token, { jwks, now: new Date(now * 1000) });
    return sdk.revocationCovers(list.entries, { install: held.install, keyId: held.keyId, passportDigest: held.passportDigest, agent: held.agent }) !== undefined;
  },
  signer: {
    keyProof: async ({ installId, nonce, privateKeyPem, now }) => (await sdk.InstallKey.fromPem(privateKeyPem)).signKeyProof(installId, nonce, { now }),
    proof: async ({ installId, claims, privateKeyPem, now }) => (await sdk.InstallKey.fromPem(privateKeyPem)).signProof(installId, claims, { now }),
  },
};

describe('@getstackrun/sdk network module (the reference install client and verifier)', () => {
  it('conforms to the network-verifier suite, signer included', async () => {
    const report = await runNetworkVerifierSuite(sdkImplementation);
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
    expect(report.passed).toBeGreaterThan(30);
  });
});

describe('network-verifier fails a verifier with one defect', () => {
  /** A verifier that checks the signature and the expiry and nothing else: not the typ, the audience, the issuer or the claims. */
  const signatureOnly = (extra = {}) => async (kind, token, { jwks, now }) => {
    const [h, p, s] = token.split('.');
    if (!s) throw new Error('not a JWS');
    const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
    const jwk = jwks.keys.find((k) => k.kid === header.kid);
    if (!jwk || header.alg !== 'EdDSA') throw new Error('unknown key');
    if (!cryptoVerify(null, Buffer.from(`${h}.${p}`), createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(s, 'base64url'))) throw new Error('bad signature');
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    if (!extra.ignoreExpiry && payload.exp <= now - 5) throw new Error('expired');
    return payload;
  };

  it('fails a verifier that checks only the signature and the expiry', async () => {
    const report = await runNetworkVerifierSuite({ verify: signatureOnly() });
    expect(mustFailedIds(report)).toEqual(expect.arrayContaining(['N10', 'N11', 'N12', 'N13', 'N20', 'N30', 'N31', 'N32', 'N33', 'N34', 'N36', 'N40']));
    // What it does check, it checks: the attacks on the signature and the clock are still refused.
    for (const id of ['N14', 'N15', 'N16', 'N17', 'N18']) expect(mustFailedIds(report)).not.toContain(id);
  });

  it('fails a verifier that does not check the expiry', async () => {
    const report = await runNetworkVerifierSuite({ verify: signatureOnly({ ignoreExpiry: true }) });
    expect(mustFailedIds(report)).toContain('N18');
  });

  it('fails a verifier that matches a revocation entry on the subject alone', async () => {
    const digestOnly = {
      ...sdkImplementation,
      revoked: async (token, held, { jwks, now }) => {
        const list = await sdk.verifyRevocationList(token, { jwks, now: new Date(now * 1000) });
        return list.entries.some((e) => (e.kind === 'passport' && e.subject === held.passportDigest) || (e.kind === 'agent' && e.subject === held.agent) || (e.kind === 'key' && e.subject === held.keyId) || (e.kind === 'install' && e.subject === held.install));
      },
    };
    const report = await runNetworkVerifierSuite(digestOnly);
    // It finds what is its own (N60 passes) and so also finds what is somebody else's.
    expect(mustFailedIds(report)).toEqual(['N61', 'N62']);
  });

  it('fails a verifier that never finds a revocation, and one that acts on an expired list', async () => {
    const never = await runNetworkVerifierSuite({ ...sdkImplementation, revoked: async () => false });
    expect(mustFailedIds(never)).toEqual(['N60', 'N61']);
    const ignoresClock = {
      ...sdkImplementation,
      revoked: async (token, held, { jwks, now }) => {
        const list = await sdk.verifyRevocationList(token, { jwks, now: new Date((now > 1_790_000_100 ? 1_790_000_010 : now) * 1000) });
        return sdk.revocationCovers(list.entries, { install: held.install, keyId: held.keyId, passportDigest: held.passportDigest, agent: held.agent }) !== undefined;
      },
    };
    expect(mustFailedIds(await runNetworkVerifierSuite(ignoresClock))).toEqual(['N64']);
  });

  it('fails a verifier that accepts everything', async () => {
    const report = await runNetworkVerifierSuite({ verify: async () => true });
    expect(mustFailedIds(report)).toEqual(expect.arrayContaining(['N10', 'N14', 'N15', 'N16', 'N17', 'N18', 'N19']));
  });

  it('fails a verifier that refuses everything', async () => {
    const report = await runNetworkVerifierSuite({ verify: async () => { throw new Error('no'); } });
    expect(mustFailedIds(report)).toEqual(expect.arrayContaining(['N01', 'N02', 'N03', 'N06']));
  });

  it('fails a signer whose proofs share a jti', async () => {
    const sameJti = async (input) => {
      const token = await sdkImplementation.signer.proof(input);
      const [h, p] = token.split('.');
      const fixed = { ...JSON.parse(Buffer.from(p, 'base64url').toString('utf8')), jti: 'jtiFixedForEveryProof' };
      return `${h}.${Buffer.from(JSON.stringify(fixed)).toString('base64url')}.${token.split('.')[2]}`;
    };
    const report = await runNetworkVerifierSuite({ ...sdkImplementation, signer: { ...sdkImplementation.signer, proof: sameJti } });
    // The edit also breaks each proof's signature, so N51 fails too; N52 is the one that names the defect.
    expect(mustFailedIds(report)).toContain('N52');
  });

  it('runs a program in another language through the command interface', async () => {
    const program = fileURLToPath(new URL('./network-command-verifier.mjs', import.meta.url));
    const implementation = commandNetworkImplementation(process.execPath, [program]);
    const vectors = buildNetworkVectors();
    const jwks = vectors.stack.jwks;
    const now = vectors.now + 10;
    // One of each answer, through a process each: the suite itself would start hundreds.
    await implementation.verify('revocation_list', vectors.revocation_list.join('.'), { jwks, now });
    await expect(implementation.verify('verified', vectors.revocation_list.join('.'), { jwks, now })).rejects.toThrow();
    // The list of the vectors revokes the agent of the install: found under its own install, not under another.
    const held = { install: vectors.install.id, keyId: vectors.install.kid, passportDigest: vectors.passport.digest, agent: 'support-bot' };
    expect(await implementation.revoked(vectors.revocation_list.join('.'), held, { jwks, now })).toBe(true);
    expect(await implementation.revoked(vectors.revocation_list.join('.'), { ...held, install: 'ins_vector_rival0000000' }, { jwks, now })).toBe(false);
    const { install } = vectorKeys();
    const pem = install.key.privateKey.export({ type: 'pkcs8', format: 'pem' });
    const proof = await implementation.signer.proof({ installId: vectors.install.id, claims: { act: 'rules' }, privateKeyPem: pem, now: new Date(vectors.now * 1000) });
    expect(proof.split('.')).toHaveLength(3);
    const popProof = await implementation.signer.keyProof({ installId: vectors.install.id, nonce: 'n'.repeat(32), privateKeyPem: pem, now: new Date(vectors.now * 1000) });
    expect(popProof.split('.')[0]).toBe(vectors.key_proof_of_possession.proof[0]);
  });
});

describe('the vectors file', () => {
  it('names the public generator and holds the negative cases the verifier suite runs', () => {
    const vectors = buildNetworkVectors();
    expect(vectors.generator).toBe('spec/conformance/scripts/build-network-vectors.mjs');
    expect(vectors.negative.cases.length).toBeGreaterThan(15);
    expect(vectors.negative.cross_kind).toHaveLength(12);
    expect(vectors.stack.jwks.keys[0].kid).toBe(vectorKeys().stack.kid);
  });
});

describe('network-service', () => {
  const started = [];
  afterAll(() => Promise.all(started.map((s) => s.close())));

  const INSTALL_ID = 'ins_conformance_flow0000';
  async function start(quirk = 'none') {
    const service = await startReferenceNetworkService({ quirk });
    started.push(service);
    const { install } = vectorKeys();
    service.registerInstall(INSTALL_ID, install.public_jwk);
    return {
      service,
      options: {
        url: service.url,
        install: { id: INSTALL_ID, privateKeyPem: install.key.privateKey.export({ type: 'pkcs8', format: 'pem' }) },
        timeoutMs: 5000,
      },
    };
  }

  it('passes the reference service, public calls and the whole flow of an install', async () => {
    const { options } = await start();
    const report = await runNetworkServiceSuite(options);
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
    expect(report.passed).toBe(report.results.length);
  });

  it('checks the public calls alone when it is given no install, and skips the flow', async () => {
    const { options } = await start();
    const report = await runNetworkServiceSuite({ url: options.url, timeoutMs: 5000 });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.results.filter((r) => r.status === 'skip').map((r) => r.id).every((id) => id.startsWith('F') || id === 'V14')).toBe(true);
    expect(report.skipped).toBeGreaterThan(10);
  });

  const defect = async (quirk) => mustFailedIds(await runNetworkServiceSuite((await start(quirk)).options));

  it('fails a service that accepts the same install proof twice', async () => {
    expect(await defect('no-replay')).toEqual(['F02']);
  });

  it('fails a service that does not check which action a proof asks for', async () => {
    expect(await defect('any-action')).toContain('F03');
  });

  it('fails a service that accepts claims an install proof must not have', async () => {
    expect(await defect('extra-claims')).toEqual(['F04']);
  });

  it('fails a service that accepts a proof that lives too long', async () => {
    expect(await defect('long-proofs')).toEqual(['F04']);
  });

  it('fails a service that lets the revocation list be cached', async () => {
    expect(await defect('cached-list')).toEqual(['V11']);
  });

  it('fails a service that answers a forged countersignature with an error', async () => {
    expect(await defect('forged-is-error')).toContain('V20');
  });

  it('fails a service that countersigns for a revoked agent', async () => {
    expect(await defect('countersign-revoked')).toEqual(['F24']);
  });

  it('fails a service that does not apply an agent revocation to its checks', async () => {
    expect(await defect('no-agent-revoke')).toEqual(expect.arrayContaining(['F23']));
  });

  it('fails a service that signs the list under the typ of another kind', async () => {
    expect(await defect('wrong-typ')).toEqual(expect.arrayContaining(['V10']));
  });

  it('fails a service whose cursor skips an entry', async () => {
    const report = await runNetworkServiceSuite((await start('cursor-skips')).options);
    expect(mustFailedIds(report)).toContain('V14');
  });

  it('fails a service that lists a revocation naming no install', async () => {
    expect(await defect('ownerless-entry')).toEqual(['V10']);
  });

  it('fails a service that takes any bearer as an install proof', async () => {
    expect(await defect('open-countersign')).toEqual(expect.arrayContaining(['V40']));
  });
});
