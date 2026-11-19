// The reference signer, verifier and directory of reference/web-bot-auth-reference.mjs must pass
// the web-bot-auth suite, the kit's own signing must reproduce the published vectors (so the
// judge is right before it judges anyone), and the suite must fail implementations that each
// have one deliberate defect.

import { createPrivateKey, randomBytes, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { formatReport, runWebBotAuthSuite } from '../src/index.mjs';
import { RFC_KEY, OTHER_KEY, buildDirectory } from '../src/web-bot-auth.mjs';
import {
  ed25519Thumbprint, paramOf, parseSignature, parseSignatureInput, privateKeyFromJwk, publicKeyFromX, signEd25519, signatureBase, signatureBaseFrom, verifyEd25519,
} from '../src/http-signature.mjs';
import { createReferenceSigner, createReferenceVerifier, referenceDirectoryResponse } from './web-bot-auth-reference.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(HERE, '..', 'fixtures', 'web-bot-auth', 'vectors.json'), 'utf8'));

const failed = (report) => report.results.filter((r) => r.status === 'fail').map((r) => r.id);
const mustFailed = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);
const NOW_MS = 1_790_000_000_000;

describe('the kit\'s signature helpers', () => {
  it('reproduce the published vectors, so the judge is right before it judges', () => {
    const key = privateKeyFromJwk(RFC_KEY);
    expect(vectors.key.thumbprint).toBe('poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U');
    for (const v of vectors.vectors) {
      if (!v.base) continue;
      expect(signEd25519(v.base, key), v.id).toBe(v.signature);
      expect(verifyEd25519(v.base, v.signature, publicKeyFromX(RFC_KEY.x)), v.id).toBe(true);
    }
    // RFC 9421 B.2.6 and the draft's A.2.1 are the published ones.
    expect(vectors.vectors.find((v) => v.id === 'rfc9421-b26').signature)
      .toBe('wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==');
    expect(vectors.vectors.find((v) => v.id === 'web-bot-auth-draft-a21').signature)
      .toBe('FFASViSdcgsyaqqYiCnkHreeZzbNKcTzDvZC5uVlP/dn9IbWj8j0o4wKFTH3rBnUiSUBduwm1Gp5VlIPCp01Ag==');
  });

  it('the reference signer agrees with the stack-request vector\'s base construction', () => {
    const v = vectors.vectors.find((x) => x.id === 'stack-request-with-directory');
    const base = signatureBase(
      [{ name: '@authority' }, { name: '@method' }, { name: '@path' }, { name: 'signature-agent', key: 'sig1' }],
      [],
      { method: v.message.method, url: v.message.url, headers: v.message.headers },
    ).split('\n').slice(0, -1);
    expect(v.base.split('\n').slice(0, -1)).toEqual(base);
  });
});

describe('the reference implementations', () => {
  it('pass the suite, as signer, verifier and directory, with nothing skipped and no warning', async () => {
    const signer = createReferenceSigner(RFC_KEY);
    const verifier = createReferenceVerifier();
    const report = await runWebBotAuthSuite({
      signer: () => signer,
      verifier,
      directory: (authority) => referenceDirectoryResponse({ authority, keys: [{ ...RFC_KEY, nbf: 1_700_000_000 }], signingKey: RFC_KEY, now: new Date(NOW_MS) }),
    });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
    expect(report.passed).toBe(report.results.length);
  });

  it('a verifier without a nonce memory passes the MUSTs and gets one warning', async () => {
    const report = await runWebBotAuthSuite({ verifier: createReferenceVerifier({ remember: false }) });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(failed(report)).toEqual(['WV31']);
  });

  it('accepts the vector requests and the vector directory', async () => {
    const verifier = createReferenceVerifier();
    const v = vectors.vectors.find((x) => x.id === 'stack-request-with-directory');
    const directory = vectors.vectors.find((x) => x.id === 'stack-directory-response');
    const fetch = async () => new Response(directory.response.body, { status: 200, headers: directory.response.headers });
    expect(await verifier({ method: v.message.method, url: v.message.url, headers: v.headers, now: vectors.now, fetch })).toBe(true);
  });

  it('skips what it was not given, never passes it', async () => {
    const report = await runWebBotAuthSuite({ directory: (authority) => referenceDirectoryResponse({ authority, keys: [{ ...RFC_KEY, nbf: 1 }], signingKey: RFC_KEY }) });
    expect(report.results.filter((r) => r.status === 'skip').length).toBeGreaterThan(30);
    expect(report.failed).toBe(0);
  });
});

describe('the suite fails an implementation with one defect', () => {
  const badSigner = (patch) => () => {
    const good = createReferenceSigner(RFC_KEY);
    return { publicJwk: good.publicJwk, sign: (input) => patch(good.sign(input), input) };
  };
  const resign = ({ method, url, params, covered, agent }) => {
    const u = new URL(url);
    const lines = covered.map((c) => (c === '@authority' ? `"@authority": ${u.host}` : c === '@method' ? `"@method": ${method.toUpperCase()}` : c === '@path' ? `"@path": ${u.pathname || '/'}` : `${c}: "${agent}"`));
    lines.push(`"@signature-params": ${params}`);
    return `sig1=:${sign(null, Buffer.from(lines.join('\n')), createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', d: RFC_KEY.d, x: RFC_KEY.x }, format: 'jwk' })).toString('base64')}:`;
  };
  const customSigner = (build) => () => ({
    publicJwk: { x: RFC_KEY.x },
    sign: (input) => build(input),
  });
  const q = (s) => `"${s}"`;
  const paramsOf = ({ created = 1_790_000_000, keyid = ed25519Thumbprint(RFC_KEY.x), alg = 'ed25519', lifetime = 300, nonce = randomBytes(64).toString('base64url'), tag = 'web-bot-auth' } = {}) =>
    `;created=${created};keyid=${q(keyid)};alg=${q(alg)};expires=${created + lifetime};nonce=${q(nonce)};tag=${q(tag)}`;

  it('a signer that does not cover the authority', async () => {
    const report = await runWebBotAuthSuite({
      signer: customSigner(({ method, url }) => {
        const covered = ['"@method"', '"@path"'];
        const params = `(${covered.join(' ')})${paramsOf()}`;
        return { Signature: resign({ method, url, params, covered: ['@method', '@path'].map(q) }), 'Signature-Input': `sig1=${params}` };
      }),
    });
    expect(mustFailed(report)).toEqual(expect.arrayContaining(['WS03']));
  });

  it('a signer whose keyid is not the thumbprint, that reuses one nonce, signs for a day and names an http directory', async () => {
    const fixedNonce = Buffer.alloc(64, 7).toString('base64url');
    const report = await runWebBotAuthSuite({
      signer: customSigner(({ method, url, directoryOrigin }) => {
        const covered = ['"@authority"', '"@method"', '"@path"', ...(directoryOrigin ? ['"signature-agent";key="sig1"'] : [])];
        const params = `(${covered.join(' ')})${paramsOf({ keyid: 'my-key', nonce: fixedNonce, lifetime: 90_000 })}`;
        const agent = directoryOrigin ? directoryOrigin.replace(/^https:/, 'http:') : null;
        return {
          Signature: resign({ method, url, params, covered, agent }),
          'Signature-Input': `sig1=${params}`,
          ...(agent ? { 'Signature-Agent': `sig1=${q(agent)}` } : {}),
        };
      }),
    });
    expect(mustFailed(report)).toEqual(expect.arrayContaining(['WS05', 'WS06', 'WS08', 'WS10', 'WS12']));
  });

  it('a signer that signs one thing and sends another', async () => {
    const report = await runWebBotAuthSuite({ signer: badSigner((headers) => ({ ...headers, 'Signature-Input': headers['Signature-Input'].replace('"@path"', '"@query"') })) });
    expect(mustFailed(report)).toEqual(expect.arrayContaining(['WS02']));
  });

  it('a verifier that accepts everything', async () => {
    const report = await runWebBotAuthSuite({ verifier: () => true });
    expect(mustFailed(report)).toEqual(expect.arrayContaining(['WV10', 'WV11', 'WV12', 'WV13', 'WV14', 'WV15', 'WV16', 'WV17', 'WV18', 'WV19', 'WV20', 'WV21', 'WV22', 'WV23', 'WV24', 'WV25']));
  });

  it('a verifier that refuses everything', async () => {
    const report = await runWebBotAuthSuite({ verifier: () => false });
    // WV14 and WV15 also check that a correct signature inside its window is accepted.
    expect(mustFailed(report)).toEqual(['WV01', 'WV02', 'WV03', 'WV04', 'WV14', 'WV15']);
  });

  it('a verifier that never looks at the clock', async () => {
    // The reference, but told that it is always the moment the signature was made.
    const reference = createReferenceVerifier();
    const report = await runWebBotAuthSuite({
      verifier: (input) => reference({ ...input, now: Number(/created=(\d+)/.exec(input.headers['signature-input'])?.[1] ?? input.now) }),
    });
    expect(mustFailed(report)).toEqual(['WV14', 'WV15']);
  });

  it('a verifier that finds the key through a Signature-Agent the signature does not cover', async () => {
    const report = await runWebBotAuthSuite({
      verifier: async ({ method, url, headers, fetch }) => {
        // Checks the signature properly, but takes the directory from the header whether or not it is covered.
        const agent = /="([^"]+)"/.exec(headers['signature-agent'] ?? '')?.[1];
        if (!agent) return false;
        const directory = await (await fetch(`${agent}/.well-known/http-message-signatures-directory`)).json();
        const input = parseSignatureInput(headers['signature-input']).get('sig1');
        const key = directory.keys.find((k) => k.kid === paramOf(input.params, 'keyid'));
        if (!key) return false;
        const base = signatureBaseFrom(input.components, input.text, { method, url, headers });
        return verifyEd25519(base, parseSignature(headers.signature).get('sig1'), publicKeyFromX(key.x));
      },
    });
    expect(mustFailed(report)).toContain('WV20');
  });

  it('a directory with the wrong media type, a private member and no signature', async () => {
    const report = await runWebBotAuthSuite({
      directory: (authority) => {
        const response = buildDirectory({ authority, keys: [RFC_KEY], mediaType: 'application/json' });
        const body = JSON.parse(response.body);
        body.keys[0].d = RFC_KEY.d;
        const { signature: _s, 'signature-input': _i, ...headers } = response.headers;
        return { ...response, headers, body: JSON.stringify(body) };
      },
    });
    expect(mustFailed(report)).toEqual(expect.arrayContaining(['WD01', 'WD03', 'WD05']));
  });

  it('a directory whose signature is for one host whatever host it is asked at', async () => {
    const report = await runWebBotAuthSuite({ directory: () => buildDirectory({ authority: 'fixed.example', keys: [RFC_KEY] }) });
    expect(mustFailed(report)).toEqual(expect.arrayContaining(['WD05', 'WD06']));
  });

  it('a directory that lists a key under the wrong kid', async () => {
    const report = await runWebBotAuthSuite({
      directory: (authority) => {
        const response = buildDirectory({ authority, keys: [{ ...OTHER_KEY, kid: 'not-the-thumbprint' }], signingKey: OTHER_KEY });
        return response;
      },
    });
    expect(mustFailed(report)).toContain('WD04');
  });
});

