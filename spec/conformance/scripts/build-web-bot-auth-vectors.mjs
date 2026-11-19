#!/usr/bin/env node
// Builds the Web Bot Auth test vectors in fixtures/web-bot-auth/vectors.json, from the
// specification and the published vectors alone (RFC 9421 appendix B.2.6, the Web Bot Auth
// architecture draft appendix A.2, and two vectors of the STACK profile). Ed25519 is
// deterministic, so with a fixed nonce and clock the file is the same bytes every time. The key
// is the Ed25519 TEST key of RFC 9421 appendix B.1.4; it is for these vectors only.
// `--check` fails if the file on disk differs from a fresh build.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519Thumbprint, privateKeyFromJwk, signEd25519, signatureBase } from '../src/http-signature.mjs';
import { RFC_KEY, buildDirectory, signRequest } from '../src/web-bot-auth.mjs';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'web-bot-auth');
const NOW = 1_790_000_000;
const NONCE = Buffer.alloc(64, 1).toString('base64url');
const key = privateKeyFromJwk(RFC_KEY);

// RFC 9421 B.2.6: the published request, covered components, parameters and signature.
const rfcComponents = ['date', '@method', '@path', '@authority', 'content-type', 'content-length'].map((name) => ({ name }));
const rfcParams = [{ name: 'created', value: 1618884473 }, { name: 'keyid', value: 'test-key-ed25519' }];
const rfcMessage = {
  method: 'POST',
  url: 'https://example.com/foo?param=Value&Pet=dog',
  headers: { date: 'Tue, 20 Apr 2021 02:07:55 GMT', 'content-type': 'application/json', 'content-length': '18' },
};
const rfcBase = signatureBase(rfcComponents, rfcParams, rfcMessage);

// The architecture draft A.2.1: Ed25519, no Signature-Agent.
const draftNonce = 'g0iqFa9e1ffijlyOScDkXpfSmTbYpRNSGPJrQ1It20ahwgzB3jOUcdgLgFxUg7RMtW4V8IILaKKtA+YuSyIgJQ==';
const draftParams = [
  { name: 'created', value: 1735689600 },
  { name: 'keyid', value: ed25519Thumbprint(RFC_KEY.x) },
  { name: 'alg', value: 'ed25519' },
  { name: 'expires', value: 4889289600 },
  { name: 'nonce', value: draftNonce },
  { name: 'tag', value: 'web-bot-auth' },
];
const draftMessage = { method: 'GET', url: 'https://example.com/path/to/resource', headers: {} };
const draftBase = signatureBase([{ name: '@authority' }], draftParams, draftMessage);

// A.2.2: a covered Signature-Agent dictionary member.
const agentParams = draftParams.filter((p) => p.name !== 'nonce');
const agentMessage = { method: 'GET', url: 'https://example.com/', headers: { 'signature-agent': 'agent2="https://signature-agent.test"' } };
const agentComponents = [{ name: '@authority' }, { name: 'signature-agent', key: 'agent2' }];
const agentBase = signatureBase(agentComponents, agentParams, agentMessage);

const stackRequest = signRequest({
  method: 'GET', url: 'https://shop.example/products/42?utm=1', now: NOW, directoryOrigin: 'https://agent.example', params: { nonce: NONCE },
});
const stackNoAgent = signRequest({ method: 'POST', url: 'https://Shop.Example:8443/a%20b?x=1', now: NOW, directoryOrigin: null, params: { nonce: NONCE } });
const stackDirectory = buildDirectory({ authority: 'agent.example', keys: [RFC_KEY], now: NOW });

const vectors = {
  description: 'Web Bot Auth test vectors. Regenerate with `node spec/conformance/scripts/build-web-bot-auth-vectors.mjs`. The key is the RFC 9421 appendix B.1.4 TEST key. `base` is the signature base (lines joined by a newline, no trailing newline); `signature` is the standard base64 Ed25519 signature over it.',
  key: { kty: 'OKP', crv: 'Ed25519', x: RFC_KEY.x, d: RFC_KEY.d, thumbprint: ed25519Thumbprint(RFC_KEY.x) },
  now: NOW,
  vectors: [
    {
      id: 'rfc9421-b26',
      source: 'RFC 9421 appendix B.2.6',
      message: rfcMessage,
      covered: ['date', '@method', '@path', '@authority', 'content-type', 'content-length'],
      base: rfcBase,
      signature: signEd25519(rfcBase, key),
    },
    {
      id: 'web-bot-auth-draft-a21',
      source: 'draft-meunier-web-bot-auth-architecture appendix A.2.1',
      message: draftMessage,
      covered: ['@authority'],
      base: draftBase,
      signature: signEd25519(draftBase, key),
    },
    {
      id: 'web-bot-auth-draft-a22',
      source: 'draft-meunier-web-bot-auth-architecture appendix A.2.2 (the Signature-Agent member covered)',
      message: agentMessage,
      covered: ['@authority', 'signature-agent;key="agent2"'],
      base: agentBase,
      signature: signEd25519(agentBase, key),
    },
    {
      id: 'stack-request-with-directory',
      source: 'STACK profile, section 3: a request that names a directory',
      message: { method: stackRequest.message.method, url: stackRequest.message.url, headers: { 'signature-agent': stackRequest.headers['signature-agent'] } },
      headers: { 'signature-input': stackRequest.headers['signature-input'], signature: stackRequest.headers.signature, 'signature-agent': stackRequest.headers['signature-agent'] },
      base: stackRequest.base,
      signature: /^sig1=:(.+):$/.exec(stackRequest.headers.signature)[1],
    },
    {
      id: 'stack-request-no-directory-port-and-query',
      source: 'STACK profile, section 3: no Signature-Agent, an upper-case host with a port, an escaped path and a query',
      message: { method: stackNoAgent.message.method, url: stackNoAgent.message.url, headers: {} },
      headers: { 'signature-input': stackNoAgent.headers['signature-input'], signature: stackNoAgent.headers.signature },
      base: stackNoAgent.base,
      signature: /^sig1=:(.+):$/.exec(stackNoAgent.headers.signature)[1],
    },
    {
      id: 'stack-directory-response',
      source: 'STACK profile, section 5: the directory of one key, asked at agent.example',
      authority: 'agent.example',
      response: { status: stackDirectory.status, headers: stackDirectory.headers, body: stackDirectory.body },
    },
  ],
};

const content = `${JSON.stringify(vectors, null, 2)}\n`;
const path = join(OUT, 'vectors.json');
const check = process.argv.includes('--check');
const current = existsSync(path) ? readFileSync(path, 'utf8').replaceAll('\r\n', '\n') : null;
if (check) {
  if (current !== content) {
    console.error('the Web Bot Auth vectors are out of date; run `node scripts/build-web-bot-auth-vectors.mjs`');
    process.exit(1);
  }
  console.log('web-bot-auth vectors are current');
} else if (current !== content) {
  mkdirSync(OUT, { recursive: true });
  writeFileSync(path, content, 'utf8');
  console.log('wrote the Web Bot Auth vectors');
} else console.log('web-bot-auth vectors unchanged');
