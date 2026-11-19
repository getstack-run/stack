// Conformance suite for Web Bot Auth as STACK profiles it (spec/web-bot-auth/SPEC.md). Three
// things can be judged, each by handing the kit one handle:
//
//   signer    an agent-side signer: given a request it returns the `Signature-Input`, `Signature`
//             and `Signature-Agent` headers. The kit rebuilds the signature base itself and checks
//             the signature, the covered components and the parameters (sections 3 and 4).
//   verifier  a site-side verifier: given a request as the site received it, and a `fetch` that
//             serves the key directories the kit publishes, it says whether it accepts the
//             request. The kit signs requests and damages them one way at a time (section 6).
//   directory a served key directory: the response a client gets at the well-known path, for an
//             authority, as `{ status, headers, body }` (section 5).
//
// A check that needs a handle you did not provide is reported as skipped, never as passed.

import { createPrivateKey, randomBytes } from 'node:crypto';
import { assert, runChecks, skip } from './harness.mjs';
import {
  ed25519Thumbprint,
  paramOf,
  parseSignature,
  parseSignatureInput,
  privateKeyFromJwk,
  publicKeyFromX,
  signEd25519,
  signatureBaseFrom,
  signatureParamsValue,
  verifyEd25519,
} from './http-signature.mjs';

export const DIRECTORY_PATH = '/.well-known/http-message-signatures-directory';
export const DIRECTORY_MEDIA_TYPE = 'application/http-message-signatures-directory+json';
export const WEB_BOT_AUTH_TAG = 'web-bot-auth';
export const DIRECTORY_TAG = 'http-message-signatures-directory';
export const SIGNATURE_LABEL = 'sig1';
export const SIGNATURE_VALIDITY_SECONDS = 300;
/** How far ahead of its clock a verifier tolerates a `created`, in seconds. */
export const CLOCK_SKEW_SECONDS = 60;

/** The Ed25519 key of RFC 9421 appendix B.1.4, which the Web Bot Auth draft's vectors use too. A TEST key. */
export const RFC_KEY = {
  x: 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs',
  d: 'n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU',
};
RFC_KEY.kid = ed25519Thumbprint(RFC_KEY.x);

/** Another test key, from a fixed seed, for the checks that need a key that is not the signer's. */
export const OTHER_KEY = (() => {
  // The PKCS#8 prefix of an Ed25519 private key, then the 32-byte seed.
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 0x42)]);
  const jwk = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }).export({ format: 'jwk' });
  return { x: jwk.x, d: jwk.d, kid: ed25519Thumbprint(jwk.x) };
})();

const b64url = (bytes) => Buffer.from(bytes).toString('base64url');

// ─── What the kit signs ──────────────────────────────────────────

/**
 * Sign a request the way the profile says, with every part overridable, so a check can damage
 * exactly one thing. Returns the headers and the message they belong to.
 *
 * @param {{
 *   key?: { d: string, x: string, kid?: string },
 *   method?: string, url?: string, now?: number,
 *   directoryOrigin?: string | null,
 *   coverAgent?: boolean,          // cover `signature-agent` (default: when a directory is named)
 *   agentHeader?: string,          // the Signature-Agent header text, when it is not the usual one
 *   components?: object[],         // the covered components, replacing the usual list
 *   params?: object,               // replace or drop (undefined) a parameter by name
 *   label?: string,
 * }} input
 */
export function signRequest(input = {}) {
  const key = input.key ?? RFC_KEY;
  const keyid = key.kid ?? ed25519Thumbprint(key.x);
  const method = input.method ?? 'GET';
  const url = input.url ?? 'https://shop.example/products/42?utm=1';
  const now = input.now ?? 1_790_000_000;
  const label = input.label ?? SIGNATURE_LABEL;
  const directoryOrigin = input.directoryOrigin === undefined ? 'https://agent.example' : input.directoryOrigin;
  const headers = {};
  const components = input.components ? [...input.components] : [{ name: '@authority' }, { name: '@method' }, { name: '@path' }];
  if (directoryOrigin !== null) {
    headers['signature-agent'] = input.agentHeader ?? `${label}="${directoryOrigin}"`;
    if (!input.components && input.coverAgent !== false) components.push({ name: 'signature-agent', key: label });
  }
  const defaults = {
    created: now,
    keyid,
    alg: 'ed25519',
    expires: now + SIGNATURE_VALIDITY_SECONDS,
    nonce: b64url(randomBytes(64)),
    tag: WEB_BOT_AUTH_TAG,
  };
  const overrides = input.params ?? {};
  const params = [];
  for (const name of Object.keys(defaults)) {
    const value = Object.hasOwn(overrides, name) ? overrides[name] : defaults[name];
    if (value !== undefined) params.push({ name, value });
  }
  const message = { method, url, headers };
  const paramsText = signatureParamsValue(components, params);
  const base = signatureBaseFrom(components, paramsText, message);
  const signature = signEd25519(base, privateKeyFromJwk(key));
  return {
    headers: {
      ...headers,
      signature: `${label}=:${signature}:`,
      'signature-input': `${label}=${paramsText}`,
    },
    message: { method, url },
    origin: directoryOrigin,
    base,
    now,
  };
}

/** A key directory response as a server of the profile writes it. */
export function buildDirectory({ authority, keys, signingKey = RFC_KEY, now = 1_790_000_000, covered = [{ name: '@authority', req: true }], params, mediaType = DIRECTORY_MEDIA_TYPE }) {
  const body = JSON.stringify({
    keys: keys.map((k) => ({
      kty: 'OKP',
      crv: 'Ed25519',
      x: k.x,
      kid: k.kid ?? ed25519Thumbprint(k.x),
      use: 'sig',
      nbf: k.nbf ?? now - 3600,
      ...(k.exp === undefined ? {} : { exp: k.exp }),
    })),
  });
  const signed = params ?? [
    { name: 'created', value: now },
    { name: 'keyid', value: signingKey.kid ?? ed25519Thumbprint(signingKey.x) },
    { name: 'alg', value: 'ed25519' },
    { name: 'expires', value: now + 86_400 },
    { name: 'tag', value: DIRECTORY_TAG },
  ];
  const paramsText = signatureParamsValue(covered, signed);
  const base = signatureBaseFrom(covered, paramsText, { method: 'GET', url: `https://${authority}${DIRECTORY_PATH}`, headers: {} });
  return {
    status: 200,
    headers: {
      'content-type': mediaType,
      'cache-control': 'public, max-age=300',
      signature: `${SIGNATURE_LABEL}=:${signEd25519(base, privateKeyFromJwk(signingKey))}:`,
      'signature-input': `${SIGNATURE_LABEL}=${paramsText}`,
    },
    body,
  };
}

/** A `fetch` that serves the directories of a map from origin to `{ status, headers, body }`. */
export function directoryFetch(directories, calls = []) {
  return async (input) => {
    const url = new URL(typeof input === 'string' ? input : input.url ?? input.href);
    calls.push(url.href);
    const entry = url.pathname === DIRECTORY_PATH ? directories[url.origin] : undefined;
    if (!entry) return new Response('not found', { status: 404 });
    return new Response(entry.body, { status: entry.status, headers: entry.headers });
  };
}

// ─── Reading what a signer sent ──────────────────────────────────

function lower(headers) {
  return Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
}

/** Parse the signature a signer produced: its components, parameters, signature bytes and the base. */
function readSignature(headers, message) {
  const h = lower(headers);
  assert(typeof h['signature-input'] === 'string', 'no Signature-Input header');
  assert(typeof h['signature'] === 'string', 'no Signature header');
  const inputs = parseSignatureInput(h['signature-input']);
  const signatures = parseSignature(h['signature']);
  assert(inputs.size >= 1, 'Signature-Input is empty');
  const label = [...inputs.keys()].find((l) => paramOf(inputs.get(l).params, 'tag') === WEB_BOT_AUTH_TAG);
  assert(label !== undefined, `no signature carries the tag ${WEB_BOT_AUTH_TAG}`);
  assert(signatures.has(label), `Signature has no member ${label}`);
  const input = inputs.get(label);
  const base = signatureBaseFrom(input.components, input.text, { ...message, headers: h });
  return { label, ...input, signature: signatures.get(label), base, headers: h };
}

function acceptance(outcome) {
  return typeof outcome === 'boolean' ? outcome : outcome?.ok === true;
}

// ─── The suite ───────────────────────────────────────────────────

/**
 * @param {{
 *   signer?: () => ({ sign(input: { method: string, url: string, now: Date, directoryOrigin: string | null }): Promise<Record<string, string>> | Record<string, string>, publicJwk: { x: string } }) | Promise<unknown>,
 *   verifier?: (input: { method: string, url: string, headers: Record<string, string>, now: number, fetch: typeof fetch }) => boolean | { ok: boolean } | Promise<boolean | { ok: boolean }>,
 *   directory?: (authority: string) => Promise<{ status: number, headers: Record<string, string>, body: string }> | { status: number, headers: Record<string, string>, body: string },
 *   directoryHost?: string,   // the one host the directory can be asked as, when it is served at a real address
 * }} options
 */
export async function runWebBotAuthSuite(options) {
  const { signer: makeSigner, verifier, directory } = options;
  // A directory served at one address can only be asked as that host: give it as `directoryHost`.
  const directoryHost = options.directoryHost ?? 'agent.example';
  if (!makeSigner && !verifier && !directory) throw new Error('give the web-bot-auth suite a signer, a verifier or a directory');
  const need = (handle, what) => (handle ? null : skip(`needs ${what}`));
  const NOW = 1_790_000_000;
  const AGENT = 'https://agent.example';
  const SITE = 'https://shop.example';
  const REQUEST = { method: 'GET', url: `${SITE}/products/42?utm=1` };

  // ── signer ──
  let signerInstance;
  const signerOf = async () => {
    signerInstance ??= await makeSigner();
    return signerInstance;
  };
  const sign = async (input = {}) => {
    const s = await signerOf();
    const request = { method: 'GET', url: `${SITE}/products/42?utm=1`, directoryOrigin: AGENT, now: new Date(NOW * 1000), ...input };
    const headers = await s.sign(request);
    return { headers, request, s };
  };
  const readOf = async (input) => {
    const { headers, request, s } = await sign(input);
    return { ...readSignature(headers, { method: request.method, url: request.url }), request, publicX: s.publicJwk.x };
  };

  // ── verifier ──
  // A verifier may cache a directory for its max-age, so a check that changes what a directory says names its own origin.
  let originCounter = 0;
  const freshOrigin = () => `https://agent${(originCounter += 1)}.example`;
  const hostOf = (origin) => new URL(origin).host;
  const present = async ({ headers, method = REQUEST.method, url = REQUEST.url, directories, now = NOW, calls }) => {
    const outcome = await verifier({
      method,
      url,
      headers: { ...lower(headers) },
      now,
      fetch: directoryFetch(directories ?? {}, calls),
    });
    return acceptance(outcome);
  };
  const good = (extra = {}) => signRequest({ method: REQUEST.method, url: REQUEST.url, now: NOW, directoryOrigin: freshOrigin(), ...extra });
  /** The directory a correct server publishes at the origin a signed request names, or one changed by `directory`. */
  const directoryOf = (signed, change = {}) => ({
    [signed.origin]: buildDirectory({ authority: hostOf(signed.origin), keys: [RFC_KEY], now: NOW, ...change }),
  });
  const accepts = async (signed, extra = {}) =>
    present({ headers: signed.headers, method: signed.message.method, url: signed.message.url, directories: directoryOf(signed), ...extra });

  // ── directory ──
  const fetchDirectory = async (authority) => {
    const response = await directory(authority);
    return { status: response.status, headers: lower(response.headers ?? {}), body: response.body };
  };
  const readDirectory = async (authority = directoryHost) => {
    const response = await fetchDirectory(authority);
    assert(response.status === 200, `the directory answered ${response.status}`);
    let parsed;
    try {
      parsed = JSON.parse(response.body);
    } catch {
      throw new Error('the directory body is not JSON');
    }
    return { ...response, parsed, authority };
  };

  return runChecks('web-bot-auth', [
    // ─── signer ──────────────────────────────────────────────────
    {
      id: 'WS01', level: 'MUST', title: 'signs with the three headers: Signature-Input, Signature and, when a directory is named, Signature-Agent',
      async run() {
        const skipped = need(makeSigner, 'a signer');
        if (skipped) return skipped;
        const { headers } = await sign();
        const h = lower(headers);
        assert(h['signature-input'] && h['signature'], 'Signature-Input or Signature is missing');
        assert(h['signature-agent'], 'no Signature-Agent although a directory was named');
        const r = await readOf();
        assert(r.signature.length > 0 && Buffer.from(r.signature, 'base64').length === 64, 'the signature is not 64 bytes (Ed25519)');
      },
    },
    {
      id: 'WS02', level: 'MUST', title: 'the signature verifies, over the base the profile defines, under the key the signer publishes',
      async run() {
        const skipped = need(makeSigner, 'a signer');
        if (skipped) return skipped;
        const r = await readOf();
        assert(verifyEd25519(r.base, r.signature, publicKeyFromX(r.publicX)), 'the signature does not verify against the rebuilt signature base');
      },
    },
    {
      id: 'WS03', level: 'MUST', title: 'covers @authority, @method and @path, so a signature is no good for another host, verb or path',
      async run() {
        const skipped = need(makeSigner, 'a signer');
        if (skipped) return skipped;
        const r = await readOf({ directoryOrigin: null });
        const names = r.components.map((c) => c.name);
        for (const required of ['@authority', '@method', '@path']) assert(names.includes(required), `${required} is not covered`);
        const key = publicKeyFromX(r.publicX);
        for (const other of [
          { ...REQUEST, url: 'https://evil.example/products/42' },
          { ...REQUEST, method: 'POST' },
          { ...REQUEST, url: `${SITE}/admin` },
        ]) {
          const base = signatureBaseFrom(r.components, r.text, { method: other.method, url: other.url, headers: r.headers });
          assert(!verifyEd25519(base, r.signature, key), `the signature also verifies for ${other.method} ${other.url}`);
        }
      },
    },
    {
      id: 'WS04', level: 'MUST', title: 'carries created, keyid, alg="ed25519", expires, nonce and tag="web-bot-auth"',
      async run() {
        const skipped = need(makeSigner, 'a signer');
        if (skipped) return skipped;
        const r = await readOf();
        for (const name of ['created', 'keyid', 'alg', 'expires', 'nonce', 'tag']) assert(paramOf(r.params, name) !== undefined, `the parameter ${name} is missing`);
        assert(paramOf(r.params, 'alg') === 'ed25519', 'alg is not "ed25519"');
        assert(paramOf(r.params, 'tag') === WEB_BOT_AUTH_TAG, `tag is not ${JSON.stringify(WEB_BOT_AUTH_TAG)}`);
        assert(Number.isInteger(paramOf(r.params, 'created')) && Number.isInteger(paramOf(r.params, 'expires')), 'created and expires are integers');
      },
    },
    {
      id: 'WS05', level: 'MUST', title: 'names the key by its JWK thumbprint: keyid is the RFC 7638 thumbprint of the public key',
      async run() {
        const skipped = need(makeSigner, 'a signer');
        if (skipped) return skipped;
        const r = await readOf();
        const expected = ed25519Thumbprint(r.publicX);
        assert(paramOf(r.params, 'keyid') === expected, `keyid is ${JSON.stringify(paramOf(r.params, 'keyid'))}, the thumbprint of the key is ${JSON.stringify(expected)}`);
      },
    },
    {
      id: 'WS06', level: 'MUST', title: 'created is the time of signing and the signature lives at most 24 hours',
      async run() {
        const skipped = need(makeSigner, 'a signer');
        if (skipped) return skipped;
        const r = await readOf();
        const created = paramOf(r.params, 'created');
        const expires = paramOf(r.params, 'expires');
        assert(Math.abs(created - NOW) <= 1, `created is ${created}, the request was signed at ${NOW}`);
        assert(expires > created && expires - created <= 86_400, `expires - created is ${expires - created} s: it must be positive and at most 86400`);
      },
    },
    {
      id: 'WS07', level: 'SHOULD', title: 'a signature lives five minutes at most: it is for one request',
      async run() {
        const skipped = need(makeSigner, 'a signer');
        if (skipped) return skipped;
        const r = await readOf();
        const lifetime = paramOf(r.params, 'expires') - paramOf(r.params, 'created');
        assert(lifetime <= SIGNATURE_VALIDITY_SECONDS, `a signature lives ${lifetime} s`);
      },
    },
    {
      id: 'WS08', level: 'MUST', title: 'every signature has its own nonce',
      async run() {
        const skipped = need(makeSigner, 'a signer');
        if (skipped) return skipped;
        const a = await readOf();
        const b = await readOf();
        const na = paramOf(a.params, 'nonce');
        assert(typeof na === 'string' && na.length >= 22, 'the nonce is missing or too short to be unguessable');
        assert(na !== paramOf(b.params, 'nonce'), 'two signatures of the same request carry the same nonce');
      },
    },
    {
      id: 'WS09', level: 'SHOULD', title: 'the nonce is 64 random bytes, base64url without padding',
      async run() {
        const skipped = need(makeSigner, 'a signer');
        if (skipped) return skipped;
        const nonce = paramOf((await readOf()).params, 'nonce');
        assert(/^[A-Za-z0-9_-]{86}$/.test(nonce), 'the nonce is not 86 base64url characters');
      },
    },
    {
      id: 'WS10', level: 'MUST', title: 'Signature-Agent is a dictionary member with the signature\'s label, an https origin, and is itself covered',
      async run() {
        const skipped = need(makeSigner, 'a signer');
        if (skipped) return skipped;
        const r = await readOf();
        const agent = r.headers['signature-agent'];
        assert(agent === `${r.label}="${AGENT}"`, `Signature-Agent is ${JSON.stringify(agent)}, expected ${r.label}="${AGENT}"`);
        assert(r.components.some((c) => c.name === 'signature-agent' && c.key === r.label), 'Signature-Agent is not covered');
      },
    },
    {
      id: 'WS11', level: 'MUST', title: 'writes a directory origin without its trailing slash, and keeps it covered',
      async run() {
        const skipped = need(makeSigner, 'a signer');
        if (skipped) return skipped;
        const r = await readOf({ directoryOrigin: `${AGENT}/` });
        assert(r.headers['signature-agent'] === `${r.label}="${AGENT}"`, `Signature-Agent is ${JSON.stringify(r.headers['signature-agent'])}`);
      },
    },
    {
      id: 'WS12', level: 'MUST', title: 'never names a directory that is not an https origin: no http, path, query or credentials',
      async run() {
        const skipped = need(makeSigner, 'a signer');
        if (skipped) return skipped;
        for (const bad of ['http://agent.example', `${AGENT}/keys`, `${AGENT}/?q=1`, 'https://u:p@agent.example']) {
          let headers;
          try {
            ({ headers } = await sign({ directoryOrigin: bad }));
          } catch {
            continue;
          }
          assert(!lower(headers)['signature-agent'], `Signature-Agent was sent for ${bad}`);
        }
      },
    },
    {
      id: 'WS13', level: 'MUST', title: 'leaves Signature-Agent out, and uncovered, when no directory is named',
      async run() {
        const skipped = need(makeSigner, 'a signer');
        if (skipped) return skipped;
        const r = await readOf({ directoryOrigin: null });
        assert(!r.headers['signature-agent'], 'Signature-Agent was sent with no directory');
        assert(!r.components.some((c) => c.name === 'signature-agent'), 'Signature-Agent is covered though absent');
        assert(verifyEd25519(r.base, r.signature, publicKeyFromX(r.publicX)), 'the signature without a directory does not verify');
      },
    },
    {
      id: 'WS14', level: 'MUST', title: 'reads the authority as RFC 9421 does: lower case, the port kept, the query not part of the path',
      async run() {
        const skipped = need(makeSigner, 'a signer');
        if (skipped) return skipped;
        const r = await readOf({ method: 'POST', url: 'https://Shop.Example:8443/a%20b?x=1&y=2', directoryOrigin: null });
        const lines = r.base.split('\n');
        assert(lines.includes('"@authority": shop.example:8443'), `the base has ${JSON.stringify(lines.find((l) => l.startsWith('"@authority"')))}`);
        assert(verifyEd25519(r.base, r.signature, publicKeyFromX(r.publicX)), 'the signature does not verify for a request with a port, a query and an escaped path');
        const root = await readOf({ url: 'https://shop.example', directoryOrigin: null });
        assert(root.base.split('\n').includes('"@path": /'), 'an empty path is not signed as /');
        assert(verifyEd25519(root.base, root.signature, publicKeyFromX(root.publicX)), 'the signature for the root path does not verify');
      },
    },

    // ─── verifier ────────────────────────────────────────────────
    {
      id: 'WV01', level: 'MUST', title: 'accepts a correctly signed request whose key is in the directory its covered Signature-Agent names',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        assert(await accepts(good()), 'a correct request was refused');
      },
    },
    {
      id: 'WV02', level: 'MUST', title: 'verifies the request as received: a port, a query and an escaped path are read as RFC 9421 reads them',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        const signed = good({ url: 'https://Shop.Example:8443/a%20b?x=1', method: 'POST' });
        assert(await accepts(signed), 'a request with a port, a query and an escaped path was refused');
        const root = good({ url: 'https://shop.example' });
        assert(await accepts(root), 'a request for the root path was refused');
      },
    },
    {
      id: 'WV03', level: 'MUST', title: 'accepts a signature made by a key the directory still publishes after its retirement (exp in the future)',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        const signed = good();
        const directories = directoryOf(signed, { keys: [{ ...OTHER_KEY }, { ...RFC_KEY, exp: NOW + 100_000 }], signingKey: OTHER_KEY });
        assert(await accepts(signed, { directories }), 'a signature by a retiring key was refused');
      },
    },
    {
      id: 'WV04', level: 'MUST', title: 'accepts a request that carries a second, unrelated signature beside the web-bot-auth one',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        const signed = good();
        const other = signRequest({ key: OTHER_KEY, label: 'other', directoryOrigin: null, params: { tag: 'something-else' } });
        const headers = {
          ...signed.headers,
          'signature-input': `${other.headers['signature-input']}, ${signed.headers['signature-input']}`,
          signature: `${other.headers.signature}, ${signed.headers.signature}`,
        };
        assert(await present({ headers, method: signed.message.method, url: signed.message.url, directories: directoryOf(signed) }), 'the web-bot-auth signature was not found beside another');
      },
    },
    {
      id: 'WV10', level: 'MUST', title: 'refuses a request with no signature headers',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        assert(!(await present({ headers: {} })), 'an unsigned request was accepted');
        const signed = good();
        const { signature: _s, ...withoutSignature } = signed.headers;
        assert(!(await present({ headers: withoutSignature, directories: directoryOf(signed) })), 'a request with Signature-Input and no Signature was accepted');
      },
    },
    {
      id: 'WV11', level: 'MUST', title: 'refuses a signature made for another authority, method or path (a replay at another resource)',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        const signed = good();
        const directories = directoryOf(signed);
        assert(!(await present({ headers: signed.headers, method: 'GET', url: 'https://evil.example/products/42?utm=1', directories })), 'another host was accepted');
        assert(!(await present({ headers: signed.headers, method: 'POST', url: REQUEST.url, directories })), 'another method was accepted');
        assert(!(await present({ headers: signed.headers, method: 'GET', url: `${SITE}/admin`, directories })), 'another path was accepted');
      },
    },
    {
      id: 'WV12', level: 'MUST', title: 'refuses a signature that was not made by the key its keyid names',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        const forged = good({ key: { ...OTHER_KEY, kid: RFC_KEY.kid } });
        assert(!(await accepts(forged)), 'a signature by another key under the published keyid was accepted');
      },
    },
    {
      id: 'WV13', level: 'MUST', title: 'refuses a keyid that is not in the directory',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        assert(!(await accepts(good({ key: OTHER_KEY }))), 'a key the directory does not publish was accepted');
      },
    },
    {
      id: 'WV14', level: 'MUST', title: 'refuses a signature past its expires',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        assert(await accepts(good(), { now: NOW + 299 }), 'a signature inside its lifetime was refused');
        assert(!(await accepts(good(), { now: NOW + 301 })), 'an expired signature was accepted');
      },
    },
    {
      id: 'WV15', level: 'MUST', title: 'refuses a signature created in the future, beyond the clock skew it allows',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        assert(await accepts(good({ params: { created: NOW + 30, expires: NOW + 330 } })), 'a created 30 s ahead of the clock was refused');
        assert(!(await accepts(good({ params: { created: NOW + 600, expires: NOW + 900 } }))), 'a created ten minutes ahead of the clock was accepted');
      },
    },
    {
      id: 'WV16', level: 'MUST', title: 'refuses a signature without created or without expires',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        assert(!(await accepts(good({ params: { expires: undefined } }))), 'a signature with no expires was accepted');
        assert(!(await accepts(good({ params: { created: undefined } }))), 'a signature with no created was accepted');
      },
    },
    {
      id: 'WV17', level: 'MUST', title: 'refuses a signature whose tag is not web-bot-auth',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        assert(!(await accepts(good({ params: { tag: 'something-else' } }))), 'another tag was accepted');
        assert(!(await accepts(good({ params: { tag: undefined } }))), 'a signature with no tag was accepted');
      },
    },
    {
      id: 'WV18', level: 'MUST', title: 'refuses an alg that is not ed25519',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        assert(!(await accepts(good({ params: { alg: 'rsa-pss-sha512' } }))), 'another algorithm was accepted');
      },
    },
    {
      id: 'WV19', level: 'MUST', title: 'refuses a signature that does not cover @authority',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        const components = [{ name: '@method' }, { name: '@path' }, { name: 'signature-agent', key: 'sig1' }];
        assert(!(await accepts(good({ components }))), 'a signature that leaves out @authority was accepted');
      },
    },
    {
      id: 'WV20', level: 'MUST', title: 'does not look for a key at a Signature-Agent the signature does not cover',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        // Signed by a key that only the attacker's directory publishes, with a Signature-Agent added afterwards.
        const signed = signRequest({ key: OTHER_KEY, directoryOrigin: null, method: REQUEST.method, url: REQUEST.url, now: NOW });
        const attacker = freshOrigin();
        const headers = { ...signed.headers, 'signature-agent': `sig1="${attacker}"` };
        const directories = { [attacker]: buildDirectory({ authority: hostOf(attacker), keys: [OTHER_KEY], signingKey: OTHER_KEY, now: NOW }) };
        assert(!(await present({ headers, method: signed.message.method, url: signed.message.url, directories })), 'a key was taken from an uncovered Signature-Agent');
      },
    },
    {
      id: 'WV21', level: 'MUST', title: 'refuses a request whose covered Signature-Agent was changed after signing',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        const signed = good();
        const attacker = freshOrigin();
        const headers = { ...signed.headers, 'signature-agent': `sig1="${attacker}"` };
        const directories = {
          ...directoryOf(signed),
          [attacker]: buildDirectory({ authority: hostOf(attacker), keys: [RFC_KEY], now: NOW }),
        };
        assert(!(await present({ headers, method: signed.message.method, url: signed.message.url, directories })), 'a changed Signature-Agent was accepted');
      },
    },
    {
      id: 'WV22', level: 'MUST', title: 'refuses a Signature-Agent that is not an https origin',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        for (const make of [(h) => `http://${h}`, (h) => `https://${h}/keys`, (h) => `https://u:p@${h}`]) {
          const origin = freshOrigin();
          const named = make(hostOf(origin));
          const signed = good({ directoryOrigin: origin, agentHeader: `sig1="${named}"` });
          // The directory is served at the origin of the name as well as at the host's https origin.
          const directories = { ...directoryOf(signed), [origin]: buildDirectory({ authority: hostOf(origin), keys: [RFC_KEY], now: NOW }) };
          assert(!(await accepts(signed, { directories })), `${named} was accepted as a directory`);
        }
      },
    },
    {
      id: 'WV23', level: 'MUST', title: 'refuses a signature made before its key came into use (created before nbf) or after it was retired (created at or after exp)',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        const early = good();
        assert(!(await accepts(early, { directories: directoryOf(early, { keys: [{ ...RFC_KEY, nbf: NOW + 3600 }] }) })), 'a signature older than its key was accepted');
        const late = good();
        assert(!(await accepts(late, { directories: directoryOf(late, { keys: [{ ...RFC_KEY, nbf: NOW - 7200, exp: NOW - 60 }] }) })), 'a signature made after its key was retired was accepted');
      },
    },
    {
      id: 'WV24', level: 'MUST', title: 'refuses malformed signature headers without failing open',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        const signed = good();
        for (const [name, value] of [
          ['signature-input', 'not a dictionary'],
          ['signature-input', 'sig1=("@authority"'],
          ['signature', 'sig1=not-a-byte-sequence'],
          ['signature', 'sig1=:!!!:'],
          ['signature', ''],
        ]) {
          assert(!(await present({ headers: { ...signed.headers, [name]: value }, method: signed.message.method, url: signed.message.url, directories: directoryOf(signed) })), `accepted ${name}: ${JSON.stringify(value)}`);
        }
      },
    },
    {
      id: 'WV25', level: 'MUST', title: 'refuses a key directory that does not answer 200 or is not JSON with keys',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        for (const change of [{ status: 404 }, { body: 'not json' }, { body: '{"keys":[]}' }]) {
          const signed = good();
          const directory = { ...directoryOf(signed)[signed.origin], ...change };
          assert(!(await accepts(signed, { directories: { [signed.origin]: directory } })), `accepted a directory answering ${directory.status} with ${directory.body.slice(0, 20)}`);
        }
      },
    },
    {
      id: 'WV30', level: 'SHOULD', title: 'refuses a key directory whose own signature does not verify',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        // The directory is signed by a key it does not publish, under the other key's keyid.
        const forgedFor = good();
        assert(!(await accepts(forgedFor, { directories: directoryOf(forgedFor, { signingKey: OTHER_KEY }) })), 'a directory signed by a key it does not list was accepted');
        const elsewhereFor = good();
        assert(!(await accepts(elsewhereFor, { directories: { [elsewhereFor.origin]: buildDirectory({ authority: 'other.example', keys: [RFC_KEY], now: NOW }) } })), 'a directory signed for another authority was accepted');
      },
    },
    {
      id: 'WV31', level: 'SHOULD', title: 'refuses a nonce it has already seen (a captured request replayed)',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        const signed = good();
        assert(await accepts(signed), 'the first request was refused');
        assert(!(await accepts(signed)), 'the same signed request was accepted twice: no replay memory');
      },
    },
    {
      id: 'WV32', level: 'SHOULD', title: 'refuses a signature that lives longer than 24 hours',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        assert(!(await accepts(good({ params: { expires: NOW + 90_000 } }))), 'a signature valid for 25 hours was accepted');
      },
    },
    {
      id: 'WV33', level: 'SHOULD', title: 'looks a directory up once for several requests (honours max-age)',
      async run() {
        const skipped = need(verifier, 'a verifier');
        if (skipped) return skipped;
        const calls = [];
        const origin = freshOrigin();
        const directories = { [origin]: buildDirectory({ authority: hostOf(origin), keys: [RFC_KEY], now: NOW }) };
        await accepts(good({ directoryOrigin: origin }), { directories, calls });
        await accepts(good({ directoryOrigin: origin }), { directories, calls });
        assert(calls.length > 0, 'the verifier never fetched the directory');
        // A cache needs memory between calls: a function with none is not wrong, so this is a warning only.
        assert(calls.length < 2, 'the directory was fetched again for the second request');
      },
    },

    // ─── directory ───────────────────────────────────────────────
    {
      id: 'WD01', level: 'MUST', title: 'answers 200 with the media type application/http-message-signatures-directory+json',
      async run() {
        const skipped = need(directory, 'a directory');
        if (skipped) return skipped;
        const r = await fetchDirectory(directoryHost);
        assert(r.status === 200, `the directory answered ${r.status}`);
        const type = (r.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
        assert(type === DIRECTORY_MEDIA_TYPE, `content-type is ${JSON.stringify(r.headers['content-type'])}`);
      },
    },
    {
      id: 'WD02', level: 'MUST', title: 'the body is a JWKS: keys of type OKP, curve Ed25519, with a base64url public key',
      async run() {
        const skipped = need(directory, 'a directory');
        if (skipped) return skipped;
        const { parsed } = await readDirectory();
        assert(Array.isArray(parsed.keys) && parsed.keys.length > 0, 'the body has no keys');
        for (const key of parsed.keys) {
          assert(key.kty === 'OKP' && key.crv === 'Ed25519', `a key is ${key.kty}/${key.crv}`);
          assert(typeof key.x === 'string' && /^[A-Za-z0-9_-]{43}$/.test(key.x), 'a key has no 32-byte base64url x');
        }
      },
    },
    {
      id: 'WD03', level: 'MUST', title: 'publishes public keys only: no private member in any key',
      async run() {
        const skipped = need(directory, 'a directory');
        if (skipped) return skipped;
        const { body } = await readDirectory();
        for (const member of ['d', 'p', 'q', 'k']) {
          assert(!new RegExp(`"${member}"\\s*:`).test(body), `the directory has a "${member}" member`);
        }
      },
    },
    {
      id: 'WD04', level: 'MUST', title: 'each key\'s kid is its JWK thumbprint, and each carries use "sig" and an integer nbf',
      async run() {
        const skipped = need(directory, 'a directory');
        if (skipped) return skipped;
        const { parsed } = await readDirectory();
        for (const key of parsed.keys) {
          assert(key.kid === ed25519Thumbprint(key.x), `kid ${JSON.stringify(key.kid)} is not the thumbprint of the key`);
          assert(key.use === 'sig', `use is ${JSON.stringify(key.use)}`);
          assert(Number.isInteger(key.nbf), 'nbf is not an integer');
          assert(key.exp === undefined || (Number.isInteger(key.exp) && key.exp > key.nbf), 'exp is not an integer after nbf');
        }
      },
    },
    {
      id: 'WD05', level: 'MUST', title: 'is signed: Signature-Input and Signature with the directory tag over @authority of the request, by a key it lists',
      async run() {
        const skipped = need(directory, 'a directory');
        if (skipped) return skipped;
        const r = await readDirectory();
        const inputs = parseSignatureInput(r.headers['signature-input'] ?? '');
        const signatures = parseSignature(r.headers['signature'] ?? '');
        const label = [...inputs.keys()].find((l) => paramOf(inputs.get(l).params, 'tag') === DIRECTORY_TAG);
        assert(label !== undefined, `no signature carries the tag ${DIRECTORY_TAG}`);
        const input = inputs.get(label);
        assert(input.components.length === 1 && input.components[0].name === '@authority' && input.components[0].req === true,
          'the signature covers more or less than ("@authority";req)');
        assert(paramOf(input.params, 'alg') === 'ed25519', 'alg is not "ed25519"');
        const keyid = paramOf(input.params, 'keyid');
        const key = r.parsed.keys.find((k) => k.kid === keyid);
        assert(key, `the signing key ${JSON.stringify(keyid)} is not in the directory`);
        const base = signatureBaseFrom(input.components, input.text, { method: 'GET', url: `https://${r.authority}${DIRECTORY_PATH}`, headers: {} });
        assert(signatures.has(label) && verifyEd25519(base, signatures.get(label), publicKeyFromX(key.x)), 'the signature does not verify over @authority of the request');
        assert(Number.isInteger(paramOf(input.params, 'created')) && Number.isInteger(paramOf(input.params, 'expires')), 'created and expires are missing');
      },
    },
    {
      id: 'WD06', level: 'MUST', title: 'the signature is bound to the authority asked: another host\'s request does not verify it',
      async run() {
        const skipped = need(directory, 'a directory');
        if (skipped) return skipped;
        if (options.directoryHost) return skip('the directory can be asked as one host only (directoryHost)');
        const verifiesFor = async (asked, claimed) => {
          const r = await readDirectory(asked);
          const inputs = parseSignatureInput(r.headers['signature-input']);
          const label = [...inputs.keys()].find((l) => paramOf(inputs.get(l).params, 'tag') === DIRECTORY_TAG);
          const input = inputs.get(label);
          const key = r.parsed.keys.find((k) => k.kid === paramOf(input.params, 'keyid'));
          const base = signatureBaseFrom(input.components, input.text, { method: 'GET', url: `https://${claimed}${DIRECTORY_PATH}`, headers: {} });
          return verifyEd25519(base, parseSignature(r.headers['signature']).get(label), publicKeyFromX(key.x));
        };
        assert(await verifiesFor('a.example', 'a.example'), 'the directory asked as a.example does not verify for a.example');
        assert(!(await verifiesFor('a.example', 'b.example')), 'a signature made for a.example verifies for b.example');
        assert(await verifiesFor('b.example', 'b.example'), 'the directory asked as b.example does not verify for b.example');
      },
    },
    {
      id: 'WD07', level: 'SHOULD', title: 'is cacheable for a short time: cache-control public with a max-age',
      async run() {
        const skipped = need(directory, 'a directory');
        if (skipped) return skipped;
        const r = await fetchDirectory(directoryHost);
        const cache = r.headers['cache-control'] ?? '';
        assert(/\bpublic\b/.test(cache) && /max-age=\d+/.test(cache), `cache-control is ${JSON.stringify(cache)}`);
      },
    },
    {
      id: 'WD08', level: 'SHOULD', title: 'a signature lives at most 24 hours (expires - created)',
      async run() {
        const skipped = need(directory, 'a directory');
        if (skipped) return skipped;
        const r = await readDirectory();
        const inputs = parseSignatureInput(r.headers['signature-input']);
        const label = [...inputs.keys()].find((l) => paramOf(inputs.get(l).params, 'tag') === DIRECTORY_TAG);
        const { params } = inputs.get(label);
        const lifetime = paramOf(params, 'expires') - paramOf(params, 'created');
        assert(lifetime > 0 && lifetime <= 86_400, `the directory signature lives ${lifetime} s`);
      },
    },
  ]);
}

