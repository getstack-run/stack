// A reference RELYING PARTY of the single sign-on profile (spec/sso-login/SPEC.md): the sign-in address, the callback
// and the handoff, written from the specification with nothing but node:crypto and node:http. It keeps its one
// connection, its attempts and its handoffs in memory. It is the public reference the `sso-login` suite runs against in
// continuous integration, and the starting point for a relying party of your own.
//
// What it is not: a deployment. It has no accounts (`people` records who signed in), no licence and no plans, and it
// fetches the provider's addresses without the guard against private addresses a deployment applies, because the suite's
// provider is on this machine. The wire contract is the whole of what it implements.
//
// `quirk` turns on ONE deliberate defect, for the tests of the suite itself (sso-login-reference.test.mjs): a
// conformance kit that cannot fail a broken relying party would certify anything.

import { createHash, createHmac, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto';
import { createServer } from 'node:http';

export const SSO_QUIRKS = [
  'none',
  'binding-optional', // a start with no browser binding is accepted
  'slug-400', // an unknown slug is a 400, not the 404
  'secret-in-url', // the client secret is in the authorization request
  'no-pkce', // there is no PKCE
  'cookie-js', // the state cookie can be read by a script
  'cookie-not-cleared', // the state cookie outlives the callback
  'alg-none', // an ID token that says alg none is accepted
  'hmac-confusion', // an HMAC token keyed with the provider's public key is accepted
  'any-kid', // a token with an unknown kid or none is checked against the first key
  'no-refetch', // an unknown kid does not make it fetch the key set again
  'no-nonce-check', // the nonce is not compared
  'no-iss-check', // the issuer is not compared
  'no-aud-check', // the audience is not compared
  'no-exp-check', // the expiry is not checked, and may be missing
  'no-skew', // no clock tolerance
  'no-sub-check', // a token with no subject is taken
  'empty-email', // an empty e-mail address is taken
  'no-binding', // the callback does not look at the cookie
  'state-reusable', // a state can be used again
  'refusal-redirects', // a refused sign-in is a redirect to the sign-in page
  'ref-short', // the handoff reference has 8 characters
  'handoff-open', // the public handoff address answers an identity
  'no-email-verified-check', // an address the provider does not say is verified links a person
  'email-only-match', // a person is found by e-mail address alone: another subject signs in as them
  'domain-any-account', // a domain verified by another account counts as verified for this one
  'domain-subdomains', // a subdomain or the parent of a verified domain counts too
  'domain-overrides-claim', // a verified domain makes an address verified even when the provider said email_verified false
  'domain-never-expires', // a verified domain counts after its record is gone, for ever
];

const TOLERANCE = 30;
// How long a check of a domain's proof record counts (section 9.5): the engine's is six hours.
const DOMAIN_TRUST_MS = 6 * 3600 * 1000;
const MAX_FORCED_REFETCH_MS = 60_000;
const urlsafe = (bytes) => randomBytes(bytes).toString('base64url');

/** The algorithm of a key of the provider's set: its `alg` member, else the one of its type (section 8, step 1). */
function algorithmOf(jwk) {
  if (jwk.alg) return jwk.alg;
  if (jwk.kty === 'RSA') return 'RS256';
  if (jwk.kty === 'EC') return { 'P-256': 'ES256', 'P-384': 'ES384', 'P-521': 'ES512' }[jwk.crv];
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return 'EdDSA';
  return undefined;
}

/** Verify a compact JWS with a JWK, with the algorithm of the key only. Throws when it does not verify. */
function verifyJws(token, jwk, { quirk }) {
  const [h, p, s] = token.split('.');
  if (p === undefined) throw new Error('not a JWS');
  const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
  const input = Buffer.from(`${h}.${p}`);
  const signature = Buffer.from(s ?? '', 'base64url');
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  if (quirk === 'alg-none' && header.alg === 'none') return JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  if (quirk === 'hmac-confusion' && header.alg === 'HS256') {
    const mac = createHmac('sha256', key.export({ type: 'spki', format: 'pem' })).update(input).digest();
    if (mac.length === signature.length && timingSafeEqual(mac, signature)) return JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    throw new Error('bad MAC');
  }
  const alg = algorithmOf(jwk);
  if (!alg || header.alg !== alg) throw new Error(`the token says ${header.alg}, the key is ${alg}`);
  let ok;
  if (alg === 'RS256') ok = verify('sha256', input, key, signature);
  else if (alg === 'ES256') ok = verify('sha256', input, { key, dsaEncoding: 'ieee-p1363' }, signature);
  else if (alg === 'EdDSA') ok = verify(null, input, key, signature);
  else throw new Error(`unsupported algorithm ${alg}`);
  if (!ok) throw new Error('the signature does not verify');
  return JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
}

/**
 * @param {{ quirk?: string, dashboard?: string }} [options] `dashboard` is the origin the sign-in page is at.
 */
export async function startSsoReference({ quirk = 'none', dashboard = 'https://signin.example' } = {}) {
  if (!SSO_QUIRKS.includes(quirk)) throw new Error(`unknown quirk ${quirk}`);
  const q = (name) => quirk === name;
  let connection = null; // { slug, issuer, client_id, client_secret, redirect_uri, scopes }
  const attempts = new Map(); // state -> { nonce, verifier, binding, signIn, code }
  const handoffs = new Map(); // ref -> { email, binding, expires }
  const people = new Map(); // e-mail address -> { email, name, linked }
  const bySubject = new Map(); // "iss\nsub" -> the person it is linked to
  // Verified domains: domain -> { account: 'this' | 'other', recordPresent, confirmedAt }. The reference has no DNS; the
  // suite's `domains` hooks say what the deployment would have found there.
  const domains = new Map();
  let discovery = null;
  let keyCache = null;
  let lastForced = 0;

  const fail = (status, code, message) => ({ status, body: { error: { code, message } } });

  async function getJson(url) {
    // A deployment guards every address it fetches and follows no redirect (section 7.1); the reference follows none.
    const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error(`${url} answered ${response.status}`);
    return response.json();
  }
  async function discover() {
    discovery ??= await getJson(`${connection.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`);
    return discovery;
  }
  async function keySet({ force = false } = {}) {
    if (!keyCache || force) keyCache = (await getJson((await discover()).jwks_uri)).keys;
    return keyCache;
  }

  /** The key set with the key for a token: one more fetch when the key id is unknown, at most once a minute. */
  async function keyFor(header) {
    let keys = await keySet();
    let jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk && !q('no-refetch') && Date.now() - lastForced >= MAX_FORCED_REFETCH_MS) {
      lastForced = Date.now();
      keys = await keySet({ force: true });
      jwk = keys.find((k) => k.kid === header.kid);
    }
    if (!jwk && q('any-kid')) jwk = keys[0];
    if (!jwk) throw new Error('no key for that kid');
    return jwk;
  }

  async function checkIdToken(token, attempt) {
    const [h] = token.split('.');
    const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
    if (!header.kid && !q('any-kid')) throw new Error('no kid');
    const claims = verifyJws(token, await keyFor(header), { quirk });
    const t = Math.floor(Date.now() / 1000);
    const tolerance = q('no-skew') ? 0 : TOLERANCE;
    if (!q('no-iss-check') && claims.iss !== connection.issuer) throw new Error('issuer');
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!q('no-aud-check') && !aud.includes(connection.client_id)) throw new Error('audience');
    if (!q('no-exp-check')) {
      if (!Number.isFinite(claims.exp)) throw new Error('no expiry');
      if (claims.exp + tolerance <= t) throw new Error('expired');
      if (claims.nbf !== undefined && claims.nbf - tolerance > t) throw new Error('not yet valid');
    }
    if (!q('no-sub-check') && (typeof claims.sub !== 'string' || claims.sub.length === 0)) throw new Error('no subject');
    if (!q('no-nonce-check') && claims.nonce !== attempt.nonce) throw new Error('nonce');
    const email = typeof claims.email === 'string' ? claims.email.trim().toLowerCase() : '';
    if (!email && !q('empty-email')) throw new Error('no e-mail address');
    return { email, emailVerified: claims.email_verified === true, emailVerifiedAbsent: claims.email_verified === undefined, iss: claims.iss, sub: claims.sub, name: typeof claims.name === 'string' ? claims.name : null };
  }

  /** Whether an address's domain counts as verified for the account right now (section 9.5): exactly, and only while its record was seen lately. */
  function domainCounts(email) {
    const host = email.slice(email.lastIndexOf('@') + 1);
    const hosts = q('domain-subdomains') ? [...domains.keys()].filter((d) => host === d || host.endsWith(`.${d}`) || d.endsWith(`.${host}`)) : [host];
    return hosts.some((d) => {
      const entry = domains.get(d);
      if (!entry) return false;
      if (entry.account !== 'this' && !q('domain-any-account')) return false;
      if (q('domain-never-expires')) return true;
      return entry.recordPresent || Date.now() - entry.confirmedAt < DOMAIN_TRUST_MS;
    });
  }

  /**
   * Find the person (section 9): by the provider's subject once linked; before that by a VERIFIED e-mail address,
   * which links the subject; an address already linked to another subject is refused, never re-linked.
   */
  function findPerson(identity) {
    const key = `${identity.iss}\n${identity.sub}`;
    const linked = bySubject.get(key);
    if (linked) return linked;
    // The provider's word first. With no email_verified claim at all, a domain the account verified stands in for it; an
    // address the provider said something else about is not vouched for by a domain.
    const vouched = identity.emailVerified
      || ((identity.emailVerifiedAbsent || q('domain-overrides-claim')) && domainCounts(identity.email));
    if (!q('no-email-verified-check') && !vouched) throw new Error('the provider does not say the e-mail address is verified');
    const existing = people.get(identity.email);
    if (existing) {
      if (existing.linked && !q('email-only-match')) throw new Error('the address belongs to another subject');
      if (!existing.linked) { existing.linked = key; bySubject.set(key, existing); }
      return existing;
    }
    const person = { email: identity.email, name: identity.name, linked: key };
    people.set(identity.email, person);
    bySubject.set(key, person);
    return person;
  }

  const cookieLine = (value, maxAge) => [`stack_sso_state=${value}`, ...(q('cookie-js') ? [] : ['HttpOnly']), 'Path=/v1/identity', `Max-Age=${maxAge}`, 'SameSite=Lax'].join('; ');
  const readCookie = (header) => {
    for (const part of String(header ?? '').split(';')) {
      const [name, ...rest] = part.trim().split('=');
      if (name === 'stack_sso_state') return decodeURIComponent(rest.join('='));
    }
    return null;
  };

  async function start(url, slug) {
    const binding = url.searchParams.get('browser_binding');
    if (!q('binding-optional') && !/^[a-f0-9]{64}$/.test(binding ?? '')) return fail(400, 'BROWSER_BINDING_REQUIRED', 'Start sign-in from the STACK dashboard.');
    if (!connection || connection.slug !== slug) return q('slug-400') ? fail(400, 'VALIDATION_ERROR', 'unknown organisation') : fail(404, 'NOT_FOUND', 'SsoConnection not found');
    const { authorization_endpoint: endpoint } = await discover();
    const state = urlsafe(32);
    const nonce = urlsafe(32);
    const verifier = urlsafe(32);
    attempts.set(state, { nonce, verifier, binding, signIn: true, code: null, expires: Date.now() + 600_000 });
    const target = new URL(endpoint);
    target.searchParams.set('response_type', 'code');
    target.searchParams.set('client_id', connection.client_id);
    target.searchParams.set('redirect_uri', connection.redirect_uri);
    target.searchParams.set('scope', connection.scopes.join(' '));
    target.searchParams.set('state', state);
    target.searchParams.set('nonce', nonce);
    if (!q('no-pkce')) {
      target.searchParams.set('code_challenge', createHash('sha256').update(verifier).digest('base64url'));
      target.searchParams.set('code_challenge_method', 'S256');
    }
    if (q('secret-in-url')) target.searchParams.set('client_secret', connection.client_secret);
    return { status: 302, headers: { location: target.toString(), 'set-cookie': cookieLine(state, 600) }, body: undefined };
  }

  async function exchange(attempt, code) {
    const form = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: connection.redirect_uri, client_id: connection.client_id, client_secret: connection.client_secret });
    if (!q('no-pkce')) form.set('code_verifier', attempt.verifier);
    const response = await fetch((await discover()).token_endpoint, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(5000),
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' }, body: form.toString(),
    });
    if (!response.ok) throw new Error(`the token endpoint answered ${response.status}`);
    const json = await response.json();
    if (json.error || !json.id_token) throw new Error('the token endpoint gave no ID token');
    return json.id_token;
  }

  async function callback(url, cookieHeader) {
    const all = (name) => url.searchParams.getAll(name);
    if (['code', 'state', 'error', 'error_description'].some((n) => all(n).length > 1)) return fail(400, 'VALIDATION_ERROR', 'a parameter was given twice');
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    if (url.searchParams.get('error')) return fail(400, 'SSO_UPSTREAM_ERROR', url.searchParams.get('error_description') ?? url.searchParams.get('error'));
    if (!code || !state) return fail(400, 'SSO_CALLBACK_INVALID', 'OIDC callback missing required code or state parameter');
    const attempt = attempts.get(state);
    if (!attempt || attempt.expires <= Date.now() || (attempt.code !== null && !q('state-reusable'))) return fail(400, 'SSO_STATE_INVALID', 'OIDC state is unknown or expired');
    attempt.code = code;
    if (!q('no-binding')) {
      const bound = readCookie(cookieHeader);
      const a = Buffer.from(bound ?? '');
      const b = Buffer.from(state);
      if (bound === null || a.length !== b.length || !timingSafeEqual(a, b)) {
        return { ...fail(400, 'SSO_STATE_NOT_BOUND', 'This sign-in link did not start in this browser.'), headers: { 'set-cookie': cookieLine('', 0) } };
      }
    }
    if (!q('state-reusable')) attempt.signIn = false;
    const clearing = q('cookie-not-cleared') ? {} : { 'set-cookie': cookieLine('', 0) };
    const refusal = (message) => (q('refusal-redirects')
      ? { status: 302, headers: { ...clearing, location: `${dashboard}/auth/sso/callback?error=1` }, body: undefined }
      : { ...fail(400, 'SSO_LOGIN_FAILED', message), headers: clearing });
    let identity;
    try {
      identity = findPerson(await checkIdToken(await exchange(attempt, code), attempt));
    } catch (error) {
      return refusal(error.message);
    }
    const ref = q('ref-short') ? `ssoh_${urlsafe(6).slice(0, 8)}` : `ssoh_${urlsafe(24).slice(0, 32)}`;
    handoffs.set(ref, { email: identity.email, binding: attempt.binding, expires: Date.now() + 60_000 });
    return { status: 302, headers: { ...clearing, location: `${dashboard}/auth/sso/callback?ref=${ref}` }, body: undefined };
  }

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, 'http://x');
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    let result;
    try {
      let m;
      if (request.method === 'GET' && (m = /^\/v1\/identity\/sso\/([^/]+)\/start$/.exec(url.pathname))) result = await start(url, decodeURIComponent(m[1]));
      else if (request.method === 'GET' && url.pathname === '/v1/identity/oidc/callback') result = await callback(url, request.headers.cookie);
      else if (request.method === 'POST' && url.pathname === '/v1/identity/sso/handoff') {
        if (q('handoff-open')) {
          const ref = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}').ref;
          const found = handoffs.get(ref);
          result = found ? { status: 200, body: { operator_id: 'op_reference', member_id: 'mem_reference', email: found.email } } : fail(401, 'SSO_HANDOFF_INVALID', 'invalid');
        } else {
          result = fail(404, 'NOT_FOUND', 'Endpoint not found: POST /v1/identity/sso/handoff');
        }
      } else result = fail(404, 'NOT_FOUND', `Route ${request.method}:${url.pathname} not found`);
    } catch (error) {
      result = fail(500, 'INTERNAL_ERROR', 'An unexpected error occurred');
      process.stderr.write(`sso reference: ${error?.stack ?? error}\n`);
    }
    const headers = { ...(result.body === undefined ? {} : { 'content-type': 'application/json' }), ...(result.headers ?? {}) };
    response.writeHead(result.status, headers).end(result.body === undefined ? undefined : JSON.stringify(result.body));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  return {
    baseUrl,
    people,
    /** What the suite's `domains` option needs (section 9.5): the kit says what DNS would have shown. */
    domains: {
      verified: async ({ domain }) => { domains.set(domain, { account: 'this', recordPresent: true, confirmedAt: Date.now() }); },
      verifiedElsewhere: async ({ domain }) => { domains.set(domain, { account: 'other', recordPresent: true, confirmedAt: Date.now() }); },
      recordRemoved: async ({ domain }) => {
        const entry = domains.get(domain);
        // The record is gone and the window for a cached check has passed.
        if (entry) { entry.recordPresent = false; entry.confirmedAt = Date.now() - DOMAIN_TRUST_MS - 60_000; }
      },
    },
    /** Connect the provider under a slug (what the suite's `configure` does). */
    configure: async ({ issuer, client_id, client_secret, redirect_uri, slug }) => {
      connection = { slug, issuer, client_id, client_secret, redirect_uri, scopes: ['openid', 'email', 'profile'] };
      discovery = null;
      keyCache = null;
      lastForced = 0;
    },
    close: () => new Promise((resolve) => { server.close(() => resolve()); server.closeAllConnections(); }),
  };
}
