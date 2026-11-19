// Conformance suite for a deployment's single sign-on (spec/sso-login/SPEC.md): the sign-in address, the callback and
// what a deployment requires of an OpenID provider. The kit plays two parts at once: the BROWSER of a person (it
// follows each redirect by hand, carries the cookie, and can leave it out) and the PROVIDER (it serves a discovery
// document, a key set and a token endpoint of its own, and signs the ID tokens it chooses to).
//
//   { baseUrl, configure, domains?, redirectUri?, idpHost?, idpPort? }
//
//   baseUrl      the address of a TEST deployment's API, from which the kit's browser starts.
//   configure    `async ({ issuer, client_id, client_secret, redirect_uri, slug }) => void`: connect the kit's provider to
//                an account of the test deployment, enabled, under that slug. The account is the deployment's own to
//                choose, and a self-managed install must be licensed for single sign-on. The issuer is an address on this machine
//                (http://127.0.0.1:<port>), so the test deployment must allow a provider there: a development build,
//                never production, whose guard refuses a private address.
//   domains      optional, for a deployment that lets an account prove an e-mail domain with a DNS record (section 9.5):
//                `{ verified, verifiedElsewhere, recordRemoved }`, each `async ({ domain }) => void`, with domains the kit
//                makes up under example.test. `verified` makes the domain verified for the account `configure` connected
//                (the deployment decides how: a record in a DNS the test controls); `verifiedElsewhere` makes it verified for
//                ANOTHER account; `recordRemoved` takes the proof record of a verified domain away and lets the deployment's
//                window for trusting a cached check pass. Without it the checks of section 9.5 are skipped.
//   redirectUri  the address the provider returns the browser to, when the callback is served somewhere other than
//                `${baseUrl}/v1/identity/oidc/callback`.
//   idpHost      the address the kit's provider listens on (default 127.0.0.1), and idpPort the port (default any).
//
// The kit never redeems a handoff reference: that is the deployment's sign-in page's. It creates people in the
// connected account (e-mail addresses at example.test, which is not a mailbox and receives nothing). Every ID token
// it signs says `email_verified: true` unless a check is about that claim, because a deployment links a person to the
// provider's subject only on a verified address (section 9).

import { createHash, createHmac, createPublicKey, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { createServer } from 'node:http';
import { assert, runChecks, skip } from './harness.mjs';

const b64u = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
const sha256Hex = (text) => createHash('sha256').update(text).digest('hex');
const now = () => Math.floor(Date.now() / 1000);

/** A signing key of the kit's provider: its private key, the public JWK it publishes (with no `alg` member), and how it signs. */
function makeKey(kind, kid) {
  if (kind === 'RS256') {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    return { kind, kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig' }, sign: (input) => sign('sha256', input, privateKey) };
  }
  if (kind === 'EdDSA') {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    return { kind, kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig' }, sign: (input) => sign(null, input, privateKey) };
  }
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { kind: 'ES256', kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig' }, sign: (input) => sign('sha256', input, { key: privateKey, dsaEncoding: 'ieee-p1363' }) };
}

/** A compact JWS from a header, a payload and a key. */
function jws(header, payload, key) {
  const input = `${b64u(header)}.${b64u(payload)}`;
  return `${input}.${key.sign(Buffer.from(input)).toString('base64url')}`;
}

/** @param {{ baseUrl: string, configure: (connection: object) => Promise<void>, domains?: { verified: (domain: { domain: string }) => Promise<void>, verifiedElsewhere: (domain: { domain: string }) => Promise<void>, recordRemoved: (domain: { domain: string }) => Promise<void> }, redirectUri?: string, idpHost?: string, idpPort?: number }} options */
export async function runSsoLoginSuite(options) {
  const base = options.baseUrl.replace(/\/$/, '');
  const slug = `conf-${randomBytes(4).toString('hex')}`;
  const clientId = `client-${randomBytes(6).toString('hex')}`;
  const clientSecret = randomBytes(18).toString('base64url');
  const redirectUri = options.redirectUri ?? `${base}/v1/identity/oidc/callback`;

  // ─── The provider ───────────────────────────────────────────────────────────────────────────────────────────────
  const keys = { ES256: makeKey('ES256', 'es-1'), RS256: makeKey('RS256', 'rs-1'), EdDSA: makeKey('EdDSA', 'ed-1') };
  const published = [keys.ES256, keys.RS256, keys.EdDSA];
  const pending = new Map(); // code -> what the person asked for and how the token is made
  const tokenRequests = [];
  const fetches = { discovery: 0, jwks: 0 };
  let issuer = '';

  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const send = (status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
      if (req.method === 'GET' && req.url === '/.well-known/openid-configuration') {
        fetches.discovery += 1;
        return send(200, { issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks`, response_types_supported: ['code'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['ES256', 'RS256', 'EdDSA'] });
      }
      if (req.method === 'GET' && req.url === '/jwks') {
        fetches.jwks += 1;
        return send(200, { keys: published.map((k) => k.jwk) });
      }
      if (req.method === 'POST' && req.url === '/token') {
        const form = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8')));
        const record = { headers: req.headers, form, problems: [] };
        tokenRequests.push(record);
        const wanted = pending.get(form.code);
        if (!wanted) return send(400, { error: 'invalid_grant' });
        pending.delete(form.code);
        record.wanted = wanted;
        if (req.headers['content-type'] !== 'application/x-www-form-urlencoded') record.problems.push(`content type ${req.headers['content-type']}`);
        if (form.grant_type !== 'authorization_code') record.problems.push(`grant_type ${form.grant_type}`);
        if (form.client_id !== clientId) record.problems.push('client_id');
        if (form.client_secret !== clientSecret) record.problems.push('client_secret');
        if (form.redirect_uri !== redirectUri) record.problems.push(`redirect_uri ${form.redirect_uri}`);
        if (createHash('sha256').update(String(form.code_verifier)).digest('base64url') !== wanted.challenge) record.problems.push('code_verifier does not match the S256 challenge');
        if (req.headers.authorization) record.problems.push('an Authorization header was sent');
        if (record.problems.length > 0) return send(400, { error: 'invalid_request', error_description: record.problems.join('; ') });
        const plan = wanted.plan;
        if (plan.tokenResponse) return send(plan.tokenResponse.status, plan.tokenResponse.body);
        return send(200, { access_token: 'not-used', token_type: 'Bearer', expires_in: 300, id_token: buildToken(plan, wanted) });
      }
      return send(404, { error: 'not_found' });
    });
  });
  await new Promise((resolve) => server.listen(options.idpPort ?? 0, options.idpHost ?? '127.0.0.1', resolve));
  issuer = `http://${options.idpHost ?? '127.0.0.1'}:${server.address().port}`;

  /** The ID token for one sign-in, as its plan says: a good one by default, and with the change the plan makes. */
  function buildToken(plan, wanted) {
    const key = plan.key ?? keys.ES256;
    const t = now();
    const base = { iss: issuer, sub: `user-${randomBytes(4).toString('hex')}`, aud: clientId, iat: t, exp: t + 300, nonce: wanted.nonce, email: plan.email ?? `person-${randomBytes(4).toString('hex')}@example.test`, email_verified: true, name: 'Conformance Person' };
    const claims = plan.claims ? plan.claims(base) : base;
    const header = plan.header ? plan.header({ alg: key.kind, kid: key.kid, typ: 'JWT' }) : { alg: key.kind, kid: key.kid, typ: 'JWT' };
    const token = plan.build ? plan.build({ header, claims, key }) : jws(header, claims, key);
    return plan.mutate ? plan.mutate(token) : token;
  }

  // ─── The browser ────────────────────────────────────────────────────────────────────────────────────────────────
  const get = (url, headers = {}) => fetch(url, { redirect: 'manual', headers, signal: AbortSignal.timeout(20_000) });
  const bodyOf = async (response) => { const text = await response.text(); try { return JSON.parse(text); } catch { return undefined; } };
  const errorOf = async (response) => (await bodyOf(response))?.error;
  const cookieOf = (response) => {
    const lines = response.headers.getSetCookie?.() ?? [];
    return lines.find((line) => line.startsWith('stack_sso_state='));
  };

  /** Start a sign-in as a browser: the redirect to the provider, its parameters and the cookie. */
  async function start({ binder = randomBytes(16).toString('hex') } = {}) {
    const response = await get(`${base}/v1/identity/sso/${slug}/start?browser_binding=${sha256Hex(binder)}`);
    if (response.status !== 302) return { response, status: response.status, error: await errorOf(response) };
    const location = new URL(response.headers.get('location'));
    const setCookie = cookieOf(response);
    return {
      response, status: 302, location, setCookie, binder,
      params: Object.fromEntries(location.searchParams),
      cookie: setCookie ? setCookie.split(';')[0] : undefined,
    };
  }

  /** The provider's part: the person authenticated, and the provider sends the browser back with a code. */
  function authenticate(started, plan = {}) {
    const code = randomBytes(16).toString('base64url');
    pending.set(code, { nonce: started.params.nonce, challenge: started.params.code_challenge, plan });
    return code;
  }

  /** The browser comes back to the callback. `cookie` is what it sends: the started one, none, or another. */
  async function callback(started, code, { cookie = started.cookie, query } = {}) {
    const q = query ?? `code=${encodeURIComponent(code)}&state=${encodeURIComponent(started.params.state)}`;
    const response = await get(`${redirectUri}?${q}`, cookie ? { cookie } : {});
    return { response, status: response.status, location: response.headers.get('location'), error: response.status >= 400 ? await errorOf(response) : undefined, setCookie: cookieOf(response) };
  }

  /** A whole sign-in. */
  async function signIn(plan = {}, callbackOptions = {}) {
    const started = await start();
    assert(started.status === 302, `the sign-in address answered ${started.status} ${started.error?.code ?? ''}`.trim());
    const before = tokenRequests.length;
    const code = authenticate(started, plan);
    const back = await callback(started, code, callbackOptions);
    return { started, back, code, tokenCalls: tokenRequests.length - before };
  }

  const ref = (back) => (back.location ? new URL(back.location).searchParams.get('ref') : null);
  const refs = [];
  const signedIn = (result, why) => {
    assert(result.back.status === 302, `${why}: the callback answered ${result.back.status} ${result.back.error?.code ?? ''}`.trim());
    const target = new URL(result.back.location);
    assert(target.pathname === '/auth/sso/callback', `${why}: the browser was sent to ${target.pathname}, not /auth/sso/callback`);
    const r = ref(result.back);
    assert(typeof r === 'string' && /^ssoh_[A-Za-z0-9_-]{32}$/.test(r), `${why}: the handoff reference is ${JSON.stringify(r)}`);
    refs.push(r);
    return r;
  };
  const refused = (result, code, why, { token = true } = {}) => {
    assert(result.back.status === 400 && result.back.error?.code === code, `${why}: the callback answered ${result.back.status} ${result.back.error?.code ?? ''}, not 400 ${code}`.trim());
    assert(!result.back.location, `${why}: the refusal redirected to ${result.back.location}`);
    if (!token) assert(result.tokenCalls === 0, `${why}: the token endpoint was called ${result.tokenCalls} time(s)`);
  };

  let connected = false;
  const connect = async () => {
    if (connected) return;
    await options.configure({ issuer, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, slug });
    connected = true;
  };

  const report = await runChecks('single sign-on', [
    {
      id: 'S01', level: 'MUST', title: 'refuses a start with no browser binding, or one that is not 64 lower-case hexadecimal characters (400 BROWSER_BINDING_REQUIRED)',
      async run() {
        await connect();
        for (const [why, query] of [['no binding', ''], ['an empty binding', '?browser_binding='], ['63 characters', `?browser_binding=${'a'.repeat(63)}`], ['upper case', `?browser_binding=${'A'.repeat(64)}`], ['not hexadecimal', `?browser_binding=${'g'.repeat(64)}`]]) {
          const r = await get(`${base}/v1/identity/sso/${slug}/start${query}`);
          assert(r.status === 400 && (await errorOf(r))?.code === 'BROWSER_BINDING_REQUIRED', `${why}: answered ${r.status}`);
        }
      },
    },
    {
      id: 'S02', level: 'MUST', title: 'answers 404 NOT_FOUND to a slug nobody has and to an address that holds an e-mail domain in its place: the slug names the organisation, never the domain',
      async run() {
        await connect();
        for (const name of [`nobody-${randomBytes(3).toString('hex')}`, 'example.test', 'person@example.test']) {
          const r = await get(`${base}/v1/identity/sso/${encodeURIComponent(name)}/start?browser_binding=${sha256Hex('x')}`);
          assert(r.status === 404 && (await errorOf(r))?.code === 'NOT_FOUND', `${name}: answered ${r.status}`);
        }
      },
    },
    {
      id: 'S03', level: 'MUST', title: 'starts a sign-in with a redirect to the provider\'s authorization endpoint: the code flow, the client and redirect address, openid, a state and a nonce of 256 bits, an S256 challenge, and no secret',
      async run() {
        await connect();
        const s = await start();
        assert(s.status === 302, `the start answered ${s.status} ${s.error?.code ?? ''}`.trim());
        assert(s.location.origin === issuer && s.location.pathname === '/authorize', `the redirect went to ${s.location.origin}${s.location.pathname}`);
        const p = s.params;
        assert(p.response_type === 'code', `response_type is ${p.response_type}`);
        assert(p.client_id === clientId, `client_id is ${p.client_id}`);
        assert(p.redirect_uri === redirectUri, `redirect_uri is ${p.redirect_uri}`);
        assert(typeof p.scope === 'string' && p.scope.split(' ').includes('openid'), `scope is ${p.scope}`);
        for (const name of ['state', 'nonce']) assert(/^[A-Za-z0-9_-]{43,}$/.test(p[name] ?? ''), `${name} is ${JSON.stringify(p[name])}, not 256 random bits`);
        assert(p.code_challenge_method === 'S256' && /^[A-Za-z0-9_-]{43}$/.test(p.code_challenge ?? ''), `the challenge is ${p.code_challenge_method} ${p.code_challenge}`);
        assert(!('client_secret' in p) && !JSON.stringify(p).includes(clientSecret), 'the client secret is in the authorization request');
        const c = s.setCookie ?? '';
        assert(c.startsWith(`stack_sso_state=${p.state}`), `the state cookie is ${JSON.stringify(c.slice(0, 40))}, not the state`);
        assert(/;\s*HttpOnly/i.test(c) && /;\s*SameSite=Lax/i.test(c) && /;\s*Path=\/v1\/identity(;|$)/i.test(c) && /;\s*Max-Age=600/i.test(c), `the cookie is ${c.slice(c.indexOf(';'))}`);
      },
    },
    {
      id: 'S04', level: 'MUST', title: 'makes a new state, nonce and challenge for every start',
      async run() {
        await connect();
        const [a, b] = [await start(), await start()];
        for (const name of ['state', 'nonce', 'code_challenge']) assert(a.params[name] !== b.params[name], `two starts had the same ${name}`);
      },
    },
    {
      id: 'S10', level: 'MUST', title: 'signs a person in: it redeems the code with client_secret_post and the PKCE verifier, and ends at the sign-in page with a handoff reference and the state cookie cleared',
      async run() {
        await connect();
        const result = await signIn();
        signedIn(result, 'a sign-in with ES256');
        assert(result.tokenCalls === 1, `the token endpoint was called ${result.tokenCalls} time(s)`);
        const record = tokenRequests.at(-1);
        assert(record.problems.length === 0, `the token request was wrong: ${record.problems.join('; ')}`);
        assert(record.headers.accept?.includes('application/json'), 'the token request does not ask for JSON');
        assert(fetches.discovery >= 1 && fetches.jwks >= 1, 'the deployment did not fetch the discovery document and the key set');
        const cleared = result.back.setCookie ?? '';
        assert(cleared.startsWith('stack_sso_state=') && /Max-Age=0|Expires=Thu, 01 Jan 1970/i.test(cleared), `the state cookie was not cleared: ${JSON.stringify(cleared)}`);
      },
    },
    {
      id: 'S11', level: 'MUST', title: 'checks ID tokens signed with RS256 and with EdDSA by keys that publish no alg member (the algorithm of the key type), as well as ES256',
      async run() {
        await connect();
        for (const kind of ['RS256', 'EdDSA']) signedIn(await signIn({ key: keys[kind] }), `a sign-in with ${kind}`);
      },
    },
    {
      id: 'S12', level: 'MUST', title: 'takes an audience that is an array holding the client id, an e-mail address in any case with spaces around it, and no name',
      async run() {
        await connect();
        signedIn(await signIn({ claims: (c) => ({ ...c, aud: ['https://other.example', clientId] }) }), 'an audience array');
        signedIn(await signIn({ claims: (c) => ({ ...c, email: `  ${c.email.toUpperCase()}  `, name: undefined }) }), 'an upper-case address and no name');
      },
    },
    {
      id: 'S13', level: 'MUST', title: 'allows 30 seconds of clock skew on exp and nbf',
      async run() {
        await connect();
        signedIn(await signIn({ claims: (c) => ({ ...c, iat: now() - 40, exp: now() - 20 }) }), 'a token that expired 20 seconds ago');
        signedIn(await signIn({ claims: (c) => ({ ...c, nbf: now() + 20 }) }), 'a token valid in 20 seconds');
      },
    },
    {
      id: 'S14', level: 'MUST', title: 'picks up a key the provider has rotated in since it fetched the key set: an ID token signed by an unknown kid makes it fetch the set again',
      async run() {
        await connect();
        const rotated = makeKey('ES256', `es-rotated-${randomBytes(3).toString('hex')}`);
        published.push(rotated);
        const before = fetches.jwks;
        signedIn(await signIn({ key: rotated }), 'a sign-in with a key rotated in');
        assert(fetches.jwks > before, 'the key set was not fetched again');
      },
    },
    {
      id: 'S15', level: 'MUST', title: 'makes a different handoff reference for every sign-in',
      async run() {
        await connect();
        signedIn(await signIn(), 'one more sign-in');
        assert(refs.length >= 2 && new Set(refs).size === refs.length, `${refs.length} sign-ins made ${new Set(refs).size} different references`);
      },
    },
    {
      id: 'S20', level: 'MUST', title: 'refuses (400 SSO_LOGIN_FAILED, no redirect) an ID token with the wrong issuer, audience or nonce, no nonce, one that has expired, one that is not yet valid, and one with no expiry, subject or e-mail address',
      async run() {
        await connect();
        const cases = [
          ['an issuer with a trailing slash', (c) => ({ ...c, iss: `${c.iss}/` })],
          ['another issuer', (c) => ({ ...c, iss: 'https://other.example' })],
          ['another audience', (c) => ({ ...c, aud: 'someone-else' })],
          ['an audience array without the client', (c) => ({ ...c, aud: ['a', 'b'] })],
          ['another nonce', (c) => ({ ...c, nonce: 'not-the-nonce' })],
          ['no nonce', (c) => ({ ...c, nonce: undefined })],
          ['an expired token', (c) => ({ ...c, iat: now() - 400, exp: now() - 120 })],
          ['a token valid in two minutes', (c) => ({ ...c, nbf: now() + 120 })],
          ['no expiry', (c) => ({ ...c, exp: undefined })],
          ['no subject', (c) => ({ ...c, sub: undefined })],
          ['no e-mail address', (c) => ({ ...c, email: undefined })],
          ['an empty e-mail address', (c) => ({ ...c, email: '  ' })],
        ];
        for (const [why, claims] of cases) refused(await signIn({ claims }), 'SSO_LOGIN_FAILED', why);
      },
    },
    {
      id: 'S21', level: 'MUST', title: 'refuses (400 SSO_LOGIN_FAILED, no redirect) an ID token signed with none, with no signature, by another key under a known kid, with an unknown kid or none, changed after signing, or signed as an HMAC with the provider\'s public key',
      async run() {
        await connect();
        const es = keys.ES256;
        const stranger = makeKey('ES256', es.kid); // the right kid, another key
        const publicPem = createPublicKey(es.privateKey).export({ type: 'spki', format: 'pem' });
        const cases = [
          ['alg none', { build: ({ header, claims }) => `${b64u({ ...header, alg: 'none' })}.${b64u(claims)}.` }],
          ['alg none with a signature', { build: ({ header, claims }) => `${b64u({ ...header, alg: 'none' })}.${b64u(claims)}.${randomBytes(64).toString('base64url')}` }],
          ['no signature', { build: ({ header, claims }) => `${b64u(header)}.${b64u(claims)}.` }],
          ['another key under a known kid', { key: stranger }],
          ['an unknown kid', { header: (h) => ({ ...h, kid: 'no-such-key' }) }],
          ['no kid', { header: (h) => ({ alg: h.alg, typ: h.typ }) }],
          ['a payload changed after signing', { mutate: (token) => { const [h, p, s] = token.split('.'); const claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')); return `${h}.${b64u({ ...claims, email: 'admin@example.test' })}.${s}`; } }],
          ['an HMAC keyed with the public key', { build: ({ header, claims }) => { const input = `${b64u({ ...header, alg: 'HS256' })}.${b64u(claims)}`; return `${input}.${createHmac('sha256', publicPem).update(input).digest('base64url')}`; } }],
          ['a token that is not a JWT', { build: () => 'not.a.token' }],
        ];
        for (const [why, plan] of cases) refused(await signIn(plan), 'SSO_LOGIN_FAILED', why);
      },
    },
    {
      id: 'S22', level: 'MUST', title: 'refuses (400 SSO_LOGIN_FAILED, no redirect) a token endpoint that answers an error, answers without an id_token or answers with an error member',
      async run() {
        await connect();
        for (const [why, tokenResponse] of [
          ['a 500', { status: 500, body: { error: 'server_error' } }],
          ['a 400 invalid_grant', { status: 400, body: { error: 'invalid_grant' } }],
          ['a 200 with no id_token', { status: 200, body: { access_token: 'x', token_type: 'Bearer' } }],
          ['a 200 with an error', { status: 200, body: { error: 'invalid_client', error_description: 'no' } }],
        ]) refused(await signIn({ tokenResponse }), 'SSO_LOGIN_FAILED', why);
      },
    },
    {
      id: 'S23', level: 'MUST', title: 'refuses (400 SSO_LOGIN_FAILED, no redirect) the first sign-in of an address the provider does not say is verified: email_verified false, missing, or anything but the boolean true',
      async run() {
        await connect();
        const cases = [
          ['email_verified false', (c) => ({ ...c, email_verified: false })],
          ['no email_verified', (c) => ({ ...c, email_verified: undefined })],
          ['email_verified as the string "true"', (c) => ({ ...c, email_verified: 'true' })],
          ['email_verified as the number 1', (c) => ({ ...c, email_verified: 1 })],
          ['email_verified null', (c) => ({ ...c, email_verified: null })],
        ];
        for (const [why, claims] of cases) refused(await signIn({ claims }), 'SSO_LOGIN_FAILED', why);
      },
    },
    {
      id: 'S24', level: 'MUST', title: 'binds a person to the provider\'s subject on the first sign-in: the same e-mail address under another subject is refused (400 SSO_LOGIN_FAILED, no redirect), and the person\'s own subject still signs in',
      async run() {
        await connect();
        const email = `bound-${randomBytes(4).toString('hex')}@example.test`;
        const own = `sub-own-${randomBytes(4).toString('hex')}`;
        const other = `sub-other-${randomBytes(4).toString('hex')}`;
        signedIn(await signIn({ claims: (c) => ({ ...c, email, sub: own }) }), 'the first sign-in of the person');
        refused(await signIn({ claims: (c) => ({ ...c, email, sub: other }) }), 'SSO_LOGIN_FAILED', 'the same address under another subject');
        refused(await signIn({ claims: (c) => ({ ...c, email: email.toUpperCase(), sub: other }) }), 'SSO_LOGIN_FAILED', 'the same address in capitals under another subject');
        signedIn(await signIn({ claims: (c) => ({ ...c, email, sub: own }) }), 'the person\'s own subject again');
      },
    },
    {
      id: 'S25', level: 'MUST', title: 'lets an address at a domain the account verified sign in for the first time, and be created, when the ID token has no email_verified claim at all (section 9.5)',
      async run() {
        if (!options.domains) return skip('the deployment gave the kit no way to verify a domain');
        await connect();
        const domain = `verified-${randomBytes(4).toString('hex')}.example.test`;
        await options.domains.verified({ domain });
        const email = `person-${randomBytes(4).toString('hex')}@${domain}`;
        const sub = `sub-${randomBytes(4).toString('hex')}`;
        signedIn(await signIn({ claims: (c) => ({ ...c, email, sub, email_verified: undefined }) }), 'the first sign-in at the verified domain, with no email_verified');
        // The person is linked to that subject like any other: another subject under the same address is refused.
        refused(await signIn({ claims: (c) => ({ ...c, email, sub: `${sub}-other`, email_verified: undefined }) }), 'SSO_LOGIN_FAILED', 'the same address under another subject');
        signedIn(await signIn({ claims: (c) => ({ ...c, email, sub, email_verified: undefined }) }), 'the person\'s own subject again');
      },
    },
    {
      id: 'S26', level: 'MUST', title: 'refuses (400 SSO_LOGIN_FAILED, no redirect) a first sign-in with no email_verified claim at an address whose domain is not verified for the account (another domain, a subdomain or the parent of a verified one), and one that says email_verified false, or anything but true, even at a verified domain',
      async run() {
        if (!options.domains) return skip('the deployment gave the kit no way to verify a domain');
        await connect();
        const domain = `exact-${randomBytes(4).toString('hex')}.example.test`;
        await options.domains.verified({ domain });
        const at = (host) => `person-${randomBytes(4).toString('hex')}@${host}`;
        const absent = (email) => ({ claims: (c) => ({ ...c, email, email_verified: undefined }) });
        refused(await signIn(absent(at(`unverified-${randomBytes(4).toString('hex')}.example.test`))), 'SSO_LOGIN_FAILED', 'a domain nobody verified');
        refused(await signIn(absent(at(`mail.${domain}`))), 'SSO_LOGIN_FAILED', 'a subdomain of a verified domain');
        refused(await signIn(absent(at(domain.split('.').slice(1).join('.')))), 'SSO_LOGIN_FAILED', 'the parent of a verified domain');
        refused(await signIn(absent(at(`${domain}.evil.example`))), 'SSO_LOGIN_FAILED', 'a domain that merely begins with a verified one');
        // A provider that said something about the address is taken at its word, whatever the domain.
        for (const [why, value] of [['false', false], ['the string "true"', 'true'], ['the number 1', 1], ['null', null]]) {
          const email = at(domain);
          refused(await signIn({ claims: (c) => ({ ...c, email, email_verified: value }) }), 'SSO_LOGIN_FAILED', `email_verified ${why} at the verified domain`);
        }
      },
    },
    {
      id: 'S27', level: 'MUST', title: 'does not count a domain verified by another account: an address at it with no email_verified claim is refused (400 SSO_LOGIN_FAILED, no redirect)',
      async run() {
        if (!options.domains) return skip('the deployment gave the kit no way to verify a domain');
        await connect();
        const domain = `elsewhere-${randomBytes(4).toString('hex')}.example.test`;
        await options.domains.verifiedElsewhere({ domain });
        const email = `person-${randomBytes(4).toString('hex')}@${domain}`;
        refused(await signIn({ claims: (c) => ({ ...c, email, email_verified: undefined }) }), 'SSO_LOGIN_FAILED', 'an address at a domain another account verified');
      },
    },
    {
      id: 'S28', level: 'MUST', title: 'stops counting a verified domain once its proof record is gone and the deployment\'s window for a cached check has passed: a first sign-in with no email_verified claim is refused (400 SSO_LOGIN_FAILED, no redirect), while a person already linked still signs in',
      async run() {
        if (!options.domains) return skip('the deployment gave the kit no way to verify a domain');
        await connect();
        const domain = `lapsing-${randomBytes(4).toString('hex')}.example.test`;
        await options.domains.verified({ domain });
        const email = `person-${randomBytes(4).toString('hex')}@${domain}`;
        const sub = `sub-${randomBytes(4).toString('hex')}`;
        signedIn(await signIn({ claims: (c) => ({ ...c, email, sub, email_verified: undefined }) }), 'a sign-in while the domain is verified');
        await options.domains.recordRemoved({ domain });
        const newcomer = `newcomer-${randomBytes(4).toString('hex')}@${domain}`;
        refused(await signIn({ claims: (c) => ({ ...c, email: newcomer, email_verified: undefined }) }), 'SSO_LOGIN_FAILED', 'a first sign-in after the record was removed');
        signedIn(await signIn({ claims: (c) => ({ ...c, email, sub, email_verified: undefined }) }), 'the person already linked, after the record was removed');
      },
    },
    {
      id: 'S30', level: 'MUST', title: 'uses a state once: a replayed callback is 400 SSO_STATE_INVALID and redeems nothing',
      async run() {
        await connect();
        const first = await signIn();
        signedIn(first, 'the sign-in');
        const again = authenticate(first.started, {});
        const before = tokenRequests.length;
        const replay = await callback(first.started, again);
        assert(replay.status === 400 && replay.error?.code === 'SSO_STATE_INVALID', `a replayed callback answered ${replay.status} ${replay.error?.code ?? ''}`.trim());
        assert(tokenRequests.length === before, 'a replayed callback reached the token endpoint');
        pending.delete(again);
      },
    },
    {
      id: 'S31', level: 'MUST', title: 'refuses a callback that did not come from the browser that started (no cookie, another sign-in\'s cookie, a forged one): 400 SSO_STATE_NOT_BOUND, and the token endpoint is never called',
      async run() {
        await connect();
        const other = await start();
        for (const [why, cookie] of [['no cookie', null], ['another sign-in\'s cookie', other.cookie], ['a forged cookie', 'stack_sso_state=not-the-state']]) {
          const started = await start();
          const before = tokenRequests.length;
          const code = authenticate(started, {});
          const back = await callback(started, code, { cookie });
          assert(back.status === 400 && back.error?.code === 'SSO_STATE_NOT_BOUND', `${why}: the callback answered ${back.status} ${back.error?.code ?? ''}`.trim());
          assert(!back.location, `${why}: the refusal redirected to ${back.location}`);
          assert(tokenRequests.length === before, `${why}: the code was redeemed`);
          pending.delete(code);
        }
      },
    },
    {
      id: 'S32', level: 'MUST', title: 'answers a provider\'s error with 400 SSO_UPSTREAM_ERROR and the provider\'s description',
      async run() {
        await connect();
        const started = await start();
        const back = await callback(started, null, { query: `error=access_denied&error_description=${encodeURIComponent('the person said no')}&state=${encodeURIComponent(started.params.state)}` });
        assert(back.status === 400 && back.error?.code === 'SSO_UPSTREAM_ERROR', `answered ${back.status} ${back.error?.code ?? ''}`.trim());
        const response = await get(`${redirectUri}?error=access_denied&error_description=${encodeURIComponent('the person said no')}`);
        assert(JSON.stringify(await bodyOf(response)).includes('the person said no'), 'the provider\'s description is not in the answer');
      },
    },
    {
      id: 'S33', level: 'MUST', title: 'refuses a callback with no code or no state (400 SSO_CALLBACK_INVALID), one with a state it never made (400 SSO_STATE_INVALID) and one with a parameter twice (400 VALIDATION_ERROR)',
      async run() {
        await connect();
        const started = await start();
        const state = encodeURIComponent(started.params.state);
        for (const [why, query, code] of [
          ['no code', `state=${state}`, 'SSO_CALLBACK_INVALID'],
          ['no state', 'code=abc', 'SSO_CALLBACK_INVALID'],
          ['an empty query', '', 'SSO_CALLBACK_INVALID'],
          ['a state it never made', `code=abc&state=${encodeURIComponent(randomBytes(32).toString('base64url'))}`, 'SSO_STATE_INVALID'],
          ['a code twice', `code=a&code=b&state=${state}`, 'VALIDATION_ERROR'],
        ]) {
          const back = await callback(started, null, { query });
          assert(back.status === 400 && back.error?.code === code, `${why}: answered ${back.status} ${back.error?.code ?? ''}, not ${code}`.trim());
        }
      },
    },
    {
      id: 'S40', level: 'MUST', title: 'leaves the public handoff address inert: POST /v1/identity/sso/handoff is a 404 and answers no identity',
      async run() {
        await connect();
        const result = await signIn();
        const r = ref(result.back) ?? 'ssoh_unknown';
        const response = await fetch(`${base}/v1/identity/sso/handoff`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ref: r }), redirect: 'manual' });
        const body = await response.text();
        assert(response.status === 404, `the address answered ${response.status}`);
        assert(!/operator_id|member_id|email/.test(body), 'the answer carries an identity');
      },
    },
  ]);
  await new Promise((resolve) => { server.close(() => resolve()); server.closeAllConnections?.(); });
  return report;
}

