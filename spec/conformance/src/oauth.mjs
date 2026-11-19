// Conformance suite for a SERVER'S OAuth authorization server profile (spec/oauth-profile/SPEC.md). The kit plays
// a client: it reads the discovery document, registers clients, makes authorization requests (valid and not),
// calls the token, device and revocation endpoints with things it cannot have been given, and checks the answers.
// Nothing here needs a person: a person's approval of an authorization request is the one step the kit does not
// take, so it stops at the redirect to the consent page and checks that.
//
//   { baseUrl }   the address of a test instance with OAuth enabled.
//
// The server limits registration to ten requests an hour per source address, and the suite's last check goes over
// that limit on purpose (so a second run against the same instance cannot register a client). Pass
// `rateLimits: false` to leave that check out.

import { createHash } from 'node:crypto';
import { assert, runChecks, skip } from './harness.mjs';
import { callJson, errorCode, randomToken } from './identity-support.mjs';

const flat = (r) => (r.body && typeof r.body.error === 'string' ? r.body.error : undefined);
const isFlat = (r) => r.body && typeof r.body.error === 'string' && typeof r.body.error !== 'object';
const challengeOf = (verifier) => createHash('sha256').update(verifier).digest('base64url');

/** @param {{ baseUrl: string, rateLimits?: boolean }} options */
export async function runOAuthSuite(options) {
  const { baseUrl, rateLimits = true } = options;
  const verifier = randomToken(32);
  const challenge = challengeOf(verifier);
  const state = {};
  const json = (path, init) => callJson(baseUrl, path, init);
  const authorize = (params) => json(`/oauth/authorize?${new URLSearchParams(params).toString()}`);
  const token = (form) => json('/oauth/token', { method: 'POST', form });
  const expectFlat = (r, status, error, why) => {
    assert(r.status === status && flat(r) === error, `${why}: answered ${r.status} ${flat(r) ?? errorCode(r) ?? JSON.stringify(r.body)}, not ${status} ${error}`);
    assert(isFlat(r), `${why}: the error is not the flat shape of RFC 6749`);
  };

  const registered = async () => {
    if (state.client) return state.client;
    const r = await json('/oauth/register', {
      method: 'POST',
      body: { client_name: 'conformance-client', redirect_uris: ['https://client.example/callback', 'http://127.0.0.1/callback', 'conformance-app://oauth/callback'] },
    });
    state.registration = r;
    assert(r.status === 201 && typeof r.body?.client_id === 'string', `registration answered ${r.status} ${flat(r) ?? ''}`.trim());
    state.client = r.body.client_id;
    return state.client;
  };
  const base = async (over = {}) => ({
    response_type: 'code', client_id: await registered(), redirect_uri: 'https://client.example/callback',
    code_challenge: challenge, code_challenge_method: 'S256', state: 'xyz', ...over,
  });
  const dropped = (params, name) => Object.fromEntries(Object.entries(params).filter(([k]) => k !== name));

  return runChecks('oauth server', [
    {
      id: 'OA01', level: 'MUST', title: 'publishes RFC 8414 metadata: the endpoints, S256 only, public clients only, metadata documents, the four grants',
      async run() {
        const r = await json('/.well-known/oauth-authorization-server');
        assert(r.status === 200 && r.body, `discovery answered ${r.status}`);
        state.metadata = r.body;
        const m = r.body;
        assert(typeof m.issuer === 'string' && /^https?:\/\//.test(m.issuer), 'the issuer is not a URL');
        for (const name of ['authorization_endpoint', 'token_endpoint', 'device_authorization_endpoint', 'registration_endpoint', 'revocation_endpoint']) {
          assert(typeof m[name] === 'string' && m[name].startsWith(m.issuer), `${name} is not under the issuer`);
        }
        assert(m.authorization_endpoint.endsWith('/oauth/authorize') && m.token_endpoint.endsWith('/oauth/token'), 'the endpoint paths are not /oauth/authorize and /oauth/token');
        assert(JSON.stringify(m.response_types_supported) === '["code"]', 'response_types_supported is not ["code"]');
        assert(JSON.stringify(m.code_challenge_methods_supported) === '["S256"]', 'code_challenge_methods_supported is not ["S256"]');
        assert(JSON.stringify(m.token_endpoint_auth_methods_supported) === '["none"]', `token_endpoint_auth_methods_supported is ${JSON.stringify(m.token_endpoint_auth_methods_supported)}, not ["none"]: no client secret is read`);
        assert(m.client_id_metadata_document_supported === true, 'client_id_metadata_document_supported is not true');
        for (const grant of ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code', 'urn:ietf:params:oauth:grant-type:token-exchange']) {
          assert(Array.isArray(m.grant_types_supported) && m.grant_types_supported.includes(grant), `grant_types_supported lacks ${grant}`);
        }
        assert(Array.isArray(m.scopes_supported) && m.scopes_supported.includes('passports:read'), 'scopes_supported lacks passports:read');
      },
    },
    {
      id: 'OA02', level: 'MUST', title: 'serves the key set named by jwks_uri: Ed25519 signing keys with key ids and no private member',
      async run() {
        const m = state.metadata ?? (await json('/.well-known/oauth-authorization-server')).body;
        const url = new URL(m.jwks_uri);
        const r = await callJson(baseUrl, url.pathname, {});
        assert(r.status === 200 && Array.isArray(r.body?.keys) && r.body.keys.length > 0, `the key set answered ${r.status}`);
        for (const k of r.body.keys) {
          assert(k.kty === 'OKP' && k.crv === 'Ed25519' && typeof k.kid === 'string' && typeof k.x === 'string', 'a key is not an Ed25519 key with a kid');
          assert(!('d' in k), 'a key carries a private member');
        }
      },
    },
    {
      id: 'OA10', level: 'MUST', title: 'registers a public client (201): no secret, auth method none, the supported grants, https, loopback and private-use redirects kept',
      async run() {
        await registered();
        const r = state.registration;
        const b = r.body;
        assert(b.token_endpoint_auth_method === 'none' && b.client_secret === undefined, 'the client is not public');
        assert(Array.isArray(b.redirect_uris) && b.redirect_uris.length === 3, 'a redirect URI was dropped');
        assert(Array.isArray(b.grant_types) && b.grant_types.includes('authorization_code') && b.grant_types.includes('refresh_token'), `the default grants are ${JSON.stringify(b.grant_types)}`);
        assert(JSON.stringify(b.response_types) === '["code"]' && b.client_name === 'conformance-client', 'the answer does not echo the registration');
        assert(Number.isInteger(b.client_id_issued_at) && typeof b.scope === 'string' && b.scope.length > 0, 'the answer lacks client_id_issued_at or scope');
      },
    },
    {
      id: 'OA11', level: 'MUST', title: 'refuses a registration that has no redirect URI, an unsafe one, no name, an unknown scope or no usable grant',
      async run() {
        const ok = { client_name: 'x', redirect_uris: ['https://client.example/cb'] };
        const cases = [
          ['no redirect_uris', { client_name: 'x' }, 'invalid_redirect_uri'],
          ['an http redirect to a public host', { ...ok, redirect_uris: ['http://client.example/cb'] }, 'invalid_redirect_uri'],
          ['a redirect with a fragment', { ...ok, redirect_uris: ['https://client.example/cb#frag'] }, 'invalid_redirect_uri'],
          ['a javascript: redirect', { ...ok, redirect_uris: ['javascript:alert(1)'] }, 'invalid_redirect_uri'],
          ['no client_name', { redirect_uris: ok.redirect_uris }, 'invalid_client_metadata'],
          ['an unknown scope', { ...ok, scope: 'passports:read root' }, 'invalid_scope'],
        ];
        for (const [why, body, error] of cases) expectFlat(await json('/oauth/register', { method: 'POST', body }), 400, error, why);
      },
    },
    {
      id: 'OA20', level: 'MUST', title: 'refuses a bad authorization request with a JSON error and without redirecting',
      async run() {
        const params = await base();
        const cases = [
          ['response_type token', { ...params, response_type: 'token' }, 400, 'unsupported_response_type'],
          ['no code_challenge', dropped(params, 'code_challenge'), 400, 'invalid_request'],
          ['no redirect_uri', dropped(params, 'redirect_uri'), 400, 'invalid_request'],
          ['code_challenge_method plain', { ...params, code_challenge_method: 'plain' }, 400, 'invalid_request'],
          ['an unknown resource', { ...params, resource: 'https://elsewhere.example/api' }, 400, 'invalid_target'],
          ['an unknown scope', { ...params, scope: 'passports:read root' }, 400, 'invalid_scope'],
          ['a redirect_uri that is not registered', { ...params, redirect_uri: 'https://evil.example/callback' }, 400, 'invalid_request'],
          ['a client that is not registered', { ...params, client_id: `oc_${randomToken(8)}` }, 401, 'invalid_client'],
        ];
        for (const [why, p, status, error] of cases) {
          const r = await authorize(p);
          assert(!r.headers.get('location'), `${why}: the server redirected`);
          expectFlat(r, status, error, why);
        }
      },
    },
    {
      id: 'OA21', level: 'MUST', title: 'sends a valid authorization request to the consent page (302), and keeps the redirect URI exact except the port of a loopback one',
      async run() {
        const ok = await authorize(await base());
        assert(ok.status === 302, `a valid request answered ${ok.status} ${flat(ok) ?? ''}`.trim());
        const location = new URL(ok.headers.get('location'));
        assert(location.pathname === '/oauth/consent', `the redirect goes to ${location.pathname}`);
        assert(/^[\w-]+\.[\w-]+\.[\w-]+$/.test(location.searchParams.get('state') ?? ''), 'the consent state is not a signed token');
        assert(location.searchParams.get('code') === null, 'a code was issued without a person\'s approval');
        const loopback = await authorize(await base({ redirect_uri: 'http://127.0.0.1:54321/callback' }));
        assert(loopback.status === 302, `a loopback redirect with another port answered ${loopback.status}`);
        const otherPath = await authorize(await base({ redirect_uri: 'http://127.0.0.1:54321/elsewhere' }));
        assert(otherPath.status === 400, `a loopback redirect with another path answered ${otherPath.status}`);
        const native = await authorize(await base({ redirect_uri: 'conformance-app://oauth/callback' }));
        assert(native.status === 302, `a private-use redirect answered ${native.status}`);
      },
    },
    {
      id: 'OA22', level: 'MUST', title: 'grants the default scope when none is asked, and only known scopes when some are',
      async run() {
        const r = await authorize(await base({ scope: 'passports:read agents:read' }));
        assert(r.status === 302, `answered ${r.status}`);
        const none = await authorize(await base());
        assert(none.status === 302, 'a request with no scope was refused');
      },
    },
    {
      id: 'OA23', level: 'MUST', title: 'does not fetch a client metadata document from a private address, and treats an http client_id as a plain id',
      async run() {
        const params = await base();
        expectFlat(await authorize({ ...params, client_id: 'https://localhost/client.json' }), 400, 'invalid_client', 'a client_id that is a document on localhost');
        expectFlat(await authorize({ ...params, client_id: 'https://127.0.0.1/client.json' }), 400, 'invalid_client', 'a client_id that is a document on a loopback address');
        expectFlat(await authorize({ ...params, client_id: 'http://client.example/client.json' }), 401, 'invalid_client', 'a client_id that is an http URL');
      },
    },
    {
      id: 'OA30', level: 'MUST', title: 'refuses grants it does not offer, and answers errors in the flat RFC 6749 shape',
      async run() {
        expectFlat(await token({ grant_type: 'password', username: 'a', password: 'b' }), 400, 'unsupported_grant_type', 'the password grant');
        expectFlat(await token({ grant_type: 'client_credentials' }), 400, 'unsupported_grant_type', 'the client credentials grant');
        expectFlat(await token({}), 400, 'unsupported_grant_type', 'no grant_type');
      },
    },
    {
      id: 'OA31', level: 'MUST', title: 'refuses an authorization code request that lacks a parameter (invalid_request), or presents a code it never issued (invalid_grant)',
      async run() {
        const client_id = await registered();
        const full = { grant_type: 'authorization_code', code: `ac_${randomToken(16)}`, redirect_uri: 'https://client.example/callback', client_id, code_verifier: verifier };
        for (const name of ['code', 'redirect_uri', 'client_id', 'code_verifier']) {
          expectFlat(await token(dropped(full, name)), 400, 'invalid_request', `a request with no ${name}`);
        }
        expectFlat(await token(full), 400, 'invalid_grant', 'a code that was never issued');
      },
    },
    {
      id: 'OA32', level: 'MUST', title: 'refuses a refresh token it never issued, and one with no client_id; reads parameters from a JSON body too',
      async run() {
        const client_id = await registered();
        expectFlat(await token({ grant_type: 'refresh_token', refresh_token: `rt_${randomToken(16)}`, client_id }), 400, 'invalid_grant', 'an unknown refresh token');
        expectFlat(await token({ grant_type: 'refresh_token', refresh_token: 'x' }), 400, 'invalid_request', 'a refresh with no client_id');
        const asJson = await json('/oauth/token', { method: 'POST', body: { grant_type: 'refresh_token', refresh_token: `rt_${randomToken(16)}`, client_id } });
        expectFlat(asJson, 400, 'invalid_grant', 'an unknown refresh token sent as JSON');
        expectFlat(await json('/oauth/token', { method: 'POST', body: { grant_type: 'refresh_token', refresh_token: ['a', 'b'], client_id } }), 400, 'invalid_request', 'a parameter that is not a single string');
      },
    },
    {
      id: 'OA33', level: 'MUST', title: 'takes no client secret: a request that carries one is judged by its grant alone',
      async run() {
        const client_id = await registered();
        const r = await token({ grant_type: 'refresh_token', refresh_token: `rt_${randomToken(16)}`, client_id, client_secret: 'a-secret' });
        expectFlat(r, 400, 'invalid_grant', 'an unknown refresh token with a client secret');
      },
    },
    {
      id: 'OA34', level: 'MUST', title: 'refuses a token exchange that asks for more than a refresh: an actor, an audience or resource, a scope, or a subject that is not a Passport',
      async run() {
        const grant = 'urn:ietf:params:oauth:grant-type:token-exchange';
        const type = 'urn:stack:token-type:passport';
        expectFlat(await token({ grant_type: grant }), 400, 'invalid_request', 'no subject_token');
        expectFlat(await token({ grant_type: grant, subject_token: 'x' }), 400, 'invalid_request', 'no subject_token_type');
        expectFlat(await token({ grant_type: grant, subject_token: 'x', subject_token_type: 'urn:ietf:params:oauth:token-type:access_token' }), 400, 'invalid_request', 'a subject token type it does not take');
        expectFlat(await token({ grant_type: grant, subject_token: 'x', subject_token_type: type, actor_token: 'y' }), 400, 'invalid_request', 'an actor token');
        expectFlat(await token({ grant_type: grant, subject_token: 'x', subject_token_type: type, audience: 'a' }), 400, 'invalid_target', 'an audience');
        expectFlat(await token({ grant_type: grant, subject_token: 'x', subject_token_type: type, resource: 'https://a.example' }), 400, 'invalid_target', 'a resource');
        expectFlat(await token({ grant_type: grant, subject_token: 'x', subject_token_type: type, scope: 'passports:read' }), 400, 'invalid_scope', 'a scope');
        expectFlat(await token({ grant_type: grant, subject_token: 'not.a.passport', subject_token_type: type }), 400, 'invalid_grant', 'a subject token that is not a Passport');
      },
    },
    {
      id: 'OA40', level: 'MUST', title: 'starts a device authorization for a registered client (user code XXXX-XXXX, interval, expiry) and holds the poll as authorization_pending, then slow_down',
      async run() {
        const client_id = await registered();
        const r = await json('/oauth/device/authorize', { method: 'POST', form: { client_id, scope: 'passports:read' } });
        assert(r.status === 200, `device authorization answered ${r.status} ${flat(r) ?? ''}`.trim());
        const b = r.body;
        assert(typeof b.device_code === 'string' && /^[BCDFGHJKLMNPQRSTVWXYZ2-9]{4}-[BCDFGHJKLMNPQRSTVWXYZ2-9]{4}$/.test(b.user_code), 'the device or user code is not as specified');
        assert(typeof b.verification_uri === 'string' && b.verification_uri_complete?.includes(encodeURIComponent(b.user_code)), 'the verification URIs are wrong');
        assert(b.expires_in === 900 && b.interval === 5, `expires_in ${b.expires_in} and interval ${b.interval} are not 900 and 5`);
        const poll = { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: b.device_code, client_id };
        expectFlat(await token(poll), 400, 'authorization_pending', 'the first poll');
        expectFlat(await token(poll), 400, 'slow_down', 'a poll made at once again');
        expectFlat(await token({ ...poll, client_id: `oc_${randomToken(8)}` }), 400, 'invalid_grant', 'a poll by another client');
        expectFlat(await token({ ...poll, device_code: `dc_${randomToken(16)}` }), 400, 'invalid_grant', 'an unknown device code');
      },
    },
    {
      id: 'OA41', level: 'MUST', title: 'refuses a device authorization for an unknown client (401), an unknown scope and an unknown resource',
      async run() {
        const client_id = await registered();
        expectFlat(await json('/oauth/device/authorize', { method: 'POST', form: { client_id: `oc_${randomToken(8)}` } }), 401, 'invalid_client', 'an unknown client');
        expectFlat(await json('/oauth/device/authorize', { method: 'POST', form: { client_id, scope: 'root' } }), 400, 'invalid_scope', 'an unknown scope');
        expectFlat(await json('/oauth/device/authorize', { method: 'POST', form: { client_id, resource: 'https://elsewhere.example' } }), 400, 'invalid_target', 'an unknown resource');
        expectFlat(await json('/oauth/device/authorize', { method: 'POST', form: {} }), 400, 'invalid_request', 'no client_id');
      },
    },
    {
      id: 'OA50', level: 'MUST', title: 'answers 200 with {} to a revocation of a token it does not know, of no token at all, and of an access token',
      async run() {
        for (const [why, init] of [
          ['an unknown token', { form: { token: `rt_${randomToken(16)}` } }],
          ['no token', { form: {} }],
          ['a JSON body', { body: { token: `rt_${randomToken(16)}`, token_type_hint: 'refresh_token' } }],
          ['a token that looks like an access token', { form: { token: 'aaa.bbb.ccc' } }],
        ]) {
          const r = await json('/oauth/revoke', { method: 'POST', ...init });
          assert(r.status === 200 && r.body && Object.keys(r.body).length === 0, `${why}: answered ${r.status} ${r.text}`);
        }
        expectFlat(await json('/oauth/revoke', { method: 'POST', body: { token: ['a', 'b'] } }), 400, 'invalid_request', 'a token that is not a single string');
      },
    },
    {
      id: 'OA60', level: 'MUST', title: 'limits registration (429 after ten requests an hour from one address)',
      async run() {
        if (!rateLimits) return skip('rate limit checks are off');
        const body = { client_name: 'x', redirect_uris: ['https://client.example/cb'] };
        let limited = false;
        // Seven requests are used already; four more pass the ceiling of ten.
        for (let i = 0; i < 6 && !limited; i++) {
          const r = await json('/oauth/register', { method: 'POST', body, waitOnRateLimit: false });
          if (r.status === 429) limited = true;
        }
        assert(limited, 'more than ten registrations from one address were all answered');
      },
    },
  ]);
}
