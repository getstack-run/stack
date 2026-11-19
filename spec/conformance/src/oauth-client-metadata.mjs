// Conformance suite for the CHECK of a client metadata document (spec/oauth-profile/SPEC.md, section 4.1 and 4.3):
// the rules a server applies to the document it fetched at an https client_id, and to the client_id itself. The
// fetch (public addresses only, no redirects, 5 KiB, 5 seconds) is not tested here: it needs a server that can be
// made to fetch, and the `oauth` suite checks that the server refuses a private address.
//
//   validate(clientId, document) -> { client_id, client_name, redirect_uris, grant_types }   or throws
//   isMetadataClientId(clientId) -> boolean                                                  (optional)
//
// `document` is the parsed JSON the server fetched. The result is what the server stores for the client.

import { assert, runChecks, skip } from './harness.mjs';

const ID = 'https://client.example/oauth/client.json';

/**
 * @param {{ validate: (clientId: string, document: unknown) => object | Promise<object>, isMetadataClientId?: (clientId: string) => boolean }} options
 */
export async function runClientMetadataSuite(options) {
  const { validate } = options;
  const doc = (over = {}) => ({ client_id: ID, client_name: 'Conformance Client', redirect_uris: ['https://client.example/callback'], ...over });
  const accepts = async (document, why, clientId = ID) => {
    try {
      return await validate(clientId, document);
    } catch (error) {
      assert(false, `${why} was refused: ${error instanceof Error ? error.message : String(error)}`);
    }
  };
  const refuses = async (document, why, clientId = ID) => {
    let result;
    try {
      result = await validate(clientId, document);
    } catch {
      return;
    }
    assert(false, `${why} was accepted (${JSON.stringify(result)})`);
  };
  const without = (obj, name) => Object.fromEntries(Object.entries(obj).filter(([k]) => k !== name));

  return runChecks('oauth client metadata document', [
    {
      id: 'CM01', level: 'MUST', title: 'accepts a minimal document and returns the client id, name, redirect URIs and grants; the host names a client with no name',
      async run() {
        const r = await accepts(doc(), 'a minimal document');
        assert(r.client_id === ID && r.client_name === 'Conformance Client', 'the client id or name is not kept');
        assert(JSON.stringify(r.redirect_uris) === JSON.stringify(['https://client.example/callback']), 'the redirect URIs are not kept');
        assert(Array.isArray(r.grant_types) && r.grant_types.includes('authorization_code'), 'the default grants lack authorization_code');
        const unnamed = await accepts(without(doc(), 'client_name'), 'a document with no client_name');
        assert(unnamed.client_name === 'client.example', `the name is ${JSON.stringify(unnamed.client_name)}, not the host`);
      },
    },
    {
      id: 'CM02', level: 'MUST', title: 'refuses a document whose client_id is not the URL it was fetched from, byte for byte',
      async run() {
        await refuses(doc({ client_id: 'https://client.example/other.json' }), 'a document naming another client_id');
        await refuses(doc({ client_id: `${ID}/` }), 'a client_id with a trailing slash');
        await refuses(without(doc(), 'client_id'), 'a document with no client_id');
        for (const bad of [null, [], 'text', 5]) await refuses(bad, `a document that is ${JSON.stringify(bad)}`);
      },
    },
    {
      id: 'CM03', level: 'MUST', title: 'refuses a document that carries a client secret',
      async run() {
        await refuses(doc({ client_secret: 'shh' }), 'a document with client_secret');
        await refuses(doc({ client_secret_expires_at: 0 }), 'a document with client_secret_expires_at');
      },
    },
    {
      id: 'CM04', level: 'MUST', title: 'accepts a client that can work as a public one (auth method none, or none among those it supports) and refuses one that cannot',
      async run() {
        await accepts(doc({ token_endpoint_auth_method: 'none' }), 'a client that says none');
        await accepts(doc({ token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_methods_supported: ['private_key_jwt', 'none'] }), 'a client that prefers private_key_jwt and lists none');
        await refuses(doc({ token_endpoint_auth_method: 'client_secret_post' }), 'a client that wants client_secret_post');
        await refuses(doc({ token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_methods_supported: ['private_key_jwt'] }), 'a client that lists no none');
      },
    },
    {
      id: 'CM05', level: 'MUST', title: 'accepts https, loopback http and private-use scheme redirect URIs, and refuses every other kind',
      async run() {
        const good = ['https://client.example/cb', 'http://127.0.0.1/cb', 'http://127.0.0.1:8123/cb', 'http://[::1]/cb', 'http://localhost/cb', 'cursor://anysphere.cursor-mcp/oauth/callback', 'myapp:/callback'];
        const r = await accepts(doc({ redirect_uris: good }), 'the redirect URIs of a native and a web client');
        assert(r.redirect_uris.length === good.length, 'a good redirect URI was dropped');
        for (const [why, uri] of [
          ['an http URL on a public host', 'http://client.example/cb'],
          ['a URI with a fragment', 'https://client.example/cb#x'],
          ['a javascript: URI', 'javascript:alert(1)'],
          ['a data: URI', 'data:text/html,hi'],
          ['a file: URI', 'file:///etc/passwd'],
          ['a custom scheme with no host or path', 'myapp:'],
          ['a custom scheme with credentials', 'myapp://user:pw@host/cb'],
          ['text that is not a URI', 'not a uri'],
        ]) {
          await refuses(doc({ redirect_uris: [uri] }), why);
        }
      },
    },
    {
      id: 'CM06', level: 'MUST', title: 'requires between 1 and 20 redirect URIs, each a string of at most 2048 characters, and keeps each once',
      async run() {
        await refuses(doc({ redirect_uris: [] }), 'no redirect URIs');
        await refuses(without(doc(), 'redirect_uris'), 'no redirect_uris member');
        await refuses(doc({ redirect_uris: Array.from({ length: 21 }, (_, i) => `https://client.example/cb${i}`) }), 'twenty-one redirect URIs');
        await refuses(doc({ redirect_uris: [5] }), 'a redirect URI that is not a string');
        await refuses(doc({ redirect_uris: [`https://client.example/${'a'.repeat(2100)}`] }), 'a redirect URI over 2048 characters');
        const r = await accepts(doc({ redirect_uris: ['https://client.example/cb', 'https://client.example/cb'] }), 'a repeated redirect URI');
        assert(r.redirect_uris.length === 1, 'a repeated redirect URI was kept twice');
      },
    },
    {
      id: 'CM07', level: 'MUST', title: 'requires authorization_code among the grants, and keeps only the grants the server offers',
      async run() {
        await refuses(doc({ grant_types: ['refresh_token'] }), 'a client with no authorization_code');
        await refuses(doc({ grant_types: 'authorization_code' }), 'grant_types that is not an array');
        const r = await accepts(doc({ grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'] }), 'a client that also lists jwt-bearer');
        assert(JSON.stringify([...r.grant_types].sort()) === JSON.stringify(['authorization_code', 'refresh_token']), `the grants kept are ${JSON.stringify(r.grant_types)}`);
      },
    },
    {
      id: 'CM08', level: 'MUST', title: 'accepts response_types ["code"] and refuses any other; keeps a name of 1 to 200 characters, trimmed, and refuses a blank or longer one',
      async run() {
        await accepts(doc({ response_types: ['code'] }), 'response_types ["code"]');
        await refuses(doc({ response_types: ['token'] }), 'response_types ["token"]');
        await refuses(doc({ response_types: ['code', 'token'] }), 'two response types');
        await refuses(doc({ client_name: '   ' }), 'a blank name');
        await refuses(doc({ client_name: 'n'.repeat(201) }), 'a name of 201 characters');
        const r = await accepts(doc({ client_name: '  Padded  ' }), 'a name with spaces around it');
        assert(r.client_name === 'Padded', `the name is ${JSON.stringify(r.client_name)}`);
      },
    },
    {
      id: 'CM10', level: 'MUST', title: 'takes an https client_id with a path as a metadata document URL, and nothing else',
      async run() {
        const { isMetadataClientId } = options;
        if (!isMetadataClientId) return skip('give the suite isMetadataClientId to check which client ids name a document');
        for (const [yes, id] of [
          [true, 'https://client.example/oauth/client.json'],
          [true, 'https://client.example:8443/a'],
          [false, 'https://client.example/'],
          [false, 'https://client.example'],
          [false, 'http://client.example/client.json'],
          [false, 'https://client.example/a?x=1'],
          [false, 'https://client.example/a#x'],
          [false, 'https://user:pw@client.example/a'],
          [false, 'https://client.example/a/../b'],
          [false, 'https://client.example/./a'],
          [false, 'oc_0123456789'],
          [false, `https://client.example/${'a'.repeat(1100)}`],
        ]) {
          assert(isMetadataClientId(id) === yes, `${id.slice(0, 60)} was ${yes ? 'refused' : 'taken'} as a metadata document URL`);
        }
      },
    },
  ]);
}
