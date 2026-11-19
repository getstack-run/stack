import { generateKeyPairSync } from 'node:crypto';
import { SignJWT, importJWK, type JWK } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AgentIdentityVerificationError, Stack, verifyAgentIdentity } from '../index.js';

const AGENT = 'agt_Q2x5b3Vkc0FyZUp1c3RlA';
const KEY_ID = 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U';
const NOW = new Date('2026-10-25T09:00:00Z');
const IAT = Math.floor(NOW.getTime() / 1000);

function keys() {
  const pair = generateKeyPairSync('ed25519');
  const privateJwk = { ...pair.privateKey.export({ format: 'jwk' }), kid: 'stack-passport-v1', alg: 'EdDSA', use: 'sig' } as JWK;
  const publicJwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'stack-passport-v1', alg: 'EdDSA', use: 'sig' } as JWK;
  return { privateJwk, publicJwk };
}

const FACTS = {
  v: 1,
  agent: { id: AGENT, status: 'active' },
  owner: { identity_verified: true, good_standing: true },
  lookup: { key_id: KEY_ID },
};

async function statement(over: { claims?: Record<string, unknown>; header?: Record<string, unknown>; key?: ReturnType<typeof keys> } = {}) {
  const key = over.key ?? signing;
  const claims = { identity: FACTS, ...(over.claims ?? {}) };
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA', kid: 'stack-passport-v1', typ: 'stack-agent-identity+jwt', ...(over.header ?? {}) })
    .setIssuer('getstack.run')
    .setAudience('stack:agent-identity')
    .setSubject(AGENT)
    .setIssuedAt(IAT)
    .setExpirationTime(IAT + 300)
    .sign(await importJWK(key.privateJwk, 'EdDSA'));
}

const signing = keys();
const options = { jwks: { keys: [signing.publicJwk] }, now: NOW };

describe('verifyAgentIdentity', () => {
  it('returns the claims of a statement that is right, for what was asked', async () => {
    const claims = await verifyAgentIdentity(await statement(), { ...options, expect: { key_id: KEY_ID } });
    expect(claims.sub).toBe(AGENT);
    expect(claims.identity.owner).toEqual(FACTS.owner);
    expect(claims.identity.lookup).toEqual({ key_id: KEY_ID });
  });

  it('refuses a statement that is about something else than what was asked', async () => {
    await expect(verifyAgentIdentity(await statement(), { ...options, expect: { key_id: 'A'.repeat(43) } })).rejects.toMatchObject({ reason: 'wrong_lookup' });
    await expect(verifyAgentIdentity(await statement(), { ...options, expect: { agent_id: AGENT } })).rejects.toMatchObject({ reason: 'wrong_lookup' });
  });

  it('refuses an expired statement, one made in the future and one good for too long', async () => {
    const later = new Date(NOW.getTime() + 301_000 + 10_000);
    await expect(verifyAgentIdentity(await statement(), { ...options, now: later })).rejects.toMatchObject({ reason: 'expired' });
    const earlier = new Date(NOW.getTime() - 60_000);
    await expect(verifyAgentIdentity(await statement(), { ...options, now: earlier })).rejects.toBeInstanceOf(AgentIdentityVerificationError);
    const long = await new SignJWT({ identity: FACTS })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'stack-passport-v1', typ: 'stack-agent-identity+jwt' })
      .setIssuer('getstack.run').setAudience('stack:agent-identity').setSubject(AGENT).setIssuedAt(IAT).setExpirationTime(IAT + 3600)
      .sign(await importJWK(signing.privateJwk, 'EdDSA'));
    await expect(verifyAgentIdentity(long, options)).rejects.toBeInstanceOf(AgentIdentityVerificationError);
  });

  it('is not a Passport: the type and the audience of an identity statement are both required', async () => {
    const passportLike = await new SignJWT({ identity: FACTS })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'stack-passport-v1' })
      .setIssuer('getstack.run').setAudience('stack:passport').setSubject(AGENT).setIssuedAt(IAT).setExpirationTime(IAT + 300)
      .sign(await importJWK(signing.privateJwk, 'EdDSA'));
    await expect(verifyAgentIdentity(passportLike, options)).rejects.toBeInstanceOf(AgentIdentityVerificationError);
    const noType = await new SignJWT({ identity: FACTS })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'stack-passport-v1' })
      .setIssuer('getstack.run').setAudience('stack:agent-identity').setSubject(AGENT).setIssuedAt(IAT).setExpirationTime(IAT + 300)
      .sign(await importJWK(signing.privateJwk, 'EdDSA'));
    await expect(verifyAgentIdentity(noType, options)).rejects.toBeInstanceOf(AgentIdentityVerificationError);
  });

  it('refuses another issuer, another version, a subject that is not the agent, an unknown key and another key under a known id', async () => {
    await expect(verifyAgentIdentity(await statement(), { ...options, issuer: 'issuer.example' })).rejects.toBeInstanceOf(AgentIdentityVerificationError);
    await expect(verifyAgentIdentity(await statement({ claims: { identity: { ...FACTS, v: 2 } } }), options)).rejects.toBeInstanceOf(AgentIdentityVerificationError);
    const otherSubject = await new SignJWT({ identity: FACTS })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'stack-passport-v1', typ: 'stack-agent-identity+jwt' })
      .setIssuer('getstack.run').setAudience('stack:agent-identity').setSubject('agt_T3RoZXJBZ2VudElkMTIzNA').setIssuedAt(IAT).setExpirationTime(IAT + 300)
      .sign(await importJWK(signing.privateJwk, 'EdDSA'));
    await expect(verifyAgentIdentity(otherSubject, options)).rejects.toBeInstanceOf(AgentIdentityVerificationError);
    await expect(verifyAgentIdentity(await statement({ header: { kid: 'stack-passport-v9' } }), options)).rejects.toBeInstanceOf(AgentIdentityVerificationError);
    await expect(verifyAgentIdentity(await statement({ key: keys() }), options)).rejects.toBeInstanceOf(AgentIdentityVerificationError);
    await expect(verifyAgentIdentity('not-a-statement', options)).rejects.toBeInstanceOf(AgentIdentityVerificationError);
  });

  it('takes exactly one source of keys', async () => {
    await expect(verifyAgentIdentity(await statement(), { now: NOW })).rejects.toThrow('exactly one');
    await expect(verifyAgentIdentity(await statement(), { ...options, publicJwk: signing.publicJwk })).rejects.toThrow('exactly one');
  });
});

describe('stack.agentIdentity', () => {
  afterEach(() => vi.unstubAllGlobals());

  function stub(answer: (url: URL) => { status: number; body: unknown }) {
    const calls: Array<{ url: URL; headers: Record<string, string> }> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: string, init: { headers?: Record<string, string> }) => {
      const url = new URL(input);
      calls.push({ url, headers: init.headers ?? {} });
      const { status, body } = answer(url);
      return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
    }));
    return calls;
  }
  // No credential at all: the lookup is public and must work without one.
  const stack = () => new Stack({ baseUrl: 'http://api.fixture' });

  it('asks by each way, sending no credential', async () => {
    const calls = stub(() => ({ status: 200, body: { statement: 'x' } }));
    await stack().agentIdentity.lookup({ keyId: KEY_ID });
    await stack().agentIdentity.lookup({ site: 'acme.sites.example' });
    await stack().agentIdentity.lookup({ agentId: AGENT });
    expect(calls.map((c) => c.url.pathname + c.url.search)).toEqual([
      `/v1/agent-identity?key_id=${KEY_ID}`,
      '/v1/agent-identity?site=acme.sites.example',
      `/v1/agent-identity?agent_id=${AGENT}`,
    ]);
    for (const call of calls) expect(Object.keys(call.headers).map((h) => h.toLowerCase())).not.toContain('authorization');
  });

  it('checks the statement against the keys it was told to trust, and takes the facts from it', async () => {
    const token = await statement();
    stub(() => ({ status: 200, body: { statement: token, agent: { id: AGENT, status: 'closed' }, owner: { identity_verified: false, good_standing: false }, lookup: { key_id: KEY_ID }, issued_at: IAT, expires_at: IAT + 300 } }));
    const verified = await stack().agentIdentity.verified({ keyId: KEY_ID }, { keys: { jwks: { keys: [signing.publicJwk] } }, now: NOW });
    // The plain JSON beside the statement lied; the signed facts are what is returned.
    expect(verified.facts.agent.status).toBe('active');
    expect(verified.facts.owner.good_standing).toBe(true);
    expect(verified.validUntil.getTime()).toBe((IAT + 300) * 1000);
  });

  it('refuses a statement signed by a key it does not trust, and one that answers something else', async () => {
    const token = await statement();
    stub(() => ({ status: 200, body: { statement: token } }));
    await expect(stack().agentIdentity.verified({ keyId: KEY_ID }, { keys: { jwks: { keys: [keys().publicJwk] } }, now: NOW })).rejects.toBeInstanceOf(AgentIdentityVerificationError);
    await expect(stack().agentIdentity.verified({ agentId: AGENT }, { keys: { jwks: { keys: [signing.publicJwk] } }, now: NOW })).rejects.toMatchObject({ reason: 'wrong_lookup' });
  });

  it('passes the 404 of an agent that is not found on, with its fixed code', async () => {
    stub(() => ({ status: 404, body: { error: { code: 'AGENT_IDENTITY_NOT_FOUND', message: 'No agent answers to this lookup.' } } }));
    await expect(stack().agentIdentity.lookup({ agentId: AGENT })).rejects.toMatchObject({ code: 'AGENT_IDENTITY_NOT_FOUND', status: 404 });
  });

  it('knows where an agent\'s machine files are', () => {
    expect(stack().agentIdentity.urls(AGENT)).toEqual({
      lookup: `http://api.fixture/v1/agent-identity?agent_id=${AGENT}`,
      agentCard: `http://api.fixture/v1/agent-identity/agents/${AGENT}/agent-card.json`,
      mcpServerCard: `http://api.fixture/v1/agent-identity/agents/${AGENT}/mcp-server-card.json`,
      keyDirectory: `http://api.fixture/v1/agent-identity/agents/${AGENT}/http-message-signatures-directory`,
    });
  });
});
