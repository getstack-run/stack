import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { StoredAgentKey, StoredOperatorCredentials } from './credentials-files.js';

const credentials = {
  client_id: 'oclient_example',
  refresh_token: 'refresh-one',
  issued_at: 1_790_000_000,
  refresh_expires_at: 1_792_592_000,
  operator_email: 'owner@example.test',
  scope: 'agents:read',
};

function agentKey(agentId = 'agt_example') {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'jwk' });
  const priv = privateKey.export({ format: 'jwk' });
  return {
    agent_id: agentId,
    publicKey: { kty: pub.kty, crv: pub.crv, x: pub.x },
    privateKey: { kty: priv.kty, crv: priv.crv, x: priv.x, d: priv.d },
    enrolled_at: 1_790_000_000,
  };
}

describe('the sign-in file', () => {
  it('reads a complete file, with the fields of a later version kept', () => {
    expect(StoredOperatorCredentials.parse({ ...credentials, later: 1 })).toEqual({ ...credentials, later: 1 });
    const { operator_email: _email, ...without } = credentials;
    expect(StoredOperatorCredentials.parse(without)).toEqual(without);
  });

  it('refuses a file that cannot sign anyone in', () => {
    for (const bad of [{}, { ...credentials, client_id: '' }, { ...credentials, refresh_token: '' }, { ...credentials, refresh_token: 5 }, { ...credentials, issued_at: 1.5 }, { ...credentials, scope: undefined }]) {
      expect(StoredOperatorCredentials.safeParse(bad).success).toBe(false);
    }
  });
});

describe('the agent key file', () => {
  it('reads a key the way the clients write it', () => {
    const key = agentKey();
    expect(StoredAgentKey.parse(key)).toEqual(key);
  });

  it('refuses a key that is not an Ed25519 pair of 32 byte values, or an enrolment time that is not whole seconds', () => {
    const key = agentKey();
    for (const bad of [
      { ...key, publicKey: { ...key.publicKey, crv: 'P-256' } },
      { ...key, privateKey: { ...key.privateKey, d: 'short' } },
      { ...key, privateKey: { kty: key.privateKey.kty, crv: key.privateKey.crv, x: key.privateKey.x } },
      { ...key, enrolled_at: '2026-10-24T09:30:00.000Z' },
      { ...key, enrolled_at: 1.5 },
      { ...key, agent_id: '' },
    ]) {
      expect(StoredAgentKey.safeParse(bad).success).toBe(false);
    }
  });
});
