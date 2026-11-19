import { describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';
import {
  LEGACY_DEPLOYMENT_SIGNING_KID,
  MAX_TRUSTED_HISTORICAL_DEPLOYMENT_KEYS,
  readDeploymentSigningConfig,
} from '@stack/vault';

async function publicDeploymentJwk(kid: string) {
  const { publicKey } = await generateKeyPair('EdDSA', {
    crv: 'Ed25519',
    extractable: true,
  });
  return {
    ...(await exportJWK(publicKey)),
    kid,
    alg: 'EdDSA',
    use: 'sig',
  };
}

describe('deployment signing configuration', () => {
  it('uses the legacy kid and no historical keys by default', () => {
    expect(readDeploymentSigningConfig({})).toEqual({
      kid: LEGACY_DEPLOYMENT_SIGNING_KID,
      trustedHistoricalPublicJwks: [],
    });
  });

  it('loads a unique future kid and pinned historical deployment keys', async () => {
    const historical = await publicDeploymentJwk('stack-passport-v1');

    const config = readDeploymentSigningConfig({
      DEPLOYMENT_SIGNING_KID: 'stack-passport-v2-2026-08',
      TRUSTED_HISTORICAL_DEPLOYMENT_JWKS_JSON: JSON.stringify({
        keys: [historical, { ...historical }],
      }),
    });

    expect(config.kid).toBe('stack-passport-v2-2026-08');
    expect(config.trustedHistoricalPublicJwks).toEqual([historical]);
  });

  it('fails boot configuration on malformed JSON or an invalid kid', () => {
    expect(() =>
      readDeploymentSigningConfig({
        TRUSTED_HISTORICAL_DEPLOYMENT_JWKS_JSON: '{not-json',
      }),
    ).toThrow(/TRUSTED_HISTORICAL_DEPLOYMENT_JWKS_JSON/);

    expect(() =>
      readDeploymentSigningConfig({ DEPLOYMENT_SIGNING_KID: 'stack-passport-v1' }),
    ).not.toThrow();
    expect(() =>
      readDeploymentSigningConfig({ DEPLOYMENT_SIGNING_KID: 'operator-controlled-kid' }),
    ).toThrow(/DEPLOYMENT_SIGNING_KID/);
  });

  it('caps the pinned historical deployment key list', async () => {
    const keys = await Promise.all(
      Array.from(
        { length: MAX_TRUSTED_HISTORICAL_DEPLOYMENT_KEYS + 1 },
        () => publicDeploymentJwk(LEGACY_DEPLOYMENT_SIGNING_KID),
      ),
    );

    expect(() =>
      readDeploymentSigningConfig({
        TRUSTED_HISTORICAL_DEPLOYMENT_JWKS_JSON: JSON.stringify({ keys }),
      }),
    ).toThrow(/at most 16 keys/);
  });
});
