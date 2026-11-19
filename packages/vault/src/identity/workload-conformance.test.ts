import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { JWK } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
// The kit is plain JavaScript with no declarations.
// @ts-expect-error TS7016
import * as conformanceKit from '../../../../spec/conformance/src/index.mjs';
import { SpiffeSvidValidator, SpiffeValidationError } from './spiffe-svid-validator.js';
import { WimseValidationError, WimseWitValidator } from './wimse-wit-validator.js';

/**
 * The engine's SPIFFE and WIMSE validators against the conformance kit's `workload-token` suite and its test
 * vectors (spec/workload-identity, section 4): the kit mints tokens and the issuer's key set, and these validators
 * accept or refuse them. The key set is served by an injected fetcher, never from the network.
 */

type Report = { conforms: boolean; failed: number; warnings: number; passed: number; skipped: number };
type Kit = {
  runWorkloadTokenSuite(options: { accept: (input: AcceptInput) => Promise<unknown> }): Promise<Report>;
  formatReport(report: Report): string;
};
type AcceptInput = {
  kind: 'spiffe' | 'wimse';
  token: string;
  config: { trust_domain?: string; issuer_uri?: string; audience: string | null };
  jwks: { keys: JWK[] };
};

/** The two Redis calls the validators make, in memory. */
function memoryRedis() {
  const values = new Map<string, string>();
  return {
    get: async (key: string) => values.get(key) ?? null,
    set: async (key: string, value: string, ...args: unknown[]) => {
      if (args.includes('NX') && values.has(key)) return null;
      values.set(key, value);
      return 'OK';
    },
  } as never;
}

const persistor = { persistLastKnownGood: async () => {} };

/** The validators of this package as the specification's `accept` function. */
async function accept(input: AcceptInput) {
  const fetcher = (async () => new Response(JSON.stringify(input.jwks), { status: 200 })) as unknown as typeof fetch;
  const guard = (async () => new URL('https://issuer.conformance.example/jwks')) as never;
  const common = { id: 'cfg_conformance', jwks_uri: 'https://issuer.conformance.example/jwks', audience: input.config.audience, jwks_cache_ttl_seconds: 300, jwks_cached_jwks_json: null };
  try {
    if (input.kind === 'spiffe') {
      const validator = new SpiffeSvidValidator(memoryRedis(), persistor, fetcher, guard);
      const result = await validator.validateJwtSvid(input.token, { ...common, trust_domain: input.config.trust_domain! });
      return { subject: result.spiffe_id, issuer: result.issuer, ...(result.audience ? { audience: result.audience } : {}), not_after: result.not_after };
    }
    const validator = new WimseWitValidator(memoryRedis(), persistor, fetcher, guard);
    const result = await validator.validateWit(input.token, { ...common, issuer_uri: input.config.issuer_uri! });
    return { subject: result.workload_id, issuer: result.issuer, ...(result.audience ? { audience: result.audience } : {}), not_after: result.not_after };
  } catch (error) {
    if (error instanceof SpiffeValidationError || error instanceof WimseValidationError) throw Object.assign(new Error(error.message), { code: error.code });
    throw error;
  }
}

describe('the engine\'s workload token validators', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('pass the workload-token suite', async () => {
    const kit = conformanceKit as unknown as Kit;
    const report = await kit.runWorkloadTokenSuite({ accept });
    expect(report.failed, kit.formatReport(report)).toBe(0);
    expect(report.warnings, kit.formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
  }, 120_000);

  it('give the verdict and the reason of every test vector', async () => {
    const vectors = JSON.parse(readFileSync(fileURLToPath(new URL('../../../../spec/conformance/fixtures/identity/vectors.json', import.meta.url)), 'utf8')) as {
      workload_token: { now: number; cases: Array<Omit<AcceptInput, 'token'> & { token_parts: string[]; name: string; valid: boolean; reason?: string }> };
    };
    // The vectors are dated: judge them on the day they were made.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(vectors.workload_token.now * 1000);
    for (const c of vectors.workload_token.cases) {
      const outcome = await accept({ ...c, token: c.token_parts.join('.') }).then(
        () => ({ valid: true as const }),
        (error: { code?: string }) => ({ valid: false as const, reason: error.code }),
      );
      expect(outcome.valid, c.name).toBe(c.valid);
      if (c.reason) expect((outcome as { reason?: string }).reason, c.name).toBe(c.reason);
    }
  });
});
