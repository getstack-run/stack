import { describe, it, expect, afterEach, vi } from 'vitest';
import { createHash, createHmac } from 'node:crypto';

// Each test here calls `vi.resetModules()` and re-imports the utils barrel to
// read API_KEY_PEPPER + NODE_ENV at module load — that dynamic re-import is the
// contract being tested, so it cannot be hoisted the way audit-hash's was. The
// barrel is heavy (url-guard, constraints, delegation, ...), so a cold re-parse
// runs ~2s and, under the parallel suite CI now runs, tips past the 5s default
// and fails on a TIMEOUT rather than a real regression. Give the re-import room.
vi.setConfig({ testTimeout: 30000 });

// . hashApiKey / verifyApiKeyHash read API_KEY_PEPPER + NODE_ENV at
// MODULE LOAD, so every regime test resets modules and re-imports under a
// freshly-set env. Helper does exactly that.
async function loadUtils(env: { pepper?: string; nodeEnv?: string }) {
  vi.resetModules();
  if (env.pepper === undefined) delete process.env.API_KEY_PEPPER;
  else process.env.API_KEY_PEPPER = env.pepper;
  if (env.nodeEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = env.nodeEnv;
  return import('./index.js');
}

const KEY = 'sk_live_testkey_0123456789abcdef';
const PEPPER = 'pepper-value-for-tests';
const plain = (k: string) => createHash('sha256').update(k).digest('hex');
const peppered = (k: string, p: string) => createHmac('sha256', p).update(k).digest('hex');

const savedPepper = process.env.API_KEY_PEPPER;
const savedNodeEnv = process.env.NODE_ENV;

afterEach(() => {
  if (savedPepper === undefined) delete process.env.API_KEY_PEPPER;
  else process.env.API_KEY_PEPPER = savedPepper;
  if (savedNodeEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = savedNodeEnv;
  vi.restoreAllMocks();
});

describe('hashApiKey — peppered writer', () => {
  it('produces HMAC-SHA256 under the pepper when set', async () => {
    const { hashApiKey } = await loadUtils({ pepper: PEPPER, nodeEnv: 'production' });
    expect(hashApiKey(KEY)).toBe(peppered(KEY, PEPPER));
    expect(hashApiKey(KEY)).not.toBe(plain(KEY));
  });

  it('is deterministic — same key + same pepper → same hash (cross-surface contract)', async () => {
    const { hashApiKey: h1 } = await loadUtils({ pepper: PEPPER, nodeEnv: 'production' });
    const { hashApiKey: h2 } = await loadUtils({ pepper: PEPPER, nodeEnv: 'production' });
    expect(h1(KEY)).toBe(h2(KEY));
  });
});

describe('hashApiKey — fail-closed in prod', () => {
  it('throws when pepper unset AND NODE_ENV=production', async () => {
    const { hashApiKey } = await loadUtils({ pepper: undefined, nodeEnv: 'production' });
    expect(() => hashApiKey(KEY)).toThrow(/API_KEY_PEPPER is not set/);
  });

  it('warns (does not throw) when pepper unset in dev, and returns plain SHA-256', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { hashApiKey } = await loadUtils({ pepper: undefined, nodeEnv: 'development' });
    expect(hashApiKey(KEY)).toBe(plain(KEY));
    expect(warn).toHaveBeenCalledOnce();
  });
});

describe('verifyApiKeyHash — dual-verify migration window', () => {
  it('(a) peppered-stored hash → matches, no rehash', async () => {
    const { hashApiKey, verifyApiKeyHash } = await loadUtils({ pepper: PEPPER, nodeEnv: 'production' });
    const stored = hashApiKey(KEY); // current (peppered) scheme
    expect(verifyApiKeyHash(KEY, stored)).toEqual({ matches: true, needsRehash: false });
  });

  it('(b) legacy plain-SHA-256 hash + pepper set → matches, needsRehash', async () => {
    const { verifyApiKeyHash } = await loadUtils({ pepper: PEPPER, nodeEnv: 'production' });
    const legacyStored = plain(KEY); // written before the pepper existed
    expect(verifyApiKeyHash(KEY, legacyStored)).toEqual({ matches: true, needsRehash: true });
  });

  it('(c) wrong key → no match', async () => {
    const { hashApiKey, verifyApiKeyHash } = await loadUtils({ pepper: PEPPER, nodeEnv: 'production' });
    const stored = hashApiKey(KEY);
    expect(verifyApiKeyHash('sk_live_wrong_key', stored)).toEqual({ matches: false, needsRehash: false });
  });

  it('dev (no pepper): verifies plain-stored hash, never asks for rehash', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { hashApiKey, verifyApiKeyHash } = await loadUtils({ pepper: undefined, nodeEnv: 'development' });
    const stored = hashApiKey(KEY); // plain in dev
    expect(verifyApiKeyHash(KEY, stored)).toEqual({ matches: true, needsRehash: false });
  });

  it('throws in prod with no pepper (fail-closed applies to verify too)', async () => {
    const { verifyApiKeyHash } = await loadUtils({ pepper: undefined, nodeEnv: 'production' });
    expect(() => verifyApiKeyHash(KEY, plain(KEY))).toThrow(/API_KEY_PEPPER is not set/);
  });
});

describe('cross-surface consistency (shared writer ↔ shared verifier)', () => {
  it('a key hashed under a pepper verifies under the same pepper', async () => {
    // Simulates: dashboard hashes on registration, API verifies later —
    // both use the identical peppered scheme.
    const { hashApiKey } = await loadUtils({ pepper: PEPPER, nodeEnv: 'production' });
    const storedByWriter = hashApiKey(KEY);
    const { verifyApiKeyHash } = await loadUtils({ pepper: PEPPER, nodeEnv: 'production' });
    expect(verifyApiKeyHash(KEY, storedByWriter).matches).toBe(true);
  });
});
