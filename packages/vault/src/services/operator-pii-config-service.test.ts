import { describe, it, expect } from 'vitest';
import { PII_DEFAULT_THRESHOLD } from '@stack/shared';
import { OperatorPiiConfigService } from './operator-pii-config-service.js';
import type { PiiConfigRow } from '../repositories/operator-pii-config-repo.js';

/** In-memory stand-ins. The point of these tests is the decision logic, not
 *  Drizzle or Redis. */
function harness(seed?: Partial<PiiConfigRow>) {
  const store = new Map<string, PiiConfigRow>();
  if (seed) {
    store.set('op_1', {
      id: 'cfg_1',
      operator_id: 'op_1',
      enabled: true,
      threshold: null,
      countries: null,
      created_at: new Date(0),
      updated_at: new Date(0),
      ...seed,
    });
  }
  const cache = new Map<string, string>();
  const repo = {
    findByOperator: async (id: string) => store.get(id),
    upsert: async (input: { id: string; operator_id: string; enabled?: boolean; threshold?: number | null; countries?: string[] | null }) => {
      const prior = store.get(input.operator_id);
      const row: PiiConfigRow = {
        id: prior?.id ?? input.id,
        operator_id: input.operator_id,
        enabled: input.enabled ?? prior?.enabled ?? true,
        threshold: input.threshold !== undefined ? input.threshold : (prior?.threshold ?? null),
        countries: input.countries !== undefined ? input.countries : (prior?.countries ?? null),
        created_at: prior?.created_at ?? new Date(0),
        updated_at: new Date(0),
      };
      store.set(input.operator_id, row);
      return row;
    },
    delete: async (id: string) => store.delete(id),
  };
  const redis = {
    get: async (k: string) => cache.get(k) ?? null,
    set: async (k: string, v: string) => { cache.set(k, v); return 'OK'; },
    del: async (k: string) => { cache.delete(k); return 1; },
  };
  return { svc: new OperatorPiiConfigService(repo as never, redis as never), store, cache };
}

describe('OperatorPiiConfigService — resolveScanOptions', () => {
  it('no row means built-in defaults, not "off"', async () => {
    const { svc } = harness();
    expect(await svc.resolveScanOptions('op_1')).toEqual({});
  });

  it('disabled returns null, which is NOT the same as defaults', async () => {
    // The distinction the caller depends on. If these collapsed, switching
    // redaction off would silently re-enable it at the built-in threshold.
    const { svc } = harness({ enabled: false });
    expect(await svc.resolveScanOptions('op_1')).toBeNull();
  });

  it('passes threshold and countries through', async () => {
    const { svc } = harness({ threshold: 0.2, countries: ['SE', 'NO'] });
    expect(await svc.resolveScanOptions('op_1')).toEqual({ threshold: 0.2, countries: ['SE', 'NO'] });
  });

  it('omits an empty country list rather than scoping to nothing', async () => {
    // countries: [] would otherwise scope out every national scheme, which is
    // not what an empty array means to anyone who sends one.
    const { svc } = harness({ countries: [] });
    expect(await svc.resolveScanOptions('op_1')).toEqual({});
  });

  it('caches the absent row so a fresh operator does not hit the DB every call', async () => {
    const { svc, cache } = harness();
    await svc.getForOperator('op_1');
    expect(cache.get('op_pii_config:op_1')).toBe('null');
    expect(await svc.getForOperator('op_1')).toBeUndefined();
  });
});

describe('OperatorPiiConfigService — isLoosening (decides if a human must approve)', () => {
  const svc = harness().svc;
  const row = (over: Partial<PiiConfigRow>): PiiConfigRow => ({
    id: 'c', operator_id: 'op_1', enabled: true, threshold: null, countries: null,
    created_at: new Date(0), updated_at: new Date(0), ...over,
  });

  it('turning redaction off is loosening', () => {
    expect(svc.isLoosening(undefined, { enabled: false })).toBe(true);
  });

  it('RAISING the threshold is loosening', () => {
    // The counter-intuitive direction, and the one worth a test: a higher
    // number demands more confidence, so fewer things get redacted.
    expect(svc.isLoosening(undefined, { threshold: 0.8 })).toBe(true);
    expect(svc.isLoosening(undefined, { threshold: 0.2 })).toBe(false);
  });

  it('measures the threshold against the built-in when no row exists', () => {
    expect(svc.isLoosening(undefined, { threshold: PII_DEFAULT_THRESHOLD })).toBe(false);
  });

  it('narrowing from every country to a list is loosening', () => {
    expect(svc.isLoosening(row({ countries: null }), { countries: ['SE'] })).toBe(true);
  });

  it('widening to every country is not loosening', () => {
    expect(svc.isLoosening(row({ countries: ['SE'] }), { countries: null })).toBe(false);
  });

  it('dropping a country from an existing list is loosening', () => {
    expect(svc.isLoosening(row({ countries: ['SE', 'NO'] }), { countries: ['SE'] })).toBe(true);
  });

  it('adding a country is not loosening', () => {
    expect(svc.isLoosening(row({ countries: ['SE'] }), { countries: ['SE', 'NO'] })).toBe(false);
  });

  it('compares country codes case-insensitively', () => {
    expect(svc.isLoosening(row({ countries: ['SE'] }), { countries: ['se', 'no'] })).toBe(false);
  });
});

describe('OperatorPiiConfigService — validation', () => {
  it('rejects a threshold outside 0-1', async () => {
    const { svc } = harness();
    await expect(svc.upsert({ operator_id: 'op_1', threshold: 1.5 })).rejects.toThrow(/between 0 and 1/);
  });

  it('rejects a country code that is not alpha-2', async () => {
    const { svc } = harness();
    await expect(svc.upsert({ operator_id: 'op_1', countries: ['SWE'] })).rejects.toThrow(/alpha-2/);
  });

  it('uppercases and de-duplicates country codes', async () => {
    const { svc } = harness();
    const row = await svc.upsert({ operator_id: 'op_1', countries: ['se', 'SE', 'no'] });
    expect(row.countries).toEqual(['SE', 'NO']);
  });

  it('a write invalidates the cache', async () => {
    const { svc, cache } = harness();
    await svc.getForOperator('op_1');
    expect(cache.has('op_pii_config:op_1')).toBe(true);
    await svc.upsert({ operator_id: 'op_1', threshold: 0.3 });
    expect(cache.has('op_pii_config:op_1')).toBe(false);
  });
});
