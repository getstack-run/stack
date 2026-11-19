import { describe, expect, it } from 'vitest';
import { EngineRegistries, SealedList, SealedMap } from './registries.js';

describe('the engine registries', () => {
  it('accept entries until they are sealed, then refuse every later one', () => {
    const registries = new EngineRegistries();
    registries.cmekEphemeralStores.register('scratch_store');
    registries.archiveErasePrefixes.register((operatorId) => [`drive/${operatorId}/`]);
    expect(registries.sealed).toBe(false);

    registries.seal();

    expect(registries.sealed).toBe(true);
    expect(() => registries.cmekEphemeralStores.register('late_store')).toThrow(/sealed/);
    expect(() => registries.archiveErasePrefixes.register(() => [])).toThrow(/sealed/);
    expect(() => registries.routeScopes.register('GET /x', null)).toThrow(/sealed/);
    // What was registered before the seal is still there, in order.
    expect(registries.cmekEphemeralStores.list()).toEqual(['scratch_store']);
    expect(registries.archiveErasePrefixes.list()[0]?.('op_1')).toEqual(['drive/op_1/']);
  });

  it('refuse a key registered twice: that is a wiring mistake, not an override', () => {
    const map = new SealedMap<number>('test');
    map.register('a', 1);
    expect(() => map.register('a', 2)).toThrow(/already has a/);
    expect(map.get('a')).toBe(1);
  });

  it('keep a list in registration order and hand out copies', () => {
    const list = new SealedList<string>('test');
    list.register('first');
    list.register('second');
    const copy = list.list() as string[];
    copy.push('third');
    expect(list.list()).toEqual(['first', 'second']);
  });

  it('are all sealed by one call', () => {
    const registries = new EngineRegistries();
    expect(registries.sealed).toBe(false);
    registries.seal();
    expect(registries.sealed).toBe(true);
    expect(() => registries.governanceActions.register('x', { payload: {} as never })).toThrow(/sealed/);
    expect(() => registries.erasureBefore.register({} as never)).toThrow(/sealed/);
  });
});
