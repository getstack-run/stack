import { describe, expect, it } from 'vitest';
import { isDedicatedVaultTestDatabase } from './dedicated-test-database.js';

describe('dedicated Vault test database guard', () => {
  it('accepts only reviewed loopback database names and ports', () => {
    expect(
      isDedicatedVaultTestDatabase(
        'postgresql://stack:test@127.0.0.1:5433/stack_ci_gate',
      ),
    ).toBe(true);
    expect(
      isDedicatedVaultTestDatabase(
        'postgresql://stack:test@db.example.com:5433/stack_ci_gate',
      ),
    ).toBe(false);
    expect(
      isDedicatedVaultTestDatabase('postgresql://stack:test@127.0.0.1:5432/stack_ci_gate'),
    ).toBe(false);
    expect(
      isDedicatedVaultTestDatabase(
        'postgresql://stack:test@127.0.0.1:5433/stack_ci_gate?database=stack',
      ),
    ).toBe(false);
    expect(isDedicatedVaultTestDatabase('postgresql://stack:test@127.0.0.1:55433/stack')).toBe(true);
    expect(isDedicatedVaultTestDatabase('postgresql://stack:test@127.0.0.1:5433/stack')).toBe(false);
    expect(isDedicatedVaultTestDatabase(undefined)).toBe(false);
  });

  it('accepts one database per parallel run inside the throwaway container on 55433', () => {
    for (const name of ['stack', 'stack_wake', 'stack_b', 'stack_a1_b2', 'stack_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']) {
      expect(isDedicatedVaultTestDatabase(`postgresql://stack:test@127.0.0.1:55433/${name}`)).toBe(true);
    }
  });

  it('rejects names on 55433 outside that pattern, and the same names on other ports', () => {
    for (const name of [
      'stackx',
      'stack_',
      'stack_UPPER',
      'stack_a?x=1',
      'stack_a-b',
      'stack_a.b',
      'stack_a/b',
      'stack_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'postgres',
    ]) {
      expect(isDedicatedVaultTestDatabase(`postgresql://stack:test@127.0.0.1:55433/${name}`)).toBe(false);
    }
    expect(isDedicatedVaultTestDatabase('postgresql://stack:test@127.0.0.1:55433/stack_a#frag')).toBe(false);
    expect(isDedicatedVaultTestDatabase('postgresql://stack:test@db.example.com:55433/stack_a')).toBe(false);
    expect(isDedicatedVaultTestDatabase('postgresql://stack:test@127.0.0.1:5433/stack_a')).toBe(false);
    expect(isDedicatedVaultTestDatabase('postgresql://stack:test@127.0.0.1:5432/stack_a')).toBe(false);
    expect(isDedicatedVaultTestDatabase('mysql://stack:test@127.0.0.1:55433/stack_a')).toBe(false);
  });
});
