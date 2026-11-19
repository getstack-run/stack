import { describe, expect, it } from 'vitest';
import { isDedicatedStackTestDatabase } from './dedicated-test-database.js';

describe('dedicated STACK test database guard', () => {
  it('accepts only the reviewed loopback databases and safe isolated CI suffixes', () => {
    expect(
      isDedicatedStackTestDatabase(
        'postgresql://stack:test@127.0.0.1:5433/stack_ci_i3_erasure_0913a',
      ),
    ).toBe(true);
    expect(
      isDedicatedStackTestDatabase('postgresql://stack:test@[::1]:5433/stack_ci_agent-42'),
    ).toBe(true);
    expect(
      isDedicatedStackTestDatabase('postgresql://stack:test@127.0.0.1:5497/stack_security_resume'),
    ).toBe(true);
    expect(
      isDedicatedStackTestDatabase('postgresql://stack:test@127.0.0.1:55433/stack'),
    ).toBe(true);

    expect(
      isDedicatedStackTestDatabase('postgresql://stack:test@db.example.com:5433/stack_ci_agent-42'),
    ).toBe(false);
    expect(
      isDedicatedStackTestDatabase('postgresql://stack:test@127.0.0.1:5432/stack_ci_agent-42'),
    ).toBe(false);
    expect(
      isDedicatedStackTestDatabase('postgresql://stack:test@127.0.0.1:5433/stack_ci_agent.42'),
    ).toBe(false);
    expect(
      isDedicatedStackTestDatabase(
        'postgresql://stack:test@127.0.0.1:5433/stack_ci_agent/production',
      ),
    ).toBe(false);
    expect(
      isDedicatedStackTestDatabase(
        'postgresql://stack:test@127.0.0.1:5433/stack_ci?database=stack',
      ),
    ).toBe(false);
    expect(
      isDedicatedStackTestDatabase(
        'postgresql://stack:test@127.0.0.1:5433/stack_ci?user=production',
      ),
    ).toBe(false);
    expect(isDedicatedStackTestDatabase(undefined)).toBe(false);
  });

  it('accepts one database per parallel run inside the throwaway container on 55433', () => {
    for (const name of ['stack', 'stack_wake', 'stack_b', 'stack_a1_b2', 'stack_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']) {
      expect(isDedicatedStackTestDatabase(`postgresql://stack:test@127.0.0.1:55433/${name}`)).toBe(true);
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
      expect(isDedicatedStackTestDatabase(`postgresql://stack:test@127.0.0.1:55433/${name}`)).toBe(false);
    }
    expect(isDedicatedStackTestDatabase('postgresql://stack:test@127.0.0.1:55433/stack_a#frag')).toBe(false);
    expect(isDedicatedStackTestDatabase('postgresql://stack:test@db.example.com:55433/stack_a')).toBe(false);
    expect(isDedicatedStackTestDatabase('postgresql://stack:test@127.0.0.1:5433/stack_a')).toBe(false);
    expect(isDedicatedStackTestDatabase('postgresql://stack:test@127.0.0.1:5432/stack_a')).toBe(false);
    expect(isDedicatedStackTestDatabase('mysql://stack:test@127.0.0.1:55433/stack_a')).toBe(false);
  });
});
