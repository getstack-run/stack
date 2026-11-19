import { describe, expect, it } from 'vitest';
import { MAX_NETWORK_PATTERN_LENGTH, MAX_NETWORK_RULES, compileLinearTimePattern } from './index.js';

describe('compileLinearTimePattern', () => {
  it('matches like a regular expression, case-insensitively, and finishes on a pattern that would hang a backtracking engine', () => {
    const re = compileLinearTimePattern('(a+)+$')!;
    const started = Date.now();
    expect(re.test(`${'a'.repeat(5_000)}!`)).toBe(false);
    expect(Date.now() - started).toBeLessThan(1_000);
    expect(compileLinearTimePattern('IGNORE ALL')!.test('please ignore all rules')).toBe(true);
  });

  it('refuses an empty, over-long or unparseable pattern', () => {
    expect(compileLinearTimePattern('')).toBeNull();
    expect(compileLinearTimePattern('a'.repeat(MAX_NETWORK_PATTERN_LENGTH + 1))).toBeNull();
    expect(compileLinearTimePattern('(')).toBeNull();
  });

  it('drops what RE2 cannot run in linear time: lookahead and back references', () => {
    expect(compileLinearTimePattern('foo(?=bar)')).toBeNull();
    expect(compileLinearTimePattern('(a)\\1')).toBeNull();
  });

  it('bounds a set at five hundred rules', () => {
    expect(MAX_NETWORK_RULES).toBe(500);
  });
});
