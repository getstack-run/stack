import { describe, it, expect } from 'vitest';
import { ruleState } from './notifications.js';

// eslint-disable-next-line no-control-regex -- strips ANSI color escape sequences from terminal output
const strip = (s: string) => s.replace(/\u001b\[[0-9;]*m/g, '');

describe('ruleState', () => {
  it('is on only for a rule the API says delivers', () => {
    expect(strip(ruleState({ id: 'nch_1', active: true, delivers: true }))).toBe('on');
  });
  it('is not on for an active rule whose delivery method is unverified', () => {
    expect(strip(ruleState({ id: 'nch_1', active: true, delivers: false, delivery_methods: [{ id: 'd', channel_type: 'email', destination: 'a@example.com', verified: false }] }))).toBe('unverified');
  });
  it('is not on for an active rule with no delivery method, or for a rule that is off', () => {
    expect(strip(ruleState({ id: 'nch_1', active: true, delivers: false, delivery_methods: [] }))).toBe('off');
    expect(strip(ruleState({ id: 'nch_1', active: false, delivers: false }))).toBe('off');
  });
  it('reads an answer from before the API said delivers by active', () => {
    expect(strip(ruleState({ id: 'nch_1', active: true }))).toBe('on');
    expect(strip(ruleState({ id: 'nch_1', active: false }))).toBe('off');
  });
});
