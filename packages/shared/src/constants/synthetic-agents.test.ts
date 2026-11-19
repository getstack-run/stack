import { describe, expect, it } from 'vitest';
import { isSyntheticAgentId, SYNTHETIC_AGENT_IDS, SYNTHETIC_AGENT_PREFIXES } from './index.js';

describe('isSyntheticAgentId', () => {
  it('matches sandbox prefix', () => {
    expect(isSyntheticAgentId('agt_sandbox_payments')).toBe(true);
    expect(isSyntheticAgentId('agt_sandbox_reader')).toBe(true);
    expect(isSyntheticAgentId('agt_sandbox_writer')).toBe(true);
    expect(isSyntheticAgentId('agt_sandbox_')).toBe(true);
  });

  it('matches exact pseudo-agent ids', () => {
    expect(isSyntheticAgentId('oauth')).toBe(true);
  });

  it('rejects real operator agents', () => {
    expect(isSyntheticAgentId('agt_AbCdEf123')).toBe(false);
    expect(isSyntheticAgentId('agt_real_user_writer')).toBe(false);
  });

  it('rejects null and empty', () => {
    expect(isSyntheticAgentId(null)).toBe(false);
    expect(isSyntheticAgentId(undefined)).toBe(false);
    expect(isSyntheticAgentId('')).toBe(false);
  });

  it('rejects partial matches that aren\'t real prefixes', () => {
    expect(isSyntheticAgentId('sandbox_xxx')).toBe(false);
    expect(isSyntheticAgentId('agt_sandboxy_xxx')).toBe(false);
    expect(isSyntheticAgentId('oauth_real_provider')).toBe(false);
  });

  it('exposes the constants for external use', () => {
    expect(SYNTHETIC_AGENT_PREFIXES).toContain('agt_sandbox_');
    expect(SYNTHETIC_AGENT_IDS).toContain('oauth');
  });
});
