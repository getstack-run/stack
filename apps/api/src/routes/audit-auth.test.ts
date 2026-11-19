import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { resolveAuditAgentScope } from './audit.js';

describe('audit principal scope', () => {
  it('keeps operator and human-member audit filtering unchanged', () => {
    expect(resolveAuditAgentScope(undefined, undefined)).toBeUndefined();
    expect(resolveAuditAgentScope(undefined, 'agt_requested')).toBe('agt_requested');
  });

  it('forces an agent-bearing principal onto its verified agent id', () => {
    expect(resolveAuditAgentScope('agt_authenticated', undefined)).toBe('agt_authenticated');
    expect(resolveAuditAgentScope('agt_authenticated', 'agt_authenticated')).toBe(
      'agt_authenticated',
    );
  });

  it('rejects an agent that asks for another agent audit stream', () => {
    expect(() => resolveAuditAgentScope('agt_authenticated', 'agt_other')).toThrow(
      /limited to its own entries/i,
    );
  });

  it('keeps bulk export and chain-wide proofs behind the non-agent gate', () => {
    const source = readFileSync(new URL('./audit.ts', import.meta.url), 'utf8');
    for (const route of [
      '/v1/audit/export',
      '/v1/audit/chain-head',
      '/v1/audit/verify-chain',
    ]) {
      const start = source.indexOf(`'${route}'`);
      expect(start, `${route} is registered`).toBeGreaterThanOrEqual(0);
      expect(source.slice(start, start + 240), `${route} denies agent contexts`).toContain(
        'denyAgentContexts',
      );
    }
  });
});
