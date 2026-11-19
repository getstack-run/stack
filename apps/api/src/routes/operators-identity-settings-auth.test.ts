import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('operator identity settings authorization', () => {
  it('requires an operator owner or admin member for policy writes', () => {
    const source = readFileSync(new URL('./operators.ts', import.meta.url), 'utf8');
    const route = source.slice(
      source.indexOf("app.patch('/v1/operators/me/identity-settings'"),
      source.indexOf('// List MCP sessions'),
    );

    expect(route).toContain('requireOperatorAdmin');
    expect(route).toContain('denyAgentContexts');
  });
});
