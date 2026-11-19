import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

function source(name: string): string {
  return readFileSync(new URL(`./${name}`, import.meta.url), 'utf8');
}

describe('secret argv guardrails', () => {
  it('does not read passport tokens from command arguments', () => {
    expect(source('passports.ts')).not.toContain("takeFlag(args, '--token')");
    expect(source('passports.ts')).not.toContain("takeFlag(args, '--parent-token')");
    expect(source('llm.ts')).not.toContain("takeFlag(args, '--passport')");
    expect(source('intents.ts')).not.toContain('<passport-token>');
  });

  it('does not accept the OIDC client secret in a JSON file', () => {
    const identity = source('identity.ts');
    expect(identity).toContain("if ('client_secret' in body)");
    expect(identity).toContain("readSecretFromStdin('OIDC client secret: ')");
  });

  it('does not pass credentials to MCP client setup commands', () => {
    const setup = source('setup.ts');
    expect(setup).not.toMatch(/Authorization:\s*Bearer/i);
    expect(setup).not.toMatch(/api[_-]?key/i);
    expect(setup).not.toMatch(/client[_-]?secret/i);
  });
});
