import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { assertOAuthSecurityConfiguration, assertStagingConfiguration } from './env.js';

// The private repository's export manifest lists what must never reach the public tree. It is not part of that tree,
// so the terms are read from it here when it is present (a private run) and the engine's own invariants below are
// checked either way.
const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST = resolve(HERE, '../../../../scripts/public-repo/manifest.json');

function manifestTerms(): RegExp[] {
  if (!existsSync(MANIFEST)) return [];
  const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8')) as { forbidden_terms?: string[]; pending_forbidden_terms?: string[] };
  return [...(manifest.forbidden_terms ?? []), ...(manifest.pending_forbidden_terms ?? [])].map((term) => new RegExp(term, 'i'));
}

/** The code of a TypeScript file, without its comments. */
function codeOf(file: string): string {
  return readFileSync(file, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

const ENV_SOURCE = resolve(HERE, 'env.ts');
const CONFIGURATION_GUIDE = resolve(HERE, '../../../../docs/self-managed/configuration.md');

describe('the engine configuration', () => {
  it('names no host in any default but the loopback', () => {
    // An install's defaults come from where it says it is (deployment()); a host written into a default is somebody's.
    const code = codeOf(ENV_SOURCE);
    const hosts = [...code.matchAll(/https?:\/\/([^/'"`\s:]+)/gi)].map((m) => m[1]);
    expect(hosts.filter((host) => host !== 'localhost' && host !== '127.0.0.1')).toEqual([]);
    expect(code.match(/\b[a-z0-9-]+\.(?:com|run|io|dev|net|org|app|ai|sh)\b/gi) ?? []).toEqual([]);
  });

  it('reads only the variables the install guide documents', () => {
    // A variable of a vendor an install has no account with (a payment, text or identity provider's) is not in the guide.
    const code = codeOf(ENV_SOURCE);
    const names = new Set([...code.matchAll(/(?:optional|required)\('([A-Z0-9_]+)'/g)].map((m) => m[1]!));
    const guide = readFileSync(CONFIGURATION_GUIDE, 'utf8');
    const undocumented = [...names].filter((name) => {
      if (guide.includes(name)) return false;
      const wildcard = name.replace(/_[A-Z0-9]+$/, '_*');
      return !guide.includes(wildcard);
    });
    expect(undocumented).toEqual([]);
  });

  it('names nothing the export manifest forbids (read when the manifest is present)', () => {
    const code = codeOf(ENV_SOURCE);
    const offenders = manifestTerms().filter((term) => term.test(code)).map((term) => term.source);
    expect(offenders).toEqual([]);
  });
});

describe('OAuth production configuration', () => {
  it.each(['true', '1'])('refuses enabled OAuth with a disabled scope ceiling (%s)', (enabled) => {
    expect(() => assertOAuthSecurityConfiguration({
      NODE_ENV: 'production',
      OAUTH_ENABLED: enabled,
      OAUTH_SCOPE_ENFORCEMENT: 'false',
    })).toThrow(/OAuth scope enforcement must be enabled/i);
  });

  it('treats an absent scope-ceiling setting as disabled in production', () => {
    expect(() => assertOAuthSecurityConfiguration({
      NODE_ENV: 'production',
      OAUTH_ENABLED: 'true',
      OAUTH_SCOPE_ENFORCEMENT: '',
    })).toThrow(/OAuth scope enforcement must be enabled/i);
  });

  it('allows production OAuth only with the scope ceiling enabled', () => {
    expect(() => assertOAuthSecurityConfiguration({
      NODE_ENV: 'production',
      OAUTH_ENABLED: 'true',
      OAUTH_SCOPE_ENFORCEMENT: 'true',
    })).not.toThrow();
  });

  it('allows OAuth to remain disabled', () => {
    expect(() => assertOAuthSecurityConfiguration({
      NODE_ENV: 'production',
      OAUTH_ENABLED: 'false',
      OAUTH_SCOPE_ENFORCEMENT: 'false',
    })).not.toThrow();
  });
});

describe('staging configuration', () => {
  it('boots a deployment that is not staging, with or without an allow-list', () => {
    expect(() => assertStagingConfiguration({ STACK_STAGING: 'false', STAGING_SIGNIN_ALLOWLIST: '' })).not.toThrow();
    expect(() => assertStagingConfiguration({ STACK_STAGING: '', STAGING_SIGNIN_ALLOWLIST: '' })).not.toThrow();
  });

  it('boots a staging deployment that names who may sign in', () => {
    expect(() => assertStagingConfiguration({ STACK_STAGING: 'true', STAGING_SIGNIN_ALLOWLIST: 'tester@example.com' })).not.toThrow();
  });

  it('refuses to boot a staging deployment with an empty allow-list (fail closed)', () => {
    expect(() => assertStagingConfiguration({ STACK_STAGING: 'true', STAGING_SIGNIN_ALLOWLIST: '' })).toThrow(
      /STAGING_SIGNIN_ALLOWLIST must name at least one address when STACK_STAGING=true/,
    );
    expect(() => assertStagingConfiguration({ STACK_STAGING: 'true', STAGING_SIGNIN_ALLOWLIST: ' ,, ' })).toThrow(/STAGING_SIGNIN_ALLOWLIST/);
  });

  it('refuses a value of STACK_STAGING that is neither true nor false', () => {
    expect(() => assertStagingConfiguration({ STACK_STAGING: 'yes', STAGING_SIGNIN_ALLOWLIST: 'tester@example.com' })).toThrow(/STACK_STAGING/);
  });
});
