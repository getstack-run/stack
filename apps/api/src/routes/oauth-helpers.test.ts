import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import {
  hashToken,
  verifyPkceS256,
  generateUserCode,
  audienceForResource,
  isValidScope,
  redirectUriRegistered,
  isLoopbackOrHttps,
  isAllowedRedirectUri,
} from './oauth-helpers.js';

describe('hashToken', () => {
  it('produces stable sha256 hex', () => {
    const raw = 'rt_abc123';
    const hashed = hashToken(raw);
    expect(hashed).toHaveLength(64);
    expect(hashed).toMatch(/^[0-9a-f]{64}$/);
    expect(hashed).toBe(hashToken(raw)); // deterministic
  });

  it('different inputs produce different hashes', () => {
    expect(hashToken('a')).not.toBe(hashToken('b'));
  });
});

describe('verifyPkceS256', () => {
  it('accepts a correct verifier/challenge pair', () => {
    const verifier = 'this-is-a-43-char-min-pkce-code-verifier-12';
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    expect(verifyPkceS256(verifier, challenge)).toBe(true);
  });

  it('rejects a wrong verifier', () => {
    const verifier = 'correct-verifier-string-43-chars-or-more-x';
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    expect(verifyPkceS256('wrong-verifier-string-43-chars-or-more-yyy', challenge)).toBe(false);
  });

  it('rejects mismatched lengths without throwing (timingSafeEqual would throw)', () => {
    expect(verifyPkceS256('short', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678901234567')).toBe(false);
  });

  it('rejects an empty challenge', () => {
    expect(verifyPkceS256('verifier-string', '')).toBe(false);
  });
});

describe('generateUserCode', () => {
  it('returns 9 chars in XXXX-XXXX format', () => {
    for (let i = 0; i < 100; i++) {
      const code = generateUserCode();
      expect(code).toMatch(/^[BCDFGHJKLMNPQRSTVWXYZ23456789]{4}-[BCDFGHJKLMNPQRSTVWXYZ23456789]{4}$/);
    }
  });

  it('does not produce visually-confusable characters (I/O/0/1/A/E/U)', () => {
    for (let i = 0; i < 200; i++) {
      const code = generateUserCode();
      expect(code).not.toMatch(/[IO01AEU]/);
    }
  });

  it('codes are not all identical (entropy sanity check)', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 50; i++) seen.add(generateUserCode());
    expect(seen.size).toBeGreaterThan(40); // collisions vanishingly rare in 50 draws
  });
});

describe('audienceForResource', () => {
  it('maps API resource → stack:api', () => {
    expect(audienceForResource('https://api.getstack.run')).toBe('stack:api');
  });

  it('maps MCP resource → stack:mcp', () => {
    expect(audienceForResource('https://mcp.getstack.run/mcp')).toBe('stack:mcp');
  });

  it('returns null for unknown resource', () => {
    expect(audienceForResource('https://evil.example.com')).toBeNull();
    expect(audienceForResource('')).toBeNull();
  });
});

describe('isValidScope', () => {
  it('accepts the default scope vocab', () => {
    expect(isValidScope('passports:read agents:read')).toBe(true);
    expect(isValidScope('admin')).toBe(true);
    expect(isValidScope('skills:invoke skills:publish proxy:write')).toBe(true);
  });

  it('rejects unknown scopes', () => {
    expect(isValidScope('passports:read unknown:scope')).toBe(false);
    expect(isValidScope('root')).toBe(false);
  });

  it('rejects empty + oversized', () => {
    expect(isValidScope('')).toBe(false);
    expect(isValidScope('passports:read '.repeat(200))).toBe(false);
  });
});

describe('redirectUriRegistered', () => {
  it('returns true on exact match', () => {
    expect(redirectUriRegistered(['http://localhost:8080/cb'], 'http://localhost:8080/cb')).toBe(true);
  });

  it('returns false on no match', () => {
    expect(redirectUriRegistered(['http://localhost:8080/cb'], 'http://localhost:8080/other')).toBe(false);
    expect(redirectUriRegistered(['https://app.example.com/cb'], 'https://app.example.com:8443/cb')).toBe(false);
  });

  it('accepts any port on an http loopback redirect (RFC 8252 §7.3)', () => {
    // Claude Code's client metadata document, then its real sign-in redirect.
    const claudeCode = ['http://localhost/callback', 'http://127.0.0.1/callback'];
    expect(redirectUriRegistered(claudeCode, 'http://localhost:53682/callback')).toBe(true);
    expect(redirectUriRegistered(claudeCode, 'http://127.0.0.1:61001/callback')).toBe(true);
    expect(redirectUriRegistered(['http://localhost:8080/cb'], 'http://localhost:8081/cb')).toBe(true);
    expect(redirectUriRegistered(['http://[::1]/cb'], 'http://[::1]:9000/cb')).toBe(true);
  });

  it('relaxes only the port: host, scheme, path and query still match exactly', () => {
    const reg = ['http://localhost/callback'];
    expect(redirectUriRegistered(reg, 'http://127.0.0.1:5000/callback')).toBe(false);
    expect(redirectUriRegistered(reg, 'https://localhost:5000/callback')).toBe(false);
    expect(redirectUriRegistered(reg, 'http://localhost:5000/callback/x')).toBe(false);
    expect(redirectUriRegistered(reg, 'http://localhost:5000/callback?next=evil')).toBe(false);
    expect(redirectUriRegistered(reg, 'http://user@localhost:5000/callback')).toBe(false);
    expect(redirectUriRegistered(reg, 'http://localhost.evil.com:5000/callback')).toBe(false);
    expect(redirectUriRegistered(['http://evil.com/callback'], 'http://evil.com:5000/callback')).toBe(false);
  });

  it('does NOT do prefix matching (RFC 6749 §3.1.2.4)', () => {
    expect(redirectUriRegistered(['http://localhost:8080/'], 'http://localhost:8080/cb')).toBe(false);
  });

  it('is case-sensitive (URI scheme + host should be lowercase but path is not normalized)', () => {
    expect(redirectUriRegistered(['http://localhost:8080/CB'], 'http://localhost:8080/cb')).toBe(false);
  });

  it('returns false on empty registry', () => {
    expect(redirectUriRegistered([], 'http://localhost:8080/cb')).toBe(false);
  });
});

describe('isLoopbackOrHttps', () => {
  it('accepts https://', () => {
    expect(isLoopbackOrHttps('https://app.example.com/cb')).toBe(true);
  });

  it('accepts http://localhost:PORT', () => {
    expect(isLoopbackOrHttps('http://localhost:8080/cb')).toBe(true);
    expect(isLoopbackOrHttps('http://127.0.0.1:54321/callback')).toBe(true);
    expect(isLoopbackOrHttps('http://[::1]:8080/cb')).toBe(true);
  });

  it('rejects http://non-loopback', () => {
    expect(isLoopbackOrHttps('http://example.com/cb')).toBe(false);
    expect(isLoopbackOrHttps('http://192.168.1.5/cb')).toBe(false);
  });

  it('rejects non-http schemes', () => {
    expect(isLoopbackOrHttps('javascript:alert(1)')).toBe(false);
    expect(isLoopbackOrHttps('file:///etc/passwd')).toBe(false);
    expect(isLoopbackOrHttps('data:text/html,<script>alert(1)</script>')).toBe(false);
  });

  it('rejects malformed URIs without throwing', () => {
    expect(isLoopbackOrHttps('not-a-url')).toBe(false);
    expect(isLoopbackOrHttps('')).toBe(false);
  });
});

describe('isAllowedRedirectUri (native app schemes, RFC 8252 §7.1)', () => {
  it("accepts every URI Cursor registers", () => {
    for (const uri of [
      'cursor://anysphere.cursor-mcp/oauth/callback',
      'https://www.cursor.com/agents/mcp/oauth/callback',
      'http://localhost:8787/callback',
    ]) expect(isAllowedRedirectUri(uri)).toBe(true);
    expect(isAllowedRedirectUri('vscode://vscode.github-authentication/did-authenticate')).toBe(true);
    expect(isAllowedRedirectUri('com.example.app:/oauth2redirect')).toBe(true);
  });

  it('refuses code-running, local-file, browser-internal and non-loopback http targets', () => {
    for (const uri of [
      'javascript:alert(1)', 'JavaScript://x/%0aalert(1)', 'data:text/html,<script>1</script>',
      'file:///etc/passwd', 'blob:https://x/1', 'about:blank', 'vbscript:msgbox',
      'chrome-extension://abc/cb', 'view-source:https://x', 'ws://x/cb', 'ftp://x/cb',
      'http://evil.com/callback', 'mailto:a@b.c', 'intent://x#Intent;end',
    ]) expect(isAllowedRedirectUri(uri), uri).toBe(false);
  });

  it('refuses fragments, credentials and empty targets', () => {
    expect(isAllowedRedirectUri('cursor://anysphere.cursor-mcp/cb#x')).toBe(false);
    expect(isAllowedRedirectUri('https://app.example.com/cb#x')).toBe(false);
    expect(isAllowedRedirectUri('cursor://user:pw@host/cb')).toBe(false);
    expect(isAllowedRedirectUri('cursor:')).toBe(false);
    expect(isAllowedRedirectUri('not a uri')).toBe(false);
  });
});
