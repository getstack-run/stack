import { describe, expect, it, vi } from 'vitest';
import { CREDENTIAL_TEMPLATES, deriveConnectionHosts } from '@stack/shared';
import { ConnectionVerifierService } from './connection-verifier.js';
import { OAuthLifecycleError } from './oauth-token-lifecycle.js';
import { templateApplies, proxyFieldsFromCredential } from './credential-fields.js';
import { ProxyService } from './proxy-service.js';

/**
 * STACK registers no OAuth app at GitHub, Linear, Notion, Figma, Discord, Jira,
 * Confluence or Cal.com, so each connects with the key or token the service issues. The
 * template for that key applies to a credential that carries its fields and to
 * nothing else: a connection made through an OAuth app keeps its bearer header.
 */
const KEY_PROVIDERS = ['github', 'linear', 'notion', 'figma', 'discord', 'jira', 'confluence', 'cal_com'] as const;

const KEY_CREDENTIALS: Record<(typeof KEY_PROVIDERS)[number], Record<string, string>> = {
  github: { token: 'ghp_synthetic' },
  linear: { api_key: 'lin_api_synthetic' },
  notion: { api_key: 'ntn_synthetic' },
  figma: { token: 'figd_synthetic' },
  discord: { bot_token: 'synthetic-bot' },
  jira: { site_url: 'https://acme.atlassian.net', email: 'a@acme.test', api_token: 'synthetic-atlassian' },
  confluence: { site_url: 'https://acme.atlassian.net', email: 'a@acme.test', api_token: 'synthetic-atlassian' },
  cal_com: { api_key: 'cal_live_synthetic' },
};

describe('key paths of services that also have an OAuth app', () => {
  it('has a key template for every service STACK no longer runs an OAuth app for', () => {
    for (const provider of KEY_PROVIDERS) {
      const template = CREDENTIAL_TEMPLATES[provider];
      expect(template?.own_fields_only, provider).toBe(true);
      expect(template?.fields.some((field) => field.type === 'secret'), provider).toBe(true);
      expect(template?.verification_url, provider).toBeTruthy();
    }
  });

  it('puts each key where the service expects it', () => {
    const proxy = new ProxyService();
    const header = (provider: (typeof KEY_PROVIDERS)[number]) =>
      proxy.resolveAuthHeaders(provider, JSON.stringify(KEY_CREDENTIALS[provider]));
    expect(header('github')).toEqual({ Authorization: 'Bearer ghp_synthetic' });
    expect(header('linear')).toEqual({ Authorization: 'lin_api_synthetic', 'Content-Type': 'application/json' });
    expect(header('notion')).toEqual({ Authorization: 'Bearer ntn_synthetic', 'Notion-Version': '2022-06-28' });
    expect(header('figma')).toEqual({ 'X-Figma-Token': 'figd_synthetic' });
    expect(header('discord')).toEqual({ Authorization: 'Bot synthetic-bot' });
    expect(header('cal_com')).toEqual({ Authorization: 'Bearer cal_live_synthetic' });
    const basic = `Basic ${Buffer.from('a@acme.test:synthetic-atlassian').toString('base64')}`;
    expect(header('jira')).toEqual({ Authorization: basic });
    expect(header('confluence')).toEqual({ Authorization: basic });
  });

  it('keeps an OAuth connection of the same service on its bearer header', () => {
    const proxy = new ProxyService();
    const oauth = JSON.stringify({ access_token: 'synthetic-access', refresh_token: 'r', expires_at: 1 });
    for (const provider of KEY_PROVIDERS) {
      if (provider === 'jira' || provider === 'confluence') continue; // not in the bearer list: read by common patterns
      expect(proxy.resolveAuthHeaders(provider, oauth), provider).toEqual({ Authorization: 'Bearer synthetic-access' });
      // A legacy bare token is read as it always was.
      expect(proxy.resolveAuthHeaders(provider, 'synthetic-bare'), provider).toEqual({ Authorization: 'Bearer synthetic-bare' });
    }
    expect(proxy.resolveAuthHeaders('jira', oauth)).toEqual({ Authorization: 'Bearer synthetic-access' });
  });

  it('takes a pasted key for any service that is otherwise connected by OAuth', () => {
    const proxy = new ProxyService();
    expect(proxy.resolveAuthHeaders('dropbox', JSON.stringify({ api_key: 'synthetic-key' })))
      .toEqual({ Authorization: 'Bearer synthetic-key' });
    expect(() => proxy.resolveAuthHeaders('dropbox', JSON.stringify({ refresh_token: 'only' }))).toThrow();
  });

  it('limits an Atlassian key to the site it names', () => {
    expect(deriveConnectionHosts('jira', KEY_CREDENTIALS.jira)).toEqual(['acme.atlassian.net']);
    expect(deriveConnectionHosts('confluence', KEY_CREDENTIALS.confluence)).toEqual(['acme.atlassian.net']);
  });

  it('applies a key template only to a credential that carries its required fields', () => {
    const github = CREDENTIAL_TEMPLATES.github!;
    expect(templateApplies(github, proxyFieldsFromCredential(JSON.stringify({ token: 'x' })))).toBe(true);
    expect(templateApplies(github, proxyFieldsFromCredential(JSON.stringify({ access_token: 'x' })))).toBe(false);
    expect(templateApplies(github, proxyFieldsFromCredential('bare'))).toBe(false);
    // Every other template is unchanged.
    expect(templateApplies(CREDENTIAL_TEMPLATES.openai!, proxyFieldsFromCredential('bare'))).toBe(true);
  });
});

describe('verifying a connection made with a key', () => {
  function verifierFor(provider: string, credential: string, current?: () => Promise<string>) {
    const request = vi.fn(async () => new Response('{}', { status: 200 }));
    const update = vi.fn(async () => undefined);
    const verifier = new ConnectionVerifierService(
      {
        findConnectionById: vi.fn(async () => ({
          id: 'scon_x', operator_id: 'op_x', provider, status: 'active', credential_encrypted: 'env',
        })),
        updateConnectionVerification: update,
      } as never,
      { current: vi.fn(current ?? (async () => credential)) } as never,
      { request: request as typeof fetch, assertPublicUrl: vi.fn(async (url: string) => new URL(url)), timeoutMs: 20 },
    );
    return { verifier, request, update };
  }

  it('checks a GitHub token against GitHub with the token, and an OAuth token the way it always was', async () => {
    const key = verifierFor('github', JSON.stringify({ token: 'ghp_synthetic' }));
    expect((await key.verifier.verify('scon_x', 'op_x')).status).toBe('healthy');
    expect(key.request).toHaveBeenCalledWith('https://api.github.com/user', expect.objectContaining({
      headers: { Authorization: 'Bearer ghp_synthetic' },
    }));

    const oauth = verifierFor('github', JSON.stringify({ access_token: 'synthetic-access' }));
    await oauth.verifier.verify('scon_x', 'op_x');
    expect(oauth.request).toHaveBeenCalledWith('https://api.github.com/user', expect.objectContaining({
      headers: { Authorization: 'Bearer synthetic-access' },
    }));
  });

  it('checks a Jira token against the customer\'s own site', async () => {
    const h = verifierFor('jira', JSON.stringify(KEY_CREDENTIALS.jira));
    expect((await h.verifier.verify('scon_x', 'op_x')).status).toBe('healthy');
    expect(h.request).toHaveBeenCalledWith('https://acme.atlassian.net/rest/api/3/myself', expect.anything());
  });

  it('reports a connection the renewal path marked retired as unhealthy, in the words of its reason', async () => {
    const h = verifierFor('github', '{}', async () => { throw new OAuthLifecycleError(true, 'stack_oauth_app_retired'); });
    const result = await h.verifier.verify('scon_x', 'op_x');
    expect(result.status).toBe('unhealthy');
    expect(result.message).toContain('API key or token');
    expect(h.request).not.toHaveBeenCalled();
    expect(h.update).toHaveBeenCalledWith('scon_x', 'unhealthy');
  });

  it('says the same for a connection that holds more scopes than its app may ask for, and plainly for one whose renewal failed', async () => {
    const narrowed = verifierFor('gmail', '{}', async () => { throw new OAuthLifecycleError(true, 'oauth_app_scopes_narrowed'); });
    expect((await narrowed.verifier.verify('scon_x', 'op_x')).message).toContain('more access than the app');
    const revoked = verifierFor('gmail', '{}', async () => { throw new OAuthLifecycleError(true); });
    expect((await revoked.verifier.verify('scon_x', 'op_x')).message).toBe('The provider no longer honours this connection; reconnect it');
    const pending = verifierFor('gmail', '{}', async () => { throw new OAuthLifecycleError(); });
    expect((await pending.verifier.verify('scon_x', 'op_x')).message).toContain('try again shortly');
  });
});
