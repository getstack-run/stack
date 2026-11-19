import { describe, it, expect } from 'vitest';
import {
  deriveConnectionHosts,
  defaultHostsForProvider,
  isPerTenantHostProvider,
  normalizeAllowedHosts,
} from '@stack/shared';

/**
 * The resolution rule every connect path shares.
 *
 * The operator must never be asked where a credential goes unless STACK
 * genuinely cannot know. Three sources answer in order, and only a provider
 * whose host is the operator's own instance falls through to a question.
 *
 * These assert the rule over the real catalogue, so adding a provider without
 * a host, or mis-marking one as per-tenant, shows up here.
 */

/** Mirrors ServiceConnectionService.resolveConnectionHosts ordering. */
function resolve(
  provider: string,
  declared: string[] | undefined,
  credential: Record<string, string> | undefined,
): { hosts: string[] | null; asks: boolean } {
  if (declared && declared.length > 0) {
    const cleaned = normalizeAllowedHosts(declared);
    if (cleaned.length > 0) return { hosts: cleaned, asks: false };
  }
  const derived = deriveConnectionHosts(provider, credential);
  if (derived && derived.length > 0) return { hosts: derived, asks: false };
  const catalogue = defaultHostsForProvider(provider);
  if (catalogue && catalogue.length > 0) return { hosts: [...catalogue], asks: false };
  if (isPerTenantHostProvider(provider)) return { hosts: null, asks: true };
  return { hosts: null, asks: false };
}

describe('connection host resolution', () => {
  it('answers a catalogued provider without asking', () => {
    // The motivating example: add an OpenRouter key, get asked nothing.
    const r = resolve('openrouter', undefined, { api_key: 'sk-or-x' });
    expect(r.asks).toBe(false);
    expect(r.hosts).toEqual(['openrouter.ai']);
  });

  it.each([
    ['stripe', 'api.stripe.com'],
    ['slack', 'slack.com'],
    ['microsoft_teams', 'graph.microsoft.com'],
    ['cohere', 'api.cohere.com'],
    ['front', 'api2.frontapp.com'],
  ])('resolves %s without asking', (provider, expected) => {
    const r = resolve(provider, undefined, { api_key: 'x' });
    expect(r.asks).toBe(false);
    expect(r.hosts).toContain(expected);
  });

  it('derives a per-tenant host from the credential the operator pasted', () => {
    const r = resolve('salesforce', undefined, {
      instance_url: 'https://acme.my.salesforce.com',
      access_token: 'x',
    });
    expect(r.asks).toBe(false);
    expect(r.hosts).toEqual(['acme.my.salesforce.com']);
  });

  it('asks only when a per-tenant provider gave no host anywhere', () => {
    const r = resolve('okta', undefined, { api_token: 'x' });
    expect(r.asks).toBe(true);
    expect(r.hosts).toBeNull();
  });

  it('stops asking once the operator declares it', () => {
    const r = resolve('okta', ['acme.okta.com'], { api_token: 'x' });
    expect(r.asks).toBe(false);
    expect(r.hosts).toEqual(['acme.okta.com']);
  });

  it('prefers an explicit declaration over the catalogue', () => {
    // A self-hosted GitLab is still `gitlab`, and the operator's own host wins.
    const r = resolve('gitlab', ['git.mycorp.example'], undefined);
    expect(r.hosts).toEqual(['git.mycorp.example']);
  });

  it('refuses a declaration broad enough to cover a TLD', () => {
    expect(() => resolve('okta', ['.com'], undefined)).toThrow();
  });

  it('keeps both regional twins where a vendor mirrors them', () => {
    // Sending a credential to the wrong regional twin is a cross-jurisdiction
    // leak; omitting the twin breaks the operator who legitimately uses it.
    expect(defaultHostsForProvider('bitwarden')).toContain('api.bitwarden.eu');
    expect(defaultHostsForProvider('contentful')).toContain('cdn.eu.contentful.com');
  });

  it('never marks a provider as both catalogued and per-tenant', () => {
    // The two are mutually exclusive: a fixed host means no question, a
    // per-tenant host means we must not invent one.
    const both: string[] = [];
    for (const p of ['stripe', 'okta', 'salesforce', 'gitlab', 'aws', 'supabase']) {
      if (defaultHostsForProvider(p) && isPerTenantHostProvider(p)) both.push(p);
    }
    expect(both).toEqual([]);
  });
});
