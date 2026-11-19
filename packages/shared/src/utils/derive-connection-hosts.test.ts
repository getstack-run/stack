import { describe, it, expect } from 'vitest';
import { deriveConnectionHosts } from './derive-connection-hosts.js';

/**
 * The operator must never be asked "where does this credential go?" when they
 * have already told us. Per-tenant providers carry their host in the
 * credential itself, and the credential template says which field.
 */
describe('deriveConnectionHosts', () => {
  it('derives a Salesforce org host from instance_url via the template', () => {
    // salesforce verification_url is '{{instance_url}}/services/data/v59.0/limits'
    expect(
      deriveConnectionHosts('salesforce', {
        instance_url: 'https://acme.my.salesforce.com',
        access_token: 'x',
      }),
    ).toEqual(['acme.my.salesforce.com']);
  });

  it('derives a Supabase project host from url', () => {
    // supabase verification_url is '{{url}}/rest/v1/'
    expect(
      deriveConnectionHosts('supabase', { url: 'https://abcdefgh.supabase.co', service_key: 'x' }),
    ).toEqual(['abcdefgh.supabase.co']);
  });

  it('derives a self-hosted PostHog host from host', () => {
    // posthog verification_url is '{{host}}/api/projects/'
    expect(
      deriveConnectionHosts('posthog', { host: 'https://analytics.internal-corp.example', api_key: 'x' }),
    ).toEqual(['analytics.internal-corp.example']);
  });

  it('derives an Algolia app host from a composed template', () => {
    // algolia verification_url is 'https://{{app_id}}-dsn.algolia.net/1/keys'
    expect(
      deriveConnectionHosts('algolia', { app_id: 'XYZ123', api_key: 'x' }),
    ).toEqual(['xyz123-dsn.algolia.net']);
  });

  it('accepts a bare hostname without a scheme', () => {
    expect(deriveConnectionHosts('posthog', { host: 'analytics.example.com' })).toEqual([
      'analytics.example.com',
    ]);
  });

  it('picks up a host-bearing field even with no template', () => {
    expect(
      deriveConnectionHosts('custom_my_internal_api', { base_url: 'https://api.mycorp.example/v2', token: 'x' }),
    ).toEqual(['api.mycorp.example']);
  });

  it('resolves a custom_ prefixed provider against its base template', () => {
    expect(
      deriveConnectionHosts('custom_supabase', { url: 'https://proj.supabase.co' }),
    ).toEqual(['proj.supabase.co']);
  });

  describe('returns null rather than guessing', () => {
    it('for a bare string credential, which carries no host', () => {
      expect(deriveConnectionHosts('openai', 'sk-abc123')).toBeNull();
    });

    it('for an unset credential', () => {
      expect(deriveConnectionHosts('openai', undefined)).toBeNull();
    });

    it('when the template placeholder was never filled in', () => {
      // An empty instance_url would interpolate to '/services/data/...' — a
      // path, not a URL. Deriving a host from that would be nonsense.
      expect(deriveConnectionHosts('salesforce', { access_token: 'x' })).toBeNull();
    });

    it('when a host field still contains an unresolved placeholder', () => {
      expect(deriveConnectionHosts('posthog', { host: '{{host}}' })).toBeNull();
    });

    it('for a single-label host with no dot', () => {
      expect(deriveConnectionHosts('posthog', { host: 'localhost' })).toBeNull();
    });

    it('for a wildcard, which would widen the control', () => {
      expect(deriveConnectionHosts('posthog', { host: '*.example.com' })).toBeNull();
    });

    it('for a credential with no host-bearing field at all', () => {
      expect(deriveConnectionHosts('openai', { api_key: 'sk-x', organization: 'org-y' })).toBeNull();
    });
  });

  it('returns every distinct host when several fields carry one', () => {
    const hosts = deriveConnectionHosts('custom_thing', {
      base_url: 'https://api.example.com',
      site: 'https://files.example.com',
    });
    expect(hosts).toEqual(['api.example.com', 'files.example.com']);
  });

  it('does not duplicate when the template and a field agree', () => {
    expect(
      deriveConnectionHosts('supabase', { url: 'https://proj.supabase.co' }),
    ).toEqual(['proj.supabase.co']);
  });
});
