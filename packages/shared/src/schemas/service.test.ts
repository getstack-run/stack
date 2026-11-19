import { describe, expect, it } from 'vitest';
import { ConnectCustomServiceInput, ConnectionName, ConnectServiceInput, Service, ServiceConnection, ServiceProvider } from './service.js';
import { ProxyRequestInput } from './proxy.js';

describe('ServiceProvider', () => {
  it('accepts any catalog provider, not a fixed shortlist', () => {
    for (const provider of ['slack', 'okta', 'zendesk', 'stripe', 'custom_acme']) {
      expect(ServiceProvider.safeParse(provider).success, provider).toBe(true);
    }
  });

  it('rejects an empty provider', () => {
    expect(ServiceProvider.safeParse('').success).toBe(false);
    expect(ServiceProvider.safeParse(undefined).success).toBe(false);
  });

  it('lets Service and ServiceConnection carry a provider outside the original eight', () => {
    expect(
      Service.safeParse({
        id: 'svc_1',
        provider: 'okta',
        name: 'Okta',
        description: 'Identity',
        oauth_config: { auth_url: 'https://a.example/auth', token_url: 'https://a.example/token', scopes_available: [] },
        available: true,
      }).success,
    ).toBe(true);
    expect(
      ServiceConnection.safeParse({
        id: 'conn_1',
        operator_id: 'op_1',
        service_id: 'svc_1',
        provider: 'zendesk',
        name: 'default',
        scopes: ['read'],
        credential_ref: 'ref',
        status: 'active',
        connected_at: new Date(),
        expires_at: null,
      }).success,
    ).toBe(true);
  });
});

describe('ConnectionName', () => {
  it('accepts a plain name and trims it', () => {
    expect(ConnectionName.parse('work')).toBe('work');
    expect(ConnectionName.parse('Personal 2')).toBe('Personal 2');
    expect(ConnectionName.parse('  eu-west  ')).toBe('eu-west');
    expect(ConnectionName.parse('x'.repeat(40))).toHaveLength(40);
  });

  it('rejects an empty name, a long one, a line break and anything that could pass for an id', () => {
    for (const bad of ['', '   ', 'x'.repeat(41), 'a\nb', 'a\r\nb', 'scon_abc', 'SCON_abc', 'a_b', 'a/b', 'a.b']) {
      expect(ConnectionName.safeParse(bad).success, JSON.stringify(bad)).toBe(false);
    }
  });

  it('is optional on the connect inputs and on a proxy call, and checked when given', () => {
    const connect = { service_id: 'svc_1', scopes: ['read'] };
    expect(ConnectServiceInput.safeParse(connect).success).toBe(true);
    expect(ConnectServiceInput.safeParse({ ...connect, connection_name: 'work' }).success).toBe(true);
    expect(ConnectServiceInput.safeParse({ ...connect, connection_name: 'scon_1' }).success).toBe(false);
    expect(ConnectCustomServiceInput.safeParse({ name: 'Acme', connection_name: 'work' }).success).toBe(true);
    expect(ConnectCustomServiceInput.safeParse({ name: 'Acme', connection_name: 'a\nb' }).success).toBe(false);
    const call = { service: 'slack', url: 'https://slack.com/api/x', method: 'GET' as const };
    expect(ProxyRequestInput.safeParse(call).success).toBe(true);
    expect(ProxyRequestInput.safeParse({ ...call, connection: 'work' }).success).toBe(true);
    expect(ProxyRequestInput.safeParse({ ...call, connection: 'scon_abc123' }).success).toBe(true);
    expect(ProxyRequestInput.safeParse({ ...call, connection: '' }).success).toBe(false);
  });
});
