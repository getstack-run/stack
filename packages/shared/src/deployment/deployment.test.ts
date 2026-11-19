import { describe, expect, it } from 'vitest';
import { readDeployment } from './index.js';

describe('readDeployment', () => {
  it('keeps every hosted value the code carried before it was configurable', () => {
    const d = readDeployment({});
    expect(d.mode).toBe('hosted');
    expect(d.selfManaged).toBe(false);
    expect(d.passportIssuer).toBe('getstack.run');
    expect(d.oauthIssuer).toBe('getstack.run');
    expect(d.oauthMetadataIssuer).toBe('https://api.getstack.run');
    expect(d.apiBaseUrl).toBe('https://api.getstack.run');
    expect(d.mcpResource).toBe('https://mcp.getstack.run/mcp');
    expect(d.mcpDirectoryResource).toBe('https://mcp.getstack.run/directory');
    expect(d.dashboardUrl).toBe('https://getstack.run');
    expect(d.siteUrl).toBe('https://getstack.run');
    expect(d.presentationIssuer).toBe('https://getstack.run');
  });

  it('follows DASHBOARD_URL and STACK_API_BASE_URL on the hosted default', () => {
    const d = readDeployment({
      DASHBOARD_URL: 'http://localhost:3100/',
      STACK_API_BASE_URL: 'http://localhost:3001',
    });
    expect(d.dashboardUrl).toBe('http://localhost:3100');
    expect(d.apiBaseUrl).toBe('http://localhost:3001');
    expect(d.oauthMetadataIssuer).toBe('http://localhost:3001');
    expect(d.passportIssuer).toBe('getstack.run');
  });

  it('names a self-managed install by its own address', () => {
    const d = readDeployment({
      STACK_DEPLOYMENT: 'self_managed',
      STACK_API_BASE_URL: 'https://stack.example.com',
    });
    expect(d.selfManaged).toBe(true);
    expect(d.passportIssuer).toBe('stack.example.com');
    expect(d.oauthIssuer).toBe('stack.example.com');
    expect(d.oauthMetadataIssuer).toBe('https://stack.example.com');
    expect(d.mcpResource).toBe('https://stack.example.com/mcp');
    expect(d.dashboardUrl).toBe('https://stack.example.com');
    expect(JSON.stringify(d)).not.toContain('getstack.run');
  });

  it('lets a self-managed install pick its issuer and a separate MCP origin', () => {
    const d = readDeployment({
      STACK_DEPLOYMENT: 'self_managed',
      STACK_API_BASE_URL: 'https://api.corp.example',
      STACK_MCP_BASE_URL: 'https://mcp.corp.example',
      DASHBOARD_URL: 'https://console.corp.example',
      STACK_ISSUER: 'stack.corp.example',
    });
    expect(d.passportIssuer).toBe('stack.corp.example');
    expect(d.mcpResource).toBe('https://mcp.corp.example/mcp');
    expect(d.mcpDirectoryResource).toBe('https://mcp.corp.example/directory');
    expect(d.dashboardUrl).toBe('https://console.corp.example');
  });

  it('refuses a self-managed install with no address or an untrusted one', () => {
    expect(() => readDeployment({ STACK_DEPLOYMENT: 'self_managed' })).toThrow(/STACK_API_BASE_URL/);
    expect(() =>
      readDeployment({ STACK_DEPLOYMENT: 'self_managed', STACK_API_BASE_URL: 'http://stack.example.com' }),
    ).toThrow(/https origin/);
    expect(() =>
      readDeployment({ STACK_DEPLOYMENT: 'self_managed', STACK_API_BASE_URL: 'https://u:p@stack.example.com' }),
    ).toThrow(/https origin/);
    expect(() =>
      readDeployment({ STACK_DEPLOYMENT: 'self_managed', STACK_API_BASE_URL: 'https://stack.example.com/api' }),
    ).toThrow(/no path/);
    expect(() =>
      readDeployment({ STACK_DEPLOYMENT: 'self_managed', STACK_API_BASE_URL: 'http://localhost:3001' }),
    ).not.toThrow();
  });

  it('keeps getstack.run as the site when STACK_SITE_URL is unset', () => {
    const d = readDeployment({});
    expect(d.siteUrl).toBe('https://getstack.run');
    expect(d.dashboardUrl).toBe('https://getstack.run');
    expect(d.siteConfigured).toBe(false);
  });

  it('follows STACK_SITE_URL for the site and the Console, and leaves every signed and published value alone', () => {
    const d = readDeployment({ STACK_SITE_URL: 'https://staging-site.example.test/' });
    expect(d.siteUrl).toBe('https://staging-site.example.test');
    expect(d.dashboardUrl).toBe('https://staging-site.example.test');
    expect(d.siteConfigured).toBe(true);
    // The issuers and the presentation issuer are what STACK signs: they never follow the site.
    expect(d.passportIssuer).toBe('getstack.run');
    expect(d.oauthIssuer).toBe('getstack.run');
    expect(d.oauthMetadataIssuer).toBe('https://api.getstack.run');
    expect(d.presentationIssuer).toBe('https://getstack.run');
    // DASHBOARD_URL still names the Console when both are set.
    expect(readDeployment({ STACK_SITE_URL: 'https://site.example', DASHBOARD_URL: 'https://console.example' }).dashboardUrl)
      .toBe('https://console.example');
  });

  it('refuses a STACK_SITE_URL that is not an https origin, loopback included', () => {
    for (const value of [
      'http://staging-site.example.test',
      'http://localhost:3100',
      'https://u:p@site.example',
      'https://site.example/app',
      'https://site.example/?a=1',
      'ftp://site.example',
      'not a url',
    ]) {
      expect(() => readDeployment({ STACK_SITE_URL: value })).toThrow(/STACK_SITE_URL/);
    }
  });

  it('refuses STACK_SITE_URL on a self-managed install, whose site is DASHBOARD_URL', () => {
    expect(() =>
      readDeployment({ STACK_DEPLOYMENT: 'self_managed', STACK_API_BASE_URL: 'https://stack.example.com', STACK_SITE_URL: 'https://site.example' }),
    ).toThrow(/STACK_SITE_URL/);
  });

  it('refuses an unknown mode so a typo cannot start a hosted-shaped install', () => {
    expect(() => readDeployment({ STACK_DEPLOYMENT: 'selfmanaged' })).toThrow(/STACK_DEPLOYMENT/);
  });
});
