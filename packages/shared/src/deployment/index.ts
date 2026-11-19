/**
 * Where this STACK installation lives, and what it calls itself.
 *
 * Every hosted default is the value the code carried before this module
 * existed, so STACK's own deployment is unchanged. A self-managed install
 * (`STACK_DEPLOYMENT=self_managed`) names its own address, and the issuer of
 * its tokens follows from it, so nothing it signs says `getstack.run`.
 *
 * A hosted deployment that is not STACK's production (staging) names its own
 * site with `STACK_SITE_URL`: email links, the CORS default origin, OAuth
 * metadata and the Console's default address follow it. The issuers of what
 * STACK signs and the published protocol constants do not.
 *
 * Read lazily from the process environment: the API, the worker and the MCP
 * server all import this and read the same variables.
 */

export type DeploymentMode = 'hosted' | 'self_managed';

export interface DeploymentConfig {
  mode: DeploymentMode;
  selfManaged: boolean;
  /** Public origin of the API, no trailing slash. */
  apiBaseUrl: string;
  /** Public origin of the Console, or of whatever page people approve on. */
  dashboardUrl: string;
  /** Public origin of the MCP server, no trailing slash. */
  mcpBaseUrl: string;
  /** The MCP resource identifier (`<mcpBaseUrl>/mcp`). */
  mcpResource: string;
  /** The connector-directory resource (`<mcpBaseUrl>/directory`). */
  mcpDirectoryResource: string;
  /** The `iss` of passports, sessions, fleet sessions and OAuth tokens. */
  passportIssuer: string;
  oauthIssuer: string;
  /** The RFC 8414 metadata issuer, also accepted when verifying. */
  oauthMetadataIssuer: string;
  /** The `iss` of an authority receiver presentation. */
  presentationIssuer: string;
  /** The origin links in emails and in error messages point at. */
  siteUrl: string;
  /** `STACK_SITE_URL` was set: the hosted site is not STACK's production site. */
  siteConfigured: boolean;
}

export const HOSTED_API_BASE_URL = 'https://api.getstack.run';
export const HOSTED_SITE_URL = 'https://getstack.run';
export const HOSTED_MCP_BASE_URL = 'https://mcp.getstack.run';
export const HOSTED_ISSUER = 'getstack.run';

type Env = Record<string, string | undefined>;

function trimOrigin(value: string): string {
  return value.replace(/\/+$/, '');
}

function nonEmpty(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function isLoopback(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}

function requireOrigin(name: string, value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`[BOOT] ${name} must be a URL`);
  }
  const trusted = url.protocol === 'https:' || (url.protocol === 'http:' && isLoopback(url.hostname));
  if (!trusted || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error(`[BOOT] ${name} must be an https origin with no path (http only for localhost)`);
  }
  return trimOrigin(url.origin);
}

/** An https origin and nothing else: no other scheme, no loopback, no credentials, path, query or fragment. */
function requireHttpsOrigin(name: string, value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`[BOOT] ${name} must be a URL`);
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error(`[BOOT] ${name} must be an https origin with no path`);
  }
  return trimOrigin(url.origin);
}

export function readDeployment(env: Env = process.env): DeploymentConfig {
  const rawMode = nonEmpty(env['STACK_DEPLOYMENT']) ?? 'hosted';
  if (rawMode !== 'hosted' && rawMode !== 'self_managed') {
    throw new Error('[BOOT] STACK_DEPLOYMENT must be "hosted" or "self_managed"');
  }
  const mode: DeploymentMode = rawMode;
  const selfManaged = mode === 'self_managed';

  const apiBase = nonEmpty(env['STACK_API_BASE_URL']);
  const dashboard = nonEmpty(env['DASHBOARD_URL']);
  const mcpBase = nonEmpty(env['STACK_MCP_BASE_URL']);
  const issuerOverride = nonEmpty(env['STACK_ISSUER']);
  const site = nonEmpty(env['STACK_SITE_URL']);

  if (selfManaged) {
    // An install's site is its Console (DASHBOARD_URL); a second name for it would only be a way for the two to disagree.
    if (site) throw new Error('[BOOT] STACK_SITE_URL is for a hosted deployment; a self-managed install names its site with DASHBOARD_URL');
    // A self-managed install has no address of its own to fall back on, and
    // signing tokens under STACK's would make them look like STACK's.
    if (!apiBase) throw new Error('[BOOT] STACK_API_BASE_URL is required when STACK_DEPLOYMENT=self_managed');
    const apiBaseUrl = requireOrigin('STACK_API_BASE_URL', apiBase);
    const dashboardUrl = dashboard ? requireOrigin('DASHBOARD_URL', dashboard) : apiBaseUrl;
    const mcpBaseUrl = mcpBase ? requireOrigin('STACK_MCP_BASE_URL', mcpBase) : apiBaseUrl;
    const issuer = issuerOverride ?? new URL(apiBaseUrl).host;
    return {
      mode,
      selfManaged,
      apiBaseUrl,
      dashboardUrl,
      mcpBaseUrl,
      mcpResource: `${mcpBaseUrl}/mcp`,
      mcpDirectoryResource: `${mcpBaseUrl}/directory`,
      passportIssuer: issuer,
      oauthIssuer: issuer,
      oauthMetadataIssuer: apiBaseUrl,
      presentationIssuer: apiBaseUrl,
      siteUrl: dashboardUrl,
      siteConfigured: false,
    };
  }

  const apiBaseUrl = trimOrigin(apiBase ?? HOSTED_API_BASE_URL);
  const mcpBaseUrl = trimOrigin(mcpBase ?? HOSTED_MCP_BASE_URL);
  const issuer = issuerOverride ?? HOSTED_ISSUER;
  const siteUrl = site ? requireHttpsOrigin('STACK_SITE_URL', site) : HOSTED_SITE_URL;
  return {
    mode,
    selfManaged,
    apiBaseUrl,
    dashboardUrl: trimOrigin(dashboard ?? siteUrl),
    mcpBaseUrl,
    mcpResource: `${mcpBaseUrl}/mcp`,
    mcpDirectoryResource: `${mcpBaseUrl}/directory`,
    passportIssuer: issuer,
    oauthIssuer: issuer,
    // The metadata issuer is a published RFC 8414 value; it follows the API
    // origin only when that origin was configured.
    oauthMetadataIssuer: apiBase ? apiBaseUrl : HOSTED_API_BASE_URL,
    // A signed value (the `iss` of an authority receiver presentation): it stays STACK's whatever the site is.
    presentationIssuer: HOSTED_SITE_URL,
    siteUrl,
    siteConfigured: site !== undefined,
  };
}

const WATCHED = [
  'STACK_DEPLOYMENT',
  'STACK_API_BASE_URL',
  'DASHBOARD_URL',
  'STACK_MCP_BASE_URL',
  'STACK_ISSUER',
  'STACK_SITE_URL',
] as const;

let cached: { key: string; config: DeploymentConfig } | undefined;

/**
 * The configuration of this process. Parsed again only when one of the
 * variables it reads changes, so a hot path (every token verification asks)
 * costs a few string reads and a comparison.
 */
export function deployment(): DeploymentConfig {
  const key = WATCHED.map((name) => process.env[name] ?? '').join('\u0000');
  if (cached?.key !== key) cached = { key, config: readDeployment(process.env) };
  return cached.config;
}

export function isSelfManaged(): boolean {
  return deployment().selfManaged;
}
export {
  readStaging,
  staging,
  signinAllowed,
  stagingRecipientAllowed,
  STAGING_ROBOTS_TAG,
  STAGING_SKIPPED_EMAIL_ID,
  type StagingConfig,
} from './staging.js';
export { assertEngineEntryAllowed, assertHostedEntryAllowed } from './entry.js';
