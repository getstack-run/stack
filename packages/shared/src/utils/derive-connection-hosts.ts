// Derive a connection's allowed hosts from the credential the operator
// already supplied.
//
// WHY. Credential-to-destination binding needs to know where a connection's
// credential may be sent. For catalogued providers we know the host outright
// (PROVIDER_API_HOSTS). For a per-tenant provider we cannot: the host IS the
// operator's own instance — their Salesforce org, their Supabase project,
// their self-hosted PostHog, their Algolia app.
//
// Asking the operator to type it would be absurd, because they already gave
// it to us. Those credential templates literally carry the host in a field:
// `{{instance_url}}`, `{{url}}`, `{{host}}`, `{{app_id}}`. The proxy's own
// `resolveTargetUrl` interpolates those same fields to build the outbound
// URL, so a host derived this way is by construction the host the proxy will
// actually reach. No question asked, and no guessing.
//
// Returns null when nothing can be derived. Null is not permission — the
// caller falls back to the catalog, and failing that the connection stays
// undeclared and the proxy denies.

import { CREDENTIAL_TEMPLATES } from '../constants/credential-templates.js';

/** Credential fields that are themselves a host or a base URL. */
const HOST_BEARING_FIELDS = [
  'instance_url',
  'base_url',
  'api_url',
  'url',
  'host',
  'hostname',
  'endpoint',
  'domain',
  'site',
  'site_url',
  'server',
  'server_url',
];

/**
 * Best-effort host extraction for a connection.
 *
 * Two sources, in order:
 *   1. The provider's `verification_url` template with the operator's fields
 *      interpolated. This is the strongest signal — it is the same template
 *      the connection verifier hits and the same interpolation the proxy
 *      applies to `{{...}}` placeholders in a target URL.
 *   2. Any credential field that is itself a host or base URL.
 *
 * `credential` is the operator's plaintext credential: either a bare string
 * (a single API key, which carries no host) or a field map.
 */
export function deriveConnectionHosts(
  provider: string,
  credential: string | Record<string, string> | undefined,
): string[] | null {
  if (!credential || typeof credential === 'string') return null;

  const fields = credential;
  const hosts: string[] = [];

  const templateKey = provider.replace(/^custom_/, '').toLowerCase();
  const verificationUrl = CREDENTIAL_TEMPLATES[templateKey]?.verification_url;

  if (verificationUrl && verificationUrl.includes('{{')) {
    const interpolated = verificationUrl.replace(
      /\{\{(\w+)\}\}/g,
      (_, key: string) => fields[key] ?? '',
    );
    const host = hostOf(interpolated);
    if (host) hosts.push(host);
  }

  for (const key of HOST_BEARING_FIELDS) {
    const raw = fields[key];
    if (!raw) continue;
    const host = hostOf(raw);
    if (host && !hosts.includes(host)) hosts.push(host);
  }

  return hosts.length > 0 ? hosts : null;
}

/**
 * Hostname from a URL, or from a bare hostname. Returns null for anything
 * that is neither — an unresolved `{{placeholder}}`, a path fragment, an
 * empty string. Deliberately strict: a bad derivation would widen a security
 * control, and returning null merely falls through to the catalog.
 */
function hostOf(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed || trimmed.includes('{{') || trimmed.includes('}}')) return null;

  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let host: string;
  try {
    host = new URL(candidate).hostname.toLowerCase();
  } catch {
    return null;
  }
  // Must look like a real public hostname: at least one dot, no wildcards.
  if (!host || !host.includes('.') || host.includes('*')) return null;
  if (!/^[a-z0-9.-]+$/.test(host)) return null;
  return host;
}
