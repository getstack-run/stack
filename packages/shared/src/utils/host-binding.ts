// Credential-to-destination binding.
//
// The proxy takes `service` and `url` as independent inputs: `service`
// selects which stored credential is decrypted and injected, `url` is
// wherever the agent wants to go. Nothing used to connect the two, so a
// passport granting `stripe` could send the live Stripe key to any public
// HTTPS host the agent named. `assertPublicUrl` did not catch it — that is
// an SSRF guard (private ranges, link-local, metadata IPs), and an
// attacker's server is a perfectly public address.
//
// This module is the missing half: a credential may only be injected into a
// request whose host belongs to the connection that owns it. Deny by
// default. A connection with no declared hosts cannot be proxied at all.
//
// Deliberately NOT a detector. This is a string comparison against an
// operator declaration, so it denies rather than flags, and it holds on the
// injections the classifier misses.

/**
 * Does `host` satisfy one of `allowedHosts`?
 *
 * Two forms are accepted in `allowedHosts`:
 *   - an exact host      `api.stripe.com`      matches only itself
 *   - a dot-led suffix   `.amazonaws.com`      matches any subdomain of it,
 *                                              and the bare parent domain
 *
 * The suffix form exists because some providers are inherently multi-host
 * (AWS regional endpoints, per-store Shopify domains). It requires at least
 * two labels after the leading dot, so `.com` can never be declared and a
 * typo cannot silently open the whole TLD.
 *
 * Comparison is case-insensitive. A port on the candidate host is ignored
 * for matching purposes — the port is not a security boundary here and
 * `assertPublicUrl` already pins the protocol to https.
 */
export function isHostAllowed(host: string, allowedHosts: readonly string[]): boolean {
  const candidate = normalizeHost(host);
  if (!candidate) return false;
  if (allowedHosts.length === 0) return false;

  for (const raw of allowedHosts) {
    const entry = raw.trim().toLowerCase();
    if (!entry) continue;

    if (entry.startsWith('.')) {
      const suffix = entry.slice(1);
      // Reject a too-broad wildcard rather than honouring it: `.com` or a
      // bare `.` must never match anything.
      if (suffix.split('.').filter(Boolean).length < 2) continue;
      if (candidate === suffix) return true;
      if (candidate.endsWith(`.${suffix}`)) return true;
      continue;
    }

    if (candidate === entry) return true;
  }

  return false;
}

/**
 * Extract the comparable host from a URL string. Returns null when the URL
 * does not parse, which callers must treat as a denial (the proxy already
 * refuses unparseable URLs upstream in `assertPublicUrl`, so this is
 * belt-and-braces rather than the primary guard).
 */
export function hostOfUrl(url: string): string | null {
  try {
    return normalizeHost(new URL(url).hostname) || null;
  } catch {
    return null;
  }
}

/** Thrown when a declared host is malformed or dangerously broad. */
export class InvalidAllowedHostError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidAllowedHostError';
  }
}

/**
 * Validate and canonicalise an operator-declared host list.
 *
 * Shared by every path that accepts a declaration (custom-service connect,
 * the allowed-hosts endpoint) so the rules cannot drift apart — a looser
 * validator on one path would be the way around the tighter one.
 *
 * Rejects rather than silently drops, because a declaration that never
 * matches looks to the operator like the binding is broken, and a
 * declaration that is too broad hands the credential to anyone who can
 * register a domain under it.
 */
export function normalizeAllowedHosts(hosts: readonly string[]): string[] {
  const cleaned: string[] = [];
  for (const raw of hosts) {
    const host = raw.trim().toLowerCase();
    if (!host) continue;
    if (host.includes('/') || host.includes(':') || host.includes(' ')) {
      throw new InvalidAllowedHostError(
        `"${raw}" is not a host. Give a bare hostname (api.example.com) or a dot-led domain ` +
          `suffix (.example.com), with no scheme, port or path.`,
      );
    }
    if (host.startsWith('.')) {
      if (host.slice(1).split('.').filter(Boolean).length < 2) {
        throw new InvalidAllowedHostError(
          `"${raw}" is too broad — a suffix must name a domain, not a TLD (use .example.com).`,
        );
      }
    } else if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(host)) {
      throw new InvalidAllowedHostError(`"${raw}" is not a valid hostname.`);
    }
    if (!cleaned.includes(host)) cleaned.push(host);
  }
  return cleaned;
}

/**
 * Lowercase, strip IPv6 brackets, strip a trailing dot (the root label —
 * `api.stripe.com.` and `api.stripe.com` resolve identically, so treating
 * them as different strings would be a bypass).
 */
function normalizeHost(host: string): string {
  return host
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
}
