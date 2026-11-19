// The pure rules of single sign-on's verified domains (spec/sso-login/SPEC.md section 9.5): what a domain name is,
// where its proof record is and what it says, the domain of an e-mail address, and Microsoft Entra's own statement
// that an address's domain is verified. No lookup happens here; the service that does one is in @stack/vault.

import {
  SSO_DOMAIN_RECORD_LABEL,
  SSO_DOMAIN_RECORD_PREFIX,
} from '../constants/sso-login.js';

const LABEL = /^(?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
// A top-level label is letters (or an IDNA label), never all digits: that keeps an IPv4 address from passing as a name.
const TLD = /^(?:xn--[a-z0-9-]{1,59}|[a-z]{2,63})$/;

const NON_PUBLIC_TLDS: ReadonlySet<string> = new Set(['internal', 'local', 'localhost', 'arpa', 'onion', 'invalid']);

/**
 * The canonical form of a domain name, or null when it is not one a person's mail can be at: lower case, no trailing
 * dot, internationalised names in their ASCII (punycode) form, at least two labels, each label and the whole within
 * the DNS limits, and no address, port, path, user or space. The result is the form stored, looked up and compared.
 */
export function normalizeDomain(input: string): string | null {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim();
  // Anything that is not a bare name (a URL, an address with a port, a wildcard, a space) is refused before URL parsing
  // can make it into something else.
  if (trimmed.length === 0 || trimmed.length > 254 || /[\s/\\?#@:*%[\]]/.test(trimmed)) return null;
  let host: string;
  try {
    host = new URL(`http://${trimmed}`).hostname;
  } catch {
    return null;
  }
  const name = (host.endsWith('.') ? host.slice(0, -1) : host).toLowerCase();
  if (name.length === 0 || name.length > 253) return null;
  const labels = name.split('.');
  if (labels.length < 2) return null;
  if (!labels.every((label) => LABEL.test(label))) return null;
  const tld = labels[labels.length - 1]!;
  if (!TLD.test(tld)) return null;
  // Names that are never public (the local-only and special-use names of RFC 6761, 6762, 7686 and 8375): mail there is not mail a person's own domain receives, and a lookup of one would read
  // a private zone. `example` and `test` stay allowed: RFC 2606 keeps them out of the public DNS, so a lookup answers
  // nothing, and the specification's own examples and the conformance kit's fixtures (`*.example.test`) use them.
  if (NON_PUBLIC_TLDS.has(tld)) return null;
  return name;
}

/** The domain of an e-mail address in canonical form, or null when the address is not one that has a domain. */
export function emailDomainOf(email: string): string | null {
  if (typeof email !== 'string') return null;
  const trimmed = email.trim();
  const at = trimmed.lastIndexOf('@');
  if (at <= 0 || at === trimmed.length - 1) return null;
  // One at-sign only: an address with two (a quoted local part, or something made to read two ways) names no domain a
  // person's mail can be at, so it never counts as being at a verified one.
  if (trimmed.indexOf('@') !== at) return null;
  // The local part is not otherwise read; only the part after the at-sign names the domain.
  return normalizeDomain(trimmed.slice(at + 1));
}

/** The DNS name an account publishes its proof of a domain at. */
export function ssoDomainRecordName(domain: string): string {
  return `${SSO_DOMAIN_RECORD_LABEL}.${domain}`;
}

/** What the TXT record at that name must say for a token. */
export function ssoDomainRecordValue(token: string): string {
  return `${SSO_DOMAIN_RECORD_PREFIX}${token}`;
}

/**
 * Whether any TXT record of an answer is the proof of the token. A record may be split into several strings by the name
 * server; they are read as one. The comparison is on the whole record, not on a part of it, and a record that carries
 * the token with anything added, removed or changed does not count.
 */
export function txtRecordsProve(records: readonly (readonly string[])[], token: string): boolean {
  const wanted = ssoDomainRecordValue(token);
  return records.some((parts) => parts.join('').trim() === wanted);
}

const ENTRA_V2_ISSUER =
  /^https:\/\/(?:login\.microsoftonline\.com|login\.microsoftonline\.us|login\.partner\.microsoftonline\.cn)\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/v2\.0$/i;

/**
 * Microsoft Entra's optional ID token claim `xms_edov` ("email domain owner verified"): a JSON boolean that is true when
 * the address belongs to the tenant the user's account lives in and that tenant's administrator has verified the domain
 * (Microsoft Learn, "Optional claims reference"). It is read only when the issuer is one tenant of Entra's own v2
 * endpoints (`https://login.microsoftonline.com/{tenant id}/v2.0`, or the US government or China cloud's host) and the
 * token's `tid` is that same tenant, so a provider that is not Entra, or a token from another tenant, cannot say it. The
 * claim must be the boolean true (not a string, not a number), and an address must be present for it to speak of.
 */
export function entraVouchesForEmailDomain(claims: Readonly<Record<string, unknown>>, issuer: string): boolean {
  const match = ENTRA_V2_ISSUER.exec(issuer);
  if (!match) return false;
  const tenant = match[1]!.toLowerCase();
  const tid = claims['tid'];
  if (typeof tid !== 'string' || tid.toLowerCase() !== tenant) return false;
  if (typeof claims['email'] !== 'string' || claims['email'].trim() === '') return false;
  return claims['xms_edov'] === true;
}
