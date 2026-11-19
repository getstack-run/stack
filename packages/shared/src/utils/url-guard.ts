import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'ip6-localhost',
  'ip6-loopback',
  'broadcasthost',
  'fly-local-6pn',
  'metadata.google.internal',
  'metadata',
]);

const BLOCKED_HOSTNAME_SUFFIXES = ['.local', '.internal', '.localhost'];

function ipv4ToLong(ip: string): number {
  const parts = ip.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return -1;
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
}

function isBlockedIPv4(ip: string): boolean {
  const long = ipv4ToLong(ip);
  if (long < 0) return true;
  const inRange = (start: string, maskBits: number) => {
    const s = ipv4ToLong(start);
    const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
    return (long & mask) === (s & mask);
  };
  return (
    inRange('0.0.0.0', 8) ||
    inRange('10.0.0.0', 8) ||
    inRange('100.64.0.0', 10) ||
    inRange('127.0.0.0', 8) ||
    inRange('169.254.0.0', 16) ||
    inRange('172.16.0.0', 12) ||
    inRange('192.0.0.0', 24) ||
    inRange('192.0.2.0', 24) ||
    inRange('192.88.99.0', 24) ||
    inRange('192.168.0.0', 16) ||
    inRange('198.18.0.0', 15) ||
    inRange('198.51.100.0', 24) ||
    inRange('203.0.113.0', 24) ||
    inRange('224.0.0.0', 4) ||
    inRange('240.0.0.0', 4)
  );
}

function isBlockedIPv6(ip: string): boolean {
  if (ip.includes('%')) return true;
  // URL canonicalization handles expanded and dotted IPv4-mapped forms.
  const normalized = new URL(`http://[${ip}]/`).hostname.slice(1, -1);
  const words = normalized.split(':');
  const first = parseInt(words[0] || '0', 16);
  const second = parseInt(words[1] || '0', 16);
  // Only global unicast 2000::/3 is eligible. This also excludes mapped,
  // compatible, NAT64, link/site-local, multicast and scoped addresses.
  if ((first & 0xe000) !== 0x2000) return true;
  // IANA special-use ranges: protocol assignments, documentation, 6to4.
  return (first === 0x2001 && (second < 0x200 || second === 0xdb8)) ||
    first === 0x2002 || (first === 0x3fff && second < 0x1000);
}

export function isBlockedIp(ip: string): boolean {
  const kind = isIP(ip);
  if (kind === 4) return isBlockedIPv4(ip);
  if (kind === 6) return isBlockedIPv6(ip);
  return true;
}

export interface UrlGuardOptions {
  allowedProtocols?: string[];
}

export interface PublicUrlResolution {
  url: URL;
  addresses: Array<{ address: string; family: number }>;
}

export class UnsafeUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsafeUrlError';
  }
}

export function parsePublicUrl(
  rawUrl: string,
  options: UrlGuardOptions = {},
): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new UnsafeUrlError('Invalid URL');
  }

  const allowed = options.allowedProtocols ?? ['https:', 'http:'];
  if (!allowed.includes(url.protocol)) {
    throw new UnsafeUrlError(`Protocol ${url.protocol} not allowed`);
  }

  if (url.username || url.password) throw new UnsafeUrlError('URL credentials are not allowed');
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (!hostname) throw new UnsafeUrlError('URL has no hostname');

  if (BLOCKED_HOSTNAMES.has(hostname)) {
    throw new UnsafeUrlError(`Host ${hostname} is not allowed`);
  }
  for (const suffix of BLOCKED_HOSTNAME_SUFFIXES) {
    if (hostname.endsWith(suffix)) {
      throw new UnsafeUrlError(`Host ${hostname} is not allowed`);
    }
  }

  if (isIP(hostname)) {
    if (isBlockedIp(hostname)) {
      throw new UnsafeUrlError(`IP ${hostname} is not allowed`);
    }
  }
  return url;
}

export async function resolvePublicUrl(rawUrl: string, options: UrlGuardOptions = {}): Promise<PublicUrlResolution> {
  const url = parsePublicUrl(rawUrl, options);
  const hostname = url.hostname.replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (isIP(hostname)) return { url, addresses: [{ address: hostname, family: isIP(hostname) }] };

  let timer: ReturnType<typeof setTimeout> | undefined;
  const addresses = await Promise.race([
    lookup(hostname, { all: true }),
    new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new UnsafeUrlError('DNS resolution timed out')), 5_000);
      timer.unref();
    }),
  ]).catch(() => {
    throw new UnsafeUrlError(`Cannot resolve host ${hostname}`);
  }).finally(() => clearTimeout(timer));
  if (!addresses.length) throw new UnsafeUrlError(`Cannot resolve host ${hostname}`);
  for (const addr of addresses) {
    if (isBlockedIp(addr.address)) {
      throw new UnsafeUrlError(`Host ${hostname} resolves to a non-public address`);
    }
  }
  return { url, addresses };
}

/** Validation only. Outbound requests must use publicFetch to pin this check. */
export async function assertPublicUrl(rawUrl: string, options: UrlGuardOptions = {}): Promise<URL> {
  return (await resolvePublicUrl(rawUrl, options)).url;
}
