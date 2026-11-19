// A reference signer, verifier and key directory for the Web Bot Auth profile
// (spec/web-bot-auth/SPEC.md), written from the specification with node:crypto and nothing
// else, in the way a small site or agent runtime would write them. It shares no code with the
// kit's own judge (`src/web-bot-auth.mjs`), so a pass means two independent readings agree.

import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto';

const DIRECTORY_PATH = '/.well-known/http-message-signatures-directory';
const MEDIA_TYPE = 'application/http-message-signatures-directory+json';
const TAG = 'web-bot-auth';
const DIRECTORY_TAG = 'http-message-signatures-directory';
const SKEW = 60;
const MAX_LIFETIME = 86_400;

const q = (s) => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
const thumbprint = (x) => createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest('base64url');
const privateOf = (jwk) => createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', d: jwk.d, x: jwk.x }, format: 'jwk' });
const publicOf = (x) => createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' });

/** The origin of a directory, or null when it is not an https origin without a path, query or credentials. */
function httpsOrigin(text) {
  try {
    const u = new URL(text);
    if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || (u.pathname !== '/' && u.pathname !== '')) return null;
    return u.origin;
  } catch {
    return null;
  }
}

function derived(name, { method, url }) {
  const u = new URL(url);
  if (name === '@authority') return u.host.toLowerCase();
  if (name === '@method') return method.toUpperCase();
  if (name === '@path') return u.pathname || '/';
  throw new Error(`unsupported component ${name}`);
}

// ─── The signer ──────────────────────────────────────────────────

/** A signer over one Ed25519 key: `{ sign(request), publicJwk }`, the shape the kit's `signer` handle takes. */
export function createReferenceSigner(jwk) {
  const keyid = thumbprint(jwk.x);
  return {
    publicJwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x },
    sign({ method, url, now, directoryOrigin }) {
      const created = Math.floor(now.getTime() / 1000);
      let origin = null;
      if (directoryOrigin !== null && directoryOrigin !== undefined) {
        origin = httpsOrigin(directoryOrigin);
        if (origin === null) throw new Error('a directory is an https origin');
      }
      const covered = ['"@authority"', '"@method"', '"@path"', ...(origin ? ['"signature-agent";key="sig1"'] : [])];
      const params = `(${covered.join(' ')});created=${created};keyid=${q(keyid)};alg="ed25519";expires=${created + 300};nonce=${q(randomBytes(64).toString('base64url'))};tag=${q(TAG)}`;
      const lines = [
        `"@authority": ${derived('@authority', { method, url })}`,
        `"@method": ${derived('@method', { method, url })}`,
        `"@path": ${derived('@path', { method, url })}`,
        ...(origin ? [`"signature-agent";key="sig1": ${q(origin)}`] : []),
        `"@signature-params": ${params}`,
      ];
      const signature = sign(null, Buffer.from(lines.join('\n'), 'utf8'), privateOf(jwk)).toString('base64');
      return {
        Signature: `sig1=:${signature}:`,
        'Signature-Input': `sig1=${params}`,
        ...(origin ? { 'Signature-Agent': `sig1=${q(origin)}` } : {}),
      };
    },
  };
}

// ─── The directory ───────────────────────────────────────────────

/**
 * What a server of the profile answers at the well-known path: `{ status, headers, body }`,
 * signed by `signingKey` (a key in `keys`) over the authority of the request.
 * @param {{ authority: string, keys: { x: string, d?: string, nbf: number, exp?: number }[], signingKey: { x: string, d: string }, now?: Date }} input
 */
export function referenceDirectoryResponse({ authority, keys, signingKey, now = new Date() }) {
  const created = Math.floor(now.getTime() / 1000);
  const body = JSON.stringify({
    keys: keys.map((k) => ({ kty: 'OKP', crv: 'Ed25519', x: k.x, kid: thumbprint(k.x), use: 'sig', nbf: k.nbf, ...(k.exp === undefined ? {} : { exp: k.exp }) })),
  });
  const params = `("@authority";req);created=${created};keyid=${q(thumbprint(signingKey.x))};alg="ed25519";expires=${created + 86_400};tag=${q(DIRECTORY_TAG)}`;
  const base = `"@authority";req: ${authority.toLowerCase()}\n"@signature-params": ${params}`;
  return {
    status: 200,
    headers: {
      'content-type': MEDIA_TYPE,
      'cache-control': 'public, max-age=300',
      'signature-input': `sig1=${params}`,
      signature: `sig1=:${sign(null, Buffer.from(base, 'utf8'), privateOf(signingKey)).toString('base64')}:`,
    },
    body,
  };
}

// ─── The verifier ────────────────────────────────────────────────

/** Read `label=(...)params` members of Signature-Input, quote-aware. */
function members(header) {
  const out = [];
  let depth = 0;
  let quoted = false;
  let current = '';
  for (let i = 0; i < header.length; i += 1) {
    const c = header[i];
    if (quoted) {
      current += c;
      if (c === '\\') current += header[++i] ?? '';
      else if (c === '"') quoted = false;
      continue;
    }
    if (c === '"') quoted = true;
    if (c === '(') depth += 1;
    if (c === ')') depth -= 1;
    if (c === ',' && depth === 0) {
      out.push(current.trim());
      current = '';
    } else current += c;
  }
  if (current.trim()) out.push(current.trim());
  return out;
}

function readParams(text) {
  const out = {};
  for (const m of text.matchAll(/;([a-z]+)=("(?:[^"\\]|\\.)*"|-?\d+)/g)) out[m[1]] = m[2].startsWith('"') ? m[2].slice(1, -1).replace(/\\(["\\])/g, '$1') : Number(m[2]);
  return out;
}

/** Parse one `Signature-Input` member: the components (as written), the parameters and the raw `@signature-params`. */
function parseMember(member) {
  const m = /^([A-Za-z][\w.*-]*)=(\(([^)]*)\)(.*))$/.exec(member);
  if (!m) throw new Error('unreadable Signature-Input member');
  const components = m[3].trim() === '' ? [] : m[3].trim().split(/ +/);
  return { label: m[1], raw: m[2], components, params: readParams(m[4]) };
}

function signatureBytes(header, label) {
  for (const member of members(header)) {
    const m = /^([A-Za-z][\w.*-]*)=:([A-Za-z0-9+/]*={0,2}):$/.exec(member);
    if (!m) throw new Error('unreadable Signature member');
    if (m[1] === label) return Buffer.from(m[2], 'base64');
  }
  return null;
}

/**
 * A verifier with a directory cache that honours `max-age` against the clock it is given.
 * Returns the `verify` function of the kit's `verifier` handle.
 * @param {{ remember?: boolean }} [options] `remember: false` turns the nonce memory off
 */
export function createReferenceVerifier(options = {}) {
  const seen = new Map();
  const cache = new Map();

  async function directoryOf(origin, fetchImpl, now) {
    const cached = cache.get(origin);
    if (cached && cached.until > now) return cached.keys;
    const response = await fetchImpl(`${origin}${DIRECTORY_PATH}`);
    if (response.status !== 200) throw new Error('the directory did not answer 200');
    const body = await response.text();
    const parsed = JSON.parse(body);
    if (!Array.isArray(parsed.keys) || parsed.keys.length === 0) throw new Error('no keys');
    const headers = Object.fromEntries([...response.headers].map(([k, v]) => [k.toLowerCase(), v]));
    // The directory is signed by a key it lists, over the host it was asked at.
    const input = parseMember(members(headers['signature-input'] ?? '')[0] ?? '');
    if (input.params.tag !== DIRECTORY_TAG || input.params.alg !== 'ed25519') throw new Error('not a directory signature');
    if (input.raw.slice(0, input.raw.indexOf(')') + 1) !== '("@authority";req)') throw new Error('the directory signature covers the wrong components');
    const signer = parsed.keys.find((k) => k.x && thumbprint(k.x) === input.params.keyid);
    if (!signer) throw new Error('the directory is signed by a key it does not list');
    const base = `"@authority";req: ${new URL(origin).host.toLowerCase()}\n"@signature-params": ${input.raw}`;
    const bytes = signatureBytes(headers.signature ?? '', input.label);
    if (!bytes || !verify(null, Buffer.from(base, 'utf8'), publicOf(signer.x), bytes)) throw new Error('the directory signature does not verify');
    const maxAge = Number(/max-age=(\d+)/.exec(headers['cache-control'] ?? '')?.[1] ?? 0);
    cache.set(origin, { keys: parsed.keys, until: now + maxAge });
    return parsed.keys;
  }

  return async function verifyRequest({ method, url, headers, now, fetch: fetchImpl }) {
    const h = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
    if (!h['signature-input'] || !h.signature) return false;
    let chosen;
    try {
      chosen = members(h['signature-input']).map(parseMember).find((m) => m.params.tag === TAG);
    } catch {
      return false;
    }
    if (!chosen) return false;
    const { params, components } = chosen;
    if (params.alg !== undefined && params.alg !== 'ed25519') return false;
    if (!Number.isInteger(params.created) || !Number.isInteger(params.expires) || typeof params.keyid !== 'string') return false;
    if (now >= params.expires || params.created > now + SKEW || params.expires - params.created > MAX_LIFETIME || params.expires <= params.created) return false;
    if (!components.includes('"@authority"')) return false;

    // Rebuild the base from the request as received.
    const lines = [];
    let origin = null;
    try {
      for (const c of components) {
        const name = /^"([^"]+)"/.exec(c)?.[1];
        if (name === '@authority' || name === '@method' || name === '@path') lines.push(`${c}: ${derived(name, { method, url })}`);
        else if (name === 'signature-agent' && c === `"signature-agent";key="${chosen.label}"`) {
          const value = new RegExp(`(?:^|,\\s*)${chosen.label}=("(?:[^"\\\\]|\\\\.)*")`).exec(h['signature-agent'] ?? '')?.[1];
          if (!value) return false;
          lines.push(`${c}: ${value}`);
          origin = httpsOrigin(value.slice(1, -1));
        } else return false;
      }
    } catch {
      return false;
    }
    if (components.some((c) => c.startsWith('"signature-agent"')) && origin === null) return false;
    // Without a covered Signature-Agent the key has no home here: this verifier needs a directory.
    if (origin === null) return false;
    lines.push(`"@signature-params": ${chosen.raw}`);

    let keys;
    try {
      keys = await directoryOf(origin, fetchImpl, now);
    } catch {
      return false;
    }
    const key = keys.find((k) => k.x && thumbprint(k.x) === params.keyid);
    if (!key) return false;
    if (typeof key.nbf === 'number' && params.created + SKEW < key.nbf) return false;
    if (typeof key.exp === 'number' && params.created >= key.exp) return false;
    let bytes;
    try {
      bytes = signatureBytes(h.signature, chosen.label);
    } catch {
      return false;
    }
    if (!bytes || !verify(null, Buffer.from(lines.join('\n'), 'utf8'), publicOf(key.x), bytes)) return false;

    if (options.remember !== false && typeof params.nonce === 'string') {
      const id = `${params.keyid}:${params.nonce}`;
      for (const [k, until] of seen) if (until <= now) seen.delete(k);
      if (seen.has(id)) return false;
      seen.set(id, params.expires);
    }
    return true;
  };
}
