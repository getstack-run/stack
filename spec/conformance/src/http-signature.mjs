// HTTP Message Signatures (RFC 9421) as the Web Bot Auth profile uses them, written from the
// RFC and the Web Bot Auth drafts and independent of every STACK package, so that the kit can
// judge an implementation without trusting its libraries.
//
// What is here: the signature base of a request (derived components and header fields, one
// dictionary member of a header), the Ed25519 signature over it, the RFC 8941 structured field
// pieces the profile needs (strings, integers, inner lists, parameters), the JWK thumbprint of an
// Ed25519 key (RFC 7638 and RFC 8037 appendix A.3), and a parser for `Signature-Input` and
// `Signature`.

import { createHash, createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';

/** RFC 8941 section 3.3.3: a string is quoted, `\` and `"` escaped, printable ASCII only. */
export function sfString(value) {
  if (!/^[\x20-\x7e]*$/.test(value)) throw new Error('a structured field string is printable ASCII');
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/** The identifier of a covered component: `"@authority"`, `"signature-agent";key="sig1"`, `"@authority";req`. */
export function componentIdentifier({ name, key, req }) {
  return `${sfString(name)}${key === undefined ? '' : `;key=${sfString(key)}`}${req ? ';req' : ''}`;
}

/** The value of `@signature-params`: `("@authority" "@method");created=1;keyid="k"`. */
export function signatureParamsValue(components, params) {
  const serialised = params.map(({ name, value }) => {
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value)) throw new Error('a structured field integer is a whole number');
      return `;${name}=${value}`;
    }
    return `;${name}=${sfString(value)}`;
  });
  return `(${components.map(componentIdentifier).join(' ')})${serialised.join('')}`;
}

/** One member of a dictionary header, in its serialised form: `a="x", b=2` and `b` give `2`. */
export function dictionaryMember(header, key) {
  for (const raw of splitTopLevel(header, ',')) {
    const member = raw.trim();
    const eq = member.indexOf('=');
    if (eq <= 0) continue;
    if (member.slice(0, eq) === key) return member.slice(eq + 1).split(';')[0].trim();
  }
  throw new Error(`the header has no member ${key}`);
}

/** Split on a separator that is outside every quoted string. */
export function splitTopLevel(text, separator) {
  const parts = [];
  let current = '';
  let quoted = false;
  let depth = 0;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (quoted) {
      current += char;
      if (char === '\\') {
        i += 1;
        current += text[i] ?? '';
      } else if (char === '"') quoted = false;
      continue;
    }
    if (char === '"') quoted = true;
    else if (char === '(') depth += 1;
    else if (char === ')') depth -= 1;
    if (char === separator && depth === 0) {
      parts.push(current);
      current = '';
    } else current += char;
  }
  parts.push(current);
  return parts;
}

function componentValue(component, message) {
  const url = new URL(message.url);
  switch (component.name) {
    case '@authority': return url.host.toLowerCase();
    case '@method': return message.method.toUpperCase();
    case '@path': return url.pathname === '' ? '/' : url.pathname;
    case '@query': return url.search === '' ? '?' : url.search;
    case '@target-uri': return url.href;
    case '@scheme': return url.protocol.slice(0, -1).toLowerCase();
    default: {
      if (component.name.startsWith('@')) throw new Error(`unsupported component ${component.name}`);
      const value = message.headers[component.name];
      if (value === undefined) throw new Error(`the message has no ${component.name} header`);
      const trimmed = String(value).trim();
      return component.key === undefined ? trimmed : dictionaryMember(trimmed, component.key);
    }
  }
}

/**
 * RFC 9421 section 2.5. `paramsText` is the `@signature-params` value as it is written in
 * `Signature-Input` (what a verifier received), or as built by `signatureParamsValue`.
 * `message.headers` has lower-case names.
 */
export function signatureBaseFrom(components, paramsText, message) {
  const lines = components.map((component) => `${componentIdentifier(component)}: ${componentValue(component, message)}`);
  lines.push(`"@signature-params": ${paramsText}`);
  return lines.join('\n');
}

export function signatureBase(components, params, message) {
  return signatureBaseFrom(components, signatureParamsValue(components, params), message);
}

// ─── Keys ────────────────────────────────────────────────────────

export function privateKeyFromJwk({ d, x }) {
  return createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', d, x }, format: 'jwk' });
}

export function publicKeyFromX(x) {
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' });
}

/** RFC 7638 and RFC 8037 appendix A.3: SHA-256 of the required members in order, base64url. */
export function ed25519Thumbprint(x) {
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":${JSON.stringify(x)}}`;
  return createHash('sha256').update(canonical, 'utf8').digest('base64url');
}

export function signEd25519(base, privateKey) {
  return cryptoSign(null, Buffer.from(base, 'utf8'), privateKey).toString('base64');
}

export function verifyEd25519(base, signatureBase64, publicKey) {
  try {
    return cryptoVerify(null, Buffer.from(base, 'utf8'), publicKey, Buffer.from(signatureBase64, 'base64'));
  } catch {
    return false;
  }
}

// ─── Parsing ─────────────────────────────────────────────────────

/** Parse `;name=value;name="value";flag` into `[{ name, value }]` (integers as numbers, flags as true). */
function parseParams(text) {
  const params = [];
  for (const part of splitTopLevel(text, ';').slice(1)) {
    const eq = part.indexOf('=');
    if (eq < 0) {
      params.push({ name: part.trim(), value: true });
      continue;
    }
    const name = part.slice(0, eq).trim();
    const raw = part.slice(eq + 1).trim();
    if (raw.startsWith('"')) {
      if (!raw.endsWith('"') || raw.length < 2) throw new Error('unterminated structured field string');
      params.push({ name, value: raw.slice(1, -1).replace(/\\(["\\])/g, '$1') });
    } else if (/^-?\d+$/.test(raw)) params.push({ name, value: Number(raw) });
    else params.push({ name, value: raw });
  }
  return params;
}

/**
 * `Signature-Input`: a dictionary of inner lists. Returns `Map<label, { components, params, text }>`
 * where `text` is the `@signature-params` value exactly as received. Throws on a header it cannot read.
 */
export function parseSignatureInput(header) {
  const out = new Map();
  for (const member of splitTopLevel(header, ',')) {
    const trimmed = member.trim();
    if (trimmed === '') continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) throw new Error('a Signature-Input member has no label');
    const label = trimmed.slice(0, eq);
    const text = trimmed.slice(eq + 1);
    if (!text.startsWith('(')) throw new Error('a Signature-Input member is not an inner list');
    const close = text.indexOf(')', 1);
    // A component identifier may hold a `)` only inside a quoted string, which the profile never writes.
    if (close < 0) throw new Error('an unterminated inner list');
    const components = [];
    const inner = text.slice(1, close).trim();
    if (inner !== '') {
      for (const item of splitTopLevel(inner, ' ').filter((s) => s !== '')) {
        const [nameText, ...rest] = splitTopLevel(item, ';');
        if (!/^".*"$/.test(nameText)) throw new Error('a component name is a string');
        const component = { name: nameText.slice(1, -1) };
        for (const flag of rest) {
          if (flag === 'req') component.req = true;
          else if (flag.startsWith('key=')) component.key = flag.slice(5, -1);
          else throw new Error(`unsupported component parameter ${flag}`);
        }
        components.push(component);
      }
    }
    out.set(label, { components, params: parseParams(`x${text.slice(close + 1)}`), text });
  }
  return out;
}

/** `Signature`: `sig1=:BASE64:` members. Returns `Map<label, base64 text>`. */
export function parseSignature(header) {
  const out = new Map();
  for (const member of splitTopLevel(header, ',')) {
    const trimmed = member.trim();
    if (trimmed === '') continue;
    const match = /^([A-Za-z*][A-Za-z0-9_\-.*]*)=:([A-Za-z0-9+/]*={0,2}):$/.exec(trimmed);
    if (!match) throw new Error('a Signature member is not a byte sequence');
    out.set(match[1], match[2]);
  }
  return out;
}

export const paramOf = (params, name) => params.find((p) => p.name === name)?.value;
