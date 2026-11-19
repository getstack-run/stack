// Helpers shared by the identity suites (agent sign-in, agent keys, workload identity, OAuth): Ed25519 keys,
// compact JWS signing and decoding, and a JSON HTTP call that never throws on a non-2xx answer.

import { createHmac, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign } from 'node:crypto';

export const b64url = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');

/** A fresh Ed25519 key pair, with its JWKs. */
export function newEd25519() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateJwk = privateKey.export({ format: 'jwk' });
  const publicJwk = publicKey.export({ format: 'jwk' });
  return { privateKey, publicKey, privateJwk, publicJwk };
}

/** An Ed25519 key pair from a private JWK. */
export function ed25519FromJwk(privateJwk) {
  const privateKey = createPrivateKey({ key: privateJwk, format: 'jwk' });
  const publicKey = createPublicKey(privateKey);
  return { privateKey, publicKey, privateJwk, publicJwk: publicKey.export({ format: 'jwk' }) };
}

/** A compact JWS signed with EdDSA. `header` and `payload` are objects. */
export function signEdDsa(header, payload, privateKey) {
  const input = `${b64url(header)}.${b64url(payload)}`;
  return `${input}.${sign(null, Buffer.from(input), privateKey).toString('base64url')}`;
}

/** A compact JWS with an HMAC-SHA256 signature over `secret`. */
export function signHs256(header, payload, secret) {
  const input = `${b64url(header)}.${b64url(payload)}`;
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
}

/** The header and payload of a compact JWS, without checking anything. */
export function decodeCompact(token) {
  const [h, p] = String(token).split('.');
  return { header: JSON.parse(Buffer.from(h, 'base64url').toString('utf8')), payload: JSON.parse(Buffer.from(p, 'base64url').toString('utf8')) };
}

export const randomToken = (bytes = 16) => randomBytes(bytes).toString('base64url');

export const unixNow = () => Math.floor(Date.now() / 1000);

/** A JSON request. Never throws on a status; returns `{ status, headers, body, text }`, with `body` parsed when it is JSON. */
export async function callJson(base, path, { method = 'GET', headers = {}, body, rawBody, form, timeoutMs = 15_000, redirect = 'manual', waitOnRateLimit = true } = {}) {
  const init = { method, headers: { ...headers }, redirect };
  if (form) {
    init.headers['content-type'] = 'application/x-www-form-urlencoded';
    init.body = new URLSearchParams(form).toString();
  } else if (body !== undefined) {
    init.headers['content-type'] = init.headers['content-type'] ?? 'application/json';
    init.body = JSON.stringify(body);
  } else if (rawBody !== undefined) {
    init.body = rawBody;
  }
  // A server limits how often one caller may use some routes (enrollment, issuing and verifying a Passport). The
  // limit is part of the interface, so the kit waits for the window it is told about and asks again.
  let response;
  for (let attempt = 0; ; attempt++) {
    response = await fetch(`${base}${path}`, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    if (response.status !== 429 || !waitOnRateLimit || attempt >= 5) break;
    const after = Number(response.headers.get('retry-after'));
    // A window of more than two minutes is not one to wait for (an hourly limit): the caller sees the 429.
    if (Number.isFinite(after) && after > 120) break;
    await response.arrayBuffer();
    await new Promise((resolve) => setTimeout(resolve, (Number.isFinite(after) && after > 0 ? after : 20) * 1000 + 250));
  }
  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  return { status: response.status, headers: response.headers, body: parsed, text };
}

/** The code of an API error envelope, if the body is one. */
export const errorCode = (response) => response.body?.error?.code;
