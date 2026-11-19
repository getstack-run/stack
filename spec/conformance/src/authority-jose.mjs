// The JOSE parts the authority receiver suite needs, written against the
// specifications (RFC 7515 compact JWS, RFC 7516 compact JWE, RFC 7518
// ECDH-ES+A256KW and A256GCM) with node:crypto alone, so the kit judges an
// implementation with no library of its own between them.

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  randomBytes,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';

export const b64u = (value) => Buffer.from(typeof value === 'string' ? value : value).toString('base64url');
export const fromB64u = (text) => Buffer.from(text, 'base64url');
const json = (value) => b64u(JSON.stringify(value));

/** `sha256:` and 64 lowercase hexadecimal digits, the digest form every authority artefact uses. */
export const digest = (text) => `sha256:${createHash('sha256').update(text, 'utf8').digest('hex')}`;

// ─── Keys ───────────────────────────────────────────────────────────

/** An Ed25519 key pair from a one-byte seed, so a run is reproducible. */
export function ed25519FromSeed(seedByte, kid) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seedByte)]);
  const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const publicJwk = { ...createPublicKey(privateKey).export({ format: 'jwk' }), kid, alg: 'EdDSA' };
  return { kid, alg: 'EdDSA', privateKey, publicJwk, privateJwk: { ...privateKey.export({ format: 'jwk' }), kid, alg: 'EdDSA' } };
}

/** A P-256 key pair from a one-byte scalar seed (the public point is derived). */
export function p256FromSeed(seedByte, kid, alg = 'ES256') {
  const der = Buffer.concat([
    Buffer.from('3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420', 'hex'),
    Buffer.alloc(32, seedByte),
  ]);
  const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const publicJwk = { ...createPublicKey(privateKey).export({ format: 'jwk' }), kid, alg };
  return { kid, alg, privateKey, publicJwk, privateJwk: { ...privateKey.export({ format: 'jwk' }), kid, alg } };
}

/** Import a private JWK (Ed25519 or P-256) a harness was configured with. */
export function privateKeyFromJwk(jwk) {
  const { kid: _kid, alg: _alg, use: _use, ...rest } = jwk;
  return createPrivateKey({ key: rest, format: 'jwk' });
}

export function publicKeyFromJwk(jwk) {
  const { kid: _kid, alg: _alg, use: _use, d: _d, ...rest } = jwk;
  return createPublicKey({ key: rest, format: 'jwk' });
}

// ─── Compact JWS ────────────────────────────────────────────────────

/** Sign a compact JWS. `alg` is EdDSA or ES256; `privateKey` a node key object. */
export function signJws(header, payload, privateKey, alg = header.alg) {
  const signingInput = `${json(header)}.${typeof payload === 'string' ? b64u(payload) : json(payload)}`;
  const signature = alg === 'EdDSA'
    ? nodeSign(null, Buffer.from(signingInput), privateKey)
    : nodeSign('sha256', Buffer.from(signingInput), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${signingInput}.${b64u(signature)}`;
}

/** Split a compact JWS into its parts; null for anything that is not three base64url JSON-shaped parts. */
export function decodeJws(compact) {
  if (typeof compact !== 'string') return null;
  const parts = compact.split('.');
  if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]*$/.test(part)) || parts[0] === '' || parts[1] === '') return null;
  try {
    const header = JSON.parse(fromB64u(parts[0]).toString('utf8'));
    const payload = JSON.parse(fromB64u(parts[1]).toString('utf8'));
    if (!header || typeof header !== 'object' || !payload || typeof payload !== 'object') return null;
    return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: fromB64u(parts[2]) };
  } catch {
    return null;
  }
}

/** Verify a compact JWS signature with a public JWK for the stated algorithm. */
export function verifyJwsSignature(decoded, publicJwk, alg) {
  try {
    const key = publicKeyFromJwk(publicJwk);
    if (alg === 'EdDSA') return nodeVerify(null, Buffer.from(decoded.signingInput), key, decoded.signature);
    if (alg === 'ES256') return nodeVerify('sha256', Buffer.from(decoded.signingInput), { key, dsaEncoding: 'ieee-p1363' }, decoded.signature);
    return false;
  } catch {
    return false;
  }
}

// ─── Compact JWE: ECDH-ES+A256KW with A256GCM ───────────────────────

const lengthPrefixed = (buffer) => Buffer.concat([Buffer.from([(buffer.length >>> 24) & 255, (buffer.length >>> 16) & 255, (buffer.length >>> 8) & 255, buffer.length & 255]), buffer]);

/** RFC 7518 section 4.6.2 Concat KDF, one SHA-256 round (at most 256 bits of key). */
export function concatKdf(sharedSecret, algorithmId, keyBits) {
  const counter = Buffer.from([0, 0, 0, 1]);
  const info = Buffer.concat([
    lengthPrefixed(Buffer.from(algorithmId, 'ascii')),
    lengthPrefixed(Buffer.alloc(0)),
    lengthPrefixed(Buffer.alloc(0)),
    Buffer.from([(keyBits >>> 24) & 255, (keyBits >>> 16) & 255, (keyBits >>> 8) & 255, keyBits & 255]),
  ]);
  return createHash('sha256').update(Buffer.concat([counter, sharedSecret, info])).digest().subarray(0, keyBits / 8);
}

const AES_KW_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

/**
 * Build a compact JWE for a P-256 recipient key. The defaults are the only
 * combination the protocol accepts (`ECDH-ES+A256KW`, `A256GCM`); the options
 * let the suite build the deliberately wrong ones.
 *
 * @param {{
 *   plaintext: string, recipientPublicJwk: object, kid: string,
 *   alg?: string, enc?: string, cty?: string | null,
 *   ephemeral?: { privateKey: import('node:crypto').KeyObject },
 *   cek?: Buffer, iv?: Buffer, headerExtra?: object,
 * }} options
 */
export function encryptJwe(options) {
  const { plaintext, recipientPublicJwk, kid, alg = 'ECDH-ES+A256KW', enc = 'A256GCM', cty = 'JWT' } = options;
  const ephemeral = options.ephemeral ?? generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const epkJwk = createPublicKey(ephemeral.privateKey).export({ format: 'jwk' });
  const contentKeyBytes = enc === 'A128GCM' ? 16 : 32;
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: publicKeyFromJwk(recipientPublicJwk) });
  const header = { alg, enc, ...(cty ? { cty } : {}), kid, epk: { kty: 'EC', crv: 'P-256', x: epkJwk.x, y: epkJwk.y }, ...(options.headerExtra ?? {}) };
  const protectedHeader = json(header);
  let encryptedKey = Buffer.alloc(0);
  let cek;
  if (alg === 'ECDH-ES') {
    cek = concatKdf(shared, enc, contentKeyBytes * 8);
  } else {
    const keyBits = alg === 'ECDH-ES+A128KW' ? 128 : 256;
    const kek = concatKdf(shared, alg, keyBits);
    cek = options.cek ?? randomBytes(contentKeyBytes);
    const wrap = createCipheriv(keyBits === 128 ? 'id-aes128-wrap' : 'id-aes256-wrap', kek, AES_KW_IV);
    encryptedKey = Buffer.concat([wrap.update(cek), wrap.final()]);
  }
  const iv = options.iv ?? randomBytes(12);
  const cipher = createCipheriv(enc === 'A128GCM' ? 'aes-128-gcm' : 'aes-256-gcm', cek, iv);
  cipher.setAAD(Buffer.from(protectedHeader, 'ascii'));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return [protectedHeader, b64u(encryptedKey), b64u(iv), b64u(ciphertext), b64u(cipher.getAuthTag())].join('.');
}

/**
 * Open a compact JWE built for `ECDH-ES+A256KW` and `A256GCM` with the
 * recipient's private key. Returns `{ header, plaintext }` or throws. This is
 * the reference reading of the protocol: it refuses every other combination.
 */
export function decryptJwe(compact, recipientPrivateKey) {
  const parts = typeof compact === 'string' ? compact.split('.') : [];
  if (parts.length !== 5 || parts.some((part) => !/^[A-Za-z0-9_-]*$/.test(part))) throw new Error('not a compact JWE');
  const [protectedPart, encryptedKeyPart, ivPart, ciphertextPart, tagPart] = parts;
  const header = JSON.parse(fromB64u(protectedPart).toString('utf8'));
  if (header.alg !== 'ECDH-ES+A256KW' || header.enc !== 'A256GCM') throw new Error('unsupported JWE algorithms');
  if (header.zip !== undefined || header.crit !== undefined) throw new Error('unsupported JWE header');
  const epk = header.epk;
  if (!epk || epk.kty !== 'EC' || epk.crv !== 'P-256' || typeof epk.x !== 'string' || typeof epk.y !== 'string') throw new Error('bad ephemeral key');
  const shared = diffieHellman({ privateKey: recipientPrivateKey, publicKey: createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: epk.x, y: epk.y }, format: 'jwk' }) });
  const kek = concatKdf(shared, 'ECDH-ES+A256KW', 256);
  const unwrap = createDecipheriv('id-aes256-wrap', kek, AES_KW_IV);
  const cek = Buffer.concat([unwrap.update(fromB64u(encryptedKeyPart)), unwrap.final()]);
  if (cek.length !== 32) throw new Error('bad content key');
  const iv = fromB64u(ivPart);
  if (iv.length !== 12) throw new Error('bad iv');
  const tag = fromB64u(tagPart);
  if (tag.length !== 16) throw new Error('bad tag');
  const decipher = createDecipheriv('aes-256-gcm', cek, iv);
  decipher.setAAD(Buffer.from(protectedPart, 'ascii'));
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(fromB64u(ciphertextPart)), decipher.final()]).toString('utf8');
  return { header, plaintext };
}
