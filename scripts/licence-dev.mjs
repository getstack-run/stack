#!/usr/bin/env node
/**
 * DEVELOPMENT ONLY. Issues licence keys for tests and for rehearsing an
 * install. It is not a licence-issuing service: STACK's real licence signing
 * key never lives in this repository, and nothing here reaches it.
 *
 *   node scripts/licence-dev.mjs keygen  --out <private-key.pem>
 *       Writes a new Ed25519 private key (mode 0600) and prints the public half
 *       in the form `STACK_LICENCE_PUBLIC_KEYS` takes.
 *
 *   node scripts/licence-dev.mjs sign --key <private-key.pem> --kid <kid> \
 *        --customer "<name>" --expires 2027-01-01 --features sso,roles,siem [--operator op_...]
 *       Prints a licence key, which carries a fresh id (`jti`). `--issued` defaults to now.
 *
 *   node scripts/licence-dev.mjs verify <key> --kid <kid> --public <base64url>
 *       Checks a key against a public key you name (not STACK's).
 *
 * To check a key against STACK's own built-in keys, use the install's CLI:
 *   stack-engine licence verify <key>
 */
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const FEATURES = ['sso', 'provisioning', 'roles', 'siem', 'evidence_exports', 'partners', 'lts'];
const CONTEXT = 'stack-licence-v1\n';
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function option(args, name) {
  const at = args.indexOf(`--${name}`);
  return at >= 0 ? args[at + 1] : undefined;
}

function fail(message) {
  console.error(message);
  process.exit(2);
}

const [command, ...args] = process.argv.slice(2);

if (command === 'keygen') {
  const out = option(args, 'out');
  if (!out) fail('keygen needs --out <file>');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  writeFileSync(out, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(SPKI_PREFIX.length);
  console.log(`public key (base64url): ${raw.toString('base64url')}`);
} else if (command === 'sign') {
  const keyFile = option(args, 'key');
  const kid = option(args, 'kid');
  const customer = option(args, 'customer');
  const expires = option(args, 'expires');
  const features = (option(args, 'features') ?? '').split(',').filter(Boolean);
  const operatorId = option(args, 'operator');
  if (!keyFile || !kid || !customer || !expires) fail('sign needs --key, --kid, --customer and --expires');
  for (const feature of features) if (!FEATURES.includes(feature)) fail(`unknown feature: ${feature}`);
  const expiresAt = new Date(expires);
  if (Number.isNaN(expiresAt.getTime())) fail('--expires is not a date');
  const issuedAt = option(args, 'issued') ? new Date(option(args, 'issued')) : new Date();
  const claims = {
    v: 1,
    kid,
    customer,
    issued_at: issuedAt.toISOString(),
    expires_at: expiresAt.toISOString(),
    features,
    ...(operatorId ? { operator_id: operatorId } : {}),
    // Every key carries its own id, which is what lets the account it was issued to revoke it.
    jti: `lk_${randomBytes(12).toString('base64url')}`,
  };
  const payload = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  const signature = sign(null, Buffer.from(CONTEXT + payload, 'utf8'), createPrivateKey(readFileSync(keyFile)));
  console.log(`STACKLIC1.${payload}.${signature.toString('base64url')}`);
} else if (command === 'verify') {
  const key = args[0];
  const kid = option(args, 'kid');
  const pub = option(args, 'public');
  if (!key || !kid || !pub) fail('verify needs <key> --kid <kid> --public <base64url>');
  const [prefix, payload, signature] = key.split('.');
  if (prefix !== 'STACKLIC1' || !payload || !signature) fail('not a STACKLIC1 key');
  const publicKey = createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, Buffer.from(pub, 'base64url')]),
    format: 'der',
    type: 'spki',
  });
  const ok = verify(null, Buffer.from(CONTEXT + payload, 'utf8'), publicKey, Buffer.from(signature, 'base64url'));
  console.log(ok ? JSON.stringify(JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')), null, 2) : 'signature does not verify');
  process.exit(ok ? 0 : 1);
} else {
  fail('usage: licence-dev.mjs keygen | sign | verify (see the header of this file)');
}
