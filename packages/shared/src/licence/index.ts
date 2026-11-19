import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

/**
 * STACK licence keys.
 *
 * A self-managed install runs the whole engine without a key. A key unlocks
 * the enterprise features: it says who it was issued to, until when, and which
 * features it covers, and it is signed with STACK's licence key (Ed25519) so
 * that an install can check it with no network and no account.
 *
 *   STACKLIC1.<payload>.<signature>
 *
 *   payload    base64url of the JSON claims below
 *   signature  base64url Ed25519 over  "stack-licence-v1\n" + <payload as written>
 *
 * The signed bytes are the payload text exactly as it appears in the key, so a
 * verifier never re-serialises anything. The public keys it trusts are built
 * in below, each under a `kid` the key names; a rotation adds a kid, it never
 * replaces one that issued keys are still using.
 *
 * Nothing here is a security boundary against the install's own operator: the
 * code runs on their machine. It is how a licence is honest about what it
 * grants, and how an expired or tampered key stops granting it.
 */

export const LICENCE_PREFIX = 'STACKLIC1';
const SIGNING_CONTEXT = 'stack-licence-v1\n';

/** The enterprise features a key can cover. */
export const LICENCE_FEATURES = [
  /** Single sign-on: identity provider configuration and sign-in through it. */
  'sso',
  /** User provisioning: members created from the identity provider's sign-in. */
  'provisioning',
  /** Member roles beyond owner and member (admin, read-only). */
  'roles',
  /** Security-monitoring connectors: events exported to a syslog or HTTP collector. */
  'siem',
  /** Signed evidence exports and compliance reports. */
  'evidence_exports',
  /** Partner and multi-tenant features. */
  'partners',
  /** Long-term-support versions: receive fixes on an older release line. */
  'lts',
] as const;
export type LicenceFeature = (typeof LICENCE_FEATURES)[number];

/** What each feature is called to a person. */
export const LICENCE_FEATURE_LABELS: Readonly<Record<LicenceFeature, string>> = {
  sso: 'single sign-on',
  provisioning: 'user provisioning',
  roles: 'member roles beyond owner and member',
  siem: 'security-monitoring connectors',
  evidence_exports: 'signed evidence exports and compliance reports',
  partners: 'partner and multi-tenant features',
  lts: 'long-term-support versions',
};

export interface LicenceClaims {
  v: 1;
  /** Which of STACK's licence keys signed it. */
  kid: string;
  /** Who it was issued to. */
  customer: string;
  issued_at: string;
  expires_at: string;
  features: LicenceFeature[];
  /**
   * The STACK account the key was issued to, when it was issued to one. STACK's
   * network services accept the key as that account's credential for live
   * detection rules and the hosted classifier, and bill the account.
   */
  operator_id?: string;
  /**
   * The key's own id. The network services refuse a key that has none, because
   * only an id can be revoked: the account the key was issued to can revoke it
   * before it expires, and the network checks the id against its list of
   * revoked keys on every request.
   */
  jti?: string;
}

export type LicenceInvalidReason =
  | 'malformed'
  | 'unknown_key'
  | 'bad_signature'
  | 'unsupported_version'
  | 'bad_claims'
  | 'not_yet_valid';

export type LicenceState =
  /** No key configured: the engine runs, the enterprise features are off. */
  | { status: 'none' }
  | { status: 'invalid'; reason: LicenceInvalidReason }
  | { status: 'expired'; claims: LicenceClaims }
  | { status: 'valid'; claims: LicenceClaims };

/**
 * STACK's licence public keys: kid to the raw 32-byte Ed25519 public key,
 * base64url. The private halves are held by STACK, never by an install.
 */
export const STACK_LICENCE_PUBLIC_KEYS: Readonly<Record<string, string>> = {
  'stack-licence-2026-1': '9mnQRGk4HfTtfsn0J2WdKG72hFqMx7nYh5KF3VQf6fw',
};

// RFC 8410: the DER prefix of an Ed25519 SubjectPublicKeyInfo, followed by the 32 key bytes.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function publicKeyFromRaw(raw: string) {
  const bytes = Buffer.from(raw, 'base64url');
  if (bytes.length !== 32) throw new Error('licence public key must be 32 bytes');
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, bytes]), format: 'der', type: 'spki' });
}

/** The shape of a key id: unguessable, so a revocation names exactly one key. */
export const LICENCE_KEY_ID = /^[A-Za-z0-9_-]{16,64}$/;

/** A licence issued more than this far in the future is not yet valid (clock skew allowance). */
const FUTURE_SKEW_MS = 24 * 60 * 60 * 1000;

function parseClaims(json: unknown): LicenceClaims | null {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return null;
  const c = json as Record<string, unknown>;
  if (c['v'] !== 1) return null;
  const { kid, customer, issued_at: issuedAt, expires_at: expiresAt, features } = c;
  if (typeof kid !== 'string' || kid.length === 0 || kid.length > 128) return null;
  if (typeof customer !== 'string' || customer.length === 0 || customer.length > 256) return null;
  if (typeof issuedAt !== 'string' || Number.isNaN(Date.parse(issuedAt))) return null;
  if (typeof expiresAt !== 'string' || Number.isNaN(Date.parse(expiresAt))) return null;
  if (!Array.isArray(features) || features.length > LICENCE_FEATURES.length) return null;
  const known = new Set<string>(LICENCE_FEATURES);
  // A feature this build does not know is not an error: a newer key may grant
  // features an older install has no code for. It is simply never granted.
  const granted = [...new Set(features.filter((f): f is LicenceFeature => typeof f === 'string' && known.has(f)))];
  if (features.some((f) => typeof f !== 'string')) return null;
  // Signed by STACK, so a malformed account is STACK's mistake: the key is refused rather than read without it.
  const operatorId = c['operator_id'];
  if (operatorId !== undefined && (typeof operatorId !== 'string' || !/^op_[A-Za-z0-9_-]{1,64}$/.test(operatorId))) return null;
  const jti = c['jti'];
  if (jti !== undefined && (typeof jti !== 'string' || !LICENCE_KEY_ID.test(jti))) return null;
  return {
    v: 1,
    kid,
    customer,
    issued_at: issuedAt,
    expires_at: expiresAt,
    features: granted,
    ...(operatorId !== undefined ? { operator_id: operatorId } : {}),
    ...(jti !== undefined ? { jti } : {}),
  };
}

export interface VerifyLicenceOptions {
  now?: Date;
  /** Trusted public keys by kid. Defaults to STACK's own; tests pass their own. */
  trustedKeys?: Readonly<Record<string, string>>;
}

/** Check a key: its shape, its signature under a trusted kid, and its dates. Never throws. */
export function verifyLicence(key: string | undefined | null, options: VerifyLicenceOptions = {}): LicenceState {
  const text = key?.trim();
  if (!text) return { status: 'none' };
  const parts = text.split('.');
  if (parts.length !== 3 || parts[0] !== LICENCE_PREFIX) {
    return { status: 'invalid', reason: parts[0]?.startsWith('STACKLIC') ? 'unsupported_version' : 'malformed' };
  }
  const [, payload, signature] = parts as [string, string, string];
  if (!/^[A-Za-z0-9_-]+$/.test(payload) || !/^[A-Za-z0-9_-]+$/.test(signature)) {
    return { status: 'invalid', reason: 'malformed' };
  }

  let rawClaims: unknown;
  try {
    rawClaims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return { status: 'invalid', reason: 'malformed' };
  }
  const kid = (rawClaims as { kid?: unknown } | null)?.kid;
  const trusted = options.trustedKeys ?? STACK_LICENCE_PUBLIC_KEYS;
  const rawKey = typeof kid === 'string' ? trusted[kid] : undefined;
  if (!rawKey) return { status: 'invalid', reason: 'unknown_key' };

  let signatureOk: boolean;
  try {
    signatureOk = cryptoVerify(
      null,
      Buffer.from(SIGNING_CONTEXT + payload, 'utf8'),
      publicKeyFromRaw(rawKey),
      Buffer.from(signature, 'base64url'),
    );
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) return { status: 'invalid', reason: 'bad_signature' };

  // Only now, with the signature good, is the content worth reading.
  const claims = parseClaims(rawClaims);
  if (!claims) return { status: 'invalid', reason: 'bad_claims' };
  const now = (options.now ?? new Date()).getTime();
  if (Date.parse(claims.issued_at) > now + FUTURE_SKEW_MS) return { status: 'invalid', reason: 'not_yet_valid' };
  if (Date.parse(claims.expires_at) <= now) return { status: 'expired', claims };
  return { status: 'valid', claims };
}

/** Does this state grant the feature right now? Expiry is read against `now`, not against when it was checked. */
export function licenceGrants(state: LicenceState, feature: LicenceFeature, now: Date = new Date()): boolean {
  return (
    state.status === 'valid'
    && Date.parse(state.claims.expires_at) > now.getTime()
    && state.claims.features.includes(feature)
  );
}
