import { createLocalJWKSet, createRemoteJWKSet, errors as joseErrors, importJWK, jwtVerify, type JWK, type JWTPayload } from 'jose';
import { installKeyThumbprint, passportDigest, type InstallPublicJwk } from './network-install-key.js';

// Offline checks of everything STACK signs for the network: a countersignature
// over a passport, the signed revocation list, a "STACK-verified" statement and
// the detection rule set. Public-key crypto only: nothing here calls the STACK
// API except an optional `jwksUrl` fetch of STACK's public keys.
//
// What no offline check can tell you is whether a key, an install, an agent or a
// passport was revoked after the token was issued. A countersignature lives 15
// minutes by default for that reason; for a live answer call
// `stack.network.verify(...)` or `stack.network.verified(...)`, or follow the
// signed revocation list.

/** Where to get STACK's public keys: exactly one of these. */
export interface NetworkKeySource {
  /** The keys, as served by `GET /v1/network/jwks.json`: a JWKS or its `keys`. */
  jwks?: { keys: JWK[] } | JWK[];
  /** The URL of `/v1/network/jwks.json`; fetched once and cached per process. */
  jwksUrl?: string;
  /** A single pre-fetched public key, for fully air-gapped checks. */
  publicJwk?: JWK;
}

export interface VerifyNetworkOptions extends NetworkKeySource {
  /** The clock to check expiry against. Defaults to now. */
  now?: Date;
}

export type NetworkVerificationReason =
  | 'invalid'
  | 'expired'
  | 'digest_mismatch'
  | 'passport_invalid'
  | 'passport_expired'
  | 'revision_too_old';

/** A network object did not check out. `reason` says why in a few fixed words. */
export class NetworkVerificationError extends Error {
  constructor(readonly reason: NetworkVerificationReason, message: string) {
    super(message);
    this.name = 'NetworkVerificationError';
  }
}

const ISSUER = 'getstack.run';

const KINDS = {
  countersignature: { typ: 'stack-countersignature+jwt', aud: 'stack:countersignature' },
  revocationList: { typ: 'stack-revocation-list+jwt', aud: 'stack:revocation-list' },
  verified: { typ: 'stack-verified+jwt', aud: 'stack:verified' },
  detectionRules: { typ: 'stack-detection-rules+jwt', aud: 'stack:detection-rules' },
} as const;
type Kind = keyof typeof KINDS;

const remoteCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function keyResolver(source: NetworkKeySource) {
  const given = [source.jwks, source.jwksUrl, source.publicJwk].filter((v) => v !== undefined).length;
  if (given !== 1) throw new Error('Pass exactly one of jwks, jwksUrl or publicJwk');
  if (source.jwksUrl) {
    let remote = remoteCache.get(source.jwksUrl);
    if (!remote) {
      remote = createRemoteJWKSet(new URL(source.jwksUrl));
      remoteCache.set(source.jwksUrl, remote);
    }
    return remote;
  }
  const keys = source.publicJwk ? [source.publicJwk] : Array.isArray(source.jwks) ? source.jwks : source.jwks!.keys;
  return createLocalJWKSet({ keys });
}

async function verifyStatement(kind: Kind, token: string, options: VerifyNetworkOptions): Promise<JWTPayload> {
  const { typ, aud } = KINDS[kind];
  try {
    const { payload } = await jwtVerify(token, keyResolver(options), {
      algorithms: ['EdDSA'],
      typ,
      audience: aud,
      issuer: ISSUER,
      clockTolerance: 5,
      ...(options.now ? { currentDate: options.now } : {}),
    });
    return payload;
  } catch (error) {
    if (error instanceof joseErrors.JWTExpired) throw new NetworkVerificationError('expired', 'The token has expired');
    if (error instanceof Error && /exactly one of/.test(error.message)) throw error;
    throw new NetworkVerificationError('invalid', 'The token is not a valid signed object from STACK');
  }
}

// ─── countersigned passports ─────────────────────────────────────────

export interface CountersignatureClaims {
  iss: string;
  aud: string;
  /** The install id. */
  sub: string;
  iat: number;
  exp: number;
  jti: string;
  cs: {
    v: 1;
    install: string;
    /** The STACK account that registered the install. Opaque. */
    owner: string;
    /** Whether STACK had verified the owner's identity when it issued this. Informational. */
    owner_verified: boolean;
    key: { kid: string; jwk: InstallPublicJwk };
    passport: { alg: 'sha256'; digest: string; jti?: string; agent?: string };
  };
}

export interface VerifiedCountersignedPassport {
  countersignature: CountersignatureClaims;
  /** The passport's own claims, signature-checked against the install's key. */
  passport: JWTPayload;
  /** When the countersignature stops being good, as a Date. */
  validUntil: Date;
}

/**
 * Check a passport an install issued and the countersignature STACK made over it,
 * offline: STACK's signature on the countersignature (type, audience, issuer,
 * expiry), that the passport hashes to the digest it names, and the install's
 * signature on the passport with the key the countersignature carries.
 *
 * It tells you STACK saw this install's key proved by its holder, the owner who
 * registered it, and this passport digest, when it issued the countersignature.
 * It cannot tell you that the key, the install, the agent or the passport was
 * revoked since: see the note at the top of this file.
 */
export async function verifyCountersignedPassport(
  input: { countersignature: string; passport: string } & VerifyNetworkOptions,
): Promise<VerifiedCountersignedPassport> {
  const payload = await verifyStatement('countersignature', input.countersignature, input);
  const claims = payload as unknown as CountersignatureClaims;
  const cs = claims.cs;
  if (!cs || cs.v !== 1 || cs.passport?.alg !== 'sha256' || cs.key?.jwk?.crv !== 'Ed25519') {
    throw new NetworkVerificationError('invalid', 'The countersignature is not in a known format');
  }
  if (installKeyThumbprint(cs.key.jwk) !== cs.key.kid) {
    throw new NetworkVerificationError('invalid', 'The countersignature names a key id that is not its key');
  }
  if (passportDigest(input.passport) !== cs.passport.digest) {
    throw new NetworkVerificationError('digest_mismatch', 'This passport is not the one the countersignature covers');
  }
  try {
    const key = await importJWK(cs.key.jwk as JWK, 'EdDSA');
    const verified = await jwtVerify(input.passport, key, {
      algorithms: ['EdDSA'],
      clockTolerance: 5,
      ...(input.now ? { currentDate: input.now } : {}),
    });
    return { countersignature: claims, passport: verified.payload, validUntil: new Date(claims.exp * 1000) };
  } catch (error) {
    if (error instanceof joseErrors.JWTExpired) throw new NetworkVerificationError('passport_expired', 'The passport has expired');
    throw new NetworkVerificationError('passport_invalid', "The passport is not signed by the install's key");
  }
}

// ─── the revocation list ─────────────────────────────────────────────

export interface RevocationEntry {
  seq: number;
  id: string;
  kind: 'passport' | 'agent' | 'key' | 'install';
  /** passport: its digest; agent: its id; key: its thumbprint; install: its id. */
  subject: string;
  /** The install the subject belongs to. Every entry names one: match on the subject AND the install (`revocationCovers`). */
  install: string;
  reason: string;
  by: 'install' | 'owner' | 'stack';
  at: string;
}

export interface RevocationList {
  /** The cursor this page started after. */
  after: number;
  /** The highest sequence number STACK had published when it signed this. */
  head: number;
  /** Where the next page starts, or null when this page reached the end. */
  next: number | null;
  entries: RevocationEntry[];
  /** Where to resume: `next` when there is one, else `head`. */
  resumeFrom: number;
  expiresAt: Date;
}

/**
 * What a counterparty knows about a countersigned passport it holds, from the countersignature's `cs` claims:
 * the install, the install's key id, the passport digest and the agent the install named, if any.
 */
export interface CountersignedSubject {
  install: string;
  keyId?: string;
  passportDigest?: string;
  agent?: string;
}

/**
 * The first entry of a verified revocation list that covers a countersigned passport, or undefined. An entry
 * matches only on the subject AND the install: a digest or an agent name that matches while the install is
 * another's (or missing) is somebody else's revocation and is ignored, so one company can never have another's
 * agent refused. An entry of kind `install` names the install itself; `key`, the install's key id.
 */
export function revocationCovers(entries: readonly RevocationEntry[], held: CountersignedSubject): RevocationEntry | undefined {
  return entries.find((entry) => {
    if (typeof entry.install !== 'string' || entry.install !== held.install) return false;
    switch (entry.kind) {
      case 'passport':
        return held.passportDigest !== undefined && entry.subject === held.passportDigest;
      case 'agent':
        return held.agent !== undefined && entry.subject === held.agent;
      case 'key':
        return held.keyId !== undefined && entry.subject === held.keyId;
      case 'install':
        return entry.subject === held.install;
      default:
        return false;
    }
  });
}

/** Check a signed revocation list, from the pollable endpoint or a webhook, and read its entries. */
export async function verifyRevocationList(list: string, options: VerifyNetworkOptions): Promise<RevocationList> {
  const payload = await verifyStatement('revocationList', list, options);
  const rl = (payload as unknown as { rl?: { v: number; after: number; head: number; next: number | null; entries: RevocationEntry[] } }).rl;
  if (!rl || rl.v !== 1 || !Array.isArray(rl.entries)) throw new NetworkVerificationError('invalid', 'The list is not in a known format');
  return { after: rl.after, head: rl.head, next: rl.next, entries: rl.entries, resumeFrom: rl.next ?? rl.head, expiresAt: new Date((payload.exp ?? 0) * 1000) };
}

// ─── the "STACK-verified" statement ──────────────────────────────────

export interface VerifiedStatement {
  /** `passport:<digest>` or `agent:<install>:<agent>`. */
  subject: string;
  /** Only `live` earns the mark. */
  status: 'live' | 'expired' | 'revoked';
  mark: 'STACK-verified';
  install: string;
  countersignature: string;
  /** When the countersignature behind it stops being good. */
  validUntil: Date;
  passportDigest: string;
  issuedAt: Date;
  /** A statement is a five-minute snapshot: show nothing older. */
  expiresAt: Date;
}

export async function verifyVerifiedStatement(statement: string, options: VerifyNetworkOptions): Promise<VerifiedStatement> {
  const payload = await verifyStatement('verified', statement, options);
  const vs = (payload as unknown as { vs?: { v: number; mark: 'STACK-verified'; status: VerifiedStatement['status']; install: string; countersignature: string; valid_until: string; passport_digest: string } }).vs;
  if (!vs || vs.v !== 1) throw new NetworkVerificationError('invalid', 'The statement is not in a known format');
  return {
    subject: String(payload.sub), status: vs.status, mark: vs.mark, install: vs.install, countersignature: vs.countersignature,
    validUntil: new Date(vs.valid_until), passportDigest: vs.passport_digest,
    issuedAt: new Date((payload.iat ?? 0) * 1000), expiresAt: new Date((payload.exp ?? 0) * 1000),
  };
}

// ─── detection rules ─────────────────────────────────────────────────

export interface DetectionRule {
  id: string;
  severity: 'warning' | 'critical';
  /** An ECMAScript regular expression: `new RegExp(pattern, flags)`. */
  pattern: string;
  flags: string;
}

export interface DetectionRulePack {
  id: string;
  direction: 'input' | 'output';
  rules: DetectionRule[];
}

export interface DetectionRuleSet {
  version: string;
  revision: number;
  sha256: string;
  packs: DetectionRulePack[];
  expiresAt: Date;
}

/**
 * Check a signed rule set. Pass the highest revision you already run as
 * `heldRevision`: a lower one is refused, so an old set replayed to you cannot
 * undo a newer one. An expired set is refused too.
 */
export async function verifyDetectionRules(
  statement: string,
  options: VerifyNetworkOptions & { heldRevision?: number },
): Promise<DetectionRuleSet> {
  const payload = await verifyStatement('detectionRules', statement, options);
  const rs = (payload as unknown as { rs?: { v: number; version: string; revision: number; sha256: string; packs: DetectionRulePack[] } }).rs;
  if (!rs || rs.v !== 1 || !Array.isArray(rs.packs)) throw new NetworkVerificationError('invalid', 'The rule set is not in a known format');
  if (options.heldRevision !== undefined && rs.revision < options.heldRevision) {
    throw new NetworkVerificationError('revision_too_old', `This rule set is revision ${rs.revision}; revision ${options.heldRevision} is already held`);
  }
  return { version: rs.version, revision: rs.revision, sha256: rs.sha256, packs: rs.packs, expiresAt: new Date((payload.exp ?? 0) * 1000) };
}

