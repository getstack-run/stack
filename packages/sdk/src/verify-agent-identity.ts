import { createLocalJWKSet, createRemoteJWKSet, errors as joseErrors, jwtVerify, type JWK, type JWTPayload } from 'jose';

// The check of a statement that says who an agent is (spec/agent-identity/SPEC.md section 12),
// offline: public-key crypto only. Nothing here calls the STACK API except an optional `jwksUrl`
// fetch of STACK's public keys, which are the issuer's keys at `/v1/.well-known/jwks.json`, the
// ones that sign Passports.
//
// A verified statement says that STACK, when it signed, vouched that the agent exists and that
// these facts about its owner were true. It cannot say that they are still true, that the request
// you hold was made by the agent (check the request's signature first), or that the agent is
// honest. Ask again rather than keep a statement past its expiry.

export const AGENT_IDENTITY_TYP = 'stack-agent-identity+jwt';
export const AGENT_IDENTITY_AUDIENCE = 'stack:agent-identity';
const ISSUER = 'getstack.run';
const MAX_SECONDS = 900;
const CLOCK_TOLERANCE_SECONDS = 5;

export type AgentIdentityStatus = 'active' | 'suspended' | 'closed';

/** What a lookup names: exactly one of these. */
export type AgentIdentityLookup = { key_id: string } | { site: string } | { agent_id: string };

/** The facts of a statement. */
export interface AgentIdentityFacts {
  agent: {
    id: string;
    /** Present only when the agent's owner chose to show it. */
    name?: string;
    status: AgentIdentityStatus;
  };
  owner: {
    /** STACK has verified who the owner is. */
    identity_verified: boolean;
    /** The owner's account is one STACK serves: not suspended, and its subscription or contract is in force. */
    good_standing: boolean;
  };
  /** What was asked, as the server answered it. */
  lookup: AgentIdentityLookup;
}

export interface AgentIdentityClaims {
  iss: string;
  aud: string;
  /** The agent id. */
  sub: string;
  iat: number;
  exp: number;
  identity: AgentIdentityFacts & { v: 1 };
}

/** Where to get STACK's public keys: exactly one of these. */
export interface AgentIdentityKeySource {
  /** The keys, as served by `GET /v1/.well-known/jwks.json`: a JWKS or its `keys`. */
  jwks?: { keys: JWK[] } | JWK[];
  /** The URL of `/v1/.well-known/jwks.json`; fetched once and cached per process. */
  jwksUrl?: string;
  /** A single pre-fetched public key, for fully air-gapped checks. */
  publicJwk?: JWK;
}

const remoteCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function keyResolver(source: AgentIdentityKeySource) {
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

export interface VerifyAgentIdentityOptions extends AgentIdentityKeySource {
  /** The clock to check expiry against. Defaults to now. */
  now?: Date;
  /** The issuer you trust. Defaults to `getstack.run`. */
  issuer?: string;
  /** What you asked: the statement must be an answer to exactly this. */
  expect?: AgentIdentityLookup;
}

export type AgentIdentityVerificationReason = 'invalid' | 'expired' | 'wrong_lookup';

/** A statement did not check out. `reason` says why in a few fixed words. */
export class AgentIdentityVerificationError extends Error {
  constructor(readonly reason: AgentIdentityVerificationReason, message: string) {
    super(message);
    this.name = 'AgentIdentityVerificationError';
  }
}

const isObject = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const invalid = (message: string) => new AgentIdentityVerificationError('invalid', message);

function readFacts(value: unknown): AgentIdentityClaims['identity'] {
  if (!isObject(value) || value['v'] !== 1) throw invalid('The statement is not in a known format');
  const { agent, owner, lookup } = value;
  if (!isObject(agent) || typeof agent['id'] !== 'string' || !['active', 'suspended', 'closed'].includes(String(agent['status']))) {
    throw invalid('The statement names no agent');
  }
  if (agent['name'] !== undefined && typeof agent['name'] !== 'string') throw invalid('The statement names the agent wrongly');
  if (!isObject(owner) || ['identity_verified', 'good_standing'].some((fact) => typeof owner[fact] !== 'boolean')) {
    throw invalid('The statement says nothing of the owner');
  }
  if (!isObject(lookup) || Object.keys(lookup).length !== 1 || !['key_id', 'site', 'agent_id'].includes(Object.keys(lookup)[0]!) || typeof Object.values(lookup)[0] !== 'string') {
    throw invalid('The statement does not say what was asked');
  }
  return value as unknown as AgentIdentityClaims['identity'];
}

/**
 * Check a statement as the specification says: EdDSA under STACK's keys, the type and audience of
 * an identity statement (never a Passport's), the issuer, the clock, the lifetime, the shape of
 * the claims, that it is about one agent and, with `expect`, that it answers what you asked.
 * Throws {@link AgentIdentityVerificationError} for anything else; treat any throw as no statement.
 */
export async function verifyAgentIdentity(statement: string, options: VerifyAgentIdentityOptions): Promise<AgentIdentityClaims> {
  const now = options.now ?? new Date();
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(statement, keyResolver(options), {
      algorithms: ['EdDSA'],
      typ: AGENT_IDENTITY_TYP,
      audience: AGENT_IDENTITY_AUDIENCE,
      issuer: options.issuer ?? ISSUER,
      requiredClaims: ['sub', 'iat', 'exp'],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
      currentDate: now,
    }));
  } catch (error) {
    if (error instanceof joseErrors.JWTExpired) throw new AgentIdentityVerificationError('expired', 'The statement has expired');
    if (error instanceof Error && /exactly one of/.test(error.message)) throw error;
    throw invalid('The token is not a valid identity statement from STACK');
  }
  const { iat, exp, sub } = payload;
  if (typeof iat !== 'number' || typeof exp !== 'number' || typeof sub !== 'string') throw invalid('The statement has no times');
  if (exp - iat > MAX_SECONDS) throw invalid('The statement is good for too long');
  if (iat > Math.floor(now.getTime() / 1000) + CLOCK_TOLERANCE_SECONDS) throw invalid('The statement was made in the future');
  const identity = readFacts(payload['identity']);
  if (sub !== identity.agent.id) throw invalid('The statement is about two agents');
  if (options.expect) {
    const [by] = Object.keys(options.expect) as Array<keyof AgentIdentityLookup>;
    const asked = options.expect as Record<string, string>;
    const answered = identity.lookup as Record<string, string>;
    if (!by || answered[by] !== asked[by]) throw new AgentIdentityVerificationError('wrong_lookup', 'The statement answers another lookup');
  }
  return { iss: String(payload.iss), aud: AGENT_IDENTITY_AUDIENCE, sub, iat, exp, identity };
}
