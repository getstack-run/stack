import { z } from 'zod';

// The wire shapes of agent runtime sign-in (spec/agent-auth) and of the keys an
// agent publishes (spec/agent-keys). The routes parse request bodies with the
// input schemas; the specification's JSON Schemas are generated from all of
// them by scripts/generate-spec.mjs.

/** An Ed25519 public key as an OKP JWK member set: 32 bytes, base64url without padding. */
export const AgentPublicKey = z.object({
  kty: z.literal('OKP'),
  crv: z.literal('Ed25519'),
  x: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
});
export type AgentPublicKey = z.infer<typeof AgentPublicKey>;

/** POST /v1/agents/:id/enrollment-challenge: the answer. */
export const AgentEnrollmentChallengeResult = z.object({
  challenge_id: z.string().min(1).max(128),
  challenge: z.string().min(1).max(256),
  expires_in: z.number().int().positive(),
});
export type AgentEnrollmentChallengeResult = z.infer<typeof AgentEnrollmentChallengeResult>;

/**
 * POST /v1/agents/:id/enroll: the body. Members this schema does not name are
 * ignored. `signed_challenge` is the base64url Ed25519 signature, by the key
 * in `public_key`, over the UTF-8 bytes of the challenge string.
 */
export const AgentEnrollInput = z.object({
  public_key: AgentPublicKey.passthrough(),
  challenge_id: z.string().min(1).max(128),
  signed_challenge: z.string().min(1).max(512),
}).passthrough();
export type AgentEnrollInput = z.infer<typeof AgentEnrollInput>;

/** POST /v1/agents/:id/enroll: the answer. */
export const AgentEnrollResult = z.object({
  agent_id: z.string().min(1).max(128),
  enrolled_at: z.string().datetime(),
});
export type AgentEnrollResult = z.infer<typeof AgentEnrollResult>;

/** POST /v1/agents/:id/enrollment-tickets: the body. */
export const AgentEnrollmentTicketInput = z.object({
  machine_label: z.string().optional(),
});
export type AgentEnrollmentTicketInput = z.infer<typeof AgentEnrollmentTicketInput>;

/** POST /v1/agents/:id/enrollment-tickets: the answer. The ticket is a single-use bearer for the two enrollment calls of that one agent. */
export const AgentEnrollmentTicketResult = z.object({
  ticket: z.string().min(1),
  jti: z.string().min(1),
  expires_at: z.string().datetime(),
  expires_in: z.number().int().positive(),
});
export type AgentEnrollmentTicketResult = z.infer<typeof AgentEnrollmentTicketResult>;

/**
 * The payload of an agent JWT. `iss`, `aud`, `sub`, `iat`, `exp` and `jti` are
 * required; the first-party SDKs also send `nbf`. The lifetime (`exp - iat`)
 * is at most AGENT_JWT_MAX_TTL_SECONDS; the SDKs mint AGENT_JWT_TTL_SECONDS.
 */
export const AgentJwtClaims = z.object({
  iss: z.literal('stack-sdk'),
  aud: z.literal('stack:agent'),
  sub: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
  iat: z.number().int(),
  nbf: z.number().int().optional(),
  exp: z.number().int(),
  jti: z.string().regex(/^[A-Za-z0-9_-]{1,200}$/),
});
export type AgentJwtClaims = z.infer<typeof AgentJwtClaims>;

/** One key of an agent's published key set. `not_before` and `not_after` are Unix milliseconds. */
export const AgentJwk = z.object({
  kty: z.literal('OKP'),
  crv: z.literal('Ed25519'),
  x: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  kid: z.string().regex(/^agent:[^:]+:v[1-9][0-9]*$/),
  alg: z.literal('EdDSA'),
  use: z.literal('sig'),
  not_before: z.number().int().nullable(),
  not_after: z.number().int().nullable(),
});
export type AgentJwk = z.infer<typeof AgentJwk>;

/** GET /v1/agents/:id/.well-known/jwks.json: the answer. */
export const AgentJwks = z.object({ keys: z.array(AgentJwk).min(1) });
export type AgentJwks = z.infer<typeof AgentJwks>;

/** POST /v1/fleets/:id/enrollment-challenges and /v1/fleets/:id/workload/enrollment-challenges: the answer. */
export const FleetEnrollmentChallengeResult = z.object({
  challenge_id: z.string().min(1).max(128),
  challenge: z.string().min(1).max(256),
  expires_in: z.number().int().positive(),
});
export type FleetEnrollmentChallengeResult = z.infer<typeof FleetEnrollmentChallengeResult>;

/** POST /v1/fleets/:id/enroll and /v1/fleets/:id/workload/enroll: the answer. */
export const FleetEnrollmentResult = z.object({
  agent_id: z.string().min(1).max(128),
  membership_id: z.string().min(1).max(128),
  identity_expires_at: z.string().datetime(),
});
export type FleetEnrollmentResult = z.infer<typeof FleetEnrollmentResult>;
