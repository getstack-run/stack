// The local files the command line and the SDKs keep under `~/.stack/` (spec/credentials-files). They are written by one
// implementation and read by another (the CLI signs in, the SDKs use the sign-in; the Python SDK reads what the
// TypeScript SDK enrolled), so their shape is the contract between them. The published JSON Schemas are generated
// from these.

import { z } from 'zod';

/**
 * `~/.stack/credentials.json`: an operator's sign-in on this machine. The refresh token is a bearer secret: whoever
 * reads it can sign in as the operator for as long as it lives.
 */
export const StoredOperatorCredentials = z
  .object({
    /** The OAuth client this machine registered (RFC 7591): one client id for each install of the CLI or SDK. */
    client_id: z.string().min(1),
    /** The current refresh token. Every exchange returns the next one, and the file is rewritten with it. */
    refresh_token: z.string().min(1),
    /** Unix time in seconds when `refresh_token` was stored. */
    issued_at: z.number().int().nonnegative(),
    /** Unix time in seconds after which the sign-in is treated as expired and the person signs in again. */
    refresh_expires_at: z.number().int().nonnegative(),
    /** The signed-in operator's email, for display only. Absent when it could not be read. */
    operator_email: z.string().optional(),
    /** The space-separated OAuth scopes the sign-in was granted. */
    scope: z.string(),
  })
  .passthrough();
export type StoredOperatorCredentials = z.infer<typeof StoredOperatorCredentials>;

const Base64Url32 = z.string().regex(/^[A-Za-z0-9_-]{43}$/, 'the base64url of 32 bytes');

/** An Ed25519 public key as a JSON Web Key (RFC 8037). */
export const AgentPublicJwk = z.object({ kty: z.literal('OKP'), crv: z.literal('Ed25519'), x: Base64Url32 }).passthrough();
/** An Ed25519 private key as a JSON Web Key: the public key and `d`, the secret. */
export const AgentPrivateJwk = z.object({ kty: z.literal('OKP'), crv: z.literal('Ed25519'), x: Base64Url32, d: Base64Url32 }).passthrough();

/**
 * `~/.stack/agents/<agent_id>.json`: the key an agent signs its requests with. The private key never leaves the machine;
 * the API holds only the public key.
 */
export const StoredAgentKey = z
  .object({
    /** The agent the key belongs to (`agt_...`), or an enrolment that is not finished yet (`fleet_` and 64 hexadecimal characters). */
    agent_id: z.string().min(1),
    publicKey: AgentPublicJwk,
    privateKey: AgentPrivateJwk,
    /** Unix time in seconds when the key was enrolled (or generated, for an enrolment that is not finished yet). */
    enrolled_at: z.number().int().nonnegative(),
  })
  .passthrough();
export type StoredAgentKey = z.infer<typeof StoredAgentKey>;
