// The STACK network: the signed objects and the API shapes.
//
// THE FORMATS (the public specification of the passport and its checking
// carries these; this file is their source of truth):
//
//   install key        an Ed25519 public JWK `{ kty: 'OKP', crv: 'Ed25519', x }`. Its
//                      `kid` is the RFC 7638 thumbprint, base64url of the SHA-256 of
//                      `{"crv":"Ed25519","kty":"OKP","x":"<x>"}`, 43 characters.
//   passport digest    base64url (no padding) of the SHA-256 of the passport's compact
//                      serialisation, exactly as the install issued it, 43 characters.
//   install proof      a compact JWS an install signs with its key to call the network:
//                      header { alg: EdDSA, typ: stack-install+jwt, kid }, claims in
//                      `NetworkInstallProofClaims`. Single use (`jti`), at most 120 s old.
//   countersignature   a compact JWS STACK signs with its deployment key over one
//                      passport digest: header { alg: EdDSA, typ: stack-countersignature+jwt,
//                      kid: <STACK key> }, claims in `CountersignatureClaims`. The claim
//                      `cs.key.jwk` is the install's public key, so a verifier needs no
//                      lookup: it checks STACK's signature on the countersignature against
//                      STACK's JWKS, then the install's signature on the passport against
//                      `cs.key.jwk`, then that the passport hashes to `cs.passport.digest`.
//   revocation list    a compact JWS of the revocations after a cursor (`RevocationListClaims`).
//   verified statement a compact JWS saying whether a passport or agent is countersigned and
//                      live right now (`VerifiedStatementClaims`).
//   detection rules    a compact JWS of the current rule set (`DetectionRuleSetClaims`).
//
// Offline, a counterparty can check both signatures and the digest with only
// STACK's JWKS. It cannot learn from the JWS alone that a key or passport was
// revoked after issue: that is what the countersignature's short life, the signed
// revocation list and the "STACK-verified" statement are for.

import { z } from 'zod';
import {
  COUNTERSIGNATURE_MAX_TTL_SECONDS,
  COUNTERSIGNATURE_MIN_TTL_SECONDS,
  NETWORK_KEY_ROLLOVER_MAX_SECONDS,
  NETWORK_PROOF_ACTIONS,
  NETWORK_REVOCATION_KINDS,
  NETWORK_REVOCATION_PUBLISHERS,
  NETWORK_REVOCATION_REASONS,
  NETWORK_VERIFIED_STATUSES,
  REVOCATION_LIST_PAGE_MAX,
} from '../constants/network.js';

const BASE64URL_43 = /^[A-Za-z0-9_-]{43}$/;
const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

export const InstallIdSchema = z.string().regex(/^ins_[A-Za-z0-9_-]{16,40}$/);
export const InstallKeyIdSchema = z.string().regex(/^ink_[A-Za-z0-9_-]{16,40}$/);
export const NetworkSubscriptionIdSchema = z.string().regex(/^nsub_[A-Za-z0-9_-]{16,40}$/);
/** base64url SHA-256 (43 characters): a key thumbprint or a passport digest. */
export const Base64Url256Schema = z.string().regex(BASE64URL_43);
export const CompactJwsSchema = z.string().min(20).max(24_000).regex(COMPACT_JWS);

export const NetworkRevocationKindEnum = z.enum(NETWORK_REVOCATION_KINDS);
export const NetworkRevocationReasonEnum = z.enum(NETWORK_REVOCATION_REASONS);
export const NetworkRevocationPublisherEnum = z.enum(NETWORK_REVOCATION_PUBLISHERS);
export const NetworkVerifiedStatusEnum = z.enum(NETWORK_VERIFIED_STATUSES);
export const NetworkProofActionEnum = z.enum(NETWORK_PROOF_ACTIONS);

/** An Ed25519 public key as a JWK. Anything else (RSA, a private part, extra members) is refused. */
export const InstallPublicJwk = z
  .object({
    kty: z.literal('OKP'),
    crv: z.literal('Ed25519'),
    x: Base64Url256Schema,
  })
  .strict();
export type InstallPublicJwk = z.infer<typeof InstallPublicJwk>;

// ─── Signed objects ──────────────────────────────────────────────────

const ProofCommon = {
  iss: InstallIdSchema,
  sub: InstallIdSchema,
  aud: z.literal('stack:network'),
  iat: z.number().int(),
  exp: z.number().int(),
  jti: z.string().regex(/^[A-Za-z0-9_-]{16,64}$/),
};

/**
 * The claims of an install proof. `act` says what the install is asking for; the
 * request's own data rides inside the signed claims, so a proof can only ever
 * authorise the one thing it names.
 */
export const NetworkInstallProofClaims = z.discriminatedUnion('act', [
  z.object({ ...ProofCommon, act: z.literal('rules') }).strict(),
  z.object({ ...ProofCommon, act: z.literal('classify') }).strict(),
  z
    .object({
      ...ProofCommon,
      act: z.literal('countersign'),
      /** Digest of the passport to countersign. */
      pd: Base64Url256Schema,
      /** The passport's own `jti`, kept so a revocation can name it. */
      pjti: z.string().min(1).max(128).optional(),
      /** The agent the passport is for, in the install's own namespace. */
      agent: z.string().min(1).max(128).optional(),
      /** Requested countersignature life in seconds. */
      ttl: z.number().int().min(COUNTERSIGNATURE_MIN_TTL_SECONDS).max(COUNTERSIGNATURE_MAX_TTL_SECONDS).optional(),
    })
    .strict(),
  z
    .object({
      ...ProofCommon,
      act: z.literal('revoke'),
      kind: NetworkRevocationKindEnum,
      subject: z.string().min(1).max(256),
      reason: NetworkRevocationReasonEnum.optional(),
    })
    .strict(),
]);
export type NetworkInstallProofClaims = z.infer<typeof NetworkInstallProofClaims>;

/** The proof of possession of a key being registered. */
export const NetworkInstallPopClaims = z
  .object({
    iss: Base64Url256Schema,
    aud: z.literal('stack:network'),
    install: InstallIdSchema,
    nonce: z.string().regex(/^[A-Za-z0-9_-]{32,64}$/),
    iat: z.number().int(),
    exp: z.number().int(),
  })
  .strict();
export type NetworkInstallPopClaims = z.infer<typeof NetworkInstallPopClaims>;

export const CountersignatureClaims = z
  .object({
    iss: z.string(),
    aud: z.literal('stack:countersignature'),
    sub: InstallIdSchema,
    iat: z.number().int(),
    exp: z.number().int(),
    jti: z.string().regex(/^csg_[A-Za-z0-9_-]{16,40}$/),
    cs: z
      .object({
        v: z.literal(1),
        install: InstallIdSchema,
        /** The owner: the STACK account that registered the install, authenticated when it did. Opaque. */
        owner: z.string(),
        /**
         * Whether STACK had verified the owner's identity when it issued this (Stripe Identity,
         * the same check the account's own identity claims use). Informational: countersigning
         * never requires it, so a counterparty that wants it checks it.
         */
        owner_verified: z.boolean(),
        key: z.object({ kid: Base64Url256Schema, jwk: InstallPublicJwk }).strict(),
        passport: z
          .object({
            alg: z.literal('sha256'),
            digest: Base64Url256Schema,
            jti: z.string().max(128).optional(),
            agent: z.string().max(128).optional(),
          })
          .strict(),
      })
      .strict(),
  })
  .strict();
export type CountersignatureClaims = z.infer<typeof CountersignatureClaims>;

export const RevocationEntry = z
  .object({
    seq: z.number().int().positive(),
    id: z.string().regex(/^rev_[A-Za-z0-9_-]{16,40}$/),
    kind: NetworkRevocationKindEnum,
    /** passport: the passport digest. agent: the agent id. key: the key thumbprint. install: the install id. */
    subject: z.string().min(1).max(256),
    /** The install the subject belongs to. Every revocation names one: a verifier matches an entry on the subject AND the install. */
    install: InstallIdSchema,
    reason: NetworkRevocationReasonEnum,
    by: NetworkRevocationPublisherEnum,
    at: z.string(),
  })
  .strict();
export type RevocationEntry = z.infer<typeof RevocationEntry>;

export const RevocationListClaims = z
  .object({
    iss: z.string(),
    aud: z.literal('stack:revocation-list'),
    iat: z.number().int(),
    exp: z.number().int(),
    rl: z
      .object({
        v: z.literal(1),
        /** The cursor this page starts after. */
        after: z.number().int().nonnegative(),
        /** The highest sequence number STACK has published so far. */
        head: z.number().int().nonnegative(),
        /** The cursor for the next page, or null when this page reaches the head. */
        next: z.number().int().nonnegative().nullable(),
        entries: z.array(RevocationEntry),
      })
      .strict(),
  })
  .strict();
export type RevocationListClaims = z.infer<typeof RevocationListClaims>;

export const VerifiedStatementClaims = z
  .object({
    iss: z.string(),
    aud: z.literal('stack:verified'),
    /** `passport:<digest>` or `agent:<install id>:<agent>`. */
    sub: z.string().max(400),
    iat: z.number().int(),
    exp: z.number().int(),
    vs: z
      .object({
        v: z.literal(1),
        mark: z.literal('STACK-verified'),
        status: NetworkVerifiedStatusEnum,
        install: InstallIdSchema,
        countersignature: z.string(),
        /** When the countersignature behind this statement stops being good. */
        valid_until: z.string(),
        passport_digest: Base64Url256Schema,
      })
      .strict(),
  })
  .strict();
export type VerifiedStatementClaims = z.infer<typeof VerifiedStatementClaims>;

export const DetectionRuleSchema = z
  .object({
    id: z.string().min(1).max(100),
    severity: z.enum(['warning', 'critical']),
    /** An ECMAScript regular expression: `new RegExp(pattern, flags)`. */
    pattern: z.string().min(1).max(4_000),
    flags: z.string().max(8),
  })
  .strict();
export type DetectionRule = z.infer<typeof DetectionRuleSchema>;

export const DetectionRulePackSchema = z
  .object({
    id: z.string(),
    direction: z.enum(['input', 'output']),
    rules: z.array(DetectionRuleSchema),
  })
  .strict();
export type DetectionRulePack = z.infer<typeof DetectionRulePackSchema>;

export const DetectionRuleSetClaims = z
  .object({
    iss: z.string(),
    aud: z.literal('stack:detection-rules'),
    iat: z.number().int(),
    exp: z.number().int(),
    rs: z
      .object({
        v: z.literal(1),
        /** `r<revision>-<first 12 hex of sha256>`; a later revision is always a larger number. */
        version: z.string(),
        revision: z.number().int().positive(),
        /** Hex SHA-256 of the canonical JSON of `packs`. */
        sha256: z.string().regex(/^[0-9a-f]{64}$/),
        packs: z.array(DetectionRulePackSchema),
      })
      .strict(),
  })
  .strict();
export type DetectionRuleSetClaims = z.infer<typeof DetectionRuleSetClaims>;

// ─── API inputs ──────────────────────────────────────────────────────

export const RegisterInstallInput = z
  .object({ name: z.string().trim().min(1).max(80) })
  .strict();
export type RegisterInstallInput = z.infer<typeof RegisterInstallInput>;

export const AddInstallKeyInput = z
  .object({
    public_jwk: InstallPublicJwk,
    /** The install proof of possession: a JWS over the challenge, signed with the key being registered. */
    proof: CompactJwsSchema,
    /** How long the install's other live keys keep working after this one is added. */
    rollover_seconds: z.number().int().min(0).max(NETWORK_KEY_ROLLOVER_MAX_SECONDS).optional(),
  })
  .strict();
export type AddInstallKeyInput = z.infer<typeof AddInstallKeyInput>;

export const RevokeNetworkInput = z
  .object({ reason: NetworkRevocationReasonEnum.optional() })
  .strict();
export type RevokeNetworkInput = z.infer<typeof RevokeNetworkInput>;

/**
 * Revoke a licence key STACK issued to this account, before it expires. The key
 * itself is the proof it is the account's: its signed claims name the account
 * and carry its id, so nothing the caller types picks what is revoked.
 */
export const RevokeLicenceInput = z
  .object({
    licence_key: z.string().min(1).max(4_096),
    reason: NetworkRevocationReasonEnum.optional(),
  })
  .strict();
export type RevokeLicenceInput = z.infer<typeof RevokeLicenceInput>;

export const NetworkClassifyInput = z
  .object({
    /** The content to classify. Never stored. */
    content: z.union([z.string().min(1).max(200_000), z.record(z.unknown())]),
    context: z.enum(['email', 'document', 'webpage', 'chat_log', 'api_response', 'calendar', 'other']).optional(),
  })
  .strict();
export type NetworkClassifyInput = z.infer<typeof NetworkClassifyInput>;

/**
 * What an install sends to have a checkout graded for intent deviation: what the agent declared and what it then did.
 * Never stored.
 */
export const NetworkIntentDeviationInput = z
  .object({
    declared: z
      .object({
        summary: z.string().min(1).max(2_000),
        services: z.array(z.string().min(1).max(200)),
      })
      .strict(),
    observed: z
      .object({
        services_used: z.array(z.string().min(1).max(200)),
        tool_calls: z
          .array(
            z
              .object({
                service: z.string().min(1).max(200),
                method: z.string().min(1).max(200),
                target: z.string().max(500).optional(),
              })
              .strict(),
          ),
        actions_count: z.number().int().min(0),
        summary: z.string().max(2_000).optional(),
      })
      .strict(),
  })
  .strict();
export type NetworkIntentDeviationInput = z.infer<typeof NetworkIntentDeviationInput>;

export const VerifyCountersignatureInput = z
  .object({
    countersignature: CompactJwsSchema,
    /** The passport the countersignature is about; when given, STACK also checks its signature and digest. */
    passport: CompactJwsSchema.optional(),
  })
  .strict();
export type VerifyCountersignatureInput = z.infer<typeof VerifyCountersignatureInput>;

export const VerifiedStatusQuery = z
  .object({
    passport_digest: Base64Url256Schema.optional(),
    install: InstallIdSchema.optional(),
    agent: z.string().min(1).max(128).optional(),
  })
  .strict()
  .refine((q) => (q.passport_digest !== undefined) !== (q.install !== undefined && q.agent !== undefined), {
    message: 'Give either passport_digest, or install and agent together',
  })
  .refine((q) => (q.install === undefined) === (q.agent === undefined), {
    message: 'Give install and agent together',
  });
export type VerifiedStatusQuery = z.infer<typeof VerifiedStatusQuery>;

/** The owner publishing a revocation from their STACK account (an install publishes with its own proof). Every revocation names the install it belongs to. */
export const PublishRevocationInput = z
  .object({
    kind: NetworkRevocationKindEnum,
    subject: z.string().min(1).max(256),
    install: InstallIdSchema,
    reason: NetworkRevocationReasonEnum.optional(),
  })
  .strict();
export type PublishRevocationInput = z.infer<typeof PublishRevocationInput>;

export const ListRevocationsQuery = z
  .object({
    after: z.coerce.number().int().min(0).default(0),
    limit: z.coerce.number().int().min(1).max(REVOCATION_LIST_PAGE_MAX).optional(),
    install: InstallIdSchema.optional(),
  })
  .strict();
export type ListRevocationsQuery = z.infer<typeof ListRevocationsQuery>;

export const CreateNetworkSubscriptionInput = z
  .object({
    /** Where STACK posts a signed revocation list. https only, a public address, no redirects. */
    url: z.string().url().max(2_000),
    /** Follow only these installs. Omit to follow every revocation. */
    installs: z.array(InstallIdSchema).max(100).optional(),
  })
  .strict();
export type CreateNetworkSubscriptionInput = z.infer<typeof CreateNetworkSubscriptionInput>;

// ─── API views ───────────────────────────────────────────────────────

export interface NetworkInstallKeyView {
  id: string;
  kid: string;
  status: 'active' | 'revoked';
  /** When a rolled-over key stops working; null for the newest key. */
  valid_until: string | null;
  /** True when the key can sign a proof right now. */
  usable: boolean;
  created_at: string;
  revoked_at: string | null;
  revoked_reason: string | null;
  public_jwk: InstallPublicJwk;
}

export interface NetworkInstallView {
  id: string;
  name: string;
  status: 'active' | 'revoked';
  created_at: string;
  revoked_at: string | null;
  keys: NetworkInstallKeyView[];
}

export interface NetworkKeyChallengeView {
  nonce: string;
  expires_at: string;
  audience: 'stack:network';
  install: string;
}

export interface NetworkSubscriptionView {
  id: string;
  url: string;
  installs: string[] | null;
  status: 'active' | 'failing' | 'paused';
  last_delivered_seq: number;
  last_error: string | null;
  /** False for a subscription made before deliveries were signed: rotate its secret to sign them. */
  signed: boolean;
  created_at: string;
}

/**
 * A new subscription: the signing secret is shown once, here, and never read back. An OAuth
 * sign-in (a chat) is never given it: `signing_secret` is null and the note says how to get one.
 */
export interface NetworkSubscriptionCreatedView extends NetworkSubscriptionView {
  signing_secret: string | null;
  signing_secret_note?: string;
}

export interface NetworkSubscriptionSecretRotation {
  /** The new secret, shown once. */
  signing_secret: string;
  /** The previous secret keeps signing beside the new one until then. */
  previous_valid_until: string | null;
}

export interface CountersignatureView {
  id: string;
  /** The compact JWS. */
  countersignature: string;
  expires_at: string;
  install: string;
  passport_digest: string;
}

export interface NetworkRevocationView {
  id: string;
  seq: number;
  kind: z.infer<typeof NetworkRevocationKindEnum>;
  subject: string;
  install: string;
  reason: z.infer<typeof NetworkRevocationReasonEnum>;
  by: z.infer<typeof NetworkRevocationPublisherEnum>;
  at: string;
}

/** A licence key the account has revoked. The key itself is never stored or returned. */
export interface NetworkLicenceRevocationView {
  /** The key's id: what the network checks on every request. */
  jti: string;
  customer: string;
  reason: z.infer<typeof NetworkRevocationReasonEnum>;
  /** When the key would have expired; the entry is dropped some time after. */
  expires_at: string;
  revoked_at: string;
}

export interface NetworkVerifyResult {
  valid: boolean;
  /** Why not, as short codes, when `valid` is false. */
  reasons: string[];
  checked_at: string;
  install: string | null;
  owner: string | null;
  passport_digest: string | null;
  countersignature_expires_at: string | null;
  /** Set when the install's key, the install, the agent or the passport has been revoked. */
  revoked: { kind: string; at: string; reason: string } | null;
}
