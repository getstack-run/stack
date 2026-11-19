import { z } from 'zod';

const id = (prefix: string) => z.string().regex(
  new RegExp(`^${prefix}_[\\w-]+$`),
  `id must be ${prefix}_*`,
);

/** Lowercase SHA-256 on the wire. Raw digests are never accepted by authority APIs. */
export const Sha256Digest = z.string().regex(
  /^sha256:[0-9a-f]{64}$/,
  'must be a sha256: prefixed lowercase SHA-256 digest',
);
export type Sha256Digest = z.infer<typeof Sha256Digest>;

const HttpsUrl = z.string().url().regex(/^https:\/\//, 'must use https://');
const JsonPrimitive = z.union([z.string(), z.number().finite(), z.boolean(), z.null()]);
type JsonValueType = z.infer<typeof JsonPrimitive> | JsonValueType[] | { [key: string]: JsonValueType };
const JsonValue: z.ZodType<JsonValueType> = z.lazy(() => z.union([
  JsonPrimitive,
  z.array(JsonValue),
  z.record(z.string(), JsonValue),
]));
const JsonObject = z.record(z.string(), JsonValue);

const SemanticCode = z.string().min(1).max(128)
  .regex(/^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/, 'must be a lowercase semantic code')
  .refine((value) => !/\d{6,}/.test(value), 'must not contain identifier-like digit runs');

const ActionIdentifier = z.string().min(1).max(1024)
  .regex(/^[A-Za-z][A-Za-z0-9._:/-]*$/, 'must be a machine-readable action identifier')
  .refine((value) => !/\d{6,}/.test(value), 'must not contain identifier-like digit runs');

const EXECUTABLE_CONFIG_KEYS = new Set([
  'code', 'command', 'eval', 'executable', 'function', 'handler', 'import',
  'javascript', 'module', 'require', 'script', 'wasm',
]);
const PROVIDER_ENDPOINT_KEYS = new Set([
  'endpoint', 'endpoint_url', 'issuer_endpoint', 'jwks_uri', 'status_endpoint',
  'verification_endpoint',
]);

function rejectForbiddenConfigKeys(
  value: JsonValueType,
  ctx: z.RefinementCtx,
  options: { providerEndpoints: boolean },
  path: Array<string | number> = [],
): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectForbiddenConfigKeys(item, ctx, options, [...path, index]));
    return;
  }
  if (value === null || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.toLowerCase();
    if (EXECUTABLE_CONFIG_KEYS.has(normalized)
      || (options.providerEndpoints && PROVIDER_ENDPOINT_KEYS.has(normalized))) {
      ctx.addIssue({
        code: 'custom',
        message: `declarative profile configuration forbids ${key}`,
        path: [...path, key],
      });
    }
    rejectForbiddenConfigKeys(child, ctx, options, [...path, key]);
  }
}

export const AuthorityPrincipalKind = z.enum(['person', 'organisation']);
export type AuthorityPrincipalKind = z.infer<typeof AuthorityPrincipalKind>;

export const AuthorityPrincipalStatus = z.enum(['active', 'revoked', 'erased']);
export type AuthorityPrincipalStatus = z.infer<typeof AuthorityPrincipalStatus>;

export const AuthorityProofKind = z.enum([
  'identity',
  'capacity',
  'mandate',
  'consent',
  'signature',
  'domain',
  'workload',
]);
export type AuthorityProofKind = z.infer<typeof AuthorityProofKind>;

export const AuthorityProofSourceKind = z.enum([
  'legacy_identity_claim',
  'external_native',
  'stack_derived',
]);
export type AuthorityProofSourceKind = z.infer<typeof AuthorityProofSourceKind>;

export const AuthorityProofStatus = z.enum([
  'pending',
  'active',
  'suspended',
  'revoked',
  'replaced',
  'erased',
]);
export type AuthorityProofStatus = z.infer<typeof AuthorityProofStatus>;

export const AuthorityBindingStatus = z.enum([
  'draft',
  'pending_approval',
  'active',
  'suspended',
  'revoked',
  'replaced',
  'erased',
]);
export type AuthorityBindingStatus = z.infer<typeof AuthorityBindingStatus>;

export const AuthorityProfileStatus = z.enum(['draft', 'active', 'retired', 'revoked']);
export type AuthorityProfileStatus = z.infer<typeof AuthorityProfileStatus>;

export const AuthorityReceiverStatus = z.enum(['pending', 'active', 'suspended', 'revoked']);
export type AuthorityReceiverStatus = z.infer<typeof AuthorityReceiverStatus>;

export const AuthorityProofRole = z.enum([
  'principal_identity',
  'authoriser_identity',
  'authoriser_capacity',
  'mandate',
  'consent',
  'domain',
]);
export type AuthorityProofRole = z.infer<typeof AuthorityProofRole>;

export const AuthorityDisclosureMode = z.enum([
  'predicate',
  'pairwise',
  'exact_private',
  'issuer_evidence',
  'status_only',
]);
export type AuthorityDisclosureMode = z.infer<typeof AuthorityDisclosureMode>;

export const AuthorityConstraintOp = z.enum([
  'eq',
  'not_eq',
  'in',
  'not_in',
  'lt',
  'lte',
  'gt',
  'gte',
  'exists',
  'not_exists',
]);

const ConstraintValue = z.union([
  z.string().max(2048),
  z.number().finite(),
  z.boolean(),
  z.array(z.union([z.string().max(2048), z.number().finite(), z.boolean()])).max(256),
]);

/**
 * Domain-neutral constraint. Sensitive values are referenced through
 * value_ref and stay in encrypted proof facts; they are never copied into
 * the binding or Passport.
 */
export const AuthorityConstraint = z.object({
  path: z.string().min(1).max(256),
  op: AuthorityConstraintOp,
  value: ConstraintValue.optional(),
  value_ref: z.string().min(1).max(512).optional(),
}).superRefine((constraint, ctx) => {
  const ignoresValue = constraint.op === 'exists' || constraint.op === 'not_exists';
  const supplied = Number(constraint.value !== undefined) + Number(constraint.value_ref !== undefined);
  if (!ignoresValue && supplied !== 1) {
    ctx.addIssue({
      code: 'custom',
      message: 'exactly one of value or value_ref is required',
    });
  }
  if (ignoresValue && supplied !== 0) {
    ctx.addIssue({ code: 'custom', message: `${constraint.op} does not accept a value` });
  }
});
export type AuthorityConstraint = z.infer<typeof AuthorityConstraint>;

export const AuthorityActionScope = z.object({
  action_uri: ActionIdentifier,
  resource_refs: z.array(z.string().min(1).max(512)).max(256).default([]),
  constraints: z.array(AuthorityConstraint).max(64).default([]),
});
export type AuthorityActionScope = z.infer<typeof AuthorityActionScope>;

/** The fixed, provider-neutral scope carried by an authority binding. */
export const AuthorityScope = z.object({
  actions: z.array(AuthorityActionScope).min(1).max(128),
  limits: JsonObject.default({}),
});
export type AuthorityScope = z.infer<typeof AuthorityScope>;

export const AuthorityDisclosureRule = z.object({
  fact_id: z.string().min(1).max(512),
  mode: AuthorityDisclosureMode,
  profile_version_id: id('apv').optional(),
  required: z.boolean().default(true),
});
export type AuthorityDisclosureRule = z.infer<typeof AuthorityDisclosureRule>;

export const AuthorityDisclosurePolicy = z.object({
  rules: z.array(AuthorityDisclosureRule).max(128).default([]),
  principal_confirmation_required: z.boolean().default(false),
  max_retention_seconds: z.number().int().nonnegative().nullable().default(null),
  live_status_required: z.boolean().default(true),
});
export type AuthorityDisclosurePolicy = z.infer<typeof AuthorityDisclosurePolicy>;

/** The only authority object copied into a Passport JWT. */
export const AuthorityReference = z.object({
  binding_id: id('abn'),
  binding_version: z.number().int().positive(),
  binding_claim_id: id('pc'),
  binding_digest: Sha256Digest,
  receiver_id: id('rcv'),
  receiver_profile_version_id: id('apv'),
  expires_at: z.number().int().nonnegative(),
}).strict();
export type AuthorityReference = z.infer<typeof AuthorityReference>;

export const CreateAuthorityPrincipalInput = z.object({
  kind: AuthorityPrincipalKind,
  /** Optional operator-facing label. Encrypted before persistence. */
  label: z.string().min(1).max(256).optional(),
});
export type CreateAuthorityPrincipalInput = z.infer<typeof CreateAuthorityPrincipalInput>;

export const ProofProfileV1 = z.object({
  proof_kind: AuthorityProofKind,
  schema: z.object({
    uri: z.string().min(1).max(1024),
    version: z.string().min(1).max(128),
  }).strict(),
  adapter: z.object({
    key: z.string().min(1).max(128),
    version: z.number().int().positive(),
  }).strict(),
  accepted_native_formats: z.array(z.string().min(1).max(128)).min(1).max(64),
  validation: z.object({
    accepted_issuer_ids: z.array(z.string().min(1).max(1024)).max(256),
    accepted_signature_algs: z.array(z.string().min(1).max(64)).max(32),
    signature_required: z.boolean(),
    required_claim_paths: z.array(z.string().min(1).max(512)).max(256),
    subject_binding: JsonValue,
    status_method: JsonValue,
  }).strict(),
  assurance_mapping: JsonObject,
  freshness: z.object({
    maximum_age_seconds: z.number().int().nonnegative(),
    live_status_required: z.boolean(),
  }).strict(),
  disclosable_facts: z.array(z.object({
    fact_id: z.string().min(1).max(512),
    native_path: z.string().min(1).max(512),
    allowed_modes: z.array(AuthorityDisclosureMode).min(1).max(5),
  }).strict()).max(256),
}).strict().superRefine((value, ctx) => rejectForbiddenConfigKeys(
  value as JsonValueType,
  ctx,
  { providerEndpoints: true },
));
export type ProofProfileV1 = z.infer<typeof ProofProfileV1>;

export const CreateProofProfileVersionInput = z.object({
  profile_kind: z.literal('proof'),
  profile_key: z.string().min(1).max(128),
  version: z.number().int().positive(),
  schema_uri: z.string().min(1).max(1024),
  schema_version: z.string().min(1).max(128),
  adapter_key: z.string().min(1).max(128),
  adapter_version: z.number().int().positive(),
  config_json: ProofProfileV1,
}).strict();
export type CreateProofProfileVersionInput = z.infer<typeof CreateProofProfileVersionInput>;

export const DomainProfileV1 = z.object({
  domain: z.string().min(1).max(256),
  actions: z.array(z.object({
    action_uri: ActionIdentifier,
    resource_types: z.array(z.string().min(1).max(256)).max(256),
    normalized_request_schema: JsonObject,
    constraint_paths: z.array(z.string().min(1).max(512)).max(256),
  }).strict()).min(1).max(256),
  approval_templates: JsonObject,
  disclosure_templates: JsonObject,
  receipt_requirements: JsonObject,
}).strict().superRefine((value, ctx) => rejectForbiddenConfigKeys(
  value as JsonValueType,
  ctx,
  { providerEndpoints: false },
));
export type DomainProfileV1 = z.infer<typeof DomainProfileV1>;

export const CreateDomainProfileVersionInput = z.object({
  profile_kind: z.literal('domain'),
  profile_key: z.string().min(1).max(128),
  version: z.number().int().positive(),
  schema_uri: z.string().min(1).max(1024),
  schema_version: z.string().min(1).max(128),
  adapter_key: z.string().min(1).max(128),
  adapter_version: z.number().int().positive(),
  config_json: DomainProfileV1,
}).strict();
export type CreateDomainProfileVersionInput = z.infer<typeof CreateDomainProfileVersionInput>;

export const NativeReceiverProfileV1 = z.object({
  receiver_id: id('rcv'),
  protocol: z.object({
    key: z.string().min(1).max(128),
    version: z.string().min(1).max(128),
  }).strict(),
  audience: z.string().min(1).max(1024),
  request_authentication: z.object({
    method: z.string().min(1).max(128),
    signing_key_ids: z.array(z.string().min(1).max(256)).min(1).max(64),
    allowed_algs: z.array(z.enum(['EdDSA', 'ES256'])).min(1).max(2),
    maximum_age_seconds: z.number().int().positive().max(120),
  }).strict(),
  delivery: z.object({
    endpoint: HttpsUrl,
    mode: z.string().min(1).max(128),
    encryption_key_ids: z.array(z.string().min(1).max(256)).min(1).max(64),
    allowed_key_management_algs: z.array(z.literal('ECDH-ES+A256KW')).min(1).max(1),
    allowed_content_encryption_algs: z.array(z.literal('A256GCM')).min(1).max(1),
  }).strict(),
  accepted_proofs: z.array(z.object({
    proof_kind: AuthorityProofKind,
    profile_version_ids: z.array(id('apv')).min(1).max(64),
    issuer_ids: z.array(z.string().min(1).max(1024)).max(256),
    minimum_assurance_uri: z.string().min(1).max(1024).nullable(),
    maximum_age_seconds: z.number().int().nonnegative(),
    live_status_required: z.boolean(),
    evidence_modes: z.array(AuthorityDisclosureMode).min(1).max(5),
  }).strict()).max(128),
  required_facts: z.array(z.object({
    fact_id: z.string().min(1).max(512),
    allowed_modes: z.array(AuthorityDisclosureMode).min(1).max(5),
    purpose: z.string().min(1).max(1024),
    lawful_basis: z.string().min(1).max(512),
    retention_rule: JsonValue,
  }).strict()).max(256),
  approval_policy: JsonObject,
  receipt: z.object({
    required: z.boolean(),
    signing_key_ids: z.array(z.string().min(1).max(256)).max(64),
    allowed_algs: z.array(z.enum(['EdDSA', 'ES256'])).max(2),
  }).strict(),
  live_status_required: z.boolean().default(true),
}).strict().superRefine((value, ctx) => rejectForbiddenConfigKeys(
  value as JsonValueType,
  ctx,
  { providerEndpoints: false },
));
export type NativeReceiverProfileV1 = z.infer<typeof NativeReceiverProfileV1>;

/**
 * A proxy bridge is enforced inside STACK. It does not pretend to be an
 * external receiver and therefore has no receiver-owned keys or delivery
 * endpoint. The owned service connection is the trust boundary.
 */
export const ProxyBridgeReceiverProfileV1 = z.object({
  receiver_id: id('rcv'),
  protocol: z.object({
    key: z.literal('stack.proxy_bridge'),
    version: z.literal('1'),
  }).strict(),
  audience: z.string().min(1).max(1024),
  service_connection_id: z.string().regex(/^scon_[\w-]+$/),
  approval_policy: JsonObject,
  live_status_required: z.literal(true),
}).strict();
export type ProxyBridgeReceiverProfileV1 = z.infer<typeof ProxyBridgeReceiverProfileV1>;

export const InternalReceiverProfileV1 = z.object({
  receiver_id: id('rcv'),
  protocol: z.object({ key: z.literal('stack.internal_runtime'), version: z.literal('1') }).strict(),
  audience: z.string().min(1).max(1024),
  canonical_identifier: z.string().regex(/^stack:(skill|agent|dropoff):[A-Za-z0-9_-]+$/),
  approval_policy: JsonObject,
  live_status_required: z.literal(true),
}).strict();
export type InternalReceiverProfileV1 = z.infer<typeof InternalReceiverProfileV1>;

export const ReceiverProfileV1 = z.union([
  NativeReceiverProfileV1,
  ProxyBridgeReceiverProfileV1,
  InternalReceiverProfileV1,
]);
export type ReceiverProfileV1 = z.infer<typeof ReceiverProfileV1>;

export const CreateReceiverProfileVersionInput = z.object({
  profile_kind: z.literal('receiver'),
  profile_key: z.string().min(1).max(128),
  version: z.number().int().positive(),
  receiver_id: id('rcv'),
  schema_uri: z.string().min(1).max(1024),
  schema_version: z.string().min(1).max(128),
  adapter_key: z.string().min(1).max(128),
  adapter_version: z.number().int().positive(),
  config_json: ReceiverProfileV1,
}).strict();
export type CreateReceiverProfileVersionInput = z.infer<typeof CreateReceiverProfileVersionInput>;

export const CreateAuthorityProfileVersionInput = z.discriminatedUnion('profile_kind', [
  CreateProofProfileVersionInput,
  CreateDomainProfileVersionInput,
  CreateReceiverProfileVersionInput,
]).superRefine((value, ctx) => {
  if (value.profile_kind === 'receiver' && value.receiver_id !== value.config_json.receiver_id) {
    ctx.addIssue({
      code: 'custom',
      message: 'receiver_id must match config_json.receiver_id',
      path: ['config_json', 'receiver_id'],
    });
  }
});
export type CreateAuthorityProfileVersionInput = z.infer<typeof CreateAuthorityProfileVersionInput>;

export const CreateAuthorityReceiverInput = z.object({
  mode: z.enum(['native', 'proxy_bridge', 'internal']),
  canonical_identifier: z.string().min(1).max(1024),
  display_name: z.string().min(1).max(256),
  proxy_service_connection_id: z.string().regex(/^scon_[\w-]+$/).optional(),
}).strict().superRefine((value, ctx) => {
  if ((value.mode === 'native' || value.mode === 'internal') && value.proxy_service_connection_id !== undefined) {
    ctx.addIssue({
      code: 'custom',
      message: 'native receivers cannot use a proxy service connection',
      path: ['proxy_service_connection_id'],
    });
  }
  if (value.mode === 'proxy_bridge' && value.proxy_service_connection_id === undefined) {
    ctx.addIssue({
      code: 'custom',
      message: 'proxy_bridge receivers require a proxy service connection',
      path: ['proxy_service_connection_id'],
    });
  }
});
export type CreateAuthorityReceiverInput = z.infer<typeof CreateAuthorityReceiverInput>;

export const AuthorityReceiverKeyUse = z.enum([
  'request_signing',
  'response_encryption',
  'receipt_signing',
  'transport_mtls',
]);
export type AuthorityReceiverKeyUse = z.infer<typeof AuthorityReceiverKeyUse>;

const PublicAsymmetricJwk = z.record(z.string(), JsonValue).superRefine((jwk, ctx) => {
  if (!['EC', 'OKP', 'RSA'].includes(String(jwk.kty))) {
    ctx.addIssue({ code: 'custom', message: 'only public asymmetric JWKs are accepted' });
  }
  for (const member of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']) {
    if (jwk[member] !== undefined) {
      ctx.addIssue({ code: 'custom', message: `private or symmetric JWK member ${member} is forbidden` });
    }
  }
});

export const AddAuthorityReceiverKeyInput = z.object({
  key_id: z.string().min(1).max(256),
  use: AuthorityReceiverKeyUse,
  algorithm: z.enum(['EdDSA', 'ES256', 'ECDH-ES+A256KW']),
  public_jwk: PublicAsymmetricJwk,
  valid_from: z.coerce.date(),
  valid_until: z.coerce.date().optional(),
}).strict().refine((value) => !value.valid_until || value.valid_until > value.valid_from, {
  message: 'valid_until must be later than valid_from',
  path: ['valid_until'],
});
export type AddAuthorityReceiverKeyInput = z.infer<typeof AddAuthorityReceiverKeyInput>;

export const AttachAuthorityProofInput = z.object({
  subject_principal_id: id('prn'),
  represented_principal_id: id('prn').optional(),
  profile_version_id: id('apv'),
  proof_kind: AuthorityProofKind,
  issuer_identifier: z.string().min(1).max(1024),
  schema_uri: z.string().min(1).max(1024),
  schema_version: z.string().min(1).max(128),
  native_format: z.string().min(1).max(128),
  /** Provider-native bytes or compact serialization. Sensitive input. */
  native_evidence: z.string().min(1).max(1_000_000),
}).strict();
export type AttachAuthorityProofInput = z.infer<typeof AttachAuthorityProofInput>;

/** Starts provider-native collection without accepting caller-declared verification facts. */
export const CreateAuthorityProofCollectionSessionInput = z.object({
  subject_principal_id: id('prn'),
  represented_principal_id: id('prn').optional(),
  profile_version_id: id('apv'),
  issuer_identifier: z.string().min(1).max(1024),
  native_format: z.string().min(1).max(128),
}).strict();
export type CreateAuthorityProofCollectionSessionInput = z.infer<
  typeof CreateAuthorityProofCollectionSessionInput
>;

/** Write-only provider ceremony result, authenticated separately by the pinned adapter. */
export const AuthorityProofCallbackInput = z.object({
  session_id: id('pcs'),
  state_token: z.string().min(22).max(512).regex(
    /^[A-Za-z0-9_-]+$/,
    'state_token must be base64url',
  ),
  signed_callback: z.string().min(1).max(1_000_000),
}).strict();
export type AuthorityProofCallbackInput = z.infer<typeof AuthorityProofCallbackInput>;

export const AuthorityBindingProofInput = z.object({
  proof_id: id('prf'),
  proof_version: z.number().int().positive(),
  role: AuthorityProofRole,
  authoriser_principal_id: id('prn').optional(),
  group_key: SemanticCode,
  weight: z.number().int().positive().default(1),
  required: z.boolean().default(true),
  ordinal: z.number().int().nonnegative().default(0),
}).superRefine((value, ctx) => {
  const namesAuthoriser = value.role === 'authoriser_identity' || value.role === 'authoriser_capacity';
  if (namesAuthoriser !== (value.authoriser_principal_id !== undefined)) {
    ctx.addIssue({
      code: 'custom',
      message: namesAuthoriser
        ? 'authoriser proof roles require authoriser_principal_id'
        : 'authoriser_principal_id is only valid for authoriser proof roles',
      path: ['authoriser_principal_id'],
    });
  }
});

export const CreateAuthorityBindingInput = z.object({
  principal_id: id('prn'),
  agent_id: z.string().regex(/^(ag|agt)_[\w-]+$/, 'agent_id must be ag_* or agt_*'),
  agent_key_thumbprint: Sha256Digest.optional(),
  receiver_id: id('rcv'),
  receiver_profile_version_id: id('apv'),
  domain_profile_version_id: id('apv').optional(),
  mission_ids: z.array(id('ms')).max(64).default([]),
  purpose_code: SemanticCode,
  purpose_statement: z.string().min(1).max(4096).optional(),
  scope: AuthorityScope,
  approval_policy: JsonObject,
  disclosure_policy: AuthorityDisclosurePolicy,
  delegation_policy: z.object({
    allow_further_delegation: z.boolean(),
    max_delegation_depth: z.number().int().min(0).max(4),
  }).strict(),
  valid_from: z.coerce.date(),
  expires_at: z.coerce.date(),
  proofs: z.array(AuthorityBindingProofInput).min(1).max(128),
}).refine((input) => input.expires_at > input.valid_from, {
  message: 'expires_at must be later than valid_from',
  path: ['expires_at'],
}).superRefine((input, ctx) => {
  for (const requiredRole of ['principal_identity', 'authoriser_identity', 'mandate'] as const) {
    if (!input.proofs.some((proof) => proof.role === requiredRole && proof.required)) {
      ctx.addIssue({
        code: 'custom',
        message: `a required ${requiredRole} proof is required`,
        path: ['proofs'],
      });
    }
  }
});
export type CreateAuthorityBindingInput = z.infer<typeof CreateAuthorityBindingInput>;

export const DelegateAuthorityBindingInput = z.object({
  child_agent_id: z.string().regex(/^(ag|agt)_[\w-]+$/, 'child_agent_id must be ag_* or agt_*'),
  child_agent_key_thumbprint: Sha256Digest.optional(),
  mission_ids: z.array(id('ms')).max(64).default([]),
  scope: AuthorityScope,
  disclosure_policy: AuthorityDisclosurePolicy,
  allow_further_delegation: z.boolean().default(false),
  max_delegation_depth: z.number().int().min(0).max(4),
  valid_from: z.coerce.date(),
  expires_at: z.coerce.date(),
}).refine((input) => input.expires_at > input.valid_from, {
  message: 'expires_at must be later than valid_from',
  path: ['expires_at'],
});
export type DelegateAuthorityBindingInput = z.infer<typeof DelegateAuthorityBindingInput>;

/**
 * Creates immutable approval slots. Request hashes, authorisers, proof refs,
 * weights and thresholds are always derived from the stored binding/use.
 */
export const CreateAuthorityApprovalRequestsInput = z.discriminatedUnion('phase', [
  z.object({
    phase: z.literal('activation'),
  }).strict(),
  z.object({
    phase: z.enum(['action', 'presentation']),
    authority_use_id: id('aus'),
  }).strict(),
]);
export type CreateAuthorityApprovalRequestsInput = z.infer<
  typeof CreateAuthorityApprovalRequestsInput
>;

export const AuthorityApprovalDecisionInput = z.object({
  request_id: id('apr'),
  decision: z.enum(['approve', 'reject']),
  request_hash: Sha256Digest,
  /** Write-only ceremony output that must sign the exact request_hash. */
  signed_decision: z.string().min(1).max(1_000_000),
}).strict();
export type AuthorityApprovalDecisionInput = z.infer<typeof AuthorityApprovalDecisionInput>;

const OidcClaimPath = z.string().min(1).max(256).regex(
  /^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$/,
  'must be a dot-separated OIDC claim path',
).refine((value) => !value.split('.').some((part) => ['__proto__', 'prototype', 'constructor'].includes(part)), {
  message: 'contains a forbidden claim path segment',
});

/** Operator-created request for one exact proxy-mediated Authority. */
export const CreateEnterpriseOidcAuthoritySetupInput = z.object({
  organisation_name: z.string().trim().min(1).max(256),
  role_name: z.string().trim().min(1).max(256),
  role_claim_path: OidcClaimPath,
  role_claim_value: z.string().trim().min(1).max(512),
  agent_id: z.string().regex(/^(ag|agt)_[\w-]+$/),
  mission_id: id('ms').optional(),
  service_connection_id: z.string().regex(/^scon_[\w-]+$/),
  provider: SemanticCode,
  purpose: z.string().trim().min(1).max(1024),
  http_method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
  resource_path: z.string().min(1).max(1024).regex(/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$/),
  constraints: z.array(AuthorityConstraint).max(16).default([]),
  expires_at: z.coerce.date(),
}).strict().superRefine((value, ctx) => {
  const now = Date.now();
  if (value.expires_at.getTime() <= now || value.expires_at.getTime() > now + 60 * 60 * 1000) {
    ctx.addIssue({
      code: 'custom',
      message: 'expires_at must be within the next 60 minutes',
      path: ['expires_at'],
    });
  }
});
export type CreateEnterpriseOidcAuthoritySetupInput = z.infer<
  typeof CreateEnterpriseOidcAuthoritySetupInput
>;

const CompactJws = z.string()
  .min(3)
  .max(1_000_000)
  .regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, 'must be a compact JWS');

/**
 * Receiver-authenticated, one-time presentation request. The Passport is
 * write-only and the agent never receives either presentation plaintext or
 * receiver ciphertext.
 */
export const AuthorityPresentationRequestInput = z.object({
  signed_request: CompactJws,
  /** Agent proof-of-possession over this exact receiver request and Passport. */
  agent_proof: CompactJws,
  passport: z.string().min(1).max(1_000_000),
  authority_ref: AuthorityReference,
  receiver_profile_version_id: id('apv'),
  receiver_request_id: z.string().min(22).max(256)
    .regex(/^[A-Za-z0-9_-]+$/, 'receiver_request_id must be a high-entropy base64url identifier'),
  mission_id: id('ms').nullable(),
  action_uri: ActionIdentifier,
  resource_hash: Sha256Digest.nullable(),
  request_hash: Sha256Digest,
  /** Write-only transaction view used to recompute the hash and enforce constraints. */
  normalized_request: JsonObject,
  requested_facts: z.array(z.object({
    fact_id: z.string().min(1).max(512),
    mode: AuthorityDisclosureMode,
  }).strict()).min(1).max(256),
  nonce: z.string().min(22).max(256).regex(/^[A-Za-z0-9_-]+$/, 'nonce must be base64url'),
  issued_at: z.number().int().nonnegative(),
  expires_at: z.number().int().positive(),
}).strict().superRefine((value, ctx) => {
  if (value.receiver_profile_version_id !== value.authority_ref.receiver_profile_version_id) {
    ctx.addIssue({
      code: 'custom',
      message: 'receiver profile must match the authority reference',
      path: ['receiver_profile_version_id'],
    });
  }
  if (value.expires_at <= value.issued_at || value.expires_at - value.issued_at > 120) {
    ctx.addIssue({
      code: 'custom',
      message: 'presentation request expiry must be after issue and no more than 120 seconds',
      path: ['expires_at'],
    });
  }
});
export type AuthorityPresentationRequestInput = z.infer<typeof AuthorityPresentationRequestInput>;

/** Compatibility name for the receiver presentation-request ceremony. */
export const ReceiverChallengeInput = AuthorityPresentationRequestInput;
export type ReceiverChallengeInput = z.infer<typeof ReceiverChallengeInput>;

export const AuthorityStatusCheckInput = z.object({
  binding_id: id('abn'),
  binding_claim_id: id('pc'),
  agent_id: z.string().regex(/^(ag|agt)_[\w-]+$/, 'agent_id must be ag_* or agt_*'),
  agent_key_thumbprint: Sha256Digest,
  /** The one Mission used by this exact transaction, selected from the binding's mission_ids. */
  mission_id: id('ms').optional(),
  action_uri: ActionIdentifier,
  receiver_request_id: z.string().min(22).max(256)
    .regex(/^[A-Za-z0-9_-]+$/, 'receiver_request_id must be a high-entropy base64url identifier'),
  resource_ref: z.string().min(1).max(2048).optional(),
  request_hash: Sha256Digest,
  /** Write-only transaction view; never returned by a status response. */
  normalized_request: JsonObject,
}).strict();
export type AuthorityStatusCheckInput = z.infer<typeof AuthorityStatusCheckInput>;

/** Write-only native receipt. Outcome and hashes are trusted only after signature verification. */
export const ReceiverReceiptInput = z.object({
  native_format: z.string().min(1).max(128),
  signed_receipt: z.string().min(1).max(1_000_000),
}).strict();
export type ReceiverReceiptInput = z.infer<typeof ReceiverReceiptInput>;

export const AuthorityPresentationView = z.object({
  id: id('prs'),
  authority_use_id: id('aus'),
  status: z.enum([
    'pending',
    'prepared',
    'delivered',
    'delivery_failed',
    'accepted',
    'rejected',
    'expired',
    'erased',
  ]),
  disclosure_manifest: z.array(z.object({
    fact_id: z.string(),
    mode: AuthorityDisclosureMode,
  })),
  proof_refs: z.array(z.object({
    proof_id: id('prf'),
    proof_version: z.number().int().positive(),
  }).strict()),
  expires_at: z.string().datetime(),
});
export type AuthorityPresentationView = z.infer<typeof AuthorityPresentationView>;

/**
 * Strict plaintext signed before receiver encryption. It may contain released
 * values, so it is never persisted or returned through an agent-facing API.
 */
const AuthorityDisclosedFactBase = z.object({
  fact_id: z.string().min(1).max(512),
  proof_id: id('prf'),
  assertion_source: z.enum(['issuer_native', 'adapter_derived', 'stack_derived']),
  proof_strength: z.enum(['native_issuer_evidence', 'native_stack_attestation']),
  provenance: JsonObject,
});

const AuthorityDisclosedFact = z.discriminatedUnion('mode', [
  AuthorityDisclosedFactBase.extend({
    mode: z.literal('exact_private'),
    assertion_source: z.literal('stack_derived'),
    proof_strength: z.literal('native_stack_attestation'),
    value: JsonValue,
  }).strict(),
  AuthorityDisclosedFactBase.extend({
    mode: z.literal('status_only'),
    assertion_source: z.literal('stack_derived'),
    proof_strength: z.literal('native_stack_attestation'),
    status: z.enum(['pending', 'active', 'suspended', 'revoked', 'replaced', 'erased', 'valid', 'unknown']),
  }).strict(),
  AuthorityDisclosedFactBase.extend({
    mode: z.literal('predicate'),
    assertion_source: z.literal('adapter_derived'),
    proof_strength: z.literal('native_stack_attestation'),
    value: z.boolean(),
    evidence_digest: Sha256Digest,
  }).strict(),
  AuthorityDisclosedFactBase.extend({
    mode: z.literal('pairwise'),
    assertion_source: z.literal('stack_derived'),
    proof_strength: z.literal('native_stack_attestation'),
    value: z.string().regex(/^hmac-sha256:[A-Za-z0-9_-]{43}$/, 'pairwise value must be a core keyed identifier'),
    evidence_digest: Sha256Digest,
    provenance: z.object({
      profile_version_id: id('apv'),
      method: z.literal('stack.core.hmac-sha256/v1'),
    }).strict(),
  }).strict(),
  AuthorityDisclosedFactBase.extend({
    mode: z.literal('issuer_evidence'),
    assertion_source: z.literal('issuer_native'),
    proof_strength: z.literal('native_issuer_evidence'),
    value: JsonValue,
    evidence_digest: Sha256Digest,
  }).strict(),
]);

export const AuthorityReceiverPresentationPayload = z.object({
  // The issuing deployment's origin; the signer pins it to its own (deployment().presentationIssuer).
  iss: z.string().url().max(2048),
  aud: z.string().min(1).max(1024),
  jti: id('pjt'),
  iat: z.number().int().nonnegative(),
  exp: z.number().int().positive(),
  authority_use_id: id('aus'),
  agent_id: z.string().regex(/^(ag|agt)_[\w-]+$/),
  agent_key_thumbprint: Sha256Digest,
  binding_ref: AuthorityReference,
  principal_ref: id('prn'),
  mission_id: id('ms').nullable(),
  action_uri: ActionIdentifier,
  resource_hash: Sha256Digest.nullable(),
  request_hash: Sha256Digest,
  receiver_id: id('rcv'),
  receiver_profile_version_id: id('apv'),
  domain_profile_version_id: id('apv').nullable(),
  proof_profile_version_ids: z.array(id('apv')).max(256),
  live_check_time: z.number().int().nonnegative(),
  evidence_refs: z.array(z.object({
    proof_id: id('prf'),
    proof_version: z.number().int().positive(),
    role: AuthorityProofRole,
    authoriser_principal_id: id('prn').nullable(),
    group_key_hash: Sha256Digest,
    profile_version_id: id('apv'),
    issuer_identifier: z.string().min(1).max(1024),
    schema_uri: z.string().min(1).max(1024),
    schema_version: z.string().min(1).max(128),
    assurance_uri: z.string().min(1).max(1024).nullable(),
    evidence_digest: Sha256Digest,
    evidence_modes: z.array(z.union([AuthorityDisclosureMode, z.literal('none')])).min(1).max(5),
    status: z.enum(['active', 'valid', 'unknown', 'revoked']),
  }).strict()).min(1).max(256),
  approval_claim_refs: z.array(z.object({
    claim_id: id('pc'),
    claim_hash: Sha256Digest,
    phase: z.enum(['activation', 'action', 'presentation']),
  }).strict()).max(256),
  approval_requirements: z.array(z.object({
    phase: z.enum(['activation', 'action', 'presentation']),
    group_key_hash: Sha256Digest,
    required_weight: z.number().int().positive(),
    collected_weight: z.number().int().nonnegative(),
    reject_mode: z.enum(['any_reject', 'threshold_reject']),
    request_hash: Sha256Digest,
    approval_requirement_hash: Sha256Digest,
    status: z.enum(['pending', 'satisfied', 'rejected', 'expired', 'consumed', 'cancelled']),
    decision_claim_refs: z.array(z.object({
      claim_id: id('pc'),
      claim_hash: Sha256Digest,
    }).strict()).max(256),
  }).strict().superRefine((requirement, ctx) => {
    if ((requirement.status === 'satisfied' || requirement.status === 'consumed')
      && requirement.collected_weight < requirement.required_weight) {
      ctx.addIssue({
        code: 'custom',
        message: 'satisfied approval requirement must meet its required weight',
        path: ['collected_weight'],
      });
    }
  })).max(256),
  proof_strength: z.enum([
    'native_issuer_evidence',
    'native_stack_attestation',
    'proxy_stack_enforced',
  ]),
  nonce: z.string().min(22).max(256).regex(/^[A-Za-z0-9_-]+$/),
  disclosed_facts: z.array(AuthorityDisclosedFact).max(256),
}).strict().superRefine((value, ctx) => {
  if (value.exp <= value.iat || value.exp - value.iat > 120) {
    ctx.addIssue({
      code: 'custom',
      message: 'receiver presentation expiry must be after issue and no more than 120 seconds',
      path: ['exp'],
    });
  }
  if (value.binding_ref.receiver_id !== value.receiver_id
    || value.binding_ref.receiver_profile_version_id !== value.receiver_profile_version_id) {
    ctx.addIssue({
      code: 'custom',
      message: 'receiver presentation does not match its authority reference',
      path: ['binding_ref'],
    });
  }
});
export type AuthorityReceiverPresentationPayload = z.infer<typeof AuthorityReceiverPresentationPayload>;
