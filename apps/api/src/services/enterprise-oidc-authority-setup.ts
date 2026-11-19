import {
  canonicalize,
  ForbiddenError,
  NotFoundError,
  sha256,
  type AuthorityConstraint,
  type CreateEnterpriseOidcAuthoritySetupInput,
  type HumanOperatorAuthor,
} from '@stack/shared';
import {
  ENTERPRISE_OIDC_AUTHORITY_ADAPTER_KEY,
  ENTERPRISE_OIDC_AUTHORITY_ADAPTER_VERSION,
  STACK_IDENTITY_AUTHORITY_ADAPTER_KEY,
  STACK_IDENTITY_AUTHORITY_ADAPTER_VERSION,
  STACK_PROXY_BRIDGE_PROTOCOL_KEY,
  STACK_PROXY_BRIDGE_PROTOCOL_VERSION,
  authorityMandateTermsDigest,
  type VerifiedOidcAuthorityEvidence,
  type BrowserDecisionSession,
} from '@stack/vault';
import type { Services } from '../config/services.js';

const STACK_CEREMONY_ISSUER = 'stack:authority-ceremony';
const OIDC_PROOF_FORMAT = 'application/stack-authority-oidc+jwt';
const STACK_PRINCIPAL_FORMAT = 'application/stack-authority-principal+jwt';
const STACK_DECISION_FORMAT = 'application/stack-authority-decision+jwt';

interface SetupResult extends Record<string, unknown> {
  binding_id: string;
  binding_version: number;
  binding_status: string;
  organisation_principal_id: string;
  approver_principal_id: string;
  receiver_id: string;
  identity_proof_id: string;
  capacity_proof_id: string;
  approval_request_id: string;
  expires_at: string;
}

interface PreparedAuthorityEvidence {
  person: Record<string, unknown> & { id: string };
  organisation: Record<string, unknown> & { id: string };
  identityProof: Record<string, unknown> & { id: string; version: number };
  capacityProof: Record<string, unknown> & { id: string; version: number };
  organisationProof: Record<string, unknown> & { id: string; version: number };
  decisionProfile: Record<string, unknown> & { id: string };
  decisionSchemaUri: string;
  wrapperTtl: number;
}

function ttlSeconds(expiresAt: Date): number {
  return Math.max(1, Math.min(3600, Math.floor((expiresAt.getTime() - Date.now()) / 1000)));
}

function actionUri(provider: string, method: string, path: string): string {
  const resource = path.split('/').filter(Boolean).join('.')
    .replace(/[^A-Za-z0-9._-]/g, '-') || 'root';
  return `${provider}:http:${method.toLowerCase()}:${resource}`;
}

function proofProfile(input: {
  proofKind: 'identity' | 'capacity' | 'signature';
  schemaUri: string;
  issuer: string;
  signatureAlgorithms: string[];
  nativeFormats: string[];
  requiredClaimPaths: string[];
  subjectBinding: Record<string, unknown>;
  maximumAgeSeconds: number;
  adapterKey?: string;
  adapterVersion?: number;
  assuranceMapping?: Record<string, string>;
}) {
  return {
    proof_kind: input.proofKind,
    schema: { uri: input.schemaUri, version: '1' },
    adapter: {
      key: input.adapterKey ?? ENTERPRISE_OIDC_AUTHORITY_ADAPTER_KEY,
      version: input.adapterVersion ?? ENTERPRISE_OIDC_AUTHORITY_ADAPTER_VERSION,
    },
    accepted_native_formats: input.nativeFormats,
    validation: {
      accepted_issuer_ids: [input.issuer],
      accepted_signature_algs: input.signatureAlgorithms,
      signature_required: true,
      required_claim_paths: input.requiredClaimPaths,
      subject_binding: input.subjectBinding,
      status_method: { method: 'exp' },
    },
    assurance_mapping: input.assuranceMapping ?? {
      enterprise_oidc: 'urn:stack:assurance:enterprise-oidc',
      oidc_reauthenticated: 'urn:stack:assurance:oidc-reauthenticated',
      customer_asserted_organisation: 'urn:stack:assurance:customer-asserted-organisation',
    },
    freshness: { maximum_age_seconds: input.maximumAgeSeconds, live_status_required: true },
    disclosable_facts: [],
  };
}

async function createProfile(
  services: Services,
  operatorId: string,
  workflowId: string,
  suffix: string,
  profileKind: 'proof' | 'domain' | 'receiver',
  schemaUri: string,
  adapterKey: string,
  adapterVersion: number,
  config: Record<string, unknown>,
  receiverId?: string,
): Promise<Record<string, unknown> & { id: string }> {
  const created = await services.authority.createProfileVersion(operatorId, {
    profile_kind: profileKind,
    profile_key: `console.${suffix}.${workflowId}`,
    version: 1,
    ...(receiverId ? { receiver_id: receiverId } : {}),
    schema_uri: schemaUri,
    schema_version: '1',
    adapter_key: adapterKey,
    adapter_version: adapterVersion,
    config_json: config,
  } as never, `${workflowId}:profile:${suffix}`);
  return services.authority.activateProfileVersion(
    operatorId,
    profileKind,
    String(created.id),
    `${workflowId}:profile:${suffix}:activate`,
  ) as Promise<Record<string, unknown> & { id: string }>;
}

async function ensureProxyReceiver(
  services: Services,
  operatorId: string,
  workflowId: string,
  input: CreateEnterpriseOidcAuthoritySetupInput,
): Promise<{ id: string; current_profile_version_id: string | null }> {
  const canonicalIdentifier = `stack:service-connection:${input.service_connection_id}`;
  const existing = (await services.authority.listReceivers(operatorId)).find(
    (receiver) => receiver.mode === 'proxy_bridge'
      && receiver.status !== 'revoked'
      && receiver.canonical_identifier === canonicalIdentifier,
  );
  const receiver = existing ?? await services.authority.createReceiver(operatorId, {
    mode: 'proxy_bridge',
    canonical_identifier: canonicalIdentifier,
    display_name: input.provider,
    proxy_service_connection_id: input.service_connection_id,
  }, `${workflowId}:receiver`);
  if (receiver.status === 'active' && receiver.current_profile_version_id) {
    return { id: receiver.id, current_profile_version_id: receiver.current_profile_version_id };
  }
  const approvalPolicy = { version: '1', groups: [] };
  const config = {
    receiver_id: receiver.id,
    protocol: { key: STACK_PROXY_BRIDGE_PROTOCOL_KEY, version: STACK_PROXY_BRIDGE_PROTOCOL_VERSION },
    audience: `stack:proxy:${input.provider}`,
    service_connection_id: input.service_connection_id,
    approval_policy: approvalPolicy,
    live_status_required: true,
  };
  const profile = await createProfile(
    services,
    operatorId,
    workflowId,
    'proxy-receiver',
    'receiver',
    'urn:stack:authority:proxy-bridge-receiver',
    STACK_PROXY_BRIDGE_PROTOCOL_KEY,
    1,
    config,
    receiver.id,
  );
  return { id: receiver.id, current_profile_version_id: String(profile.id) };
}

function actorHash(author: HumanOperatorAuthor): string {
  return sha256(canonicalize(author));
}

function verifiedApproverLabel(payload: Record<string, unknown>): string {
  for (const claim of ['name', 'preferred_username', 'email']) {
    const value = payload[claim];
    if (typeof value === 'string' && value.trim()) return value.trim().slice(0, 256);
  }
  const subject = String(payload['sub'] ?? '');
  return `OIDC subject ${sha256(subject).slice(0, 12)}`;
}

export async function validateEnterpriseOidcAuthoritySetupRequest(input: {
  services: Services;
  operatorId: string;
  request: CreateEnterpriseOidcAuthoritySetupInput;
}): Promise<{ agentName: string; missionSummary: string | null }> {
  const { services, operatorId, request } = input;
  const now = new Date();
  const operator = await services.operator.getById(operatorId);
  if (!operator || operator.status !== 'active') {
    throw new ForbiddenError('Authority requires an active operator');
  }
  const agent = await services.agent.getById(request.agent_id, operatorId);
  if (agent.status !== 'active' || !agent.pubkey) {
    throw new ForbiddenError('The selected agent is not active and enrolled');
  }
  // The connection the request names, by id: with several of a provider "the provider's connection" is not one row.
  const connection = await services.serviceConnection.getConnectionScoped(request.service_connection_id, operatorId);
  if (
    !connection || connection.status !== 'active' || connection.member_id !== null
    || connection.provider !== request.provider || connection.proxy_enabled === false
  ) {
    throw new NotFoundError('ServiceConnection', request.service_connection_id);
  }
  const mission = request.mission_id ? await services.mission.findById(request.mission_id) : null;
  if (request.mission_id && (!mission || mission.operator_id !== operatorId || mission.completed_at
    || mission.revoked_at || mission.expires_at <= now)) {
    throw new NotFoundError('Mission', request.mission_id);
  }
  return {
    agentName: agent.name,
    missionSummary: mission?.intent_summary ?? null,
  };
}

async function finishAuthoritySetup(input: {
  services: Services;
  operatorId: string;
  workflowId: string;
  author: HumanOperatorAuthor;
  browserSession?: BrowserDecisionSession;
  request: CreateEnterpriseOidcAuthoritySetupInput;
  evidence: PreparedAuthorityEvidence;
}): Promise<SetupResult> {
  const { services, operatorId, workflowId, author, request, evidence } = input;
  const requestedExpiry = new Date(request.expires_at);
  const now = new Date();
  const receiver = await ensureProxyReceiver(services, operatorId, workflowId, request);
  const uri = actionUri(request.provider, request.http_method, request.resource_path);
  const normalizedSchema = {
    type: 'object',
    required: ['method', 'url', 'resource_type', 'resource_ref'],
    properties: {
      method: { const: request.http_method },
      url: {
        type: 'object',
        required: ['pathname'],
        properties: { pathname: { const: request.resource_path } },
        additionalProperties: true,
      },
      resource_type: { const: 'http_endpoint' },
      resource_ref: { type: 'string' },
    },
    additionalProperties: true,
  };
  const domainConfig = {
    domain: request.provider,
    actions: [{
      action_uri: uri,
      resource_types: ['http_endpoint'],
      normalized_request_schema: normalizedSchema,
      constraint_paths: request.constraints.map((constraint: AuthorityConstraint) => constraint.path),
    }],
    approval_templates: {},
    disclosure_templates: {},
    receipt_requirements: {},
  };
  const domainProfile = await createProfile(
    services,
    operatorId,
    workflowId,
    'domain',
    'domain',
    'urn:stack:authority:proxy-http-domain',
    'stack.core.domain',
    1,
    domainConfig,
  );
  const agentKeyThumbprint = await services.authority.resolveAgentKeyThumbprint(operatorId, request.agent_id);
  const approvalPolicy = { version: '1', groups: [{
    phase: 'activation',
    group_key: 'named_approver',
    required_weight: 1,
    reject_mode: 'any_reject',
    maximum_age_seconds: 300,
    final_step: false,
  }] };
  const disclosurePolicy = {
    rules: [],
    principal_confirmation_required: false,
    max_retention_seconds: 0,
    live_status_required: true,
  };
  const delegationPolicy = { allow_further_delegation: false, max_delegation_depth: 0 };
  const scope = {
    actions: [{
      action_uri: uri,
      resource_refs: [],
      constraints: request.constraints,
    }],
    limits: {},
  };
  const validFrom = new Date(now.getTime() - 5_000);
  const mandateDigest = authorityMandateTermsDigest({
    principalId: evidence.organisation.id,
    authoriserPrincipalIds: [evidence.person.id],
    agentId: request.agent_id,
    agentKeyThumbprint,
    receiverId: receiver.id,
    receiverProfileVersionId: receiver.current_profile_version_id!,
    domainProfileVersionId: String(domainProfile.id),
    missionIds: request.mission_id ? [request.mission_id] : [],
    purposeCode: 'customer.approved_job',
    purposeStatement: request.purpose,
    scope,
    approvalPolicy,
    disclosurePolicy,
    delegationPolicy,
    validFrom,
    expiresAt: requestedExpiry,
  });
  const mandateEnvelope = await services.signer.signAuthorityCeremony(evidence.person.id, {
    ceremony_type: 'authority_decision_evidence',
    operator_id: operatorId,
    represented_principal_id: evidence.organisation.id,
    decision_purpose: 'mandate',
    mandate_terms_digest: mandateDigest,
    identity_proof_id: evidence.identityProof.id,
    capacity_proof_id: evidence.capacityProof.id,
  }, evidence.wrapperTtl);
  const mandateProof = await services.authority.importProof(operatorId, {
    subject_principal_id: evidence.person.id,
    represented_principal_id: evidence.organisation.id,
    profile_version_id: String(evidence.decisionProfile.id),
    proof_kind: 'signature',
    issuer_identifier: STACK_CEREMONY_ISSUER,
    schema_uri: evidence.decisionSchemaUri,
    schema_version: '1',
    native_format: STACK_DECISION_FORMAT,
    native_evidence: mandateEnvelope,
  }, `${workflowId}:proof:mandate`);
  const binding = await services.authority.createBinding(operatorId, {
    principal_id: evidence.organisation.id,
    agent_id: request.agent_id,
    receiver_id: receiver.id,
    receiver_profile_version_id: receiver.current_profile_version_id!,
    domain_profile_version_id: String(domainProfile.id),
    mission_ids: request.mission_id ? [request.mission_id] : [],
    purpose_code: 'customer.approved_job',
    purpose_statement: request.purpose,
    scope,
    approval_policy: approvalPolicy,
    disclosure_policy: disclosurePolicy,
    delegation_policy: delegationPolicy,
    valid_from: validFrom,
    expires_at: requestedExpiry,
    proofs: [
      { proof_id: evidence.organisationProof.id, proof_version: evidence.organisationProof.version,
        role: 'principal_identity', group_key: 'named_approver', weight: 1, required: true, ordinal: 0 },
      { proof_id: evidence.identityProof.id, proof_version: evidence.identityProof.version,
        role: 'authoriser_identity', authoriser_principal_id: evidence.person.id,
        group_key: 'named_approver', weight: 1, required: true, ordinal: 1 },
      { proof_id: evidence.capacityProof.id, proof_version: evidence.capacityProof.version,
        role: 'authoriser_capacity', authoriser_principal_id: evidence.person.id,
        group_key: 'named_approver', weight: 1, required: true, ordinal: 2 },
      { proof_id: mandateProof.id, proof_version: mandateProof.version,
        role: 'mandate', group_key: 'named_approver', weight: 1, required: true, ordinal: 3 },
    ],
  }, `${workflowId}:binding`);
  const approvalRequests = await services.authority.createApprovalRequests(
    operatorId,
    binding.id,
    { phase: 'activation' },
    `${workflowId}:approval-request`,
  );
  const approval = approvalRequests.find((candidate) => candidate.status === 'pending');
  if (!approval) throw new ForbiddenError('Authority approval request is unavailable');
  const approvalEvidence = await services.signer.signAuthorityCeremony(evidence.person.id, {
    ceremony_type: 'authority_decision_evidence',
    operator_id: operatorId,
    represented_principal_id: evidence.organisation.id,
    decision_purpose: 'approval',
    mandate_terms_digest: approval.request_hash,
  }, evidence.wrapperTtl);
  const decisionProof = await services.authority.importProof(operatorId, {
    subject_principal_id: evidence.person.id,
    represented_principal_id: evidence.organisation.id,
    profile_version_id: String(evidence.decisionProfile.id),
    proof_kind: 'signature',
    issuer_identifier: STACK_CEREMONY_ISSUER,
    schema_uri: evidence.decisionSchemaUri,
    schema_version: '1',
    native_format: STACK_DECISION_FORMAT,
    native_evidence: approvalEvidence,
  }, `${workflowId}:proof:approval`);
  const signedDecision = await services.signer.signAuthorityCeremony(evidence.person.id, {
    ceremony_type: 'authority_approval_decision',
    operator_id: operatorId,
    request_id: approval.id,
    request_hash: approval.request_hash,
    decision: 'approve',
    authenticated_author_hash: actorHash(author),
    identity_proof_id: evidence.identityProof.id,
    identity_proof_version: evidence.identityProof.version,
    capacity_proof_id: evidence.capacityProof.id,
    capacity_proof_version: evidence.capacityProof.version,
    decision_proof_id: decisionProof.id,
    decision_proof_version: decisionProof.version,
  }, 300);
  await services.authority.decideApproval(operatorId, approval.id, author, {
    request_id: approval.id,
    decision: 'approve',
    request_hash: approval.request_hash,
    signed_decision: signedDecision,
  }, `${workflowId}:approval-decision`, input.browserSession);
  const active = await services.authority.activateBinding(
    operatorId,
    binding.id,
    binding.version,
    `${workflowId}:binding:activate`,
    input.browserSession,
  );
  return {
    binding_id: active.id,
    binding_version: active.version,
    binding_status: active.status,
    organisation_principal_id: evidence.organisation.id,
    approver_principal_id: evidence.person.id,
    receiver_id: receiver.id,
    identity_proof_id: evidence.identityProof.id,
    capacity_proof_id: evidence.capacityProof.id,
    approval_request_id: approval.id,
    expires_at: active.expires_at,
  };
}

export async function completeEnterpriseOidcAuthoritySetup(input: {
  services: Services;
  operatorId: string;
  workflowId: string;
  author: HumanOperatorAuthor;
  browserSession?: BrowserDecisionSession;
  request: CreateEnterpriseOidcAuthoritySetupInput;
  evidence: VerifiedOidcAuthorityEvidence;
}): Promise<SetupResult> {
  const { services, operatorId, workflowId, author, request, evidence } = input;
  const now = new Date();
  const requestedExpiry = new Date(request.expires_at);
  if (evidence.expires_at <= requestedExpiry) {
    throw new ForbiddenError('The requested Authority lasts longer than the verified identity-provider session');
  }
  await validateEnterpriseOidcAuthoritySetupRequest({
    services,
    operatorId,
    request,
  });

  const oidcIssuer = String(evidence.payload.iss ?? '');
  const oidcSubject = String(evidence.payload.sub ?? '');
  if (!oidcIssuer || !oidcSubject) throw new ForbiddenError('OIDC identity subject is unavailable');
  const proofExpiry = new Date(Math.min(evidence.expires_at.getTime(), now.getTime() + 60 * 60 * 1000));
  const wrapperTtl = ttlSeconds(proofExpiry);
  const person = await services.authority.createPrincipal(operatorId, {
    kind: 'person', label: verifiedApproverLabel(evidence.payload as Record<string, unknown>),
  }, `${workflowId}:principal:person`);
  const organisation = await services.authority.createPrincipal(operatorId, {
    kind: 'organisation', label: request.organisation_name,
  }, `${workflowId}:principal:organisation`);

  const identitySchema = 'urn:stack:authority:enterprise-oidc-identity';
  const capacitySchema = 'urn:stack:authority:enterprise-oidc-capacity';
  const decisionSchema = 'urn:stack:authority:oidc-decision';
  const identityConfig = proofProfile({
    proofKind: 'identity',
    schemaUri: identitySchema,
    issuer: oidcIssuer,
    signatureAlgorithms: [evidence.signature_algorithm],
    nativeFormats: [OIDC_PROOF_FORMAT],
    requiredClaimPaths: ['identity.subject_hash'],
    subjectBinding: { method: 'oidc_sub', oidc_config_id: evidence.config_id },
    maximumAgeSeconds: wrapperTtl,
  });
  const capacityConfig = proofProfile({
    proofKind: 'capacity',
    schemaUri: capacitySchema,
    issuer: oidcIssuer,
    signatureAlgorithms: [evidence.signature_algorithm],
    nativeFormats: [OIDC_PROOF_FORMAT],
    requiredClaimPaths: ['identity.subject_hash', 'capacity.role_verified'],
    subjectBinding: {
      method: 'oidc_claim',
      oidc_config_id: evidence.config_id,
      claim_path: request.role_claim_path,
      claim_value_hash: sha256(request.role_claim_value),
      role_name_hash: sha256(request.role_name),
    },
    maximumAgeSeconds: wrapperTtl,
  });
  const organisationIdentityConfig = proofProfile({
    proofKind: 'identity',
    schemaUri: 'urn:stack:authority:customer-asserted-organisation',
    issuer: STACK_CEREMONY_ISSUER,
    signatureAlgorithms: ['EdDSA'],
    nativeFormats: [STACK_PRINCIPAL_FORMAT],
    requiredClaimPaths: ['identity.principal_registered'],
    subjectBinding: { method: 'stack_principal_registration' },
    maximumAgeSeconds: wrapperTtl,
  });
  const decisionConfig = proofProfile({
    proofKind: 'signature',
    schemaUri: decisionSchema,
    issuer: STACK_CEREMONY_ISSUER,
    signatureAlgorithms: ['EdDSA'],
    nativeFormats: [STACK_DECISION_FORMAT],
    requiredClaimPaths: ['mandate_terms_digest'],
    subjectBinding: { method: 'oidc_reauthenticated_stack_decision' },
    maximumAgeSeconds: wrapperTtl,
  });
  const [identityProfile, capacityProfile, organisationProfile, decisionProfile] = await Promise.all([
    createProfile(services, operatorId, workflowId, 'identity', 'proof', identitySchema,
      ENTERPRISE_OIDC_AUTHORITY_ADAPTER_KEY, ENTERPRISE_OIDC_AUTHORITY_ADAPTER_VERSION, identityConfig),
    createProfile(services, operatorId, workflowId, 'capacity', 'proof', capacitySchema,
      ENTERPRISE_OIDC_AUTHORITY_ADAPTER_KEY, ENTERPRISE_OIDC_AUTHORITY_ADAPTER_VERSION, capacityConfig),
    createProfile(services, operatorId, workflowId, 'organisation', 'proof',
      'urn:stack:authority:customer-asserted-organisation', ENTERPRISE_OIDC_AUTHORITY_ADAPTER_KEY,
      ENTERPRISE_OIDC_AUTHORITY_ADAPTER_VERSION, organisationIdentityConfig),
    createProfile(services, operatorId, workflowId, 'decision', 'proof', decisionSchema,
      ENTERPRISE_OIDC_AUTHORITY_ADAPTER_KEY, ENTERPRISE_OIDC_AUTHORITY_ADAPTER_VERSION, decisionConfig),
  ]);

  const oidcSubjectHash = sha256(`${oidcIssuer}\u0000${oidcSubject}`);
  const sharedOidcClaims = {
    ceremony_type: 'oidc_authority_evidence',
    operator_id: operatorId,
    oidc_config_id: evidence.config_id,
    oidc_id_token: evidence.id_token,
    oidc_nonce: evidence.nonce,
    oidc_subject_hash: oidcSubjectHash,
  };
  const [identityEnvelope, capacityEnvelope, organisationEnvelope] = await Promise.all([
    services.signer.signAuthorityCeremony(person.id, {
      ...sharedOidcClaims,
      proof_kind: 'identity',
    }, wrapperTtl),
    services.signer.signAuthorityCeremony(person.id, {
      ...sharedOidcClaims,
      proof_kind: 'capacity',
      represented_principal_id: organisation.id,
      role_name: request.role_name,
    }, wrapperTtl),
    services.signer.signAuthorityCeremony(organisation.id, {
      ceremony_type: 'stack_principal_identity',
      operator_id: operatorId,
      registration_hash: sha256(canonicalize({
        organisation_principal_id: organisation.id,
        organisation_name: request.organisation_name,
        created_by: actorHash(author),
      })),
    }, wrapperTtl),
  ]);
  const [identityProof, capacityProof, organisationProof] = await Promise.all([
    services.authority.importProof(operatorId, {
      subject_principal_id: person.id,
      profile_version_id: String(identityProfile.id),
      proof_kind: 'identity',
      issuer_identifier: oidcIssuer,
      schema_uri: identitySchema,
      schema_version: '1',
      native_format: OIDC_PROOF_FORMAT,
      native_evidence: identityEnvelope,
    }, `${workflowId}:proof:identity`),
    services.authority.importProof(operatorId, {
      subject_principal_id: person.id,
      represented_principal_id: organisation.id,
      profile_version_id: String(capacityProfile.id),
      proof_kind: 'capacity',
      issuer_identifier: oidcIssuer,
      schema_uri: capacitySchema,
      schema_version: '1',
      native_format: OIDC_PROOF_FORMAT,
      native_evidence: capacityEnvelope,
    }, `${workflowId}:proof:capacity`),
    services.authority.importProof(operatorId, {
      subject_principal_id: organisation.id,
      profile_version_id: String(organisationProfile.id),
      proof_kind: 'identity',
      issuer_identifier: STACK_CEREMONY_ISSUER,
      schema_uri: 'urn:stack:authority:customer-asserted-organisation',
      schema_version: '1',
      native_format: STACK_PRINCIPAL_FORMAT,
      native_evidence: organisationEnvelope,
    }, `${workflowId}:proof:organisation`),
  ]);

  return finishAuthoritySetup({
    services,
    operatorId,
    workflowId,
    author,
    browserSession: input.browserSession,
    request,
    evidence: {
      person,
      organisation,
      identityProof,
      capacityProof,
      organisationProof,
      decisionProfile,
      decisionSchemaUri: decisionSchema,
      wrapperTtl,
    },
  });
}

export async function completeStripeIdentityAuthoritySetup(input: {
  services: Services;
  operatorId: string;
  workflowId: string;
  author: HumanOperatorAuthor;
  browserSession?: BrowserDecisionSession;
  request: CreateEnterpriseOidcAuthoritySetupInput;
  identityClaim: {
    id: string;
    provider_key: string;
    layer: string;
    assurance_level: string;
    verified_at: Date;
    expires_at: Date;
    claim_id: string | null;
  };
}): Promise<SetupResult> {
  const { services, operatorId, workflowId, author, request, identityClaim } = input;
  const now = new Date();
  const requestedExpiry = new Date(request.expires_at);
  if (identityClaim.provider_key !== 'stripe_identity'
    || identityClaim.layer !== 'identity'
    || !identityClaim.claim_id
    || identityClaim.expires_at <= now) {
    throw new ForbiddenError('A current identity verification is required');
  }
  if (identityClaim.expires_at <= requestedExpiry) {
    throw new ForbiddenError('The requested Authority lasts longer than the verified identity');
  }
  await validateEnterpriseOidcAuthoritySetupRequest({ services, operatorId, request });

  const proofExpiry = new Date(Math.min(identityClaim.expires_at.getTime(), now.getTime() + 60 * 60 * 1000));
  const wrapperTtl = ttlSeconds(proofExpiry);
  const person = await services.authority.createPrincipal(operatorId, {
    kind: 'person',
    label: `Stripe-verified person ${sha256(identityClaim.id).slice(0, 12)}`,
  }, `${workflowId}:principal:person`);
  const organisation = await services.authority.createPrincipal(operatorId, {
    kind: 'organisation', label: request.organisation_name,
  }, `${workflowId}:principal:organisation`);

  const identitySchema = 'urn:stack:authority:stripe-identity';
  const capacitySchema = 'urn:stack:authority:customer-asserted-capacity';
  const organisationSchema = 'urn:stack:authority:customer-asserted-organisation';
  const decisionSchema = 'urn:stack:authority:identity-decision';
  const identityBindingJws = await services.signer.signAuthorityCeremony(person.id, {
    ceremony_type: 'identity_claim_authority_binding',
    operator_id: operatorId,
    identity_claim_id: identityClaim.id,
    signed_claim_id: identityClaim.claim_id,
    provider_key: identityClaim.provider_key,
  }, wrapperTtl);
  const identityConfig = proofProfile({
    proofKind: 'identity',
    schemaUri: identitySchema,
    issuer: identityClaim.provider_key,
    signatureAlgorithms: ['EdDSA'],
    nativeFormats: ['stack/legacy-identity-claim-ref'],
    requiredClaimPaths: [],
    subjectBinding: { method: 'stack_identity_claim_ceremony', binding_jws: identityBindingJws },
    maximumAgeSeconds: wrapperTtl,
    adapterKey: STACK_IDENTITY_AUTHORITY_ADAPTER_KEY,
    adapterVersion: STACK_IDENTITY_AUTHORITY_ADAPTER_VERSION,
    assuranceMapping: {
      [identityClaim.assurance_level]: `urn:stack:assurance:${identityClaim.assurance_level}`,
    },
  });
  const commonStackProfile = (proofKind: 'identity' | 'capacity' | 'signature', schemaUri: string,
    nativeFormat: string, requiredClaimPaths: string[]) => proofProfile({
    proofKind,
    schemaUri,
    issuer: STACK_CEREMONY_ISSUER,
    signatureAlgorithms: ['EdDSA'],
    nativeFormats: [nativeFormat],
    requiredClaimPaths,
    subjectBinding: { method: 'stack_signed_ceremony' },
    maximumAgeSeconds: wrapperTtl,
    adapterKey: STACK_IDENTITY_AUTHORITY_ADAPTER_KEY,
    adapterVersion: STACK_IDENTITY_AUTHORITY_ADAPTER_VERSION,
    assuranceMapping: {
      customer_asserted_capacity: 'urn:stack:assurance:customer-asserted-capacity',
      customer_asserted_organisation: 'urn:stack:assurance:customer-asserted-organisation',
      provider_verified_human_decision: 'urn:stack:assurance:provider-verified-human-decision',
    },
  });
  const [identityProfile, capacityProfile, organisationProfile, decisionProfile] = await Promise.all([
    createProfile(services, operatorId, workflowId, 'identity', 'proof', identitySchema,
      STACK_IDENTITY_AUTHORITY_ADAPTER_KEY, STACK_IDENTITY_AUTHORITY_ADAPTER_VERSION, identityConfig),
    createProfile(services, operatorId, workflowId, 'capacity', 'proof', capacitySchema,
      STACK_IDENTITY_AUTHORITY_ADAPTER_KEY, STACK_IDENTITY_AUTHORITY_ADAPTER_VERSION,
      commonStackProfile('capacity', capacitySchema, 'application/stack-authority-capacity+jwt',
        ['capacity.role_asserted'])),
    createProfile(services, operatorId, workflowId, 'organisation', 'proof', organisationSchema,
      STACK_IDENTITY_AUTHORITY_ADAPTER_KEY, STACK_IDENTITY_AUTHORITY_ADAPTER_VERSION,
      commonStackProfile('identity', organisationSchema, STACK_PRINCIPAL_FORMAT,
        ['identity.principal_registered'])),
    createProfile(services, operatorId, workflowId, 'decision', 'proof', decisionSchema,
      STACK_IDENTITY_AUTHORITY_ADAPTER_KEY, STACK_IDENTITY_AUTHORITY_ADAPTER_VERSION,
      commonStackProfile('signature', decisionSchema, STACK_DECISION_FORMAT, ['mandate_terms_digest'])),
  ]);

  const identityProof = await services.authority.createLegacyIdentityProofFacade(operatorId, {
    identity_claim_id: identityClaim.id,
    subject_principal_id: person.id,
    profile_version_id: String(identityProfile.id),
  }, `${workflowId}:proof:identity`);
  const [capacityEnvelope, organisationEnvelope] = await Promise.all([
    services.signer.signAuthorityCeremony(person.id, {
      ceremony_type: 'customer_asserted_capacity',
      operator_id: operatorId,
      represented_principal_id: organisation.id,
      role_name: request.role_name,
      assertion_hash: sha256(canonicalize({
        organisation_principal_id: organisation.id,
        organisation_name: request.organisation_name,
        role_name: request.role_name,
        asserted_by: actorHash(author),
        identity_claim_id: identityClaim.id,
      })),
    }, wrapperTtl),
    services.signer.signAuthorityCeremony(organisation.id, {
      ceremony_type: 'stack_principal_identity',
      operator_id: operatorId,
      registration_hash: sha256(canonicalize({
        organisation_principal_id: organisation.id,
        organisation_name: request.organisation_name,
        created_by: actorHash(author),
      })),
    }, wrapperTtl),
  ]);
  const [capacityProof, organisationProof] = await Promise.all([
    services.authority.importProof(operatorId, {
      subject_principal_id: person.id,
      represented_principal_id: organisation.id,
      profile_version_id: String(capacityProfile.id),
      proof_kind: 'capacity',
      issuer_identifier: STACK_CEREMONY_ISSUER,
      schema_uri: capacitySchema,
      schema_version: '1',
      native_format: 'application/stack-authority-capacity+jwt',
      native_evidence: capacityEnvelope,
    }, `${workflowId}:proof:capacity`),
    services.authority.importProof(operatorId, {
      subject_principal_id: organisation.id,
      profile_version_id: String(organisationProfile.id),
      proof_kind: 'identity',
      issuer_identifier: STACK_CEREMONY_ISSUER,
      schema_uri: organisationSchema,
      schema_version: '1',
      native_format: STACK_PRINCIPAL_FORMAT,
      native_evidence: organisationEnvelope,
    }, `${workflowId}:proof:organisation`),
  ]);

  return finishAuthoritySetup({
    services,
    operatorId,
    workflowId,
    author,
    browserSession: input.browserSession,
    request,
    evidence: {
      person,
      organisation,
      identityProof,
      capacityProof,
      organisationProof,
      decisionProfile,
      decisionSchemaUri: decisionSchema,
      wrapperTtl,
    },
  });
}
