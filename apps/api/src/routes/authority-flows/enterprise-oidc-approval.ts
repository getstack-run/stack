import type { FastifyRequest } from 'fastify';
import { timingSafeEqual } from 'node:crypto';
import {
  ConflictError,
  CreateEnterpriseOidcAuthoritySetupInput,
  ForbiddenError,
  StackError,
  sha256,
} from '@stack/shared';
import { OidcIdpProvider } from '@stack/vault';
import { z } from 'zod';
import type { Services } from '../../config/services.js';
import {
  completeEnterpriseOidcAuthoritySetup,
  completeStripeIdentityAuthoritySetup,
  validateEnterpriseOidcAuthoritySetupRequest,
} from '../../services/enterprise-oidc-authority-setup.js';
import { resolveDashboardAuthorityAuthor, requireAuthorityAdmin } from './dashboard-author.js';
import { EmptyBody } from './schemas.js';
import {
  AUTHORITY_COMPLETED_REQUEST_TTL_SECONDS,
  AUTHORITY_SETUP_KEY,
  AuthoritySetupRequestParams,
  announceAuthorityDecision,
  assertAuthorityRequestPending,
  authorityApprovalUrl,
  authorityRequestProjection,
  authoritySetupKmsContext,
  loadAuthorityRequest,
  saveAuthorityRequest,
  type AuthoritySetupWorkflow,
} from './setup-requests.js';

/**
 * Cookie-only handlers for the human side of an Enterprise OIDC Authority
 * setup request: review, reject, start identity verification, complete it.
 */

type RequestIdRequest = FastifyRequest<{ Params: { requestId: string } }>;

const AuthoritySetupStartBody = z.object({
  browser_binding: z.string().length(43).regex(/^[A-Za-z0-9_-]+$/),
  method: z.enum(['company_sign_in', 'stripe_identity']),
}).strict();

const AuthoritySetupCompleteBody = z.object({
  session_ref: z.string().length(43).regex(/^[A-Za-z0-9_-]+$/),
  browser_binding: z.string().length(43).regex(/^[A-Za-z0-9_-]+$/),
  method: z.enum(['company_sign_in', 'stripe_identity']),
}).strict();

/**
 * The identity-verification approval method (the wire value `stripe_identity`, the key of the verification the
 * hosted product registers). A deployment offers it only when that provider is registered and ready: an install
 * registers none, and says so rather than naming a vendor it does not have.
 */
const VERIFICATION_METHOD = 'stripe_identity';

async function registeredVerificationMethod(services: Services, operatorId: string) {
  const providers = await services.identity.listProviders(operatorId);
  return providers.find((provider) => provider.provider_key === VERIFICATION_METHOD && provider.supported_layers.includes('identity'));
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

/**
 * The name its owner gave the connection a request is about, read now: the page shows the connection by it and not
 * by its id, only when the account has several connections of that service. Display only; nothing the request binds
 * is read from it. None when the connection cannot be read.
 */
async function liveConnectionName(services: Services, operatorId: string, connectionId: unknown): Promise<string | undefined> {
  if (typeof connectionId !== 'string') return undefined;
  try {
    return (await services.serviceConnection.connectionNameWhenSeveral(connectionId, operatorId)) || undefined;
  } catch {
    return undefined;
  }
}

export async function reviewEnterpriseOidcRequest(services: Services, request: RequestIdRequest) {
  const { operatorId, author } = await resolveDashboardAuthorityAuthor(services, request);
  requireAuthorityAdmin(author);
  const { requestId } = AuthoritySetupRequestParams.parse(request.params);
  const record = await loadAuthorityRequest(services, operatorId, requestId);
  const projection = authorityRequestProjection(record);
  const setupRequest = CreateEnterpriseOidcAuthoritySetupInput.parse(record.request);
  if (projection.status === 'pending') {
    await validateEnterpriseOidcAuthoritySetupRequest({ services, operatorId, request: setupRequest });
  }
  const [config, verificationMethod, connectionName] = await Promise.all([
    services.oidcIdpConfigRepo.findActiveByOperator(operatorId),
    registeredVerificationMethod(services, operatorId),
    liveConnectionName(services, operatorId, setupRequest.service_connection_id),
  ]);
  const approvalMethods = [
    ...(config ? [{
      method: 'company_sign_in' as const,
      name: config.display_name,
      issuer_uri: config.issuer_uri,
      role_source: 'identity_provider' as const,
    }] : []),
    ...(verificationMethod ? [{
      method: 'stripe_identity' as const,
      name: verificationMethod.name,
      price_cents: verificationMethod.price_cents,
      role_source: 'customer_assertion' as const,
    }] : []),
  ];
  return {
    ...projection,
    request: record.request,
    display: { ...record.display, ...(connectionName ? { connection_name: connectionName } : {}) },
    identity_provider: config ? {
      configured: true,
      display_name: config.display_name,
      issuer_uri: config.issuer_uri,
    } : { configured: false },
    approval_methods: approvalMethods,
  };
}

export async function rejectEnterpriseOidcRequest(services: Services, request: RequestIdRequest) {
  const { operatorId, author } = await resolveDashboardAuthorityAuthor(services, request);
  requireAuthorityAdmin(author);
  EmptyBody.parse(request.body ?? {});
  const { requestId } = AuthoritySetupRequestParams.parse(request.params);
  const record = await loadAuthorityRequest(services, operatorId, requestId);
  if (record.status === 'completed') {
    throw new ConflictError('This Authority request has already been approved');
  }
  if (record.status === 'rejected') return authorityRequestProjection(record);
  assertAuthorityRequestPending(record);
  const rejected = {
    ...record,
    status: 'rejected' as const,
    rejected_at: new Date().toISOString(),
  };
  await saveAuthorityRequest(services, rejected, AUTHORITY_COMPLETED_REQUEST_TTL_SECONDS);
  await services.audit.write({
    ctx: { trace_id: request.id, span_id: requestId, operator_id: operatorId,
      agent_id: String(record.request['agent_id'] ?? 'system'), passport_jti: 'none' },
    layer: 'vault', action: 'authority.enterprise_oidc.reject', outcome: 'success', duration_ms: 0,
  });
  await announceAuthorityDecision(services, rejected, 'rejected');
  return authorityRequestProjection(rejected);
}

export async function startEnterpriseOidcApproval(services: Services, request: RequestIdRequest) {
  const { operatorId, author } = await resolveDashboardAuthorityAuthor(services, request);
  requireAuthorityAdmin(author);
  const { requestId } = AuthoritySetupRequestParams.parse(request.params);
  const body = AuthoritySetupStartBody.parse(request.body);
  const record = await loadAuthorityRequest(services, operatorId, requestId);
  assertAuthorityRequestPending(record);
  if (record.status === 'completed') return authorityRequestProjection(record);
  let initiated: { session_ref?: string; verification_url?: string; expires_at: Date };
  if (body.method === 'company_sign_in') {
    services.features.require('sso');
    const provider = services.identity.getProvider('oidc');
    if (!(provider instanceof OidcIdpProvider)) {
      throw new StackError('Company sign-in is unavailable', 'SERVICE_UNAVAILABLE', 503);
    }
    const config = await services.oidcIdpConfigRepo.findActiveByOperator(operatorId);
    if (!config) {
      throw new ForbiddenError('Configure company sign-in under Security and sign-in before using it here');
    }
    initiated = await provider.initiate(operatorId, {
      requested_claims: ['verified_identity'],
      return_url: authorityApprovalUrl(requestId),
    } as never);
  } else {
    if (!await registeredVerificationMethod(services, operatorId)) {
      throw new ConflictError('No identity verification provider is registered on this installation; approve this request with company sign-in');
    }
    initiated = await services.identity.initiate(
      operatorId,
      VERIFICATION_METHOD,
      ['verified_identity'],
      `${authorityApprovalUrl(requestId)}?stripe_return=1`,
      { kind: 'authority', request_id: requestId },
    );
  }
  if (!initiated.session_ref || !initiated.verification_url) {
    throw new StackError('Identity verification could not be started', 'SERVICE_UNAVAILABLE', 503);
  }
  const workflow: AuthoritySetupWorkflow = {
    request_id: requestId,
    operator_id: operatorId,
    authenticated_author_hash: sha256(JSON.stringify(author)),
    browser_binding_hash: sha256(body.browser_binding),
    method: body.method,
  };
  const encrypted = await services.kms.encrypt(JSON.stringify(workflow),
    authoritySetupKmsContext(operatorId, initiated.session_ref!));
  await services.redis.set(
    AUTHORITY_SETUP_KEY + initiated.session_ref,
    encrypted.ciphertext,
    'EX',
    10 * 60,
  );
  await services.audit.write({
    ctx: { trace_id: request.id, span_id: initiated.session_ref!, operator_id: operatorId,
      agent_id: 'system', passport_jti: 'none' },
    layer: 'vault', action: 'authority.approval_verification.start', outcome: 'success', duration_ms: 0,
  });
  return {
    verification_url: initiated.verification_url,
    expires_at: initiated.expires_at.toISOString(),
    session_ref: initiated.session_ref,
    method: body.method,
  };
}

export async function completeEnterpriseOidcApproval(services: Services, request: RequestIdRequest) {
  const { operatorId, author, browserSession } = await resolveDashboardAuthorityAuthor(services, request);
  requireAuthorityAdmin(author);
  const { requestId } = AuthoritySetupRequestParams.parse(request.params);
  const body = AuthoritySetupCompleteBody.parse(request.body);
  const encrypted = await services.redis.get(AUTHORITY_SETUP_KEY + body.session_ref);
  if (!encrypted) throw new ForbiddenError('This Authority verification has expired or already been completed');
  const plaintext = await services.kms.decrypt(
    encrypted,
    authoritySetupKmsContext(operatorId, body.session_ref),
  ).catch(() => { throw new ForbiddenError('This Authority verification does not belong to this operator'); });
  let workflow = JSON.parse(plaintext) as AuthoritySetupWorkflow;
  const currentAuthorHash = sha256(JSON.stringify(author));
  if (workflow.request_id !== requestId
    || workflow.operator_id !== operatorId
    || workflow.authenticated_author_hash !== currentAuthorHash
    || workflow.method !== body.method
    || !constantTimeEqual(workflow.browser_binding_hash, sha256(body.browser_binding))) {
    throw new ForbiddenError('This Authority verification did not start in this browser or session');
  }
  if (workflow.result) return workflow.result;
  const record = await loadAuthorityRequest(services, operatorId, requestId);
  if (record.status === 'completed' && record.result) return record.result;
  assertAuthorityRequestPending(record);
  const setupRequest = CreateEnterpriseOidcAuthoritySetupInput.parse(record.request);
  let result: Awaited<ReturnType<typeof completeEnterpriseOidcAuthoritySetup>>;
  if (body.method === 'company_sign_in') {
    const provider = services.identity.getProvider('oidc');
    if (!(provider instanceof OidcIdpProvider)) {
      throw new StackError('Company sign-in is unavailable', 'SERVICE_UNAVAILABLE', 503);
    }
    const evidence = await provider.completeForAuthority(operatorId, body.session_ref);
    result = await completeEnterpriseOidcAuthoritySetup({
      services,
      operatorId,
      workflowId: requestId,
      author,
      browserSession,
      request: setupRequest,
      evidence,
    });
    await provider.discardAuthorityEvidence(body.session_ref);
  } else {
    let identityClaim = workflow.identity_claim_id
      ? (await services.identity.getValidClaims(operatorId)).find((claim) => claim.id === workflow.identity_claim_id)
      : undefined;
    if (!identityClaim) {
      const verification = await services.identity.complete(operatorId, VERIFICATION_METHOD, body.session_ref);
      if (!verification.success) {
        throw new ForbiddenError('Identity verification did not verify this person');
      }
      const createdClaimId = verification.claims.find((claim) => claim.layer === 'identity')?.id;
      if (!createdClaimId) throw new ForbiddenError('Identity verification did not return identity evidence');
      identityClaim = (await services.identity.getValidClaims(operatorId))
        .find((claim) => claim.id === createdClaimId);
      if (!identityClaim) throw new ForbiddenError('Verified identity evidence is unavailable');
      workflow = { ...workflow, identity_claim_id: identityClaim.id };
      const resumable = await services.kms.encrypt(
        JSON.stringify(workflow),
        authoritySetupKmsContext(operatorId, body.session_ref),
      );
      await services.redis.set(AUTHORITY_SETUP_KEY + body.session_ref, resumable.ciphertext, 'EX', 10 * 60);
      await services.identityVerificationCharge.charge(operatorId, VERIFICATION_METHOD, [identityClaim]);
    }
    result = await completeStripeIdentityAuthoritySetup({
      services,
      operatorId,
      workflowId: requestId,
      author,
      browserSession,
      request: setupRequest,
      identityClaim,
    });
  }
  const completedAt = new Date().toISOString();
  const completedRecord = { ...record, status: 'completed' as const, completed_at: completedAt, result };
  await saveAuthorityRequest(services, completedRecord, AUTHORITY_COMPLETED_REQUEST_TTL_SECONDS);
  await announceAuthorityDecision(services, completedRecord, 'approved');
  const completed: AuthoritySetupWorkflow = { ...workflow, result };
  const completedEncrypted = await services.kms.encrypt(
    JSON.stringify(completed),
    authoritySetupKmsContext(operatorId, body.session_ref),
  );
  await services.redis.set(
    AUTHORITY_SETUP_KEY + body.session_ref,
    completedEncrypted.ciphertext,
    'EX',
    10 * 60,
  );
  await services.audit.write({
    ctx: { trace_id: request.id, span_id: result.binding_id, operator_id: operatorId,
      agent_id: setupRequest.agent_id, passport_jti: 'none' },
    layer: 'vault', action: 'authority.approval_verification.complete', outcome: 'success', duration_ms: 0,
    payload_hash: result.binding_id,
  });
  return result;
}
