import type { FastifyInstance } from 'fastify';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import {
  denyAgentContexts,
  requireOperatorAdmin,
} from '../middleware/require-platform.js';
import { createAuthorityProofCallbackAuth } from '../middleware/authority-proof-callback-auth.js';
import { createAuthorityReceiverAuth } from '../middleware/authority-receiver-auth.js';
import { decideApproval } from './authority-flows/approval-decision.js';
import {
  createApprovalRequests,
  listApprovalRequests,
} from './authority-flows/approval-requests.js';
import {
  activateBinding,
  createBinding,
  delegateBinding,
  eraseBinding,
  getBinding,
  listBindings,
  revokeBinding,
} from './authority-flows/bindings.js';
import {
  completeEnterpriseOidcApproval,
  rejectEnterpriseOidcRequest,
  reviewEnterpriseOidcRequest,
  startEnterpriseOidcApproval,
} from './authority-flows/enterprise-oidc-approval.js';
import {
  createEnterpriseOidcRequest,
  getEnterpriseOidcRequest,
} from './authority-flows/enterprise-oidc-requests.js';
import {
  archivePrincipal,
  createPrincipal,
  erasePrincipal,
  getPrincipal,
  listPrincipals,
} from './authority-flows/principals.js';
import {
  erasePresentation,
  getPresentation,
  listPresentations,
} from './authority-flows/presentations.js';
import {
  activateProfileVersion,
  createProfileVersion,
} from './authority-flows/profiles.js';
import {
  completeProofCallback,
  createProofCollectionSession,
  getProofCollectionSession,
} from './authority-flows/proof-collection.js';
import {
  eraseProof,
  getProof,
  importProof,
  listProofs,
  revokeProof,
} from './authority-flows/proofs.js';
import {
  acceptPresentationReceipt,
  checkAuthorityStatus,
  createPresentationRequest,
  getPresentationRequest,
} from './authority-flows/receiver-protocol.js';
import {
  addReceiverKey,
  createReceiver,
  createReceiverVerificationChallenge,
  getReceiver,
  listReceivers,
  revokeReceiverKey,
  verifyReceiver,
} from './authority-flows/receivers.js';
import { getUse, listUses } from './authority-flows/uses.js';

export { assertDashboardMutationOrigin } from './authority-flows/dashboard-author.js';
export { assertNormalizedNativeReceiverOrigin } from './authority-flows/receivers.js';

/**
 * Authority routes. This file declares every route with its auth options and
 * hands the body to the matching module in `authority-flows/`:
 * principals.ts, proofs.ts, proof-collection.ts, bindings.ts,
 * approval-requests.ts, receivers.ts, profiles.ts, uses.ts, presentations.ts,
 * enterprise-oidc-requests.ts (operator side), enterprise-oidc-approval.ts and
 * approval-decision.ts (cookie-only human side), receiver-protocol.ts (receiver
 * assertion side). Shared pieces: request-support.ts, schemas.ts,
 * mutation-actor.ts, dashboard-author.ts and setup-requests.ts.
 */

/** Operator-scoped authority management. No handler accepts operator_id. */
export function registerAuthorityRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);

  app.post(
    '/v1/authority/enterprise-oidc/requests',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request, reply) => {
      return createEnterpriseOidcRequest(services, request, reply);
    },
  );

  app.get<{ Params: { requestId: string } }>(
    '/v1/authority/enterprise-oidc/requests/:requestId',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request) => {
      return getEnterpriseOidcRequest(services, request);
    },
  );

  app.post('/v1/authority/principals', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] }, async (request, reply) => {
    return createPrincipal(services, request, reply);
  });

  app.get('/v1/authority/principals', { preHandler: [auth, denyAgentContexts] }, async (request) => {
    return listPrincipals(services, request);
  });

  app.get<{ Params: { principalId: string } }>(
    '/v1/authority/principals/:principalId',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      return getPrincipal(services, request);
    },
  );

  app.post<{ Params: { principalId: string } }>(
    '/v1/authority/principals/:principalId/archive',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request) => {
      return archivePrincipal(services, request);
    },
  );

  app.post<{ Params: { principalId: string } }>(
    '/v1/authority/principals/:principalId/erase',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request) => {
      return erasePrincipal(services, request);
    },
  );

  app.post('/v1/authority/proofs/import', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] }, async (request, reply) => {
    return importProof(services, request, reply);
  });

  app.post(
    '/v1/authority/proof-collection-sessions',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request, reply) => {
      return createProofCollectionSession(services, request, reply);
    },
  );

  app.get<{ Params: { sessionId: string } }>(
    '/v1/authority/proof-collection-sessions/:sessionId',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      return getProofCollectionSession(services, request);
    },
  );

  app.get('/v1/authority/proofs', { preHandler: [auth, denyAgentContexts] }, async (request) => {
    return listProofs(services, request);
  });

  app.get<{ Params: { proofId: string } }>(
    '/v1/authority/proofs/:proofId',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      return getProof(services, request);
    },
  );

  app.post<{ Params: { proofId: string } }>(
    '/v1/authority/proofs/:proofId/revoke',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request) => {
      return revokeProof(services, request);
    },
  );

  app.post<{ Params: { proofId: string } }>(
    '/v1/authority/proofs/:proofId/erase',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request) => {
      return eraseProof(services, request);
    },
  );

  app.post('/v1/authority/bindings', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] }, async (request, reply) => {
    return createBinding(services, request, reply);
  });

  app.get('/v1/authority/bindings', { preHandler: [auth, denyAgentContexts] }, async (request) => {
    return listBindings(services, request);
  });

  app.get<{ Params: { bindingId: string } }>(
    '/v1/authority/bindings/:bindingId',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      return getBinding(services, request);
    },
  );

  app.post<{ Params: { bindingId: string } }>(
    '/v1/authority/bindings/:bindingId/approval-requests',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request, reply) => {
      return createApprovalRequests(services, request, reply);
    },
  );

  app.get<{ Params: { bindingId: string } }>(
    '/v1/authority/bindings/:bindingId/approval-requests',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      return listApprovalRequests(services, request);
    },
  );

  app.post<{ Params: { bindingId: string } }>(
    '/v1/authority/bindings/:bindingId/activate',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request) => {
      return activateBinding(services, request);
    },
  );

  app.post<{ Params: { bindingId: string } }>(
    '/v1/authority/bindings/:bindingId/delegate',
    { preHandler: auth },
    async (request, reply) => {
      return delegateBinding(services, request, reply);
    },
  );

  app.post<{ Params: { bindingId: string } }>(
    '/v1/authority/bindings/:bindingId/revoke',
    { preHandler: auth },
    async (request, reply) => {
      return revokeBinding(services, request, reply);
    },
  );

  app.post<{ Params: { bindingId: string } }>(
    '/v1/authority/bindings/:bindingId/erase',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request) => {
      return eraseBinding(services, request);
    },
  );

  app.post('/v1/authority/receivers', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] }, async (request, reply) => {
    return createReceiver(services, request, reply);
  });

  app.get('/v1/authority/receivers', { preHandler: [auth, denyAgentContexts] }, async (request) => {
    return listReceivers(services, request);
  });

  app.get<{ Params: { receiverId: string } }>(
    '/v1/authority/receivers/:receiverId',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      return getReceiver(services, request);
    },
  );

  app.post<{ Params: { receiverId: string } }>(
    '/v1/authority/receivers/:receiverId/verification-challenges',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request, reply) => {
      return createReceiverVerificationChallenge(services, request, reply);
    },
  );

  app.post<{ Params: { receiverId: string } }>(
    '/v1/authority/receivers/:receiverId/verify',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request) => {
      return verifyReceiver(services, request);
    },
  );

  app.post<{ Params: { receiverId: string } }>(
    '/v1/authority/receivers/:receiverId/keys',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request, reply) => {
      return addReceiverKey(services, request, reply);
    },
  );

  app.post<{ Params: { receiverId: string; keyId: string } }>(
    '/v1/authority/receivers/:receiverId/keys/:keyId/revoke',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request) => {
      return revokeReceiverKey(services, request);
    },
  );

  app.post(
    '/v1/authority/profile-versions',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request, reply) => {
      return createProfileVersion(services, request, reply);
    },
  );

  app.post<{ Params: { profileId: string } }>(
    '/v1/authority/profile-versions/:profileId/activate',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request) => {
      return activateProfileVersion(services, request);
    },
  );

  app.get('/v1/authority/uses', { preHandler: [auth, denyAgentContexts] }, async (request) => {
    return listUses(services, request);
  });

  app.get<{ Params: { useId: string } }>(
    '/v1/authority/uses/:useId',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      return getUse(services, request);
    },
  );

  app.get('/v1/authority/presentations', { preHandler: [auth, denyAgentContexts] }, async (request) => {
    return listPresentations(services, request);
  });

  app.get<{ Params: { presentationId: string } }>(
    '/v1/authority/presentations/:presentationId',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      return getPresentation(services, request);
    },
  );

  app.post<{ Params: { presentationId: string } }>(
    '/v1/authority/presentations/:presentationId/erase',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request) => {
      return erasePresentation(services, request);
    },
  );
}

/** Provider callbacks use their pinned adapter ceremony, never operator or agent Bearer auth. */
export function registerAuthorityProofCallbackRoutes(app: FastifyInstance, services: Services) {
  const callbackAuth = createAuthorityProofCallbackAuth(services.authority);
  app.post<{ Params: { adapterKey: string } }>(
    '/v1/authority/proof-callbacks/:adapterKey',
    { preHandler: callbackAuth },
    async (request) => {
      return completeProofCallback(services, request);
    },
  );
}

/** STACK direct-post JWT v1. These receiver-signed routes never use operator auth. */
export function registerAuthorityReceiverRoutes(app: FastifyInstance, services: Services) {
  const receiverAuth = createAuthorityReceiverAuth(services.authority);

  app.post(
    '/v1/authority/presentation-requests',
    { preHandler: receiverAuth },
    async (request, reply) => {
      return createPresentationRequest(services, request, reply);
    },
  );

  app.get<{ Params: { presentationId: string } }>(
    '/v1/authority/presentation-requests/:presentationId',
    { preHandler: receiverAuth },
    async (request) => {
      return getPresentationRequest(services, request);
    },
  );

  app.post(
    '/v1/authority/status-checks',
    { preHandler: receiverAuth },
    async (request) => {
      return checkAuthorityStatus(services, request);
    },
  );

  app.post<{ Params: { presentationId: string } }>(
    '/v1/authority/presentations/:presentationId/receipts',
    { preHandler: receiverAuth },
    async (request) => {
      return acceptPresentationReceipt(services, request);
    },
  );
}

/**
 * Approval decisions are intentionally outside Bearer auth. The dashboard
 * cookie identifies the human; the authority service maps that server-derived
 * author to an eligible authorizer and validates the exact binding digest and
 * evidence. Neither identity nor eligibility is trusted from the body.
 */
export function registerAuthorityPublicRoutes(app: FastifyInstance, services: Services) {
  app.get<{ Params: { requestId: string } }>(
    '/v1/authority/enterprise-oidc/requests/:requestId/review',
    async (request) => {
      return reviewEnterpriseOidcRequest(services, request);
    },
  );

  app.post<{ Params: { requestId: string } }>(
    '/v1/authority/enterprise-oidc/requests/:requestId/reject',
    async (request) => {
      return rejectEnterpriseOidcRequest(services, request);
    },
  );

  app.post<{ Params: { requestId: string } }>(
    '/v1/authority/enterprise-oidc/requests/:requestId/start',
    async (request) => {
      return startEnterpriseOidcApproval(services, request);
    },
  );

  app.post<{ Params: { requestId: string } }>(
    '/v1/authority/enterprise-oidc/requests/:requestId/complete',
    async (request) => {
      return completeEnterpriseOidcApproval(services, request);
    },
  );

  app.post<{ Params: { approvalId: string } }>(
    '/v1/authority/approval-requests/:approvalId/decide',
    async (request) => {
      return decideApproval(services, request);
    },
  );
}
