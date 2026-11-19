import { describe, expect, it } from 'vitest';
import {
  authorityFlowSource,
  authorityHandlerSource,
  authoritySource,
} from './stage-flow/authority-source.js';
import { routeSource } from './stage-flow/flow-source.js';

// authority.ts declares every route with its auth options and calls one handler per route;
// the handler bodies and shared helpers live in authority-flows/. `source` is the registrar
// plus every module, and each section below is a registrar slice in which every route
// declaration is followed by the body of the handler it calls, so a route block reads as the
// route and its handler together.
const registrar = routeSource('authority.ts');
const source = authoritySource();
const callbackStart = registrar.indexOf('export function registerAuthorityProofCallbackRoutes');
const receiverStart = registrar.indexOf('export function registerAuthorityReceiverRoutes');
const publicStart = registrar.indexOf('export function registerAuthorityPublicRoutes');

function withHandlers(section: string): string {
  const starts = [...section.matchAll(/app\.(?:get|post)(?:<[^>]+>)?\(/g)].map((match) => match.index ?? 0);
  const blocks = starts.map((start, index) => {
    const block = section.slice(start, starts[index + 1] ?? section.length);
    const handlers = [...block.matchAll(/return (\w+)\(services, request/g)].map((match) => match[1]!);
    if (handlers.length !== 1) {
      throw new Error(`route block must call exactly one authority-flows handler: ${block.slice(0, 120)}`);
    }
    return `${block}\n${authorityHandlerSource(handlers[0]!)}`;
  });
  return section.slice(0, starts[0] ?? section.length) + blocks.join('\n');
}

const management = withHandlers(registrar.slice(0, callbackStart));
const proofCallback = withHandlers(registrar.slice(callbackStart, receiverStart));
const receiverProtocol = withHandlers(registrar.slice(receiverStart, publicStart));
const publicApproval = withHandlers(registrar.slice(publicStart));
// The handlers plus every shared helper module (request records, query schemas), the way the
// management slice used to include the helpers declared above its registrar.
const managementWithHelpers = `${management}\n${authorityFlowSource()}`;

function routeBlocks(text: string, method: 'get' | 'post'): string[] {
  const starts = [...text.matchAll(new RegExp(`app\\.${method}(?:<[^>]+>)?\\(`, 'g'))]
    .map((match) => match.index ?? 0);
  return starts.map((start, index) => text.slice(start, starts[index + 1] ?? text.length));
}

describe('authority route security contract', () => {
  it('exposes the exact proof collection, import, callback and approval-request routes', () => {
    for (const path of [
      '/v1/authority/proof-collection-sessions',
      '/v1/authority/proof-collection-sessions/:sessionId',
      '/v1/authority/proofs/import',
      '/v1/authority/proof-callbacks/:adapterKey',
      '/v1/authority/bindings/:bindingId/approval-requests',
    ]) {
      expect(source).toContain(path);
    }
    expect(source).not.toMatch(/app\.post\(\s*['"]\/v1\/authority\/proofs['"]/);
  });

  it('denies agent and partner-grant contexts on management routes other than narrow delegate/revoke', () => {
    const unguarded = [...routeBlocks(management, 'get'), ...routeBlocks(management, 'post')]
      .filter((block) => !block.includes('/bindings/:bindingId/delegate'))
      .filter((block) => !block.includes('/bindings/:bindingId/revoke'))
      .filter((block) => !block.includes('denyAgentContexts'))
      .map((block) => block.match(/['"](\/v1\/authority\/[^'"]+)/)?.[1] ?? 'unknown');
    expect(unguarded).toEqual([]);
  });

  it('allows agent mutation only through server-derived, service-enforced narrowing or own-chain revoke', () => {
    for (const path of [
      '/v1/authority/bindings/:bindingId/delegate',
      '/v1/authority/bindings/:bindingId/revoke',
    ]) {
      const block = routeBlocks(management, 'post').find((candidate) => candidate.includes(path));
      expect(block, `${path} is missing`).toBeDefined();
      expect(block).toContain('preHandler: auth');
      expect(block).toContain('authorityMutationActor(services, request');
      expect(block).not.toContain('denyAgentContexts');
    }
    expect(source).toContain("request.headers['x-passport-token']");
    expect(source).toContain('claims.stk.agent_id !== request.agentId');
    expect(source).not.toMatch(/request\.body[^\n]*passport_jti/);
  });

  it('reserves every human management write for owner or team admin', () => {
    const humanOnlyPaths = [
      '/v1/authority/principals',
      '/v1/authority/principals/:principalId/archive',
      '/v1/authority/principals/:principalId/erase',
      '/v1/authority/proof-collection-sessions',
      '/v1/authority/proofs/import',
      '/v1/authority/proofs/:proofId/revoke',
      '/v1/authority/proofs/:proofId/erase',
      '/v1/authority/bindings',
      '/v1/authority/bindings/:bindingId/approval-requests',
      '/v1/authority/bindings/:bindingId/activate',
      '/v1/authority/bindings/:bindingId/erase',
      '/v1/authority/receivers',
      '/v1/authority/receivers/:receiverId/verification-challenges',
      '/v1/authority/receivers/:receiverId/verify',
      '/v1/authority/receivers/:receiverId/keys',
      '/v1/authority/receivers/:receiverId/keys/:keyId/revoke',
      '/v1/authority/profile-versions',
      '/v1/authority/profile-versions/:profileId/activate',
      '/v1/authority/presentations/:presentationId/erase',
    ];
    for (const path of humanOnlyPaths) {
      const block = routeBlocks(management, 'post').find((candidate) => candidate.includes(path));
      expect(block, `${path} is missing`).toBeDefined();
      expect(block).toContain('requireOperatorAdmin');
    }
  });

  it('derives tenant scope from auth and never accepts operator_id on the wire', () => {
    expect(managementWithHelpers).not.toMatch(/request\.(?:body|query|params)[^\n]*operator_id/);
    for (const block of [...routeBlocks(management, 'get'), ...routeBlocks(management, 'post')]) {
      expect(block).toContain('request.operatorId');
    }
  });

  it('requires durable idempotency keys on every management mutation', () => {
    const withoutIdempotency = routeBlocks(management, 'post')
      .filter((block) => !block.includes('idempotencyKey(request)'))
      .map((block) => block.match(/['"](\/v1\/authority\/[^'"]+)/)?.[1] ?? 'unknown');
    expect(withoutIdempotency).toEqual([]);
  });

  it('creates pending Authority requests atomically so one idempotency key cannot race two bodies', () => {
    const block = routeBlocks(management, 'post').find((candidate) =>
      candidate.includes('/v1/authority/enterprise-oidc/requests'),
    );
    expect(block).toContain('createAuthorityRequest(services, record');
    expect(managementWithHelpers).toContain("'NX'");
    expect(block).toContain('raced.request_hash !== requestHash');
  });

  it('step-up gates activation and every irreversible authority erasure', () => {
    for (const path of [
      '/v1/authority/principals/:principalId/erase',
      '/v1/authority/proofs/:proofId/erase',
      '/v1/authority/bindings/:bindingId/erase',
      '/v1/authority/bindings/:bindingId/activate',
      '/v1/authority/receivers/:receiverId/keys',
      '/v1/authority/profile-versions/:profileId/activate',
      '/v1/authority/presentations/:presentationId/erase',
    ]) {
      const block = routeBlocks(management, 'post').find((candidate) => candidate.includes(path));
      expect(block, `${path} is missing`).toBeDefined();
      expect(block).toContain('requireOperatorAdmin');
      expect(block).toContain('enforceGovernanceStepUp');
      expect(block).toContain('idempotencyKey: mutationIdempotencyKey');
      expect(block?.match(/idempotencyKey\(request\)/g)).toHaveLength(1);
    }
  });

  it('reserves principal/proof invalidation for owner or team admin', () => {
    for (const path of [
      '/v1/authority/principals/:principalId/archive',
      '/v1/authority/proofs/:proofId/revoke',
    ]) {
      const block = routeBlocks(management, 'post').find((candidate) => candidate.includes(path));
      expect(block, `${path} is missing`).toBeDefined();
      expect(block).toContain('requireOperatorAdmin');
    }
  });

  it('keeps approval decision cookie-only and passes a server-derived author', () => {
    expect(publicApproval).not.toContain('createAuthMiddleware');
    expect(source).toContain('if (request.headers.authorization)');
    expect(source).toContain('assertDashboardMutationOrigin(request.headers.origin)');
    expect(source).toContain("session.aud !== 'stack:dashboard'");
    expect(source).toContain("member.status !== 'active'");
    expect(source).toContain("member.role !== 'standard' && member.role !== 'admin'");
    expect(publicApproval.match(/resolveDashboardAuthorityAuthor\(services, request\)/g)).toHaveLength(5);
    expect(publicApproval).toContain('authenticatedAuthor');
    expect(publicApproval).toContain('services.authority.decideApproval');
    expect(publicApproval).toContain('idempotencyKey(request)');
  });

  it('uses only receiver assertion auth on every receiver protocol route', () => {
    expect(receiverProtocol).not.toContain('createAuthMiddleware');
    expect(receiverProtocol).toContain('createAuthorityReceiverAuth(services.authority)');
    for (const block of [
      ...routeBlocks(receiverProtocol, 'get'),
      ...routeBlocks(receiverProtocol, 'post'),
    ]) {
      expect(block).toContain('preHandler: receiverAuth');
      expect(block).toContain('requireAuthorityReceiver(request)');
      expect(block).toContain('safeAuthorityResponse');
    }
  });

  it('uses only pinned adapter authentication on the proof callback', () => {
    expect(proofCallback).not.toContain('createAuthMiddleware');
    expect(proofCallback).toContain('createAuthorityProofCallbackAuth(services.authority)');
    expect(proofCallback).toContain('preHandler: callbackAuth');
    expect(proofCallback).toContain('AuthorityProofCallbackInput.parse(request.body)');
    expect(proofCallback).toContain('requireAuthorityProofCallback(request)');
    expect(proofCallback).toContain('safeAuthorityResponse');
    expect(proofCallback).not.toMatch(/writeAudit\(|request\.log|console\./);
  });

  it('does not echo or audit native normalized_request payloads', () => {
    expect(receiverProtocol).toContain('ReceiverChallengeInput.parse(request.body)');
    expect(receiverProtocol).toContain('createPresentationRequest(auth, input)');
    expect(receiverProtocol).toContain('AuthorityStatusCheckInput.parse(request.body)');
    expect(receiverProtocol).not.toContain('writeAudit(');
    expect(receiverProtocol).not.toMatch(/console\.|request\.log|reply\.send\(\s*(?:input|request\.body)/);
    expect(receiverProtocol).not.toMatch(/safeAuthorityResponse\(\{\s*(?:input|normalized_request)/);
  });

  it('runs every authority response through the PII-safe projection boundary', () => {
    const sends = [...source.matchAll(/safeAuthorityResponse\(\{/g)];
    // 4 principal + 5 proof + 6 binding + 1 approval response paths.
    expect(sends.length).toBeGreaterThanOrEqual(16);
    expect(source).not.toMatch(/resolvePii|payload_encrypted|native_evidence_encrypted/);
  });
});
