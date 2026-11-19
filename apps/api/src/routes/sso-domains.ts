import type { FastifyInstance } from 'fastify';
import {
  SsoDomainAddInput,
  SsoDomainError,
  canonicalize,
  normalizeDomain,
  sha256,
} from '@stack/shared';
import type { Services } from '../config/services.js';
import { auditCtx } from '../middleware/audit.js';
import { enforceGovernanceStepUp } from '../middleware/governance-stepup.js';
import { assertSsoAvailable } from './identity-flows/oidc-config.js';

/**
 * The verified e-mail domains of an account's single sign-on (spec/sso-login/SPEC.md section 9.5).
 *
 * Registered in the operator-admin scope (start.ts): an owner or an admin member, with agent contexts refused by the
 * scope, so no route here declares its own gate. The domain a sign-in counts as verified is the account's own claim,
 * proved by a DNS record; who may make the claim is governance, not an agent's work.
 *
 * Adding a domain is a governance step-up (`sso_domain_add`, browser-only): it is the one change here that loosens who
 * the account's provider may vouch for, and the approval names the exact domain. It is asked at the add, not at the
 * check: once approved, the record in DNS is the proof, and the periodic lookup that keeps a verified domain verified
 * must not wait on a person. Removing a domain only tightens, so it needs none.
 */
export function registerSsoDomainRoutes(app: FastifyInstance, services: Services) {
  // The domains of the account and the record each one is proved with.
  app.get('/v1/identity/sso-domains', async (request) => {
    return { domains: await services.ssoDomains.list(request.operatorId) };
  });

  // Claim a domain. Grants nothing until the record is seen (verify, or the next periodic lookup).
  app.post('/v1/identity/sso-domains', async (request, reply) => {
    const start = Date.now();
    const input = SsoDomainAddInput.parse(request.body);
    // A name that is not a domain is refused before anything is asked of a person or of the licence.
    const domain = normalizeDomain(input.domain);
    if (!domain) {
      throw new SsoDomainError('invalid', 'Enter an e-mail domain such as corp.example.com: a name, with no address, port or path.');
    }
    assertSsoAvailable(services);
    await enforceGovernanceStepUp(services, request, {
      action: 'sso_domain_add',
      resourceId: domain,
      payload: { domain },
      summary: `Treat e-mail addresses at ${domain} as verified for single sign-on once this account proves the domain with a DNS record. Anyone your identity provider signs in with such an address can then take the seat of the member with that address.`,
    });
    const added = await services.ssoDomains.add(request.operatorId, domain);
    if (added.created) {
      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: 'sso.domain.add',
        outcome: 'success',
        duration_ms: Date.now() - start,
        payload_hash: sha256(canonicalize({ domain })),
      });
    }
    return reply.code(added.created ? 201 : 200).send(added.domain);
  });

  // Look the record up now. Verifies the domain when it is there; answers what the lookup found either way.
  app.post<{ Params: { id: string } }>('/v1/identity/sso-domains/:id/verify', async (request) => {
    const start = Date.now();
    assertSsoAvailable(services);
    const result = await services.ssoDomains.verify(request.operatorId, request.params.id);
    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'vault',
      action: 'sso.domain.verify',
      outcome: result.check === 'confirmed' ? 'success' : 'failure',
      duration_ms: Date.now() - start,
      payload_hash: sha256(canonicalize({ domain: result.domain.domain, check: result.check })),
      ...(result.check === 'confirmed' ? {} : { error: { code: `SSO_DOMAIN_${result.check.toUpperCase()}`, message: 'The record was not confirmed by this lookup.' } }),
    });
    return result;
  });

  // Stop claiming a domain. Takes effect at once: the next sign-in no longer counts it.
  app.delete<{ Params: { id: string } }>('/v1/identity/sso-domains/:id', async (request, reply) => {
    const start = Date.now();
    const removed = await services.ssoDomains.remove(request.operatorId, request.params.id);
    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'vault',
      action: 'sso.domain.remove',
      outcome: 'success',
      duration_ms: Date.now() - start,
      payload_hash: sha256(canonicalize({ domain: removed.domain })),
    });
    return reply.code(204).send();
  });
}
