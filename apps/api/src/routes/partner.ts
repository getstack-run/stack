// Partner-managed accounts, REST surface.
//
// All routes mounted under /v1/partner/* inside an encapsulation block
// gated by requirePartner. A non-partner operator's API key gets 403
// before the handler runs. Inside the handler, every account operation
// additionally re-checks ownership via PartnerTenantService.assertTenantOwnership
// — a partner cannot operate on an account it doesn't own even if it
// knows the id.
//
// Resources:
//   - Accounts:   POST/GET   /v1/partner/accounts[/:id]            (open one under the partner's own reference)
//                 DELETE     /v1/partner/accounts/:id              (close it)
//                 POST       /v1/partner/accounts/:account_id/rotate-key
//                 POST       /v1/partner/accounts/:account_id/invite   (invite the customer to see it)
//   - Webhooks:   POST       /v1/partner/accounts/:account_id/inbound-webhooks
//                 GET        /v1/partner/accounts/:account_id/inbound-webhooks
//                 DELETE     /v1/partner/accounts/:account_id/inbound-webhooks/:wh_id
//   - Passports:  POST       /v1/partner/accounts/:account_id/passports/issue
//
// Releasing an account to its customer (`/release`) is STACK's hosted deployment only, because the customer's claim
// runs the platform checkout.
//
// Audit: every mutating call writes an audit row on the PARTNER's chain
// (partner is the actor). Resource creation under an account ALSO writes
// to the account's own chain via the underlying service.

import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  CreateInboundWebhookInput,
  IssuePassportInput,
  NotFoundError,
  PARTNER_INVITE_ROLE,
  PartnerAccountCreateInput,
  PartnerAccountInviteInput,
  ForbiddenError,
  memberInviteEmail,
  takePartnerMailSlot,
} from '@stack/shared';
import type { Services } from '../config/services.js';
import { env } from '../config/env.js';
import { meterAction } from '../middleware/meter.js';
import { auditCtx } from '../middleware/audit.js';
import { requireOperatorAdmin } from '../middleware/require-platform.js';
import { resolveMemberInviteBaseUrl } from './members.js';

const AccountParams = z.object({ account_id: z.string().min(1).max(64) }).strict();
const AccountIdParams = z.object({ id: z.string().min(1).max(64) }).strict();
const WebhookParams = AccountParams.extend({ wh_id: z.string().min(1).max(64) });
const ListQuery = z.object({ external_ref: z.string().min(1).max(256).optional() }).strict();

// `tier` is read only to be refused by name (TENANT_TIER_NOT_ALLOWED), not as an unknown key.
const CreateAccountBody = PartnerAccountCreateInput.extend({ tier: z.unknown().optional() });

export function registerPartnerRoutes(app: FastifyInstance, services: Services) {
  // ─── Accounts ────────────────────────────────────────────────────
  //
  // An account is billed like any customer, with the partner as the payer (the hosted billing account): its own plan
  // and free amounts, and what it costs is taken from the partner's wallet. `tier` is accepted by the schema only so
  // the service can refuse it by name (TENANT_TIER_NOT_ALLOWED) instead of an opaque unknown-key error.

  // Opening is idempotent on the partner's own reference: a repeat answers 200 with the account that exists and no key.
  app.post('/v1/partner/accounts', async (request, reply) => {
    const body = CreateAccountBody.parse(request.body ?? {});
    const start = Date.now();
    const result = await services.partnerTenants.createTenant(request.operatorId, body);
    if (result.created) {
      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: 'partner.account.create',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });
    }
    return reply.status(result.created ? 201 : 200).header('Cache-Control', 'no-store').send(result);
  });

  app.get('/v1/partner/accounts', async (request) => {
    const query = ListQuery.parse(request.query ?? {});
    const accounts = await services.partnerTenants.listTenants(request.operatorId, {
      ...(query.external_ref !== undefined ? { externalRef: query.external_ref } : {}),
    });
    return { accounts };
  });

  app.get('/v1/partner/accounts/:id', async (request) => {
    const { id } = AccountIdParams.parse(request.params);
    return services.partnerTenants.getTenant(id, request.operatorId);
  });

  app.delete('/v1/partner/accounts/:id', async (request, reply) => {
    const { id } = AccountIdParams.parse(request.params);
    const start = Date.now();
    const result = await services.partnerTenants.revokeTenant(id, request.operatorId);
    // The cascade runs on every call, not only on the transition, so a
    // retried DELETE finishes a cascade that failed part-way. Each step
    // is idempotent.
    const cascade = await revokeAccountCascade(services, id);
    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'vault',
      action: 'partner.account.revoke',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });
    return reply.send({ ...result, ...cascade });
  });

  // A new key for an account the partner opened, for a partner that lost the one the create showed. It is a
  // credential, so it is never reached with OAuth and needs an owner or administrator of the partner account.
  app.post(
    '/v1/partner/accounts/:account_id/rotate-key',
    { preHandler: requireOperatorAdmin },
    async (request, reply) => {
      if (request.oauthScope !== undefined) {
        throw new ForbiddenError('Rotating an account key requires direct partner administrator authentication');
      }
      const { account_id } = AccountParams.parse(request.params);
      const start = Date.now();
      const result = await services.partnerTenants.rotateKey(account_id, request.operatorId);
      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: 'partner.account.key_rotate',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });
      return reply.header('Cache-Control', 'no-store').send(result);
    },
  );

  // Invite the customer to see the account. The address is the one the partner gives at this moment; it is stored as
  // the invited person's (the account's one stored address of a person) and becomes the customer's by their own
  // act of accepting. They see the account and change nothing: the role is read-only.
  app.post('/v1/partner/accounts/:account_id/invite', async (request, reply) => {
    const { account_id } = AccountParams.parse(request.params);
    const input = PartnerAccountInviteInput.parse(request.body);
    const account = await services.partnerTenants.assertTenantOwnership(account_id, request.operatorId);
    services.features.require('roles');
    const dashboardUrl = resolveMemberInviteBaseUrl(env.DASHBOARD_URL, env.NODE_ENV);
    if (!dashboardUrl || !services.authEmail) {
      return reply.status(503).send({ error: { code: 'SERVICE_UNAVAILABLE', message: 'Invitation email is not configured.' } });
    }
    const partner = await services.operator.getById(request.operatorId);
    if (input.email === partner.email.trim().toLowerCase() || input.email.endsWith('.stack-tenant.local')) {
      throw new ForbiddenError('This address cannot be invited to an account.');
    }
    await takePartnerMailSlot(services.redis, request.operatorId);
    const start = Date.now();
    const { member, inviteToken } = await services.member.invite(
      account.id,
      { email: input.email, name: input.name ?? input.email.split('@')[0]!, role: PARTNER_INVITE_ROLE },
    );
    const inviteUrl = new URL('/team/invite', dashboardUrl);
    inviteUrl.hash = `token=${encodeURIComponent(inviteToken)}`;
    const message = memberInviteEmail({ inviterEmail: partner.email, inviteUrl: inviteUrl.toString() });
    try {
      await services.authEmail.sendEmail(member.email, message.subject, message.text, message.html, { skipSignature: true });
    } catch {
      await services.member.revoke(member.id, account.id);
      return reply.status(502).send({ error: { code: 'SERVICE_UNAVAILABLE', message: 'The invitation could not be delivered. Try again.' } });
    }
    for (const operatorId of [request.operatorId, account.id]) {
      await services.audit.write({
        ctx: { ...auditCtx(request), operator_id: operatorId },
        layer: 'vault',
        action: 'partner.account.invite',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });
    }
    return reply.status(201).send({ status: 'invited', expires_at: member.invite_expires_at?.toISOString() ?? null });
  });

  // ─── Inbound webhooks under an account ───────────────────────────

  app.post('/v1/partner/accounts/:account_id/inbound-webhooks', async (request, reply) => {
    const { account_id } = AccountParams.parse(request.params);
    const input = CreateInboundWebhookInput.parse(request.body);
    // Ownership: partner owns this account.
    await services.partnerTenants.assertTenantOwnership(account_id, request.operatorId);
    const start = Date.now();
    // Provision under the ACCOUNT's operator id, not the partner's.
    // This roots the webhook's audit chain + KMS context to the account.
    const result = await services.inboundWebhooks.create(account_id, input);
    await services.audit.write({
      ctx: auditCtx(request, { agent_id: input.agent_id }),
      layer: 'vault',
      action: 'partner.account.inbound_webhook.create',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });
    return reply.status(201).send(result);
  });

  app.get('/v1/partner/accounts/:account_id/inbound-webhooks', async (request) => {
    const { account_id } = AccountParams.parse(request.params);
    await services.partnerTenants.assertTenantOwnership(account_id, request.operatorId);
    const webhooks = await services.inboundWebhooks.list(account_id);
    return { webhooks };
  });

  app.delete('/v1/partner/accounts/:account_id/inbound-webhooks/:wh_id', async (request, reply) => {
    const { account_id, wh_id } = WebhookParams.parse(request.params);
    await services.partnerTenants.assertTenantOwnership(account_id, request.operatorId);
    const start = Date.now();
    const result = await services.inboundWebhooks.revoke(wh_id, account_id);
    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'vault',
      action: 'partner.account.inbound_webhook.revoke',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });
    return reply.send(result);
  });

  app.post(
    '/v1/partner/accounts/:account_id/inbound-webhooks/:wh_id/rotate-secret',
    { preHandler: requireOperatorAdmin },
    async (request, reply) => {
      if (request.oauthScope !== undefined) {
        throw new ForbiddenError('Rotating a signing secret requires direct partner administrator authentication');
      }
      const { account_id, wh_id } = WebhookParams.parse(request.params);
      await services.partnerTenants.assertTenantOwnership(account_id, request.operatorId);
      const start = Date.now();
      const result = await services.inboundWebhooks.rotateDownstreamSecret(wh_id, account_id);
      await services.audit.write({
        ctx: auditCtx(request), layer: 'vault', action: 'partner.account.inbound_webhook.secret_rotate',
        outcome: 'success', duration_ms: Date.now() - start,
      });
      return reply.header('Cache-Control', 'no-store').send(result);
    },
  );

  app.put(
    '/v1/partner/accounts/:account_id/inbound-webhooks/:wh_id/provider-signing-secret',
    { preHandler: requireOperatorAdmin },
    async (request) => {
      if (request.oauthScope !== undefined) {
        throw new ForbiddenError('Signing configuration requires direct partner administrator authentication');
      }
      const { account_id, wh_id } = WebhookParams.parse(request.params);
      const input = z.object({
        signing_secret: z.string().min(1).max(256),
        downstream_signing_secret: z.string().min(1).max(256).optional(),
      }).strict().parse(request.body);
      await services.partnerTenants.assertTenantOwnership(account_id, request.operatorId);
      const start = Date.now();
      const result = await services.inboundWebhooks.setProviderSigningSecret(
        wh_id, account_id, input.signing_secret, input.downstream_signing_secret,
      );
      await services.audit.write({
        ctx: auditCtx(request), layer: 'vault', action: 'partner.account.inbound_webhook.signing_configure',
        outcome: 'success', duration_ms: Date.now() - start,
      });
      return result;
    },
  );

  // ─── Passport issuance under an account ──────────────────────────

  app.post('/v1/partner/accounts/:account_id/passports/issue', async (request, reply) => {
    const { account_id } = AccountParams.parse(request.params);
    const input = IssuePassportInput.parse(request.body);
    await services.partnerTenants.assertTenantOwnership(account_id, request.operatorId);
    // A passport issue is a recorded action wherever it is issued from. It is the account's action, counted on the
    // account's own plan (the partner pays past the free amounts), with the rollback registered so a failed issue does
    // not burn allowance.
    await meterAction(services, request, undefined, undefined, undefined, account_id);
    const start = Date.now();
    // Issue under the ACCOUNT's operator. Existing PassportService.issue
    // verifies the agent belongs to this operator and signs with the
    // deployment's key like any passport; `stk.operator_id` names the account.
    // The account's per-operator keys sign claims, never passports.
    const passport = await services.passport.issue(account_id, input);
    await services.audit.write({
      ctx: auditCtx(request, { agent_id: input.agent_id }),
      layer: 'vault',
      action: 'partner.account.passport.issue',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });
    return reply.status(201).send(passport);
  });

  void NotFoundError;
}

/**
 * Close everything a revoked account could still be reached through: its
 * inbound webhooks and its passports. Its own key already stops working on
 * the status change; the billing-account cache is dropped so no process
 * keeps serving the account from a warm entry.
 */
async function revokeAccountCascade(
  services: Services,
  accountId: string,
): Promise<{ webhooks_revoked: number; passports_revoked: number }> {
  const webhooks = await services.inboundWebhooks.list(accountId);
  let webhooksRevoked = 0;
  for (const webhook of webhooks) {
    const { transitioned } = await services.inboundWebhooks.revoke(webhook.id, accountId);
    if (transitioned) webhooksRevoked += 1;
  }
  const passports = await services.passport.revokeAllForOperator(accountId, 'Account closed by partner');
  const passportsRevoked = Array.isArray(passports)
    ? passports.length
    : Number((passports as { revoked_count?: number })?.revoked_count ?? 0);
  services.entitlements.evict(accountId);
  return { webhooks_revoked: webhooksRevoked, passports_revoked: passportsRevoked };
}
