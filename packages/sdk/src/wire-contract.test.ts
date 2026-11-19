import { expect, it } from 'vitest';
import * as api from '@stack/shared';
import {
  AGENT_ID,
  CONNECTION_ID,
  ENROLLMENT,
  FLEET_ACCESS,
  FLEET_LIMITS,
  FLEET_POLICY,
  ISSUE_INPUT,
  MISSION_ID,
  PARENT_TOKEN,
  POLICY,
  declaredKeys,
  newStack,
  registerContracts,
  stubApi,
  type Contract,
  type SchemaLike,
} from './test-support/wire-contract-kit.js';
/**
 * Wire contract between the SDK and the API.
 *
 * For every SDK method that sends a request body, this test runs the method
 * against a stubbed `fetch`, captures what would go over the wire, and checks
 * it against the Zod schema the API route parses it with (`@stack/shared`).
 * Three things are asserted per method: the HTTP verb, the path, and that the
 * body (1) parses under the API schema and (2) carries no key the schema does
 * not declare. Zod objects strip unknown keys by default, so (2) is what
 * catches a renamed or invented field that the API would silently drop.
 *
 * Not mapped, because the API validates the body inline in the route file
 * (`apps/api/src/routes/*.ts`) rather than with a schema from `@stack/shared`:
 *   passports.verify, revoke, revokeAgent, revokeSession
 *   missions.open, complete, revoke (the Mission spec inside missions.start; the recipient fields of open and start are mapped)
 *   dropoffs.deposit, collect
 *   skills.invoke, completeInvocation, failInvocation
 *   intents.simulate, submit, approve, reject
 *   evidencePacks.export
 *   scan.scan
 *   notifications.verify (legacy channel code), deliveryMethods.verify
 *   fleets.session
 *   inbound-webhook provider-signing-secret setters
 *   partner.connect, partner.tenants.create
 *   llm.* (provider-shaped bodies, forwarded as given), apart from the images routes, which take a fixed body;
 *   llm.openrouter.request and requestBytes send OpenRouter's own body for whichever endpoint the path names, which has
 *   no schema here (the gateway reads the path and passes the body on as it is)
 * Not mapped, because the schema exists but the methods need a signed
 * receiver, proof or profile fixture that is not worth hand-building here:
 *   authority.* (every POST and PUT; see authority.test.ts for shape checks)
 * Not mapped, no request body: agents.unblock, agents.dismissWarnings (an empty object), services.verify, dropoffs.expire,
 * skills.suspend/activate/claimInvocation, securityEvents.resolve,
 * missions.renew, fleets.revoke/revokeMember/enrollmentChallenge,
 * accounts.browser.startSession/read/screenshot, accounts.mailDomains.verify,
 * catalogue.get/search/forAccount (reads),
 * drive.list/get/read/delete/links/revokeLink (reads, or no body),
 * memory getSettings, getEpisodes, getEntityEdge and the two deletes (reads, or no body),
 * payments.startStripe (an empty object), website.checkHostname/resume,
 * payments.deactivateLink and the reads of website and payments,
 * services.getConnectLink and governance.getApproval (reads, no body),
 * inboundWebhooks.rotateSecret, partner.tenants.rotateInboundWebhookSecret and
 * network.subscriptions.rotateSecret (an empty object),
 * billing.subscribePlatform/subscribeControls,
 * controlSocket.get/clear/verify/test/rotateSecret and
 * controlSocket.decisions.list/get (no body; the target is in the path),
 * wakes.list/get/acknowledge/getSettings/rotateWebhookSecret/testWebhook/
 * listRules/deleteRule/listSchedules/deleteSchedule and invites.list/get
 * (reads, or no body),
 * controlPolicies.list/get/delete/startFromCurrentAccess/revisions and
 * controlReviews.list/get (reads, or no body; delete sends expected_revision as
 * a query parameter), and
 * the deprecated notification-channel send-code and test calls.
 * Not mapped, schema drift to fix first: partner.mintOutboundPassport and the
 * `services`, `named_intents` and `accountability_mode` fields of
 * IssueTenantPassportInput, which `IssuePassportInput` does not declare.
 */

/** The recipient fields of a Mission open: the shared shape, checked key by key. */
const RECIPIENT_FIELDS = {
  shape: api.MissionRecipientsInput,
  safeParse(value: unknown) {
    const fields = value as Record<string, unknown>;
    const results = Object.entries(api.MissionRecipientsInput).map(([key, schema]) => schema.safeParse(fields[key]));
    return { success: results.every((r) => r.success), error: { issues: results.flatMap((r) => (r.success ? [] : r.error.issues)) } };
  },
} as unknown as SchemaLike;

const CONTRACTS: Contract[] = [
  // ── Passports ────────────────────────────────────────────────────
  {
    name: 'passports.issue',
    call: (s) => s.passports.issue(ISSUE_INPUT),
    method: 'POST', path: '/v1/passports/issue', schema: api.IssuePassportInput,
  },
  {
    name: 'issuePassport',
    call: (s) => s.issuePassport(ISSUE_INPUT),
    method: 'POST', path: '/v1/passports/issue', schema: api.IssuePassportInput,
  },
  {
    name: 'passports.delegate (explicit scopes)',
    call: (s) => s.passports.delegate({
      parent_token: PARENT_TOKEN,
      child_agent_id: 'agt_child1',
      scopes: [{ service_connection_id: CONNECTION_ID, scopes: ['chat:write'] }],
      ttl_seconds: 300,
    }),
    method: 'POST', path: '/v1/passports/delegate', schema: api.DelegatePassportInput,
  },
  {
    name: 'passports.delegate (scopes read from the parent token)',
    call: (s) => s.passports.delegate({ parent_token: PARENT_TOKEN, child_agent_id: 'agt_child1' }),
    method: 'POST', path: '/v1/passports/delegate', schema: api.DelegatePassportInput,
  },
  {
    name: 'passports.refresh',
    call: (s) => s.passports.refresh(PARENT_TOKEN, 600),
    method: 'POST', path: '/v1/passports/refresh', schema: api.RefreshPassportInput,
  },
  {
    name: 'passports.revokeAll',
    call: (s) => s.passports.revokeAll('incident response'),
    method: 'POST', path: '/v1/passports/revoke-all', schema: api.RevokeAllInput,
  },
  {
    name: 'passports.revokeAll (no reason)',
    call: (s) => s.passports.revokeAll(),
    method: 'POST', path: '/v1/passports/revoke-all', schema: api.RevokeAllInput,
  },
  {
    name: 'passports.checkpoint',
    call: (s) => s.passports.checkpoint('pas_x', {
      services_used: ['slack'],
      tool_calls: [{ service: 'slack', method: 'chat.postMessage' }],
      actions_count: 3,
      summary: 'posted three messages',
    }),
    method: 'POST', path: '/v1/passports/pas_x/checkpoint', schema: api.CheckpointInput,
  },
  {
    name: 'passports.checkout',
    call: (s) => s.passports.checkout('pas_x', { services_used: ['slack'], actions_count: 3, summary: 'done' }),
    method: 'POST', path: '/v1/passports/pas_x/checkout', schema: api.CheckoutInput,
  },
  {
    name: 'passports.decideReview (approved)',
    call: (s) => s.passports.decideReview('chk_x', { decision: 'approved', notes: 'looks fine' }),
    method: 'POST', path: '/v1/passports/reviews/chk_x/decide', schema: api.ReviewDecisionInput,
  },
  {
    name: 'passports.decideReview (blocked)',
    call: (s) => s.passports.decideReview('chk_x', { decision: 'blocked', block_future: true }),
    method: 'POST', path: '/v1/passports/reviews/chk_x/decide', schema: api.ReviewDecisionInput,
  },
  // ── Missions ─────────────────────────────────────────────────────
  {
    name: 'missions.start (fleet form)',
    call: (s) => s.missions.start({
      fleet_policy_id: 'flp_contract1',
      idempotency_key: 'mission-key-0001',
      intent_summary: 'Summarise tickets',
      requested_access: [FLEET_ACCESS],
      limits: FLEET_LIMITS,
    }),
    method: 'POST', path: '/v1/missions/start', schema: api.FleetMissionStartInput,
  },
  {
    // The Mission spec is validated by a schema local to the API route; the
    // Passport part of the same body is the shared issue schema without the
    // fields the Mission start supplies itself.
    name: 'missions.start (operator form, passport part)',
    call: (s) => s.missions.start({
      agent_id: AGENT_ID,
      mission: { intent_summary: 'Summarise tickets', intent_services: ['slack'] },
      passport: { ttl_seconds: 600, intent: { summary: 'Summarise tickets', services: ['slack'] } },
    }),
    method: 'POST', path: '/v1/missions/start',
    schema: (api.IssuePassportInputObject as unknown as { omit(keys: Record<string, true>): { strict(): SchemaLike } })
      .omit({ agent_id: true, mission_ids: true }).strict(),
    select: (body) => body['passport'],
    extraKeys: [],
  },
  {
    // The recipient fields of a Mission open are the shared MissionRecipientsInput shape (the rest of the open body is
    // validated by a schema local to the API route, and `reply_to_message` is read by the route itself).
    name: 'missions.open (recipients)',
    call: (s) => s.missions.open({
      intent_summary: 'Answer one customer',
      agent_id: AGENT_ID,
      recipients: ['Ana@example.com', 'ben@example.com'],
      recipient_pins: [{ path: 'url.pathname', op: 'eq', value: '/v1/chats/42' }],
      reply_to_message: 'msg_contract1',
    }),
    method: 'POST', path: '/v1/missions',
    schema: RECIPIENT_FIELDS,
    select: (body) => ({ recipients: body['recipients'], recipient_pins: body['recipient_pins'] }),
  },
  {
    // The owner adds to a running Mission's recipients with the same shared fields.
    name: 'missions.addRecipients',
    call: (s) => s.missions.addRecipients('ms_contract1', {
      recipients: ['cy@example.com'],
      recipient_pins: [{ path: 'body.cc', op: 'in', value: ['dee@example.com'] }],
      reply_to_message: 'acall_contract1',
    }),
    method: 'POST', path: '/v1/missions/ms_contract1/recipients',
    schema: RECIPIENT_FIELDS,
    select: (body) => ({ recipients: body['recipients'], recipient_pins: body['recipient_pins'] }),
  },
  {
    name: 'missions.start (operator form, recipients)',
    call: (s) => s.missions.start({
      agent_id: AGENT_ID,
      mission: { intent_summary: 'Answer one customer', recipients: ['ana@example.com'], reply_to_message: 'msg_contract1' },
    }),
    method: 'POST', path: '/v1/missions/start',
    schema: RECIPIENT_FIELDS,
    select: (body) => {
      const mission = body['mission'] as Record<string, unknown>;
      return { recipients: mission['recipients'], recipient_pins: mission['recipient_pins'] };
    },
  },
  {
    name: 'missions.review',
    call: (s) => s.missions.review(MISSION_ID, { decision: 'raise', limit: 500 }),
    method: 'POST', path: `/v1/missions/${MISSION_ID}/review`,
    schema: api.MissionReviewInput,
  },
  {
    name: 'missions.setMakingAllowance',
    call: (s) => s.missions.setMakingAllowance(MISSION_ID, 25_000),
    method: 'PUT', path: `/v1/missions/${MISSION_ID}/making-allowance`,
    schema: api.SetMissionMakingAllowanceInput,
  },
  // ── Agents ───────────────────────────────────────────────────────
  {
    name: 'agents.register',
    call: (s) => s.agents.register({
      name: 'contract-bot',
      description: 'wire contract fixture',
      profile: 'proxied-llm-bot',
      accountability_mode: 'enforced',
      credential_access: 'proxy_only',
      key_mode: 'stack_managed',
      llm_inject_system_prompt: true,
      llm_redact_pii: true,
      eval_traffic: true,
    }),
    method: 'POST', path: '/v1/agents/register', schema: api.RegisterAgentInput,
  },
  {
    name: 'agents.setup',
    call: (s) => s.agents.setup({
      agent: { name: 'contract-bot', eval_traffic: true },
      grants: [{
        service_connection_id: 'scon_abcdefgh1234',
        scopes: ['read'],
        constraints: [{ path: 'url.pathname', op: 'starts_with', value: '/v1/products' }],
      }],
      allowed_hosts: [{ service_connection_id: 'scon_abcdefgh1234', allowed_hosts: ['api.example.com'] }],
    }),
    method: 'POST', path: '/v1/agents/setup', schema: api.AgentSetupInput,
  },
  {
    name: 'agents.update',
    call: (s) => s.agents.update(AGENT_ID, {
      status: 'suspended',
      accountability_mode: 'logged',
      credential_access: 'proxy_preferred',
      llm_redact_pii: false,
    }),
    method: 'PATCH', path: `/v1/agents/${AGENT_ID}`, schema: api.UpdateAgentInput,
  },
  // ── Services ─────────────────────────────────────────────────────
  {
    name: 'services.connect',
    call: (s) => s.services.connect({
      service_id: 'svc_slack',
      provider: 'slack',
      credential: JSON.stringify({ access_token: 'xoxb-fixture' }),
      scopes: ['chat:write'],
      mcp_url: 'https://slack.example.test/mcp',
      connection_name: 'Work',
    }),
    method: 'POST', path: '/v1/services/connect', schema: api.ConnectServiceInput,
    // The route reads the credential from `oauth_token`, outside the schema.
    extraKeys: ['oauth_token'],
  },
  {
    name: 'services.connectCustom',
    call: (s) => s.services.connectCustom({
      name: 'internal-api',
      description: 'wire contract fixture',
      credential: { api_key: 'fixture', base_url: 'https://internal.example.test' },
      scopes: ['read'],
      allowed_hosts: ['internal.example.test'],
      mcp_url: 'https://internal.example.test/mcp',
      connection_name: 'Work',
    }),
    method: 'POST', path: '/v1/services/custom', schema: api.ConnectCustomServiceInput,
  },
  {
    name: 'services.grantAgentAccess',
    call: (s) => s.services.grantAgentAccess({
      agent_id: AGENT_ID,
      service_connection_id: CONNECTION_ID,
      scopes: ['chat:write'],
    }),
    method: 'POST', path: '/v1/services/grant', schema: api.GrantAgentAccessInput,
  },
  {
    name: 'services.grantAgentAccess with alternatives',
    call: (s) => s.services.grantAgentAccess({
      agent_id: AGENT_ID,
      service_connection_id: CONNECTION_ID,
      scopes: ['chat:write', 'channels:history'],
      alternatives: [
        { constraints: [{ path: 'method', op: 'eq', value: 'GET' }] },
        { intents: [{ name: 'slack.post_to_channel', params: { channel: ['C0123'] } }] },
      ],
    }),
    method: 'POST', path: '/v1/services/grant', schema: api.GrantAgentAccessInput,
  },
  // ── Drop-offs ────────────────────────────────────────────────────
  {
    name: 'dropoffs.create',
    call: (s) => s.dropoffs.create({
      from_agent: AGENT_ID,
      to_agent: 'agt_contract2',
      schema: { type: 'object', properties: { summary: { type: 'string' } } },
      ttl_seconds: 600,
    }),
    method: 'POST', path: '/v1/dropoffs', schema: api.CreateDropoffInput,
  },
  // ── Team ─────────────────────────────────────────────────────────
  {
    name: 'team.invite',
    call: (s) => s.team.invite({ email: 'member@example.test', name: 'Member', role: 'standard', allowed_connections: [CONNECTION_ID] }),
    method: 'POST', path: '/v1/team/members', schema: api.InviteMemberInput,
  },
  {
    name: 'team.update',
    call: (s) => s.team.update('mem_x', { role: 'readonly', allowed_connections: null }),
    method: 'PATCH', path: '/v1/team/members/mem_x', schema: api.UpdateMemberInput,
  },
  // ── Proxy ────────────────────────────────────────────────────────
  {
    name: 'proxy.request (service)',
    call: (s) => s.proxy.request({
      service: 'slack',
      url: 'https://slack.com/api/chat.postMessage',
      method: 'POST',
      body: { channel: 'C1', text: 'hi' },
    }, { passportToken: PARENT_TOKEN }),
    method: 'POST', path: '/v1/proxy', schema: api.ProxyRequestInput,
  },
  {
    name: 'proxy.request (legacy provider key)',
    call: (s) => s.proxy.request({
      provider: 'slack',
      url: 'https://slack.com/api/auth.test',
      method: 'GET',
    } as never, { passportToken: PARENT_TOKEN }),
    method: 'POST', path: '/v1/proxy', schema: api.ProxyRequestInput,
  },
  {
    name: 'proxy.getOperation',
    call: (s) => s.proxy.getOperation('authority_request_abc123456789', { passportToken: PARENT_TOKEN, includeResponse: true }),
    method: 'POST', path: '/v1/proxy/operations/get', schema: api.ProxyOperationLookupInput,
  },
  // ── Notifications ────────────────────────────────────────────────
  {
    name: 'deliveryMethods.add',
    call: (s) => s.deliveryMethods.add({ channel_type: 'email', destination: 'oncall@example.test' }),
    method: 'POST', path: '/v1/notifications/destinations', schema: api.AddDeliveryMethodInput,
  },
  {
    name: 'notifications.createRule',
    call: (s) => s.notifications.createRule({ destination_ids: ['dst_x'], events: ['security_event'], min_severity: 'warning' }),
    method: 'POST', path: '/v1/notifications/channels', schema: api.CreateNotificationRuleInput,
  },
  {
    name: 'notifications.updateRule',
    call: (s) => s.notifications.updateRule('ntf_x', { events: ['security_event'], min_severity: 'critical' }),
    method: 'PATCH', path: '/v1/notifications/channels/ntf_x', schema: api.UpdateNotificationRuleInput,
  },
  // ── Identity ─────────────────────────────────────────────────────
  {
    name: 'identity.updateSettings',
    call: (s) => s.identity.updateSettings({ identity_claim_ttl: '90d', identity_claim_inheritance: 'opt_in', identity_auto_revoke: true }),
    method: 'PATCH', path: '/v1/operators/me/identity-settings', schema: api.UpdateIdentitySettingsInput,
  },
  {
    name: 'identity.initiateVerification',
    call: (s) => s.identity.initiateVerification({ provider_key: 'stripe_identity', requested_claims: ['identity'] }),
    method: 'POST', path: '/v1/identity/verify/initiate', schema: api.InitiateVerificationInput,
  },
  {
    name: 'identity.completeVerification',
    call: (s) => s.identity.completeVerification('stripe_identity', 'vs_x'),
    method: 'POST', path: '/v1/identity/verify/complete', schema: api.CompleteVerificationInput,
  },
  {
    name: 'identity.grantDelegation',
    call: (s) => s.identity.grantDelegation(['tax:read']),
    method: 'POST', path: '/v1/identity/delegate', schema: api.GrantDelegationInput,
  },
  {
    name: 'identity.addSsoDomain',
    call: (s) => s.identity.addSsoDomain('corp.example.com'),
    method: 'POST', path: '/v1/identity/sso-domains', schema: api.SsoDomainAddInput,
  },
  {
    name: 'identity.setServiceRequirement',
    call: (s) => s.identity.setServiceRequirement('svc_x', {
      layer: 'identity', requires_claim: 'verified_person', minimum_assurance: 'substantial',
      accepted_providers: [], requires_pii: false,
    }),
    method: 'POST', path: '/v1/services/svc_x/requirements', schema: api.SetServiceRequirementInput,
  },
  {
    name: 'identity.replaceServiceRequirement',
    call: (s) => s.identity.replaceServiceRequirement('svc_x', {
      layer: 'identity', requires_claim: 'verified_person', minimum_assurance: 'substantial',
      accepted_providers: [], requires_pii: false,
    }),
    method: 'PUT', path: '/v1/services/svc_x/requirements', schema: api.SetServiceRequirementInput,
    select: (body) => body['requirement'],
  },
  // ── Inbound webhooks ─────────────────────────────────────────────
  {
    name: 'inboundWebhooks.create',
    call: (s) => s.inboundWebhooks.create({
      provider: 'generic',
      agent_id: AGENT_ID,
      forward_url: 'https://hooks.example.test/in',
      generic_config: { signature_header: 'X-Sig', content_paths: ['body.text'] },
    }),
    method: 'POST', path: '/v1/operator/inbound-webhooks', schema: api.CreateInboundWebhookInput,
  },
  {
    name: 'partner.accounts.create',
    call: (s) => s.partner.accounts.create({ external_ref: 'cust_1' }),
    method: 'POST', path: '/v1/partner/accounts', schema: api.PartnerAccountCreateInput,
  },
  {
    name: 'partner.accounts.create with controls',
    call: (s) => s.partner.accounts.create({ external_ref: 'cust_1', controls: true }),
    method: 'POST', path: '/v1/partner/accounts', schema: api.PartnerAccountCreateInput,
  },
  {
    name: 'partner.accounts.invite',
    call: (s) => s.partner.accounts.invite('op_account1', { email: 'customer@example.com', name: 'Customer' }),
    method: 'POST', path: '/v1/partner/accounts/op_account1/invite', schema: api.PartnerAccountInviteInput,
  },
  {
    name: 'partner.accounts.release',
    call: (s) => s.partner.accounts.release('op_account1', { email: 'customer@example.com' }),
    method: 'POST', path: '/v1/partner/accounts/op_account1/release', schema: api.PartnerReleaseInput,
  },
  {
    name: 'partner.accounts.createInboundWebhook',
    call: (s) => s.partner.accounts.createInboundWebhook('op_account1', {
      provider: 'agentmail', agent_id: AGENT_ID, forward_url: null,
    }),
    method: 'POST', path: '/v1/partner/accounts/op_account1/inbound-webhooks', schema: api.CreateInboundWebhookInput,
  },
  {
    name: 'partner.accounts.issuePassport',
    call: (s) => s.partner.accounts.issuePassport('op_account1', { agent_id: AGENT_ID, mission_ids: [MISSION_ID], ttl_seconds: 900 }),
    method: 'POST', path: '/v1/partner/accounts/op_account1/passports/issue', schema: api.IssuePassportInput,
  },
  // ── Fleets ───────────────────────────────────────────────────────
  {
    name: 'fleets.activate',
    call: (s) => s.fleets.activate(FLEET_POLICY, { idempotencyKey: 'activate-key-0001' }),
    method: 'POST', path: '/v1/fleets', schema: api.FleetPolicyInput,
  },
  {
    name: 'fleets.revise',
    call: (s) => s.fleets.revise('flp_contract1', FLEET_POLICY, { expectedRevision: 1, idempotencyKey: 'revise-key-0001' }),
    method: 'PUT', path: '/v1/fleets/flp_contract1', schema: api.FleetPolicyInput,
  },
  {
    name: 'fleets.enroll',
    call: (s) => s.fleets.enroll('flp_contract1', ENROLLMENT),
    method: 'POST', path: '/v1/fleets/flp_contract1/enroll', schema: api.FleetEnrollmentInput,
  },
  {
    name: 'fleets.enrollWorkload',
    call: (s) => s.fleets.enrollWorkload('flp_contract1', ENROLLMENT),
    method: 'POST', path: '/v1/fleets/flp_contract1/workload/enroll', schema: api.FleetEnrollmentInput,
  },
  // ── Images on the customer's own provider key ──────────────────────
  {
    name: 'llm.openai.images',
    call: (s) => s.llm.openai.images.generate({ model: 'gpt-image-1', prompt: 'a cat', n: 2, size: '1024x1024', quality: 'high' }, { passport: 'agent.passport.jwt' }),
    method: 'POST', path: '/v1/llm/openai/images', schema: api.LlmImageRequest,
  },
  // ── Control socket ───────────────────────────────────────────────
  {
    name: 'controlSocket.setDecisionAddress',
    call: (s) => s.controlSocket.setDecisionAddress({ url: 'https://control.example.com/decide', timeout_ms: 800 }),
    method: 'PUT', path: '/v1/control-socket/decision', schema: api.SetControlDecisionAddressInput,
  },
  {
    name: 'controlSocket.setEventsAddress',
    call: (s) => s.controlSocket.setEventsAddress({ url: 'https://events.example.com/in' }),
    method: 'PUT', path: '/v1/control-socket/events', schema: api.SetControlEventsAddressInput,
  },
  {
    name: 'controlSocket.setMode',
    call: (s) => s.controlSocket.setMode('hosted'),
    method: 'PUT', path: '/v1/control-socket/mode', schema: api.SetControlModeInput,
  },
  {
    name: 'controlSocket.setCheckedTypes',
    call: (s) => s.controlSocket.setCheckedTypes(['email.send', 'card.checkout']),
    method: 'PUT', path: '/v1/control-socket/checked-types', schema: api.SetControlCheckedTypesInput,
  },
  {
    name: 'controlSocket.setCheckedTypes (every kind)',
    call: (s) => s.controlSocket.setCheckedTypes(null),
    method: 'PUT', path: '/v1/control-socket/checked-types', schema: api.SetControlCheckedTypesInput,
  },
  // ── Policies ─────────────────────────────────────────────────────
  {
    name: 'controlPolicies.set (create the default)',
    call: (s) => s.controlPolicies.set('default', POLICY),
    method: 'PUT', path: '/v1/control-policies/default', schema: api.SetControlPolicyInput,
  },
  {
    name: 'controlPolicies.set (revise an agent policy)',
    call: (s) => s.controlPolicies.set('agt_abcdefgh1234', POLICY, { expectedRevision: 2 }),
    method: 'PUT', path: '/v1/control-policies/agents/agt_abcdefgh1234', schema: api.SetControlPolicyInput,
  },
  {
    name: 'controlPolicies.simulate (an agent)',
    call: (s) => s.controlPolicies.simulate({ agent_id: 'agt_abcdefgh1234', call: { action: 'card.checkout', amount_cents: 900 } }),
    method: 'POST', path: '/v1/control-policies/simulate', schema: api.SimulateControlPolicyInput,
  },
  {
    name: 'controlPolicies.simulate (a draft and a proxy call)',
    call: (s) => s.controlPolicies.simulate({
      definition: POLICY,
      call: {
        action: 'proxy.call',
        connection_id: 'scon_abcdefgh',
        request: { method: 'POST', url: 'https://api.example.com/v1/send', body: { to: 'a@example.com' }, query: { dry: 'true' } },
      },
    }),
    method: 'POST', path: '/v1/control-policies/simulate', schema: api.SimulateControlPolicyInput,
  },
  {
    name: 'controlPolicies.simulate (inside a Mission)',
    call: (s) => s.controlPolicies.simulate({
      agent_id: 'agt_abcdefgh1234',
      call: {
        action: 'proxy.call',
        connection_id: 'scon_abcdefgh',
        mission_id: 'ms_abcdefgh1234',
        request: { method: 'POST', url: 'https://api.example.com/v1/send', body: { to: 'a@example.com' } },
      },
    }),
    method: 'POST', path: '/v1/control-policies/simulate', schema: api.SimulateControlPolicyInput,
  },
  // ── The STACK network (owner side) ───────────────────────────────
  {
    name: 'network.installs.register',
    call: (s) => s.network.installs.register('office'),
    method: 'POST', path: '/v1/network/installs', schema: api.RegisterInstallInput,
  },
  {
    name: 'network.installs.addKey',
    call: (s) => s.network.installs.addKey('ins_abcdefghijklmnopqrstu', {
      publicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) }, proof: 'aaaaaaaaaa.bbbbbbbbbb.cccccccccc', rolloverSeconds: 3600,
    }),
    method: 'POST', path: '/v1/network/installs/ins_abcdefghijklmnopqrstu/keys', schema: api.AddInstallKeyInput,
  },
  {
    name: 'network.installs.revoke',
    call: (s) => s.network.installs.revoke('ins_abcdefghijklmnopqrstu', 'key_compromise'),
    method: 'POST', path: '/v1/network/installs/ins_abcdefghijklmnopqrstu/revoke', schema: api.RevokeNetworkInput,
  },
  {
    name: 'network.licences.revoke',
    call: (s) => s.network.licences.revoke('STACKLIC1.eyJ2IjoxfQ.c2ln', 'key_compromise'),
    method: 'POST', path: '/v1/network/licences/revoke', schema: api.RevokeLicenceInput,
  },
  {
    name: 'network.publishRevocation',
    call: (s) => s.network.publishRevocation({ kind: 'agent', subject: 'support-bot', install: 'ins_abcdefghijklmnopqrstu', reason: 'agent_decommissioned' }),
    method: 'POST', path: '/v1/network/revocations', schema: api.PublishRevocationInput,
  },
  {
    name: 'network.subscriptions.create',
    call: (s) => s.network.subscriptions.create({ url: 'https://counterparty.example/hook', installs: ['ins_abcdefghijklmnopqrstu'] }),
    method: 'POST', path: '/v1/network/subscriptions', schema: api.CreateNetworkSubscriptionInput,
  },
  {
    name: 'network.verify',
    call: (s) => s.network.verify({ countersignature: 'aaaaaaaaaa.bbbbbbbbbb.cccccccccc', passport: 'dddddddddd.eeeeeeeeee.ffffffffff' }),
    method: 'POST', path: '/v1/network/verify', schema: api.VerifyCountersignatureInput,
  },
];

registerContracts('SDK request bodies against the API schemas', CONTRACTS, () => {
  it('services.connect sends the credential as oauth_token and drops the informational provider', async () => {
    const calls = stubApi();
    await newStack().services.connect({ service_id: 'svc_slack', provider: 'slack', credential: 'xoxb-fixture', scopes: ['chat:write'] });
    expect(calls[0]!.body).toEqual({ service_id: 'svc_slack', scopes: ['chat:write'], oauth_token: 'xoxb-fixture' });
  });

  it('passports.revokeAll always sends the confirm flag the API requires', async () => {
    const calls = stubApi();
    await newStack().passports.revokeAll('rotate everything');
    expect(calls[0]!.body).toEqual({ confirm: true, reason: 'rotate everything' });
  });

  it('passports.decideReview sends the API decision values unchanged', async () => {
    const calls = stubApi();
    const stack = newStack();
    await stack.passports.decideReview('chk_x', { decision: 'approved' });
    await stack.passports.decideReview('chk_x', { decision: 'blocked' });
    expect(calls.map((call) => call.body)).toEqual([{ decision: 'approved' }, { decision: 'blocked' }]);
  });

  it('a Passport session refreshes with a body the API refresh schema accepts', async () => {
    const calls = stubApi();
    const stack = newStack();
    // The stubbed issue reply expires in 15 minutes; a grace window longer
    // than that forces the refresh call.
    const session = await stack.issuePassport(ISSUE_INPUT);
    await session.getToken(3600);
    const refresh = calls.find((call) => call.path === '/v1/passports/refresh');
    expect(refresh, 'the session made no refresh call').toBeDefined();
    expect(api.RefreshPassportInput.safeParse(refresh!.body).success).toBe(true);
    expect([...Object.keys(refresh!.body!)].every((key) => declaredKeys(api.RefreshPassportInput).has(key))).toBe(true);
  });
});
