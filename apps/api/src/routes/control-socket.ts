// The control socket: configure who decides for the customer's agents and where
// their record is streamed, and read the decisions made.
//
//   GET    /v1/control-socket                          the socket as configured, with who decides now
//   PUT    /v1/control-socket/decision                 set or change the decision address (secret shown once on first set)
//   PUT    /v1/control-socket/events                   set or change the events address (secret shown once on first set)
//   DELETE /v1/control-socket/:target                  clear the decision or events address
//   POST   /v1/control-socket/:target/verify           the setup check; success puts the address into use
//   POST   /v1/control-socket/:target/test             one test exchange, nothing changes
//   POST   /v1/control-socket/:target/secret/rotate    a new signing secret, shown once; the old one works 24 hours more
//   POST   /v1/control-socket/secret/reveal            read a secret once, from the Console link an OAuth caller was given (dashboard session only)
//   PUT    /v1/control-socket/mode                     STACK's hosted controls, or none
//   PUT    /v1/control-socket/on-unavailable           refuse (default) or allow when your own server does not answer in time
//   PUT    /v1/control-socket/checked-types            which action kinds are checked
//   GET    /v1/control-decisions[/:id]                 the decisions made
//
// Every mutation is an owner or admin decision: agent contexts are refused, so an
// agent can never change its own controls. An address change, a rotation, and
// anything that loosens (clearing an enforcing socket, unchecking an action kind,
// letting actions through when your own server does not answer,
// switching hosted controls to none or to your own server) takes a human
// approval in a signed-in browser (governance step-up, browser-only); tightening
// applies at once. None of it is metered.
//
// A signing secret is returned only to a dashboard session or an API key. An OAuth
// caller (a chat assistant) gets `secret: null` and `secret_reveal`, a single-use
// Console link: whatever a tool returns goes into the model's context.

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  ControlSocketTarget,
  ControlsNotEnabledError,
  ForbiddenError,
  ListControlDecisionsQuery,
  NotFoundError,
  SetControlCheckedTypesInput,
  SetControlDecisionAddressInput,
  SetControlEventsAddressInput,
  SetControlModeInput,
  SetControlOnUnavailableInput,
  ids,
  type ControlActionType,
  type ControlDecisionView,
  type ControlSocketView,
  type ControlTestResultView,
  type GovernanceAction,
} from '@stack/shared';
import type { Services } from '../config/services.js';
import { auditCtx } from '../middleware/audit.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { enforceGovernanceStepUp } from '../middleware/governance-stepup.js';
import { denyAgentContexts, requireOperatorAdmin } from '../middleware/require-platform.js';
import { assertControlAddress, classifyModeChange, classifyModeSetting, hostOf, removedTypes } from '../lib/control-socket/admin.js';
import { env } from '../config/env.js';
import { ControlSecretRevealStore } from '../lib/control-socket/secret-reveal.js';
import { startPoliciesWhenControlsOn } from '../lib/control-policy/start-policies.js';
import { buildDecisionRequest } from '../lib/control-socket/request-builder.js';

const TargetParams = z.object({ target: ControlSocketTarget }).strict();
const RevealBody = z.object({ token: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).strict();
const DecisionParams = z.object({ id: z.string().regex(/^dec_[A-Za-z0-9_-]{16,64}$/) }).strict();

export interface ControlSocketRouteDeps {
  /** The set-time address check; tests replace it, production resolves DNS. */
  checkAddress?: (url: string) => Promise<string>;
  /** The Console origin the secret link points at; defaults to `DASHBOARD_URL`. */
  dashboardUrl?: string;
}

export function registerControlSocketRoutes(
  app: FastifyInstance,
  services: Services,
  deps: ControlSocketRouteDeps = {},
) {
  const auth = createAuthMiddleware(services);
  const allowHttp = process.env['NODE_ENV'] !== 'production';
  const checkAddress = deps.checkAddress ?? ((url: string) => assertControlAddress(url, allowHttp));

  const reveals = new ControlSecretRevealStore({ redis: services.redis, dashboardUrl: deps.dashboardUrl ?? env.DASHBOARD_URL });

  /**
   * What the caller gets of a secret just created: the secret itself for a
   * dashboard session or an API key (no OAuth scope), otherwise nothing but a
   * Console link to read it once. A model never holds it.
   */
  async function secretFor(request: FastifyRequest, target: 'decision' | 'events', secret: string | null) {
    if (secret === null) return { secret: null, secret_reveal: null };
    if (request.oauthScope === undefined) return { secret, secret_reveal: null };
    return { secret: null, secret_reveal: await reveals.issue(request.operatorId, target) };
  }

  async function socketView(operatorId: string): Promise<ControlSocketView> {
    return services.controlSocket.view(operatorId, await services.entitlements.controlsEnabled(operatorId));
  }

  function stepUp(
    request: FastifyRequest,
    action: Extract<GovernanceAction, 'control_socket_change' | 'account_control_loosen'>,
    payload: Record<string, unknown>,
    summary: string,
  ) {
    return enforceGovernanceStepUp(services, request, {
      action,
      resourceId: request.operatorId,
      payload,
      summary,
    });
  }

  async function record(request: FastifyRequest, action: string, start: number): Promise<void> {
    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'vault',
      action,
      outcome: 'success',
      duration_ms: Date.now() - start,
    });
  }

  app.get('/v1/control-socket', { preHandler: [auth, denyAgentContexts] }, async (request) => socketView(request.operatorId));

  app.put('/v1/control-socket/decision', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin], config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (request, reply) => {
    const start = Date.now();
    const input = SetControlDecisionAddressInput.parse(request.body);
    const url = await checkAddress(input.url);
    await stepUp(
      request,
      'control_socket_change',
      { target: 'decision', url, timeout_ms: input.timeout_ms ?? null },
      `Send every checked action of your agents to ${hostOf(url)} to be allowed or refused. An answer from that server decides each one, so only approve a server you run.`,
    );
    const { secret } = await services.controlSocket.setDecisionAddress(request.operatorId, {
      url,
      ...(input.timeout_ms !== undefined ? { timeoutMs: input.timeout_ms } : {}),
    });
    await record(request, 'control_socket.decision.set', start);
    return reply.status(secret ? 201 : 200).send({ socket: await socketView(request.operatorId), ...(await secretFor(request, 'decision', secret)) });
  });

  app.put('/v1/control-socket/events', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin], config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (request, reply) => {
    const start = Date.now();
    const input = SetControlEventsAddressInput.parse(request.body);
    const url = await checkAddress(input.url);
    await stepUp(
      request,
      'control_socket_change',
      { target: 'events', url },
      `Send your agents' whole record to ${hostOf(url)}: every action and its outcome, signed. Only approve an address you run.`,
    );
    const { secret } = await services.controlSocket.setEventsAddress(request.operatorId, url);
    await record(request, 'control_socket.events.set', start);
    return reply.status(secret ? 201 : 200).send({ socket: await socketView(request.operatorId), ...(await secretFor(request, 'events', secret)) });
  });

  app.delete('/v1/control-socket/:target', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin], config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (request) => {
    const start = Date.now();
    const { target } = TargetParams.parse(request.params);
    const before = await socketView(request.operatorId);
    if (target === 'decision') {
      if (!before.decision.url && !before.decision.pending_url) throw new NotFoundError('control socket decision address', request.operatorId);
      const enforcing = before.mode_setting === 'remote';
      await stepUp(
        request,
        enforcing ? 'account_control_loosen' : 'control_socket_change',
        { target, clear: true },
        enforcing
          ? `Remove your own control server (${hostOf(before.decision.url ?? '')}). Your agents' actions will no longer be decided by it.`
          : `Remove the decision address ${hostOf(before.decision.url ?? before.decision.pending_url ?? '')} from your control socket.`,
      );
      await services.controlSocket.clearDecision(request.operatorId);
    } else {
      if (!before.events.url) throw new NotFoundError('control socket events address', request.operatorId);
      await stepUp(
        request,
        'control_socket_change',
        { target, clear: true },
        `Stop streaming your agents' record to ${hostOf(before.events.url)}.`,
      );
      await services.controlSocket.clearEvents(request.operatorId);
    }
    await record(request, `control_socket.${target}.clear`, start);
    return socketView(request.operatorId);
  });

  app.post('/v1/control-socket/:target/test', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin], config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (request) => {
    const { target } = TargetParams.parse(request.params);
    return exchange(request, target, false);
  });

  app.post('/v1/control-socket/:target/verify', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin], config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (request) => {
    const start = Date.now();
    const { target } = TargetParams.parse(request.params);
    const result = await exchange(request, target, true);
    if (result.activated) await record(request, `control_socket.${target}.verify`, start);
    return result;
  });

  /**
   * One real exchange with the address that would be used. With `activate`, a
   * passing check puts the address into use, behind the step-up when that loosens.
   */
  async function exchange(request: FastifyRequest, target: 'decision' | 'events', activate: boolean): Promise<ControlTestResultView> {
    const operatorId = request.operatorId;
    const before = await socketView(operatorId);
    const started = Date.now();
    if (target === 'events') {
      if (!before.events.url) throw new NotFoundError('control socket events address', operatorId);
      const probe = await services.controlEvents.probe(operatorId, before.socket_id ?? 'csk_unset', before.events.url);
      if (probe.ok && activate) await services.controlSocket.activateEvents(operatorId);
      return {
        target, ok: probe.ok, latency_ms: probe.latencyMs, verdict: null,
        cause: probe.ok ? null : probe.cause === 'http_status' ? 'http_status' : (probe.cause ?? 'unreachable'),
        activated: probe.ok && activate,
      };
    }

    const address = await services.controlSocket.addressToVerify(operatorId);
    if (!address) throw new NotFoundError('control socket decision address', operatorId);
    const runtime = await services.controlSocket.runtime(operatorId);
    // The guard runs again here, at the moment of the call, as it does for every decision.
    await checkAddress(address.url);
    const { request: wire, body } = buildDecisionRequest({
      decisionId: ids.controlDecision(), now: new Date(), deadlineMs: address.timeoutMs, test: true,
      operatorId, socketId: runtime.socketId ?? 'csk_unset', accountId: null, agent: null, actorKind: 'owner',
      action: 'test', target: {}, amount: null, purpose: null, retryRef: null,
    });
    const result = await services.controlRemote.probe(address.url, { request: wire, body, operatorId, socket: runtime }, address.timeoutMs);
    const latency = Math.max(0, Date.now() - started);
    const ok = result.verdict === 'allow';
    if (ok && activate) {
      const change = classifyModeChange(before.effective_mode, 'remote');
      if (change === 'loosening') {
        await stepUp(
          request,
          'account_control_loosen',
          { target: 'decision', activate: true, url: address.url, from: before.effective_mode },
          `Switch from STACK's hosted controls to your own control server at ${hostOf(address.url)}. Your server will decide every checked action from now on.`,
        );
      }
      await services.controlSocket.activateDecision(operatorId);
    }
    return {
      target, ok, latency_ms: latency,
      verdict: result.verdict === 'allow' || result.verdict === 'deny' ? result.verdict : null,
      cause: result.verdict === 'unavailable' ? result.cause : null,
      activated: ok && activate,
    };
  }

  app.post('/v1/control-socket/:target/secret/rotate', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin], config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (request, reply) => {
    const start = Date.now();
    const { target } = TargetParams.parse(request.params);
    const before = await socketView(request.operatorId);
    const present = target === 'decision' ? before.decision.secret_set : before.events.secret_set;
    if (!present) throw new NotFoundError(`control socket ${target} signing secret`, request.operatorId);
    await stepUp(
      request,
      'control_socket_change',
      { target, rotate: true },
      `Replace the signing secret for your ${target} address. The new one is shown once; the old one keeps working for 24 hours.`,
    );
    const rotated = await services.controlSocket.rotateSecret(request.operatorId, target);
    await record(request, `control_socket.${target}.rotate`, start);
    return reply.status(201).send({
      target,
      ...(await secretFor(request, target, rotated.secret)),
      previous_valid_until: rotated.previousValidUntil.toISOString(),
    });
  });

  // The Console page behind the link an OAuth caller was given. A signed-in person only: not an API key,
  // not an OAuth token (the route has no OAuth scope), never an agent.
  app.post('/v1/control-socket/secret/reveal', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin], config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (request) => {
    const start = Date.now();
    if (request.isDashboardSession !== true) throw new ForbiddenError('A signing secret is read in the Console, signed in.');
    const { token } = RevealBody.parse(request.body);
    const redeemed = await reveals.redeem(request.operatorId, token);
    if (!redeemed) throw new NotFoundError('control socket secret link', request.operatorId);
    const live = await services.controlSocket.secrets(request.operatorId, redeemed.target);
    if (!live?.[0]) throw new NotFoundError(`control socket ${redeemed.target} signing secret`, request.operatorId);
    await record(request, `control_socket.${redeemed.target}.secret.reveal`, start);
    return { target: redeemed.target, secret: live[0] };
  });

  app.put('/v1/control-socket/mode', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin], config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (request) => {
    const start = Date.now();
    const input = SetControlModeInput.parse(request.body);
    const before = await socketView(request.operatorId);
    if (input.mode === 'hosted' && !before.controls_enabled) throw new ControlsNotEnabledError();
    const change = classifyModeSetting(before, input.mode);
    if (change === 'loosening') {
      await stepUp(
        request,
        'account_control_loosen',
        { mode: input.mode, from: before.effective_mode },
        before.effective_mode === 'none'
          ? 'Choose no checks: your agents\' actions will go through with no check, also once you switch on hosted controls.'
          : 'Turn off controls: your agents\' actions will go through with no check.',
      );
    } else if (change === 'socket_change') {
      await stepUp(
        request,
        'control_socket_change',
        { mode: input.mode, from: before.effective_mode },
        'Stop using your own control server and switch to STACK\'s hosted controls.',
      );
    }
    await services.controlSocket.setMode(request.operatorId, input.mode);
    await record(request, 'control_socket.mode.set', start);
    // Hosted controls chosen: every agent with grants gets a policy equal to them, which changes nothing until tightened.
    if (input.mode === 'hosted') await startPoliciesWhenControlsOn(services, request.operatorId, 'hosted_controls_chosen');
    return socketView(request.operatorId);
  });

  // What happens when your own decision server does not answer in time. Allowing it loosens a control, so it takes the browser-only
  // account_control_loosen approval; going back to refuse applies at once.
  app.put('/v1/control-socket/on-unavailable', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin], config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (request) => {
    const start = Date.now();
    const input = SetControlOnUnavailableInput.parse(request.body);
    const before = await socketView(request.operatorId);
    if (input.on_unavailable === 'allow' && before.decision.on_unavailable !== 'allow') {
      await stepUp(
        request,
        'account_control_loosen',
        { on_unavailable: 'allow', from: before.decision.on_unavailable },
        'When your own decision server does not answer in time, your agents\' actions will go through instead of being refused.',
      );
    }
    await services.controlSocket.setOnUnavailable(request.operatorId, input.on_unavailable);
    await record(request, 'control_socket.on_unavailable.set', start);
    return socketView(request.operatorId);
  });

  app.put('/v1/control-socket/checked-types', { preHandler: [auth, denyAgentContexts, requireOperatorAdmin], config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (request) => {
    const start = Date.now();
    const input = SetControlCheckedTypesInput.parse(request.body);
    const before = await socketView(request.operatorId);
    const current: ControlActionType[] | null = before.checks_all_types ? null : before.checked_types;
    const removed = removedTypes(current, input.types);
    if (removed.length > 0) {
      await stepUp(
        request,
        'account_control_loosen',
        { removed, types: input.types },
        `Stop checking ${removed.join(', ')}. These actions will go through with no decision.`,
      );
    }
    await services.controlSocket.setCheckedTypes(request.operatorId, input.types);
    await record(request, 'control_socket.checked_types.set', start);
    return socketView(request.operatorId);
  });

  app.get('/v1/control-decisions', { preHandler: [auth, denyAgentContexts] }, async (request) => {
    const query = ListControlDecisionsQuery.parse(request.query ?? {});
    const before = query.before ? new Date(query.before) : undefined;
    if (before && Number.isNaN(before.getTime())) throw new NotFoundError('control decision page', query.before ?? '');
    const rows = await services.controlSocketRepo.listDecisions(request.operatorId, {
      limit: query.limit,
      ...(query.account_id ? { accountId: query.account_id } : {}),
      ...(query.verdict ? { verdict: query.verdict } : {}),
      ...(before ? { before } : {}),
    });
    return { decisions: rows.map(toDecisionView) };
  });

  app.get('/v1/control-decisions/:id', { preHandler: [auth, denyAgentContexts] }, async (request) => {
    const { id } = DecisionParams.parse(request.params);
    const row = await services.controlSocketRepo.getDecision(request.operatorId, id);
    if (!row) throw new NotFoundError('control decision', id);
    return toDecisionView(row);
  });
}

function toDecisionView(row: Awaited<ReturnType<Services['controlSocketRepo']['getDecision']>> & object): ControlDecisionView {
  return {
    id: row.id,
    account_id: row.account_id,
    agent_id: row.agent_id,
    action_type: row.action_type,
    decider: row.decider as ControlDecisionView['decider'],
    verdict: row.verdict as ControlDecisionView['verdict'],
    reason_code: row.reason_code,
    cause: row.cause,
    latency_ms: row.latency_ms,
    charged: row.charged,
    request_digest: row.request_digest,
    request: row.request,
    evidence: row.evidence,
    created_at: row.created_at.toISOString(),
  };
}
