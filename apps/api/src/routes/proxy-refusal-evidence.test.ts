import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { StackError } from '@stack/shared';
import { MissionService, type MissionServiceDeps } from '@stack/vault';
import { errorHandler } from '../middleware/error-handler.js';
import { NO_METER } from '../lib/action-meter.js';

/**
 * The proxy's refusals record the request URL as evidence does: no query string,
 * secret-looking path segments redacted. A secret planted in the query string (in the
 * URL and in `query`) and in the path must reach neither the security event nor the
 * signed intent_denial, on every refusal path that records the URL: the approval gate,
 * a call that does not match its approval, a service outside the Passport's scope and
 * a call a Passport constraint refuses.
 */

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    request.operatorId = 'op_one';
    request.agentId = 'agt_one';
  },
}));
vi.mock('../middleware/meter.js', async (original) => ({
  ...(await original<typeof import('../middleware/meter.js')>()),
  meterAction: vi.fn(async () => {}),
}));
vi.mock('../lib/runtime-authority.js', async (original) => ({
  ...(await original<typeof import('../lib/runtime-authority.js')>()),
  enforceRuntimeAuthority: vi.fn(async () => ({ enforced: false })),
  markRuntimeAuthorityDispatched: vi.fn(async () => {}),
  completeRuntimeAuthorityUse: vi.fn(async () => {}),
}));

import { registerProxyRoutes } from './proxy.js';

// Built from parts so the repository holds no secret-shaped literal.
const QUERY_SECRET = ['planted', 'query', 'secret', '7d3f'].join('-');
const QUERY_PARAM_SECRET = ['planted', 'param', 'secret', '91ab'].join('-');
const PATH_SECRET = ['xox', 'b-1234567890-planted-path-secret'].join('');
const SECRETS = [QUERY_SECRET, QUERY_PARAM_SECRET, PATH_SECRET];

const missionRow = {
  mission_id: 'ms_one', operator_id: 'op_one', claim_id: 'pc_mission', passport_jti: null, assigned_agent_id: null,
  authorization_digest: null, intent_summary: 'work', intent_services: [], expected_counterparties: [], max_actions: null,
  max_dropoff_bytes: null, coverage_cap_cents: null, max_duration_seconds: null, max_concurrent_intents: null,
  max_actions_per_service: {}, cap_behavior: {}, baseline_profile: null, expected_output_shape: null, started_at: new Date(),
  expires_at: new Date(Date.now() + 3_600_000), completed_at: null, revoked_at: null, revoked_reason: null, terminal_state: null,
};

function harness(gateResult: Record<string, unknown>, scope: Record<string, unknown> = {}) {
  const claims = {
    jti: 'pas_one', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600,
    stk: { operator_id: 'op_one', agent_id: 'agt_one', session_id: 'ses_one', accountability: 'enforced', mission_ids: ['ms_one'],
      intent_services: [], services: [{ service_id: 'svc_slack', service_name: 'slack', connection_id: 'scon_slack', scopes: ['*'], credential_ref: 'c', ...scope }] },
  };
  const passportRow = { jti: 'pas_one', operator_id: 'op_one', agent_id: 'agt_one', session_id: 'ses_one', revoked_at: null,
    expires_at: new Date(Date.now() + 600_000), mission_ids: ['ms_one'], checked_out_at: null };
  const repo = {
    findById: async () => missionRow, countIntentsByMissionId: async () => 0, countIntentsByMissionIdGroupedByService: async () => ({}),
    countInflightIntentsByMissionId: async () => 0, sumWalletDebitCentsByMission: async () => 0, sumDropoffBytesByMission: async () => 0,
  };
  const recordIntentDenial = vi.fn(async (_input: Record<string, unknown>) => ({ claimId: 'pc_denial', retryCount: 1, deduped: false }));
  const record = vi.fn(async (_input: Record<string, unknown>) => ({}));
  const known: Record<string, Record<string, unknown>> = {
    passport: {
      verifyDetailed: vi.fn(async () => ({ claims, record: passportRow })),
      verify: vi.fn(async () => claims),
      assertServiceIdentityRequirements: vi.fn(async () => {}),
      findByJti: vi.fn(async () => passportRow),
    },
    passportClaimsRepo: { findObservedContentForFlow: vi.fn(async () => []) },
    accountDetection: { forAgent: vi.fn(async () => null), forOperator: vi.fn(async () => ({ mode: 'standard', skipL3: true, withhold: { warning: false, critical: false } })) },
    accountDirectory: { accountOfAgent: vi.fn(async () => null) },
    claimRegistry: { recordIntentDenial },
    securityEvent: { record },
    serviceConnection: {
      resolveProxyConnection: vi.fn(async () => ({ connection_id: 'scon_slack', service_id: 'svc_slack', credential_version: 1, proxy_enabled: true })),
    },
    entitlements: { controlsEnabled: vi.fn(async () => true), resolve: vi.fn(async () => ({ billingOperatorId: 'op_one', isTenant: false, limits: { actionsPerMonth: Infinity, overage: 'bill' } })) },
    actionMeter: { ...NO_METER },
    approvalGate: { check: vi.fn(async () => gateResult), releaseReservation: vi.fn(async () => {}) },
    fleetAdmission: { assertUnboundAgent: vi.fn(async () => {}) },
  };
  const mission = new MissionService({ repo, claimRegistry: {} } as unknown as MissionServiceDeps);
  const services = new Proxy({} as Record<string, unknown>, {
    get(_t, prop) {
      if (typeof prop === 'symbol' || prop === 'then') return undefined;
      if (prop === 'mission') return mission;
      if (prop === 'l3Classifier') return null;
      const partial = known[String(prop)] ?? {};
      return new Proxy(partial, {
        get(target, key) {
          if (key in target) return target[key as string];
          if (typeof key === 'symbol' || key === 'then') return undefined;
          return () => { throw new StackError(`reached ${String(prop)}.${String(key)}`, 'REACHED', 418); };
        },
      });
    },
  });
  const app = Fastify();
  app.setErrorHandler(errorHandler);
  registerProxyRoutes(app as never, services as never);
  return { app, recordIntentDenial, record };
}

async function refusedCall(gateResult: Record<string, unknown>, payload: Record<string, unknown>, scope: Record<string, unknown> = {}) {
  const h = harness(gateResult, scope);
  try {
    const res = await h.app.inject({ method: 'POST', url: '/v1/proxy', headers: { 'x-passport-token': 'live-token' }, payload });
    return { res, ...h };
  } finally {
    await h.app.close();
  }
}

const SECRET_URL = `https://slack.com/api/conversations.list?token=${QUERY_SECRET}`;
const APPROVED = {
  type: 'intent_claim', intent_type: 'http_call', agent_id: 'agt_one', named_intent: 'slack:http:proxy', target: 'slack',
  action: 'GET https://slack.com/api/conversations.list', parameters: { service: 'slack', method: 'GET', url: 'https://slack.com/api/conversations.list' },
  estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null }, accountability: 'enforced', reason: null, requires: [],
  user_subject: null, mission_ref: 'ms_one', submitted_at: Date.now(),
};
const ADMITTED = { allowed: true, skipped: false, intentClaim: APPROVED, intentClaimId: 'pc_approved', approvalId: 'apr_one' };

/** Everything the refusal wrote: the signed denial and the security event. */
function evidenceOf(h: { recordIntentDenial: ReturnType<typeof vi.fn>; record: ReturnType<typeof vi.fn> }) {
  return JSON.stringify([h.recordIntentDenial.mock.calls, h.record.mock.calls]);
}

function assertNoSecret(h: { recordIntentDenial: ReturnType<typeof vi.fn>; record: ReturnType<typeof vi.fn> }) {
  expect(h.recordIntentDenial).toHaveBeenCalledOnce();
  expect(h.record).toHaveBeenCalledOnce();
  const evidence = evidenceOf(h);
  for (const secret of SECRETS) expect(evidence).not.toContain(secret);
  expect(evidence).not.toMatch(/\?[a-z_]+=/i);
}

describe('proxy refusals record the URL safely', () => {
  it('approval-gate denial', async () => {
    const h = await refusedCall(
      { allowed: false, reason: 'not_found', message: 'Approval apr_missing not found.', intentClaim: null,
        metadata: { approval_id: 'apr_missing', gate_reason: 'not_found' } },
      { service: 'slack', method: 'GET', url: SECRET_URL, query: { access_token: QUERY_PARAM_SECRET } },
    );
    expect(h.res.statusCode).toBe(403);
    assertNoSecret(h);
    expect(h.recordIntentDenial.mock.calls[0]![0]).toMatchObject({
      attemptedIntent: { action: 'GET https://slack.com/api/conversations.list', parameters: { url: 'https://slack.com/api/conversations.list' } },
    });
  });

  it('approval-gate denial that names the approved intent drops the approved URL\'s query string too', async () => {
    const approvedWithQuery = {
      ...APPROVED,
      action: `GET https://slack.com/api/conversations.list?token=${QUERY_SECRET}`,
      parameters: { ...APPROVED.parameters, url: SECRET_URL, query: { access_token: QUERY_PARAM_SECRET } },
    };
    const h = await refusedCall(
      { allowed: false, reason: 'requires_unmet', message: 'A required step is missing.', intentClaim: approvedWithQuery,
        metadata: { approval_id: 'apr_one', gate_reason: 'requires_unmet' } },
      { service: 'slack', method: 'GET', url: SECRET_URL },
    );
    expect(h.res.statusCode).toBe(403);
    assertNoSecret(h);
  });

  it.each([
    ['url_query', { service: 'slack', method: 'GET', url: SECRET_URL, query: { access_token: QUERY_PARAM_SECRET } }],
    ['url_path', { service: 'slack', method: 'GET', url: `https://slack.com/api/${PATH_SECRET}?token=${QUERY_SECRET}` }],
  ])('call-shape mismatch (%s)', async (field, payload) => {
    const h = await refusedCall(ADMITTED, payload);
    expect(h.res.statusCode).toBe(403);
    assertNoSecret(h);
    expect(h.record.mock.calls[0]![0]).toMatchObject({ metadata: { field_mismatch: { field } } });
  });

  it('call-shape mismatch when the approved intent carries a query string of its own', async () => {
    const approved = { ...APPROVED, action: `GET ${SECRET_URL}`, parameters: { ...APPROVED.parameters, url: SECRET_URL } };
    const h = await refusedCall({ ...ADMITTED, intentClaim: approved }, { service: 'slack', method: 'GET', url: `https://slack.com/api/conversations.list?token=${QUERY_PARAM_SECRET}` });
    expect(h.res.statusCode).toBe(403);
    assertNoSecret(h);
    expect(h.record.mock.calls[0]![0]).toMatchObject({ metadata: { field_mismatch: { field: 'url_query' } } });
    expect(h.recordIntentDenial.mock.calls[0]![0]).toMatchObject({
      attemptedIntent: { action: 'GET https://slack.com/api/conversations.list', parameters: { url: 'https://slack.com/api/conversations.list' } },
    });
  });

  it('call-shape mismatch when the approval names no URL', async () => {
    const approved = { ...APPROVED, parameters: { service: 'slack', method: 'GET' } };
    const h = await refusedCall({ ...ADMITTED, intentClaim: approved }, { service: 'slack', method: 'GET', url: SECRET_URL });
    expect(h.res.statusCode).toBe(403);
    assertNoSecret(h);
    expect(h.record.mock.calls[0]![0]).toMatchObject({ metadata: { field_mismatch: { field: 'url', actual: 'https://slack.com/api/conversations.list' } } });
  });

  it('service outside the Passport scope', async () => {
    const h = await refusedCall({ allowed: true, skipped: true },
      { service: 'github', method: 'GET', url: `https://api.github.com/repos/a/b/issues?token=${QUERY_SECRET}`, query: { access_token: QUERY_PARAM_SECRET } });
    expect(h.res.statusCode).toBe(403);
    assertNoSecret(h);
    expect(h.recordIntentDenial.mock.calls[0]![0]).toMatchObject({
      attemptedIntent: { action: 'GET https://api.github.com/repos/a/b/issues', parameters: { url: 'https://api.github.com/repos/a/b/issues' } },
    });
  });

  it('a call the Passport\'s constraint refuses, with a secret in the path and the query', async () => {
    const h = await refusedCall({ allowed: true, skipped: true },
      { service: 'slack', method: 'GET', url: `https://slack.com/api/${PATH_SECRET}?token=${QUERY_SECRET}`, query: { access_token: QUERY_PARAM_SECRET } },
      { constraints: [{ path: 'url.pathname', op: 'eq', value: '/api/conversations.list' }] });
    expect(h.res.statusCode).toBe(403);
    assertNoSecret(h);
    expect(h.record.mock.calls[0]![0]).toMatchObject({ metadata: { request_path: '/api/{redacted}' } });
  });
});

afterEach(() => { vi.clearAllMocks(); });
