import { describe, it, expect, vi } from 'vitest';
import { engineRoutes } from '../test/route-scan.js';
import {
  defineMissionAdmissionCoverage,
  defineResolveMissionRefCoverage,
  handlerRegion,
  type Admitted,
} from './mission-admission-coverage.checks.js';

// The checks are in mission-admission-coverage.checks.ts; this runs them over the routes the engine serves. The hosted
// deployment's own routes are checked by its own test against its tables.

// The checks read and parse every route file of the tree. Warm, that is a second; on a machine under a full run (a cold
// file cache, a dozen other test files at once) it takes 20 to 50 seconds, which is the work and not a hang, so this
// file, and only this file, gives its tests two minutes instead of vitest's five seconds.
const SCAN_TIMEOUT_MS = 120_000;
vi.setConfig({ testTimeout: SCAN_TIMEOUT_MS });

const read = (file: string) => engineRoutes.readLf(file);
const region = (file: string, marker: string) => handlerRegion(engineRoutes, file, marker);

const ADMITTED: Record<string, Admitted> = {
  'POST /v1/proxy': {
    file: 'proxy.ts', region: "'/v1/proxy',",
    // The handler is composed from stage modules (proxy-call/): the gate is the admission stage
    // call and the sinks are the stage calls that reach them. The test below proves that stage
    // holds beginAgentRuntime and that those stages hold the real sinks.
    gate: 'admitMission(',
    sinks: ['executeProxyMutation(', 'retrieveProxyCredential(', 'dispatchProxyRequest('],
  },
  // The three provider routes share one handler factory.
  'POST /v1/llm/*': {
    file: 'llm.ts', region: 'function makeLlmHandler(',
    // The handler is composed from stage modules (llm-gateway/): the sinks are the stage calls
    // that reach them. The test below proves those stages hold the real sinks.
    sinks: ['retrieveProviderCredential(', 'forwardStreamingResponse(', 'forwardDirectResponse('],
  },
  'POST /v1/dropoffs': { file: 'dropoffs.ts', region: "app.post('/v1/dropoffs',", sinks: ['services.dropoff.create('] },
  'POST /v1/dropoffs/:id/deposit': { file: 'dropoffs.ts', region: "'/v1/dropoffs/:id/deposit',", sinks: ['services.dropoff.deposit('] },
  'POST /v1/dropoffs/:id/collect': { file: 'dropoffs.ts', region: "'/v1/dropoffs/:id/collect',", sinks: ['services.dropoff.collectWithProvenance('] },
  // tasks/send is the only acting method; tasks/get reads and tasks/cancel
  // expires the sender's own transfer (safety-increasing).
  'POST /v1/a2a/jsonrpc': {
    file: 'a2a.ts', region: 'async function handleTasksSend(',
    sinks: ['enforceRuntimeAuthority(', 'meterAction(', 'services.dropoff.create(', 'services.dropoff.deposit('],
  },
  'POST /v1/intents/submit': {
    file: 'intents.ts', region: "app.post('/v1/intents/submit',",
    sinks: ['meterAction(', 'services.intentApproval.submit('],
  },
  // authority.ts declares the route and calls delegateBinding; the handler body lives in authority-flows/.
  'POST /v1/authority/bindings/:bindingId/delegate': {
    file: 'authority-flows/bindings.ts', region: 'export async function delegateBinding(',
    sinks: ['services.authority.delegateBinding('],
  },
};

// OpenRouter's whole API is one wildcard path with a registration per method; its POST shares the key above and its other
// methods are admitted by the same handler, composed from the stages in llm-gateway/openrouter/.
const OPENROUTER_ADMITTED: Admitted = {
  file: 'llm-gateway/openrouter/handler.ts', region: 'export function makeOpenRouterHandler(',
  sinks: ['services.modelAccessPolicy.hold(', 'retrieveProviderCredential(', 'callOpenRouter('],
};
ADMITTED['PUT /v1/llm/openrouter/*'] = OPENROUTER_ADMITTED;
ADMITTED['PATCH /v1/llm/openrouter/*'] = OPENROUTER_ADMITTED;
ADMITTED['DELETE /v1/llm/openrouter/*'] = OPENROUTER_ADMITTED;

const EXEMPT: Record<string, string> = {
  // Passport lifecycle. Issuance, delegation and refresh are where a Mission is
  // bound (passport-service requires exactly one), not actions under one.
  'POST /v1/passports/issue': 'issuance binds the Mission; passport-service refuses zero or several',
  'POST /v1/passports/delegate': 'the child inherits the parent Passport Mission at issuance',
  'POST /v1/passports/refresh': 'refresh requires a live Mission in passport-service',
  'POST /v1/passports/verify': 'read-only signature and revocation check',
  'GET /v1/passports/active': 'read-only listing',
  // Revocation and stopping must work on a dead Mission: that is when you need them.
  'POST /v1/passports/revoke': 'revocation is safety-increasing',
  'POST /v1/passports/revoke-agent/:agentId': 'revocation is safety-increasing',
  'POST /v1/passports/revoke-session/:sessionId': 'revocation is safety-increasing',
  'POST /v1/passports/revoke-all': 'revocation is safety-increasing',
  'POST /v1/passports/:jti/checkpoint': 'a checkpoint reports progress; it must keep working while a Mission winds down',
  'POST /v1/passports/:jti/checkout': 'checkout ends work; refusing it on a dead Mission would hide the record',
  'GET /v1/passports/:jti/report': 'read-only',
  'GET /v1/passports/reviews': 'read-only',
  'POST /v1/dropoffs/:id/expire': 'expiring a transfer is safety-increasing',
  'GET /v1/dropoffs/:id': 'read-only',
  'GET /v1/dropoffs': 'read-only',
  'POST /v1/intents/simulate': 'a dry run: writes nothing that acts and never consumes a cap',
  // Missions themselves.
  'POST /v1/missions': 'opens the Mission an agent will act under',
  'POST /v1/missions/start': 'opens the Mission and issues its Passport in one step',
  'POST /v1/missions/:id/renew': 'Mission lifecycle, checked by the fleet policy and membership',
  'POST /v1/missions/:id/complete': 'ending a Mission is safety-increasing',
  'POST /v1/missions/:id/revoke': 'ending a Mission is safety-increasing',
  'POST /v1/authority/bindings/:bindingId/revoke': 'revocation is safety-increasing',
  // Reads and detection.
  'POST /v1/proxy/operations/get': 'reads the status of an earlier, already-admitted proxy call',
  'POST /v1/scan': 'scans caller-supplied content; reaches no upstream and uses no credential; the Passport only attributes the scan',
  'GET /v1/credentials/:provider':
    'raw-secret read; every agent principal is refused by assertNotProxyOnlyAgent (pinned in require-platform.test.ts)',
  'GET /v1/credentials/by-connection/:connectionId':
    'raw-secret read; every agent principal is refused by assertNotProxyOnlyAgent (pinned in require-platform.test.ts)',
  // Read-only routes that read a Passport or agent context.
  'GET /v1/audit': 'read-only',
  'GET /v1/intents/:id': 'read-only',
  'GET /v1/llm/usage': 'read-only',
  'GET /v1/llm/usage/summary': 'read-only',
  'GET /v1/missions': 'read-only',
  'GET /v1/operators/me': 'read-only',
  'POST /v1/evidence-packs': 'exports records already written; acts on nothing',
  // Authority protocol endpoints. The caller is a receiving system or a human
  // in a dashboard session, never an agent principal.
  'POST /v1/authority/proof-callbacks/:adapterKey': 'proof-provider callback, adapter-authenticated',
  'POST /v1/authority/presentation-requests': 'receiver-authenticated protocol endpoint',
  'POST /v1/authority/status-checks': 'receiver-authenticated status read',
  'POST /v1/authority/presentations/:presentationId/receipts': 'receiver-authenticated receipt',
  'POST /v1/authority/enterprise-oidc/requests/:requestId/reject': 'human dashboard-session decision',
  'POST /v1/authority/enterprise-oidc/requests/:requestId/start': 'human dashboard-session decision',
  'POST /v1/authority/enterprise-oidc/requests/:requestId/complete': 'human dashboard-session decision',
  'POST /v1/authority/approval-requests/:approvalId/decide': 'human dashboard-session decision (cookie only)',
  'POST /v1/proxy/operations/reconcile': 'human recovery, cookie session only (proxy-operation-human-auth.test.ts)',
  'POST /v1/proxy/operations/authorize-replacement': 'human recovery, cookie session only (proxy-operation-human-auth.test.ts)',
  'POST /v1/identity/sso/handoff': 'human SSO login handoff; no agent principal',
  'GET /v1/identity/oidc/callback': 'public OIDC callback; the state token is the auth',
  // Tightening: always allowed, and most needed when a Mission is dead.
  'PUT /v1/detectors/:detector_key/config': 'agents may only tighten detector config',
  'DELETE /v1/operator/inbound-webhooks/:id': 'tearing down egress is safety-increasing',
  'DELETE /v1/services/agents/:agentId/revoke': 'access revoke is tightening',
  // Fleet enrollment: proves who a worker is; it carries no Mission yet.
  'POST /v1/fleets/session': 'fresh agent key proof opens a bounded session; Missions start after',
  'POST /v1/fleets/:id/enrollment-challenges': 'enrollment proof of possession; no action',
  'POST /v1/fleets/:id/enroll': 'enrollment under the approved policy; no action',
  'POST /v1/fleets/:id/workload/enrollment-challenges': 'issuer-verified workload enrollment; no action',
  'POST /v1/fleets/:id/workload/enroll': 'issuer-verified workload enrollment; no action',
};

// Files whose auth model never admits an agent principal (scope gates,
// signature-authed receivers, cookie-only or platform-staff surfaces). Same
// classification as. Files that MIX agent routes with such routes
// (a2a.ts, authority.ts, proxy-operations.ts) are deliberately NOT here.
const NOT_AGENT_REACHABLE = new Set([
  'members.ts', 'oauth-apps.ts', 'sso-domains.ts', 'partner.ts', 'inbound.ts', 'provider-oauth.ts', 'workload.ts',
  'workload-wit.ts', 'oauth.ts', 'operator-email-change-public.ts', 'governance.ts',
]);

defineMissionAdmissionCoverage(engineRoutes, { admitted: ADMITTED, exempt: EXEMPT, notAgentReachable: NOT_AGENT_REACHABLE });

describe('mission admission coverage of the engine\'s composed handlers', () => {
  it('POST /v1/llm/* stage calls reach the real sinks, and no other stage does', () => {
    // The route is composed from stage modules (llm-gateway/). The loop above proves
    // beginAgentRuntime runs before the stage calls that reach a sink; this proves those
    // stages are where the sinks live and that no other stage - in particular none that
    // runs before Mission admission - decrypts a credential or forwards upstream.
    const sinkStages: Record<string, string> = {
      'credential-retrieval.ts': 'retrieveCredentialByConnectionId(',
      'stream-forward.ts': 'services.llmGateway.forwardStreaming',
      'direct-forward.ts': 'services.llmGateway.forward(',
      // An image on the customer's own key: its own forward stage, admitted by makeImageHandler below.
      'image-forward.ts': 'services.llmGateway.forwardImages(',
    };
    for (const [stage, sink] of Object.entries(sinkStages)) {
      expect(read(`llm-gateway/${stage}`), `${stage} no longer holds ${sink}`).toContain(sink);
    }
    const others = engineRoutes.folder('llm-gateway').filter((f) => !(f in sinkStages));
    for (const stage of others) {
      const text = read(`llm-gateway/${stage}`);
      expect(text, `${stage} reaches a credential or the provider outside the sink stages`).not.toMatch(
        /retrieveCredential(?:Pinned)?(?:ByConnectionId)?\(|services\.llmGateway\.forward/,
      );
    }
  });

  it('the image handler admits the Mission before the credential is read or anything is forwarded', () => {
    // POST /v1/llm/<provider>/images shares the chat route's key above; its handler is its own function.
    const body = region('llm.ts', 'export function makeImageHandler(');
    expect(body, 'llm.ts: cannot find makeImageHandler').not.toBe('');
    const gate = body.indexOf('beginAgentRuntime(');
    expect(gate, 'makeImageHandler no longer calls beginAgentRuntime').toBeGreaterThan(-1);
    for (const sink of ['retrieveProviderCredential(', 'forwardImageResponse(']) {
      const at = body.indexOf(sink);
      expect(at, `makeImageHandler: ${sink} not found`).toBeGreaterThan(-1);
      expect(gate < at, `beginAgentRuntime now runs AFTER ${sink}`).toBe(true);
    }
  });

  it('POST /v1/proxy admission stage runs beginAgentRuntime, its stage calls reach the real sinks, and no other stage does', () => {
    // The route is composed from stage modules (proxy-call/). The loop above proves the admission
    // stage call runs before the stage calls that reach a sink; this proves the admission stage is
    // where beginAgentRuntime lives and that those stages are where the sinks live, so no other
    // stage - in particular none that runs before Mission admission - executes the request,
    // decrypts a credential or forwards upstream.
    expect(read('proxy-call/mission-admission.ts'), 'admission stage no longer calls beginAgentRuntime').toContain(
      'beginAgentRuntime(',
    );
    const sinkStages: Record<string, string> = {
      'mutation-execution.ts': 'executeTransactionSafeProxy(',
      'credential-retrieval.ts': 'retrieveCredentialPinnedByConnectionId(',
      'upstream-dispatch.ts': 'services.proxy.forward(',
    };
    for (const [stage, sink] of Object.entries(sinkStages)) {
      expect(read(`proxy-call/${stage}`), `${stage} no longer holds ${sink}`).toContain(sink);
    }
    const others = engineRoutes.folder('proxy-call').filter((f) => !(f in sinkStages));
    for (const stage of others) {
      const text = read(`proxy-call/${stage}`);
      expect(text, `${stage} reaches a credential, executes the request or forwards outside the sink stages`).not.toMatch(
        /executeTransactionSafeProxy\(|retrieveCredential(?:Pinned)?(?:ByConnectionId)?\(|services\.proxy\.forward\(/,
      );
    }
  });

  it('POST /v1/authority/bindings/:bindingId/delegate is registered to the handler that admits the Mission', () => {
    // The loop above proves delegateBinding calls beginAgentRuntime before it delegates; this
    // proves the route in authority.ts is the one that calls delegateBinding.
    const registered = region('authority.ts', "'/v1/authority/bindings/:bindingId/delegate',");
    expect(registered, 'authority.ts: cannot find the delegate route').not.toBe('');
    expect(registered).toContain('delegateBinding(services, request, reply)');
    expect(registered).not.toContain('services.authority.delegateBinding(');
  });
});

defineResolveMissionRefCoverage(
  ['apps/api/src', 'apps/mcp-server/src', 'packages/vault/src', 'packages/dropoff/src', 'packages/mcp-server/src'],
  {
  'apps/api/src/lib/transaction-safe-proxy.ts': 'post-response claim attribution, after beginAgentRuntime admitted the call',
  'packages/vault/src/services/accountability-service.ts': 'checkpoint and checkout attribution; safety paths that must work on a dead Mission',
  'packages/vault/src/services/security-event-service.ts': 'evidence attribution on a security event; never admits anything',
  },
);
