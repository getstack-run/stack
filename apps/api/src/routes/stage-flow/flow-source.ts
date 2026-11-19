import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Reading a split route as one text.
 *
 * Several structural tests prove ordering properties of a route's source: the
 * Mission admission check runs before credential retrieval, the authority
 * decision comes before metering, the meter is committed before the provider is
 * called. Those properties were written against one handler body. When a
 * handler is composed from stage modules, the same proofs hold if two things
 * are true, and this file pins both:
 *
 *   1. The stage modules, read in the order listed here, are in the order the
 *      handler runs them, so the flattened text keeps the execution order.
 *   2. The registrar calls the stages in that same order (`calls`), and every
 *      module in the stage directory is listed, so nothing hides from a test.
 *
 * Test-only: nothing at runtime imports this file.
 */

const ROUTES_DIR = join(dirname(fileURLToPath(import.meta.url)), '..');
/** Where a route or stage module is read: the engine's routes, then any a deployment's tests add. */
const ROUTE_ROOTS = [ROUTES_DIR];

/** The root a route file or stage directory is under. */
function rootOf(path: string): string {
  return ROUTE_ROOTS.find((root) => existsSync(join(root, path))) ?? ROUTES_DIR;
}

export interface RouteFlow {
  /** The registrar under routes/ that declares the route and composes the stages. */
  registrar: string;
  /** Stage directory under routes/. */
  dir: string;
  /** Every module in the directory, in the order the handler runs them. Paths are relative to `dir`. */
  stages: readonly string[];
  /** Stage entry-point calls, in the order the registrar's handler makes them. */
  calls: readonly string[];
}

export const FLOWS: Record<string, RouteFlow> = {
  proxy: {
    registrar: 'proxy.ts',
    dir: 'proxy-call',
    stages: [
      'types.ts',
      'request-validation.ts',
      'passport-verification.ts',
      'target-resolution.ts',
      'input-scan-start.ts',
      'allowance-accounting.ts',
      'authority-decision.ts',
      'meter.ts',
      'mission-admission.ts',
      'approval-gate.ts',
      'service-scope.ts',
      'input-scan.ts',
      'control-decision.ts',
      'mutation-execution.ts',
      'credential-retrieval.ts',
      'upstream-dispatch.ts',
      'upstream-response.ts',
      'audit-telemetry.ts',
      'signed-claims.ts',
      'settlement.ts',
    ],
    calls: [
      'validateProxyRequest(',
      'verifyProxyPassport(',
      'resolveProxyTarget(',
      'startEarlyInputScan(',
      'recordProxyEvaluation(',
      'authorizeProxyAuthority(',
      'meterProxyAction(',
      'admitMission(',
      'checkApprovalGate(',
      'enforceApprovedCallShape(',
      'enforceServiceScope(',
      'runScopeWall(',
      'assertNotCheckedOut(',
      'scanInputAndScoreDrift(',
      'decideProxyCall(',
      'executeProxyMutation(',
      'retrieveProxyCredential(',
      'dispatchProxyRequest(',
    ],
  },
  llm: {
    registrar: 'llm.ts',
    dir: 'llm-gateway',
    stages: [
      'types.ts',
      'provider-configs.ts',
      'request-shaping.ts',
      'admit-call.ts',
      'meter.ts',
      'approval-gate.ts',
      'scope-wall.ts',
      'inbound-scan.ts',
      'control-decision.ts',
      'pii-redaction.ts',
      'billing-hold.ts',
      'credential-retrieval.ts',
      'stream-forward.ts',
      'direct-forward.ts',
      'image-request.ts',
      'image-forward.ts',
      'post-call-telemetry.ts',
      'usage-routes.ts',
    ],
    calls: [
      'admitCall(',
      'meterLlmCall(',
      'enforceApprovalGate(',
      'enforceProviderScope(',
      'scanInboundMessages(',
      'decideModelCall(',
      'redactUserPii(',
      'authorizeBillingHold(',
      'retrieveProviderCredential(',
      'forwardStreamingResponse(',
      'forwardDirectResponse(',
    ],
  },
  // OpenRouter's whole API, passed through: the registrar is the handler that composes the stages (the route itself is
  // declared in llm.ts, beside the other provider routes, in a scope of its own for its raw body).
  openrouter: {
    registrar: 'llm-gateway/openrouter/handler.ts',
    dir: 'llm-gateway/openrouter',
    stages: ['delivery.ts', 'handler.ts', 'hold-size.ts', 'policy.ts', 'request.ts', 'save-output.ts', 'tap.ts', 'upstream.ts'],
    calls: [
      'readOpenRouterCall(',
      'admitCaller(',
      'meterLlmCall(',
      'beginAgentRuntime',
      'enforceApprovalGate(',
      'enforceProviderScope(',
      'decideControl(',
      'modelAccessPolicy.hold(',
      'stackKey(',
      'retrieveProviderCredential(',
      'callOpenRouter(',
    ],
  },
};

/** A deployment's tests add the flows of its own routes, and the folder they are in. Idempotent. */
export function registerFlows(extra: Record<string, RouteFlow>, routesDir: string): void {
  if (!ROUTE_ROOTS.includes(routesDir)) ROUTE_ROOTS.push(routesDir);
  Object.assign(FLOWS, extra);
}

/** One file under routes/, with line endings normalised. */
export function routeSource(file: string): string {
  return readFileSync(join(rootOf(file), file), 'utf8').replace(/\r\n/g, '\n');
}

/** Modules in a flow's stage directory, as a sorted list relative to the directory. */
export function stageFiles(flow: RouteFlow): string[] {
  return readdirSync(join(rootOf(flow.dir), flow.dir), { recursive: true, encoding: 'utf8' })
    .map((f) => f.replace(/\\/g, '/'))
    .filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'))
    // A folder that is a flow of its own (llm-gateway/openrouter) is read by that flow, not by the one above it.
    .filter((f) => !Object.values(FLOWS).some((other) => other !== flow && other.dir.startsWith(`${flow.dir}/`) && `${flow.dir}/${f}`.startsWith(`${other.dir}/`)))
    .sort();
}

/**
 * The route as one text: the registrar first, then each stage module in
 * execution order. Use this wherever a test used to read a single route file
 * and compare positions inside it.
 */
export function flowSource(name: string): string {
  const flow = FLOWS[name];
  if (!flow) throw new Error(`no stage flow named ${name}`);
  return [
    routeSource(flow.registrar),
    ...flow.stages.map((stage) => routeSource(`${flow.dir}/${stage}`)),
  ].join('\n');
}
