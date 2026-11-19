import { describe, it, expect } from 'vitest';
import { CONTROL_ACTION_TYPES } from '@stack/shared';
import { engineRoutes } from '../test/route-scan.js';
import {
  askedActions,
  defineControlSocketCoverage,
  HOSTED_ASKED_ONLY,
  type Asked,
  type NeverAsked,
} from './control-socket-coverage.checks.js';

// The checks are in control-socket-coverage.checks.ts; this runs them over the routes the engine serves. The hosted
// deployment's own routes are checked by its own test against its tables.

const ASKED: Record<string, Asked> = {
  'POST /v1/proxy': {
    file: 'proxy.ts', region: "'/v1/proxy',", gate: 'admitMission(', ask: 'decideProxyCall(', action: 'proxy.call',
    stage: 'proxy-call/control-decision.ts',
    sinks: ['executeProxyMutation(', 'retrieveProxyCredential(', 'dispatchProxyRequest('],
  },
  'POST /v1/llm/<provider>/images': {
    // An image on the customer's own key asks the same decider, as a model call, before the key is read.
    file: 'llm.ts', region: 'export function makeImageHandler(', gate: 'beginAgentRuntime(', ask: 'decideModelCall(', action: 'model.call',
    stage: 'llm-gateway/control-decision.ts',
    sinks: ['retrieveProviderCredential(', 'forwardImageResponse('],
  },
  'ANY /v1/llm/openrouter/*': {
    // OpenRouter's whole API: asked for every call that is not a read, with the amount the call holds, before the hold and the key.
    file: 'llm-gateway/openrouter/handler.ts', region: 'export function makeOpenRouterHandler(', gate: 'beginAgentRuntime(', ask: 'decideControl(', action: 'model.call',
    sinks: ['services.modelAccessPolicy.hold(', 'retrieveProviderCredential(', 'callOpenRouter('],
  },
  'POST /v1/llm/*': {
    file: 'llm.ts', region: 'function makeLlmHandler(', gate: 'beginAgentRuntime(', ask: 'decideModelCall(', action: 'model.call',
    stage: 'llm-gateway/control-decision.ts',
    sinks: ['authorizeBillingHold(', 'retrieveProviderCredential(', 'forwardStreamingResponse(', 'forwardDirectResponse('],
  },
  'POST /v1/dropoffs': {
    file: 'dropoffs.ts', region: "app.post('/v1/dropoffs',", gate: 'beginAgentRuntime(', ask: 'decideControl(', action: 'dropoff.create',
    sinks: ['services.dropoff.create('],
  },
  'POST /v1/dropoffs/:id/deposit': {
    file: 'dropoffs.ts', region: "'/v1/dropoffs/:id/deposit',", gate: 'beginAgentRuntime(', ask: 'decideControl(', action: 'dropoff.deposit',
    sinks: ['computeDepositProvenance(', 'services.dropoff.deposit('],
  },
  'POST /v1/a2a/jsonrpc': {
    file: 'a2a.ts', region: 'async function handleTasksSend(', gate: 'beginAgentRuntime(', ask: 'decideControl(', action: 'a2a.send',
    sinks: ['enforceRuntimeAuthority(', 'meterAction(', 'services.dropoff.create(', 'services.dropoff.deposit('],
  },
  'POST /v1/authority/bindings/:bindingId/delegate': {
    file: 'authority-flows/bindings.ts', region: 'export async function delegateBinding(', gate: 'beginAgentRuntime(', ask: 'decideControl(',
    action: 'passport.delegate', sinks: ['services.authority.delegateBinding('],
  },
};

/** Routes that reach `beginAgentRuntime` and are deliberately not asked. Each says why. */
const NEVER_ASKED: Record<string, NeverAsked> = {
  'POST /v1/intents/submit': {
    file: 'intents.ts', region: "app.post('/v1/intents/submit',",
    reason: 'an intent approval is itself a hosted control: it asks a person before acting, it does not act',
  },
  'POST /v1/dropoffs/:id/collect': {
    file: 'dropoffs.ts', region: "'/v1/dropoffs/:id/collect',",
    reason: 'collecting receives what a deposit already sent, and the deposit was asked',
  },
};

/**
 * Every `beginAgentRuntime(` call site, by file and enclosing unit, and whether
 * its file holds asked routes. A new call site must be added here.
 */
const SITES: Record<string, 'asked' | 'never'> = {
  'a2a.ts::handleTasksSend': 'asked',
  'authority-flows/bindings.ts::delegateBinding': 'asked',
  'dropoffs.ts::/v1/dropoffs': 'asked',
  'dropoffs.ts::/v1/dropoffs/:id/collect': 'never',
  'dropoffs.ts::/v1/dropoffs/:id/deposit': 'asked',
  'intents.ts::/v1/intents/submit': 'never',
  'llm-gateway/openrouter/handler.ts::makeOpenRouterHandler': 'asked',
  'llm.ts::makeLlmHandler': 'asked',
  'llm.ts::makeImageHandler': 'asked',
  'proxy-call/mission-admission.ts::admitMission': 'asked',
};

defineControlSocketCoverage(engineRoutes, { asked: ASKED, neverAsked: NEVER_ASKED, sites: SITES, accountSinks: [] });

describe('control socket coverage of the engine\'s action kinds', () => {
  it('every action kind the customer can choose is asked somewhere, or only a hosted route asks it', () => {
    const asked = askedActions({ asked: ASKED });
    expect(CONTROL_ACTION_TYPES.filter((type) => !asked.has(type) && !HOSTED_ASKED_ONLY.includes(type)), 'an action kind with no call site').toEqual([]);
    expect([...asked].filter((type) => !(CONTROL_ACTION_TYPES as readonly string[]).includes(type)), 'asked kinds the customer cannot choose').toEqual([]);
  });
});
