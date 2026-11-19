import { describe, expect, it } from 'vitest';
import {
  ContractPlanEntitlements,
  NO_ACCOUNTS,
  NO_ACCOUNT_CALL_SETTLEMENT,
  NO_ACCOUNT_DETECTION,
  NO_ACCOUNT_LIFECYCLE,
  NO_ACTION_LIMITS,
  NO_MISSION_SPEND,
  NO_PROXY_HOLDS,
  NO_SPEND_LEDGER,
} from '@stack/vault';
import { assertHostedMoney, assertHostedSeams, type HostedExtensionSeams } from './extension.js';
import { NO_METER } from './lib/action-meter.js';
import { NO_ANALYTICS } from './lib/analytics-sink.js';
import { NO_BROWSER_SESSIONS, NO_CONSOLE_BRIDGE } from './lib/browser-session.js';
import { NO_IDENTITY_CHARGE } from './lib/identity-verification-charge.js';
import { NO_GENERATED_FILES } from './lib/generated-files.js';
import { CUSTOMER_KEY_ONLY } from './lib/model-access-policy.js';
import { EngineRegistries } from './config/registries.js';

type Seams = Parameters<typeof assertHostedSeams>[0];

/** Distinct stand-ins for the fields of a deployment's extension. */
function hostedExtension(): HostedExtensionSeams {
  return {
    planLimits: (() => ({})) as never,
    monthlyActionLimit: () => 0,
    meteredActions: new Set(['x']) as never,
    policyRepository: (() => ({})) as never,
    l3Classifier: () => null,
    operatorService: (() => ({})) as never,
    intentDeviationGrader: () => null,
  };
}

/** What the engine's own entry gives: none of the extension's fields. */
const NO_EXTENSION: HostedExtensionSeams = {};

/** The seams of an install: every one on its null implementation. */
function installSeams(): Seams {
  const registries = new EngineRegistries();
  registries.seal();
  return {
    actionMeter: NO_METER,
    spend: NO_SPEND_LEDGER,
    entitlements: new ContractPlanEntitlements({} as never),
    accountDirectory: NO_ACCOUNTS,
    actionLimits: NO_ACTION_LIMITS,
    browserSessions: NO_BROWSER_SESSIONS,
    consoleBridge: NO_CONSOLE_BRIDGE,
    identityVerificationCharge: NO_IDENTITY_CHARGE,
    modelAccessPolicy: CUSTOMER_KEY_ONLY,
    generatedFiles: NO_GENERATED_FILES,
    analytics: NO_ANALYTICS,
    accountDetection: NO_ACCOUNT_DETECTION,
    agentAccounts: NO_ACCOUNT_LIFECYCLE,
    accountModelBilling: NO_ACCOUNT_CALL_SETTLEMENT,
    notification: { hasSendMeter: () => false } as never,
    registries,
  };
}

/** Distinct stand-ins for the deployment's own objects. */
function hostedSeams(): Seams {
  const registries = new EngineRegistries();
  registries.seal();
  return {
    actionMeter: { ...NO_METER },
    spend: { ...NO_SPEND_LEDGER },
    entitlements: { resolve: async () => ({}) } as never,
    accountDirectory: { accountOfAgent: async () => null },
    actionLimits: { ...NO_ACTION_LIMITS },
    browserSessions: { ...NO_BROWSER_SESSIONS },
    consoleBridge: {
      proxyAuth: () => async () => {},
      privateResponse: (reply) => reply,
      connectLinkPrincipal: () => ({ operatorId: 'op', operatorTier: 'enterprise' }),
      connectLinks: { resolveForSession: async () => ({ row: { id: 'cl', method: 'oauth', provider: 'p', scopes: [] } }), completeWithOAuth: async () => undefined },
    },
    identityVerificationCharge: { charge: async () => {}, priceCents: () => 0 },
    modelAccessPolicy: {
      resolve: async () => ({ kind: 'customer' }),
      stackKey: () => 'key',
      hold: async () => ({ bounded: true, denyReason: null, heldCents: 0, pricing: null }),
      listings: async () => ({ find: () => null, all: () => [] }),
      release: async () => {},
      ownsJob: async () => false,
    },
    generatedFiles: { save: async () => ({ id: 'drv' }) },
    analytics: { ...NO_ANALYTICS },
    accountDetection: { ...NO_ACCOUNT_DETECTION },
    agentAccounts: { ...NO_ACCOUNT_LIFECYCLE },
    accountModelBilling: { ...NO_ACCOUNT_CALL_SETTLEMENT },
    notification: { hasSendMeter: () => true } as never,
    registries,
  };
}

describe('assertHostedMoney', () => {
  it('passes when the hold ledger, the Mission spend and the spend ledger are the deployment\'s own', () => {
    expect(() => assertHostedMoney({ spend: { ...NO_SPEND_LEDGER }, proxyHolds: { ...NO_PROXY_HOLDS }, missionSpend: { ...NO_MISSION_SPEND }, llmUsage: () => ({}) as never })).not.toThrow();
  });

  it('refuses a money hook that left any of them on the null implementation, naming each', () => {
    expect(() => assertHostedMoney({ spend: NO_SPEND_LEDGER, proxyHolds: NO_PROXY_HOLDS, missionSpend: NO_MISSION_SPEND, llmUsage: null }))
      .toThrow(/spend, proxyHolds, missionSpend, llmUsage/);
    expect(() => assertHostedMoney({ spend: { ...NO_SPEND_LEDGER }, proxyHolds: NO_PROXY_HOLDS, missionSpend: { ...NO_MISSION_SPEND }, llmUsage: () => ({}) as never }))
      .toThrow(/proxyHolds/);
  });
});

describe('assertHostedSeams', () => {
  it('passes when every seam holds the deployment\'s own object and the registries are sealed', () => {
    expect(() => assertHostedSeams(hostedSeams(), hostedExtension())).not.toThrow();
  });

  it('refuses a boot that left every seam on its null implementation, naming each', () => {
    const seams = installSeams();
    seams.registries = new EngineRegistries();
    let message = '';
    try {
      assertHostedSeams(seams, NO_EXTENSION);
    } catch (error) {
      message = (error as Error).message;
    }
    for (const name of [
      'actionMeter',
      'spend',
      'entitlements',
      'accountDirectory',
      'actionLimits',
      'browserSessions',
      'consoleBridge',
      'identityVerificationCharge',
      'modelAccessPolicy',
      'generatedFiles',
      'analytics',
      'accountDetection',
      'agentAccounts',
      'accountModelBilling',
      'planLimits',
      'monthlyActionLimit',
      'meteredActions',
      'policyRepository',
      'l3Classifier',
      'operatorService',
      'intentDeviationGrader',
      'notification sendMeter',
      'registries (not sealed)',
    ]) {
      expect(message, name).toContain(name);
    }
  });

  it.each([
    ['actionMeter', { actionMeter: NO_METER }],
    ['spend', { spend: NO_SPEND_LEDGER }],
    ['entitlements', { entitlements: new ContractPlanEntitlements({} as never) }],
    ['accountDirectory', { accountDirectory: NO_ACCOUNTS }],
    ['actionLimits', { actionLimits: NO_ACTION_LIMITS }],
    ['browserSessions', { browserSessions: NO_BROWSER_SESSIONS }],
    ['consoleBridge', { consoleBridge: NO_CONSOLE_BRIDGE }],
    ['identityVerificationCharge', { identityVerificationCharge: NO_IDENTITY_CHARGE }],
    ['modelAccessPolicy', { modelAccessPolicy: CUSTOMER_KEY_ONLY }],
    ['generatedFiles', { generatedFiles: NO_GENERATED_FILES }],
    ['analytics', { analytics: NO_ANALYTICS }],
    ['accountDetection', { accountDetection: NO_ACCOUNT_DETECTION }],
    ['agentAccounts', { agentAccounts: NO_ACCOUNT_LIFECYCLE }],
    ['accountModelBilling', { accountModelBilling: NO_ACCOUNT_CALL_SETTLEMENT }],
  ] as const)('refuses a boot with only %s left null', (name, patch) => {
    expect(() => assertHostedSeams({ ...hostedSeams(), ...patch } as Seams, hostedExtension())).toThrow(new RegExp(name));
  });

  it.each([
    'planLimits',
    'monthlyActionLimit',
    'meteredActions',
    'policyRepository',
    'l3Classifier',
    'operatorService',
    'intentDeviationGrader',
  ] as const)(
    'refuses a boot whose extension left out %s',
    (name) => {
      const extension = hostedExtension();
      delete extension[name];
      expect(() => assertHostedSeams(hostedSeams(), extension)).toThrow(new RegExp(name));
    },
  );

  it('refuses a boot whose notifications are not capped', () => {
    const seams = { ...hostedSeams(), notification: { hasSendMeter: () => false } as never };
    expect(() => assertHostedSeams(seams, hostedExtension())).toThrow(/notification sendMeter/);
  });
});
