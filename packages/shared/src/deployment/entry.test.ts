import { describe, expect, it } from 'vitest';
import { assertEngineEntryAllowed, assertHostedEntryAllowed } from './entry.js';

const SELF_MANAGED = {
  STACK_DEPLOYMENT: 'self_managed',
  STACK_API_BASE_URL: 'https://stack.example.test',
} as const;

const ENVIRONMENTS = ['production', 'staging', 'development', 'test', undefined];

describe('the engine entry point', () => {
  it('refuses to start unless the deployment says it is self-managed, in every environment', () => {
    for (const NODE_ENV of ENVIRONMENTS) {
      // Unset reads as hosted, so an engine entry with no STACK_DEPLOYMENT is refused too.
      expect(() => assertEngineEntryAllowed({ NODE_ENV }), String(NODE_ENV)).toThrow(/self_managed is required/);
      expect(() => assertEngineEntryAllowed({ NODE_ENV, STACK_DEPLOYMENT: 'hosted' }), String(NODE_ENV)).toThrow(/\[BOOT\]/);
      expect(() => assertEngineEntryAllowed({ NODE_ENV, STACK_DEPLOYMENT: '' }), String(NODE_ENV)).toThrow(/\[BOOT\]/);
    }
  });

  it('starts when the deployment is self-managed, in every environment', () => {
    for (const NODE_ENV of ENVIRONMENTS) {
      expect(() => assertEngineEntryAllowed({ NODE_ENV, ...SELF_MANAGED }), String(NODE_ENV)).not.toThrow();
    }
  });

  it('refuses a mode it does not know instead of guessing one', () => {
    expect(() => assertEngineEntryAllowed({ NODE_ENV: 'production', STACK_DEPLOYMENT: 'both' })).toThrow(/STACK_DEPLOYMENT/);
    expect(() => assertEngineEntryAllowed({ NODE_ENV: 'development', STACK_DEPLOYMENT: 'both' })).toThrow(/STACK_DEPLOYMENT/);
  });
});

describe('the hosted entry point', () => {
  it('refuses a self-managed deployment', () => {
    expect(() => assertHostedEntryAllowed({ ...SELF_MANAGED })).toThrow(/cannot run with STACK_DEPLOYMENT=self_managed/);
  });

  it('starts on STACK\'s own deployment', () => {
    expect(() => assertHostedEntryAllowed({})).not.toThrow();
    expect(() => assertHostedEntryAllowed({ STACK_DEPLOYMENT: 'hosted' })).not.toThrow();
  });
});
