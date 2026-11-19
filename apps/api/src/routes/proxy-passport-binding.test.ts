import { describe, expect, it } from 'vitest';
import { assertProxyPassportCallerBinding } from './proxy.js';

describe.each(['standard', 'logged', 'enforced'] as const)(
  'proxy caller and Passport binding in %s mode',
  (_mode) => {
    it('refuses a Passport from another tenant', () => {
      expect(() => assertProxyPassportCallerBinding({
        authenticatedOperatorId: 'op_attacker',
        passportOperatorId: 'op_victim',
        passportAgentId: 'agt_victim',
      })).toThrow(/authenticated operator/u);
    });

    it('refuses a different agent when the caller has an agent identity', () => {
      expect(() => assertProxyPassportCallerBinding({
        authenticatedOperatorId: 'op_owner',
        authenticatedAgentId: 'agt_attacker',
        passportOperatorId: 'op_owner',
        passportAgentId: 'agt_victim',
      })).toThrow(/authenticated agent/u);
    });

    it('allows a human caller to use an agent Passport in the same tenant', () => {
      expect(() => assertProxyPassportCallerBinding({
        authenticatedOperatorId: 'op_owner',
        passportOperatorId: 'op_owner',
        passportAgentId: 'agt_delegated',
      })).not.toThrow();
    });

    it('allows an agent caller only with its own Passport', () => {
      expect(() => assertProxyPassportCallerBinding({
        authenticatedOperatorId: 'op_owner',
        authenticatedAgentId: 'agt_delegated',
        passportOperatorId: 'op_owner',
        passportAgentId: 'agt_delegated',
      })).not.toThrow();
    });
  },
);
