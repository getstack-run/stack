import { describe, it, expect } from 'vitest';
import { PassportSigner } from '../crypto/passport-signer.js';
import { evaluateScopePolicy, normalizeRequest, type ServiceScope } from '@stack/shared';
import type { ProxyRequestInput } from '@stack/shared';

/**
 * A closed operation policy only protects anything if it survives the trip
 * through the signed passport. Zod strips unknown keys on parse, so a policy
 * that was not part of the ServiceScope schema would be silently dropped at
 * verify time — the passport would look correct, the proxy would find no
 * policy, and every request would sail through the legacy open path.
 *
 * That failure would be invisible: no error, no denial, just a control that
 * quietly is not there. So it gets its own test.
 */

const POLICY_SCOPE: ServiceScope = {
  service_id: 'svc_resend',
  service_name: 'resend',
  scopes: ['email:send'],
  credential_ref: 'dev-key',
  connection_id: 'scon_test',
  policy: {
    mode: 'closed',
    operations: [
      {
        id: 'send_to_alice',
        methods: ['POST'],
        path: { kind: 'exact', value: '/emails' },
        allow_fields: ['body.from', 'body.to', 'body.subject', 'body.text'],
        constraints: [{ path: 'body.to', op: 'eq', value: 'alice@corp.com' }],
      },
    ],
  },
};

function proxyReq(body: unknown) {
  return normalizeRequest({
    service: 'resend',
    url: 'https://api.resend.com/emails',
    method: 'POST',
    body,
  } as ProxyRequestInput);
}

describe('scope policy survives the signed passport', () => {
  it('round-trips through sign and verify intact', async () => {
    const signer = new PassportSigner();
    await signer.init();

    const { token } = await signer.sign(
      'pas_policy_roundtrip',
      {
        operator_id: 'op_test',
        agent_id: 'agt_test',
        agent_name: 'policy round-trip',
        services: [POLICY_SCOPE],
        identity_claims: [],
        delegation_depth: 0,
        session_id: 'ses_test',
        accountability: 'enforced',
        intent_summary: 'round-trip fixture',
        intent_services: ['resend'],
      },
      3600,
    );

    const claims = await signer.verify(token);
    const scope = claims.stk.services.find((s) => s.service_name === 'resend');

    expect(scope?.policy, 'policy was dropped in the JWT round-trip').toBeDefined();
    expect(scope?.policy?.mode).toBe('closed');
    expect(scope?.policy?.operations).toHaveLength(1);
    expect(scope?.policy?.operations[0]?.allow_fields).toContain('body.to');
    expect(scope?.policy?.operations[0]?.constraints?.[0]?.op).toBe('eq');
  });

  it('still enforces after the round-trip, which is the point', async () => {
    const signer = new PassportSigner();
    await signer.init();
    const { token } = await signer.sign(
      'pas_policy_enforce',
      {
        operator_id: 'op_test',
        agent_id: 'agt_test',
        agent_name: 'policy enforce',
        services: [POLICY_SCOPE],
        identity_claims: [],
        delegation_depth: 0,
        session_id: 'ses_test',
        accountability: 'enforced',
        intent_summary: 'enforce fixture',
        intent_services: ['resend'],
      },
      3600,
    );
    const claims = await signer.verify(token);
    const scope = claims.stk.services.find((s) => s.service_name === 'resend');

    const ok = { from: 'bot@corp.com', to: 'alice@corp.com', subject: 's', text: 't' };
    expect(evaluateScopePolicy(scope?.policy, proxyReq(ok))).toBeNull();

    const smuggled = { ...ok, bcc: 'attacker@evil.com' };
    const denial = evaluateScopePolicy(scope?.policy, proxyReq(smuggled));
    expect(denial?.reason).toBe('undeclared_field');
  });
});
