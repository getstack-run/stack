import { describe, expect, it } from 'vitest';
import { CONNECTED_SERVICES_PATH, findConnectedService } from './services.js';
import { inboundWebhookCreateOptions } from './inbound-webhooks.js';
import { takeLlmUsageLimit } from './llm.js';
import { quickstartAgentProfileProblem, quickstartGrantBody } from './quickstart.js';

describe('CLI command regressions', () => {
  it('uses the registered connected-services route and resolves show from that list', () => {
    const connections = [
      { id: 'svc_one', provider: 'anthropic', status: 'active', scopes: ['messages.create'] },
      { id: 'svc_two', provider: 'stripe', status: 'active' },
    ];

    expect(CONNECTED_SERVICES_PATH).toBe('/v1/services/connected');
    expect(findConnectedService(connections, 'svc_two')).toEqual(connections[1]);
    expect(findConnectedService(connections, 'svc_missing')).toBeUndefined();
  });

  it('wraps inbound-webhook create fields in the API body envelope', () => {
    const body = { provider: 'stripe', agent_id: 'agt_one' };
    expect(inboundWebhookCreateOptions(body)).toEqual({ body });
  });

  it('keeps the supplied LLM usage limit', () => {
    const args = ['--limit', '7', '--provider', 'anthropic'];
    expect(takeLlmUsageLimit(args)).toBe('7');
    expect(args).toEqual(['--provider', 'anthropic']);
  });

  it('creates the provider grant before quickstart issues a passport', () => {
    expect(
      quickstartGrantBody(
        { id: 'svc_anthropic', scopes: ['messages.create'] },
        [],
        'agt_quickstart',
      ),
    ).toEqual({
      agent_id: 'agt_quickstart',
      service_connection_id: 'svc_anthropic',
      scopes: ['messages.create'],
    });
  });

  it('does not replace an existing provider grant', () => {
    expect(
      quickstartGrantBody(
        { id: 'svc_anthropic', scopes: ['messages.create'] },
        [{ service_connection_id: 'svc_anthropic' }],
        'agt_quickstart',
      ),
    ).toBeUndefined();
  });

  it('fails closed when the selected provider has no grantable scopes', () => {
    expect(() => quickstartGrantBody({ id: 'svc_anthropic' }, [], 'agt_quickstart')).toThrow(
      'no grantable scopes',
    );
  });

  it('reuses a quickstart agent only when its security posture matches', () => {
    expect(
      quickstartAgentProfileProblem({
        id: 'agt_safe',
        name: 'quickstart-bot',
        credential_access: 'proxy_only',
        accountability_mode: 'logged',
        key_mode: 'stack_managed',
      }),
    ).toBeUndefined();

    expect(
      quickstartAgentProfileProblem({
        id: 'agt_other',
        name: 'quickstart-bot',
        credential_access: 'direct',
        accountability_mode: 'standard',
        key_mode: 'customer_managed',
      }),
    ).toContain('credential_access=direct (expected proxy_only)');
  });
});
