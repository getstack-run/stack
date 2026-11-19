import { describe, expect, it } from 'vitest';
import { AgentSetupInput, approvalScopeLines } from '@stack/shared';
import { buildSetupPreview, setupSummary } from './setup-preview.js';

const connections = new Map([['scon_a', { id: 'scon_a', provider: 'custom_grocer' }]]);

describe('the card of an agent setup', () => {
  const input = AgentSetupInput.parse({
    agent: { name: 'bot', accountability_mode: 'enforced', on_critical: 'block', eval_traffic: true },
    grants: [
      {
        service_connection_id: 'scon_a',
        scopes: ['read', 'write'],
        constraints: [{ path: 'url.pathname', op: 'starts_with', value: '/v1/products' }],
        allow_data_from: ['guestbook'],
      },
    ],
    allowed_hosts: [{ service_connection_id: 'scon_a', allowed_hosts: ['api.grocer.example', '.cdn.grocer.example'] }],
  });

  it('lists every part in full: posture, scopes, constraints, data flow and hosts', () => {
    expect(buildSetupPreview(input, connections)).toEqual({
      agent: {
        name: 'bot',
        description: null,
        accountability_mode: 'enforced',
        on_warning: 'notify',
        on_critical: 'block',
        credential_access: 'proxy_only',
        eval_traffic: true,
        other_fields: [],
      },
      grants: [
        {
          service_connection_id: 'scon_a',
          service: 'custom_grocer',
          scopes: ['read', 'write'],
          constraints: [{ path: 'url.pathname', op: 'starts_with', value: '/v1/products' }],
          intents: [],
          allow_data_from: ['guestbook'],
        },
      ],
      allowed_hosts: [{ service_connection_id: 'scon_a', service: 'custom_grocer', hosts: ['api.grocer.example', '.cdn.grocer.example'] }],
    });
  });

  it('shows what "nothing said" means: the defaults a bare registration gets', () => {
    const bare = AgentSetupInput.parse({ agent: { name: 'bot' }, grants: [{ service_connection_id: 'scon_a', scopes: ['read'] }] });
    expect(buildSetupPreview(bare, connections).agent).toMatchObject({
      accountability_mode: 'logged',
      on_warning: 'notify',
      on_critical: 'notify',
      credential_access: 'proxy_only',
      eval_traffic: false,
    });
  });

  it('carries the connection name as the owner gave it beside the id, and reads it as a quoted name in the chat lines', () => {
    const named = new Map([['scon_a', { id: 'scon_a', provider: 'custom_grocer', name: 'Work' }]]);
    const preview = buildSetupPreview(input, named);
    expect(preview.grants[0]).toMatchObject({ service_connection_id: 'scon_a', connection_name: 'Work', service: 'custom_grocer' });
    expect(preview.allowed_hosts[0]).toMatchObject({ service_connection_id: 'scon_a', connection_name: 'Work', service: 'custom_grocer' });
    const lines = approvalScopeLines({ action: 'agent_setup', setup_preview: preview });
    expect(lines).toContain('give it access to custom_grocer ("Work") with scopes read, write');
    expect(lines).toContain('allow the custom_grocer credential ("Work") to be sent to api.grocer.example, .cdn.grocer.example');
  });

  it('adds no name for a connection with none known: an older preview keeps the id and the lines as they were', () => {
    const preview = buildSetupPreview(input, connections);
    expect(preview.grants[0]).not.toHaveProperty('connection_name');
    expect(preview.allowed_hosts[0]).not.toHaveProperty('connection_name');
    expect(approvalScopeLines({ action: 'agent_setup', setup_preview: preview })).toContain('give it access to custom_grocer with scopes read, write');
  });

  it('falls back to the id for a connection it cannot name, never to nothing', () => {
    expect(buildSetupPreview(input, new Map()).grants[0]!.service).toBe('scon_a');
  });

  it('shows every registration field the request sets beyond the posture, read from the payload and not from a list', () => {
    const wide = AgentSetupInput.parse({
      agent: {
        name: 'bot', llm_redact_pii: false, skill_access_mode: 'all', key_mode: 'customer_managed', is_synthetic: true,
        llm_inject_system_prompt: false, twin_policy: 'never', allowed_skills: ['skl_one'], profile: 'proxied-llm-bot',
      },
      grants: [{ service_connection_id: 'scon_a', scopes: ['read'] }],
    });
    const shown = buildSetupPreview(wide, connections).agent.other_fields ?? [];
    expect(Object.fromEntries(shown.map((entry) => [entry.field, entry.value]))).toEqual({
      profile: '"proxied-llm-bot"', skill_access_mode: '"all"', allowed_skills: '"skl_one"', key_mode: '"customer_managed"',
      twin_policy: '"never"', is_synthetic: 'true', llm_inject_system_prompt: 'false', llm_redact_pii: 'false',
    });
    // The chat reads them as lines, each its own.
    const preview = buildSetupPreview(wide, connections);
    const lines = approvalScopeLines({ action: 'agent_setup', setup_preview: preview });
    expect(lines).toContain('also sets llm_redact_pii to false');
    expect(lines).toContain('also sets skill_access_mode to "all"');
    expect(buildSetupPreview(AgentSetupInput.parse({ agent: { name: 'bot' }, grants: [{ service_connection_id: 'scon_a', scopes: ['read'] }] }), connections).agent.other_fields).toEqual([]);
  });

  it('summarises in one line', () => {
    expect(setupSummary(input)).toBe('Set up agent bot: register it, 1 service grant, 1 host list');
  });
});
