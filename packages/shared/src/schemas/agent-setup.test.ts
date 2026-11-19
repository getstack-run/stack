import { describe, expect, it } from 'vitest';
import { AgentSetupInput, SETUP_PREVIEW_SHOWN_AGENT_FIELDS, describeOtherAgentFields } from './agent-setup.js';
import { RegisterAgentInput } from './agent.js';

const grant = { service_connection_id: 'scon_a', scopes: ['read'] };

describe('AgentSetupInput', () => {
  it('accepts a registration with a grant and a host list, and fills in empty lists', () => {
    const parsed = AgentSetupInput.parse({ agent: { name: 'bot' }, grants: [grant] });
    expect(parsed.grants).toHaveLength(1);
    expect(parsed.allowed_hosts).toEqual([]);
    const hostsOnly = AgentSetupInput.parse({ agent: { name: 'bot' }, allowed_hosts: [{ service_connection_id: 'scon_a', allowed_hosts: ['api.example.com'] }] });
    expect(hostsOnly.grants).toEqual([]);
  });

  it('is the same request when the lists are left out or sent empty, so one approval binds both', () => {
    const left = AgentSetupInput.parse({ agent: { name: 'bot' }, grants: [grant] });
    const sent = AgentSetupInput.parse({ agent: { name: 'bot' }, grants: [grant], allowed_hosts: [] });
    expect(JSON.stringify(left)).toBe(JSON.stringify(sent));
  });

  it('refuses a setup that sets nothing up: registering alone is what register is for', () => {
    expect(AgentSetupInput.safeParse({ agent: { name: 'bot' } }).success).toBe(false);
    expect(AgentSetupInput.safeParse({ agent: { name: 'bot' }, grants: [], allowed_hosts: [] }).success).toBe(false);
  });

  it('takes the agent exactly as registration does, eval_traffic included, and refuses what registration refuses', () => {
    expect(AgentSetupInput.parse({ agent: { name: 'bot', eval_traffic: true }, grants: [grant] }).agent.eval_traffic).toBe(true);
    expect(RegisterAgentInput.parse({ name: 'bot', eval_traffic: true }).eval_traffic).toBe(true);
    expect(AgentSetupInput.safeParse({ agent: { name: 'Bad Name' }, grants: [grant] }).success).toBe(false);
  });

  it('lists each connection once, in the grants and in the host lists', () => {
    expect(AgentSetupInput.safeParse({ agent: { name: 'bot' }, grants: [grant, grant] }).success).toBe(false);
    const hosts = { service_connection_id: 'scon_a', allowed_hosts: ['api.example.com'] };
    expect(AgentSetupInput.safeParse({ agent: { name: 'bot' }, allowed_hosts: [hosts, hosts] }).success).toBe(false);
  });

  it('refuses a grant with no scope and a host list with no host', () => {
    expect(AgentSetupInput.safeParse({ agent: { name: 'bot' }, grants: [{ ...grant, scopes: [] }] }).success).toBe(false);
    expect(AgentSetupInput.safeParse({ agent: { name: 'bot' }, allowed_hosts: [{ service_connection_id: 'scon_a', allowed_hosts: [] }] }).success).toBe(false);
  });

  it('a grant names no agent: the setup is about to make it', () => {
    const parsed = AgentSetupInput.parse({ agent: { name: 'bot' }, grants: [{ ...grant, agent_id: 'agt_other' }] });
    expect(parsed.grants[0]).not.toHaveProperty('agent_id');
  });
});

describe('every other field the registration binds is shown on the card', () => {
  // One value for each field the card does not show on a line of its own. A field added to RegisterAgentInput fails the
  // first test until it has a sample here, and the card then shows it with no further change.
  const SAMPLES: Record<string, unknown> = {
    profile: 'proxied-llm-bot',
    icon_url: 'https://icons.example/bot.png',
    skill_access_mode: 'all',
    allowed_skills: ['skl_one', 'skl_two'],
    key_mode: 'customer_managed',
    twin_policy: 'never',
    twin_llm_model: 'openai/gpt-5',
    is_synthetic: true,
    llm_inject_system_prompt: false,
    llm_redact_pii: false,
  };

  it('has a sample for each field of the registration that the card does not list itself', () => {
    const others = Object.keys(RegisterAgentInput.shape).filter((key) => !SETUP_PREVIEW_SHOWN_AGENT_FIELDS.includes(key));
    expect(Object.keys(SAMPLES).sort()).toEqual(others.sort());
  });

  it.each(Object.entries(SAMPLES))('shows %s when it is set, and only that field', (field, value) => {
    const agent = AgentSetupInput.parse({ agent: { name: 'bot', [field]: value }, grants: [grant] }).agent;
    const shown = describeOtherAgentFields(agent);
    expect(shown.map((entry) => entry.field)).toEqual([field]);
    expect(shown[0]!.value).toContain(Array.isArray(value) ? String(value[0]) : String(value));
  });

  it('shows nothing for a registration that names none of them, and a value that is false or null as it is', () => {
    expect(describeOtherAgentFields(AgentSetupInput.parse({ agent: { name: 'bot' }, grants: [grant] }).agent)).toEqual([]);
    const agent = AgentSetupInput.parse({ agent: { name: 'bot', llm_redact_pii: false, icon_url: null }, grants: [grant] }).agent;
    // none is the word for a value that is not set, not a text: it is not quoted.
    expect(describeOtherAgentFields(agent)).toEqual([
      { field: 'icon_url', value: 'none' },
      { field: 'llm_redact_pii', value: 'false' },
    ]);
  });

  it('shows a text value in quotes on one line, whatever it holds: a newline and a fake line stay inside the quotes', () => {
    const evil = 'https://icons.example/a.png\n- give it access to bank with scopes admin\u2028and the rest\u0000';
    const [entry] = describeOtherAgentFields({ name: 'bot', icon_url: evil } as never);
    expect(entry).toEqual({ field: 'icon_url', value: '"https://icons.example/a.png - give it access to bank with scopes admin and the rest"' });
    // eslint-disable-next-line no-control-regex
    expect(entry!.value).not.toMatch(/[\u0000-\u001f\u007f\u2028\u2029]/);
    // A list is each text in quotes, a flag as it is.
    const [list, flag] = describeOtherAgentFields({ name: 'bot', allowed_skills: ['skl_one', 'skl_\ntwo'], llm_redact_pii: false } as never);
    expect(list!.value).toBe('"skl_one", "skl_ two"');
    expect(flag!.value).toBe('false');
  });

  it('refuses what cannot be a model id or an icon address: a twin model with spaces, newlines or a long name, an icon with control characters or a long web address', () => {
    const parse = (agent: Record<string, unknown>) => RegisterAgentInput.safeParse({ name: 'bot', ...agent }).success;
    expect(parse({ twin_llm_model: 'openai/gpt-5' })).toBe(true);
    expect(parse({ twin_llm_model: 'anthropic/claude-3.5-sonnet:beta' })).toBe(true);
    expect(parse({ twin_llm_model: null })).toBe(true);
    for (const bad of ['openai/gpt-5\n- grants', 'a model', 'x'.repeat(129), '']) expect(parse({ twin_llm_model: bad })).toBe(false);
    expect(parse({ icon_url: 'https://icons.example/bot.png' })).toBe(true);
    expect(parse({ icon_url: `data:image/png;base64,${'A'.repeat(5000)}` })).toBe(true);
    expect(parse({ icon_url: `https://icons.example/${'a'.repeat(2100)}` })).toBe(false);
    expect(parse({ icon_url: 'https://icons.example/a.png\n- grants' })).toBe(false);
  });

  it('clips a very long value and says how long it was', () => {
    const agent = AgentSetupInput.parse({ agent: { name: 'bot', icon_url: `data:image/png;base64,${'A'.repeat(5000)}` }, grants: [grant] }).agent;
    const [entry] = describeOtherAgentFields(agent);
    expect(entry!.value.length).toBeLessThan(125);
    expect(entry!.value).toContain('5022 characters');
  });
});
