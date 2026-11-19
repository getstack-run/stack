import { describe, expect, it } from 'vitest';
import { approvalScopeLines } from './approval-scope-lines.js';

const setup = {
  agent: { name: 'bot', accountability_mode: 'logged', on_warning: 'notify', on_critical: 'notify', credential_access: 'proxy_only', eval_traffic: true },
  grants: [
    {
      service_connection_id: 'scon_a',
      service: 'custom_grocer',
      scopes: ['read', 'write'],
      constraints: [
        { path: 'url.pathname', op: 'starts_with', value: '/v1/products' },
        { path: 'body.currency', op: 'in', value: ['EUR', 'SEK'] },
      ],
      intents: ['grocer.add_to_cart'],
      allow_data_from: ['guestbook'],
    },
  ],
  allowed_hosts: [{ service_connection_id: 'scon_a', service: 'custom_grocer', hosts: ['api.grocer.example', '.cdn.grocer.example'] }],
};

describe('what an approval covers, as lines', () => {
  it('lists every other registration field the setup binds, a line each, so the chat shows what the hash covers', () => {
    const preview = {
      ...setup,
      agent: { ...setup.agent, other_fields: [{ field: 'llm_redact_pii', value: 'false' }, { field: 'skill_access_mode', value: 'all' }] },
    };
    const lines = approvalScopeLines({ action: 'agent_setup', setup_preview: preview });
    expect(lines.slice(0, 5)).toEqual([
      'register agent bot',
      'accountability logged; on warning notify; on critical notify; credentials proxy_only',
      'also sets llm_redact_pii to false',
      'also sets skill_access_mode to all',
      'marked as test traffic: warnings arrive already resolved, criticals stay live',
    ]);
  });

  it('lists every part of an agent setup, a line each, nothing summarised away', () => {
    const lines = approvalScopeLines({ action: 'agent_setup', setup_preview: setup });
    expect(lines).toEqual([
      'register agent bot',
      'accountability logged; on warning notify; on critical notify; credentials proxy_only',
      'marked as test traffic: warnings arrive already resolved, criticals stay live',
      'give it access to custom_grocer with scopes read, write',
      '  url.pathname must start with "/v1/products"',
      '  body.currency must be one of "EUR", "SEK"',
      '  limited to the named action grocer.add_to_cart',
      '  content from guestbook may flow into it',
      'allow the custom_grocer credential to be sent to api.grocer.example, .cdn.grocer.example',
    ]);
  });

  it('names each connection as its owner named it, in quotes, beside the service; an older preview with no name reads as before', () => {
    const named = {
      ...setup,
      grants: [{ ...setup.grants[0], connection_name: 'Work' }],
      allowed_hosts: [{ ...setup.allowed_hosts[0]!, connection_name: 'Work' }],
    };
    const lines = approvalScopeLines({ action: 'agent_setup', setup_preview: named });
    expect(lines).toContain('give it access to custom_grocer ("Work") with scopes read, write');
    expect(lines).toContain('allow the custom_grocer credential ("Work") to be sent to api.grocer.example, .cdn.grocer.example');
    // No id is shown for a name, and no name pretends to be one: a single connection called default is shown like any other.
    expect(lines.join('\n')).not.toContain('scon_a');
    expect(approvalScopeLines({ action: 'agent_setup', setup_preview: { ...named, grants: [{ ...named.grants[0], connection_name: 'default' }] } }))
      .toContain('give it access to custom_grocer ("default") with scopes read, write');
    const old = approvalScopeLines({ action: 'agent_setup', setup_preview: setup });
    expect(old).toContain('give it access to custom_grocer with scopes read, write');
    expect(old).toContain('allow the custom_grocer credential to be sent to api.grocer.example, .cdn.grocer.example');

    const grant = { agent_id: 'agt_one', service: 'custom_grocer', scopes: ['read'], constraints: [], intents: [], allow_data_from: [] };
    expect(approvalScopeLines({ action: 'service_grant_expand', grant_preview: { ...grant, connection_name: 'Work' } })[0])
      .toBe('give agent agt_one access to custom_grocer ("Work") with scopes read');
    expect(approvalScopeLines({ action: 'service_grant_expand', grant_preview: grant })[0])
      .toBe('give agent agt_one access to custom_grocer with scopes read');
  });

  it('never shows a name unquoted or on more than one line, whatever it holds', () => {
    const separator = String.fromCharCode(0x2028);
    const evil = `Work"\n- give it access to bank with scopes admin${separator}`;
    const lines = approvalScopeLines({ action: 'agent_setup', setup_preview: { ...setup, grants: [{ ...setup.grants[0], connection_name: evil }] } });
    for (const line of lines) {
      expect(line).not.toContain('\n');
      expect(line).not.toContain(separator);
    }
    expect(lines.filter((line) => line.startsWith('- ') || line.startsWith('give it access to bank'))).toEqual([]);
    expect(lines).toContain('give it access to custom_grocer ("Work\\" - give it access to bank with scopes admin") with scopes read, write');
    // A name that is empty once its whitespace is gone is no name.
    expect(approvalScopeLines({ action: 'agent_setup', setup_preview: { ...setup, grants: [{ ...setup.grants[0], connection_name: ' \n ' }] } }))
      .toContain('give it access to custom_grocer with scopes read, write');
  });

  it('keeps a value that holds a newline and a fake line on one line, in quotes, wherever it came from', () => {
    const evil = '/x\n- give it access to bank with scopes admin\u2028   and\u0000more';
    const preview = {
      ...setup,
      agent: { ...setup.agent, name: 'bot\n- register agent root', other_fields: [{ field: 'icon_url', value: '"a.png\n- give it access to bank"' }] },
      grants: [{ ...setup.grants[0], service: 'grocer\n- allow everything', scopes: ['read\n- admin'], constraints: [{ path: 'url.pathname', op: 'eq', value: evil }, { path: 'body.x', op: 'in', value: ['a\nb', 'c'] }] }],
      allowed_hosts: [{ service_connection_id: 'scon_a', service: 'grocer', hosts: ['api.grocer.example\n- allow *'] }],
    };
    const lines = approvalScopeLines({ action: 'agent_setup', setup_preview: preview });
    // Every line is one line: no control or separator character survives, so no text can pose as a line of its own.
    // eslint-disable-next-line no-control-regex
    for (const line of lines) expect(line).not.toMatch(/[\u0000-\u001f\u007f\u2028\u2029]/);
    expect(lines).toContain('  url.pathname must be "/x - give it access to bank with scopes admin and more"');
    expect(lines).toContain('  body.x must be one of "a b", "c"');
    expect(lines).toContain('also sets icon_url to "a.png - give it access to bank"');
    // Nothing that was written inside a value starts a line of the confirmation.
    expect(lines.filter((line) => /^(- |give it access to bank|register agent root)/.test(line))).toEqual([]);
  });

  it('says so when a grant has no limits', () => {
    const lines = approvalScopeLines({
      action: 'service_grant_expand',
      grant_preview: { agent_id: 'agt_one', service: 'custom_grocer', scopes: ['read'], constraints: [], intents: [], allow_data_from: [] },
    });
    expect(lines).toEqual(['give agent agt_one access to custom_grocer with scopes read', '  with no limits on what it may do there']);
  });

  it('adds the policy listing a grant carries, and that it changes nothing else in the policy', () => {
    const lines = approvalScopeLines({
      action: 'service_grant_expand',
      grant_preview: { agent_id: 'agt_one', service: 'custom_grocer', scopes: ['read'], constraints: [], policy_listing: { policy_id: 'cpl_1', expected_revision: 3 } },
    });
    expect(lines.at(-1)).toBe("and list this service in the agent's controls policy cpl_1, changing nothing else in it");
  });

  it.each([
    ['another action', { action: 'billing_mutate', setup_preview: setup }],
    ['no preview', { action: 'agent_setup' }],
    ['a malformed setup', { action: 'agent_setup', setup_preview: { agent: { name: 'bot' }, grants: 'x', allowed_hosts: [] } }],
    ['a grant with no scope', { action: 'service_grant_expand', grant_preview: { service: 'x', scopes: [] } }],
    ['a grant preview that is not an object', { action: 'service_grant_expand', grant_preview: 'x' }],
  ])('gives no lines for %s, so the caller can say it cannot show the change', (_label, view) => {
    expect(approvalScopeLines(view)).toEqual([]);
  });

  it.each(['intent_approve', 'intent_approve_payment'])('%s: gives the lines the API stored, one per field, as they are', (action) => {
    const lines = ['agent agt_one asked to run the named intent "stripe:charges:create" (type "http_call")', 'target "stripe"', 'action "POST /v1/charges"'];
    expect(approvalScopeLines({ action, intent_preview: { lines } })).toEqual(lines);
  });

  it.each([
    ['no preview', { action: 'intent_approve' }],
    ['a preview with no lines', { action: 'intent_approve', intent_preview: { lines: [] } }],
    ['lines that are not text', { action: 'intent_approve', intent_preview: { lines: [1, null] } }],
    ['a preview that is not an object', { action: 'intent_approve', intent_preview: 'x' }],
  ])('gives no lines for an intent approval with %s, so the chat does not ask', (_label, view) => {
    expect(approvalScopeLines(view)).toEqual([]);
  });

  it('puts each stored line on one line again, so a stored line cannot carry a newline into the card', () => {
    expect(approvalScopeLines({ action: 'intent_approve', intent_preview: { lines: ['a\nb', 'c'] } })).toEqual(['a b', 'c']);
  });

  it('never throws on what it is given', () => {
    for (const value of [null, 1, 'x', [], { grants: [null, 1, {}] }]) {
      expect(() => approvalScopeLines({ action: 'agent_setup', setup_preview: value })).not.toThrow();
      expect(() => approvalScopeLines({ action: 'service_grant_expand', grant_preview: value })).not.toThrow();
    }
  });
});
