import { describe, expect, it } from 'vitest';
import { approvalScopeLines } from '@stack/shared';
import { grantApproval } from './control-policy/grant-listing.js';
import { buildGrantPreview } from './grant-preview.js';

const input = {
  agent_id: 'agt_one',
  service_connection_id: 'scon_a',
  scopes: ['read', 'write'],
  constraints: [{ path: 'url.pathname', op: 'starts_with' as const, value: '/v1/products' }],
  intents: [{ name: 'grocer.add_to_cart', params: {} }],
  allow_data_from: ['guestbook'],
};

describe('the approval of a widened grant', () => {
  it('previews every scope, constraint, named action and data flow, by the service\'s name', () => {
    expect(buildGrantPreview(input, 'custom_grocer', null)).toEqual({
      agent_id: 'agt_one',
      service_connection_id: 'scon_a',
      service: 'custom_grocer',
      scopes: ['read', 'write'],
      constraints: [{ path: 'url.pathname', op: 'starts_with', value: '/v1/products' }],
      intents: ['grocer.add_to_cart'],
      allow_data_from: ['guestbook'],
    });
  });

  it('is what the chat shows: the lines list each part, and the policy listing when the approval carries one', () => {
    const listing = { plan: {} as never, ref: { policy_id: 'cpl_1', expected_revision: 3, definition_digest: 'd'.repeat(64) } };
    const asked = grantApproval(input, 'custom_grocer', listing);
    const lines = approvalScopeLines({ action: 'service_grant_expand', grant_preview: asked.preview });
    expect(lines).toEqual([
      'give agent agt_one access to custom_grocer with scopes read, write',
      '  url.pathname must start with "/v1/products"',
      '  limited to the named action grocer.add_to_cart',
      '  content from guestbook may flow into it',
      "and list this service in the agent's controls policy cpl_1, changing nothing else in it",
    ]);
    expect(asked.payload).toEqual({ ...input, policy_listing: listing.ref });
    expect(asked.summary).toMatch(/list the service in the agent's policy/);
  });

  it('names the connection as its owner named it, beside the id, and the chat line shows the quoted name', () => {
    const asked = grantApproval(input, 'custom_grocer', null, 'Work');
    expect(asked.preview).toMatchObject({ service_connection_id: input.service_connection_id, connection_name: 'Work', service: 'custom_grocer' });
    expect(approvalScopeLines({ action: 'service_grant_expand', grant_preview: asked.preview })[0])
      .toBe('give agent agt_one access to custom_grocer ("Work") with scopes read, write');
    // What the approval binds is the request alone: the name is display, never part of the payload or the summary.
    expect(asked.payload).toBe(input);
    expect(asked.summary).toBe('Expand this agent service grant');
  });

  it('adds no name when none is known: the preview and its lines are as they were', () => {
    const asked = grantApproval(input, 'custom_grocer', null, null);
    expect(asked.preview).not.toHaveProperty('connection_name');
    expect(approvalScopeLines({ action: 'service_grant_expand', grant_preview: asked.preview })[0])
      .toBe('give agent agt_one access to custom_grocer with scopes read, write');
  });

  it('binds the grant alone, with no policy fields, when nothing needs listing', () => {
    const asked = grantApproval(input, 'custom_grocer', null);
    expect(asked.payload).toBe(input);
    expect(asked.summary).toBe('Expand this agent service grant');
    expect(asked.preview).not.toHaveProperty('policy_listing');
  });
});
