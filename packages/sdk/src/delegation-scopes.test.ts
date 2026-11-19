import { describe, expect, it } from 'vitest';
import { delegationScopesFromToken } from './delegation-scopes.js';

describe('delegation request scope inheritance', () => {
  it('preserves connection constraints and data flow when selecting a parent service', () => {
    const constraints = [{ path: 'body.channel', op: 'eq', value: 'C123' }];
    const token = ['e30', Buffer.from(JSON.stringify({ stk: { services: [
      { service_name: 'slack', connection_id: 'scon_slack', scopes: ['chat:write'], constraints, allow_data_from: ['github'] },
      { service_name: 'github', connection_id: 'scon_github', scopes: ['read'] },
    ] } })).toString('base64url'), 'signature'].join('.');
    expect(delegationScopesFromToken(token, ['slack'])).toEqual([
      { service_connection_id: 'scon_slack', scopes: ['chat:write'], constraints, allow_data_from: ['github'] },
    ]);
    expect(delegationScopesFromToken(token)).toHaveLength(2);
    expect(() => delegationScopesFromToken(token, ['stripe'])).toThrow('Invalid input');
  });
});
