import { describe, expect, it, vi } from 'vitest';
import { fakeBrowserSessions } from '../test/browser-sessions.js';
import { OperatorSuspendedError } from '@stack/shared';
import { registerGovernancePublicRoutes } from './governance.js';

describe('POST /v1/governance/approvals/:id/decide lifecycle', () => {
  it('rejects a suspended operator even when the dashboard session is still valid', async () => {
    let handler: ((request: unknown, reply: unknown) => Promise<unknown>) | undefined;
    const app = {
      post(_path: string, routeHandler: typeof handler) {
        handler = routeHandler;
      },
    };
    const decideGovernance = vi.fn();
    registerGovernancePublicRoutes(app as never, {
      signer: {
        verifyAccessOrSession: vi.fn(async () => ({
          aud: 'stack:dashboard',
          sub: 'op_one',
          payload: {},
        })),
      },
      operator: {
        getById: vi.fn(async () => ({ status: 'suspended', suspended_reason: 'security hold' })),
      },
      operatorDecision: { decideGovernance },
      get browserSessions() { return fakeBrowserSessions(this); },
    } as never);

    await expect(handler!({
      id: 'req_one',
      headers: { cookie: 'stack_session=session' },
      params: { id: 'gvr_one' },
      body: { decision: 'approve' },
    }, { send: vi.fn() })).rejects.toBeInstanceOf(OperatorSuspendedError);
    expect(decideGovernance).not.toHaveBeenCalled();
  });
});
