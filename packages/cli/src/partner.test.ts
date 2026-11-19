import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { cmdPartner } from './partner.js';

vi.mock('./api.js', async (importOriginal) => ({
  ...await importOriginal<object>(),
  api: vi.fn(async () => ({ account_id: 'op_1', external_ref: 'cus_1', status: 'active', billing: 'partner', created: true, created_at: 'now', api_key: 'sk_live_x' })),
  requireToken: vi.fn(async () => undefined),
}));

beforeEach(() => vi.clearAllMocks());

describe('partner account create', () => {
  it('opens an account with its controls off, and on only when --controls is given', async () => {
    await cmdPartner(['account', 'create', '--ref', 'cus_1', '--json']);
    await cmdPartner(['account', 'create', '--ref', 'cus_2', '--controls', '--json']);
    expect(vi.mocked(api).mock.calls).toEqual([
      ['POST', '/v1/partner/accounts', { body: { external_ref: 'cus_1' } }],
      ['POST', '/v1/partner/accounts', { body: { external_ref: 'cus_2', controls: true } }],
    ]);
  });
});
