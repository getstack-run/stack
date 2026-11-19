import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { printJson } from './format.js';
import { cmdBilling } from './billing.js';

vi.mock('./api.js', async importOriginal => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({ checkout_url: 'https://checkout.stripe.test/c/pay/cs_1' })) }));
vi.mock('./format.js', async importOriginal => ({ ...await importOriginal<object>(), printJson: vi.fn() }));

beforeEach(() => vi.clearAllMocks());

describe('billing CLI wire contract', () => {
  it('reads the subscription state', async () => {
    await cmdBilling(['subscriptions']);
    expect(api).toHaveBeenCalledWith('GET', '/v1/billing/subscriptions');
  });

  it('starts the platform and controls checkouts with no approval step and prints the result', async () => {
    await cmdBilling(['subscribe', 'platform']);
    await cmdBilling(['subscribe', 'controls']);
    expect(api).toHaveBeenNthCalledWith(1, 'POST', '/v1/billing/platform/subscribe');
    expect(api).toHaveBeenNthCalledWith(2, 'POST', '/v1/billing/controls/subscribe');
    expect(printJson).toHaveBeenCalledWith({ checkout_url: 'https://checkout.stripe.test/c/pay/cs_1' });
  });

  it('refuses a missing or unknown subscription kind before any request', async () => {
    await expect(cmdBilling(['subscribe'])).rejects.toThrow(/platform or controls/);
    await expect(cmdBilling(['subscribe', 'enterprise'])).rejects.toThrow(/platform or controls/);
    expect(api).not.toHaveBeenCalled();
  });

  it('refuses an unknown subcommand', async () => {
    await expect(cmdBilling(['nope'])).rejects.toThrow(/billing takes/);
    await expect(cmdBilling([])).rejects.toThrow(/billing takes/);
  });
});
