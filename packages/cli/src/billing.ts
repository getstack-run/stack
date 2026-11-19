import { api, takeFlag } from './api.js';
import { printJson } from './format.js';

// The agent-account subscriptions: the platform subscription and hosted
// controls, each a card subscription through Stripe Checkout with a free trial
// the first time. `subscribe` prints the Checkout URL to open; the
// subscription itself is written from Stripe's events and read back with
// `subscriptions`. Starting one needs no approval: the person pays on Stripe's page.

const SUBSCRIBE_KINDS = ['platform', 'controls'] as const;

export async function cmdBilling(argv: string[]): Promise<void> {
  const args = [...argv];
  takeFlag(args, '--json');
  const sub = args.shift();

  if (sub === 'subscriptions') return printJson(await api('GET', '/v1/billing/subscriptions'));

  if (sub === 'subscribe') {
    const kind = args.shift();
    if (kind !== 'platform' && kind !== 'controls') {
      throw new Error(`Invalid input: subscribe takes ${SUBSCRIBE_KINDS.join(' or ')}`);
    }
    return printJson(await api('POST', `/v1/billing/${kind}/subscribe`));
  }

  throw new Error('Invalid input: billing takes subscriptions or subscribe');
}
