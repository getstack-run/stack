import { z } from 'zod';
import { defineIntent } from './types.js';

// Stripe API — https://stripe.com/docs/api. Base: api.stripe.com/v1/….
// Deliberately NO `create_charge` intent — charges are destructive /
// irreversible and should require raw constraints with explicit binding
// on customer ID or amount caps.

export const stripeIntents = [
  defineIntent({
    name: 'stripe.read_customers',
    effect: 'read',
    description:
      'List or retrieve Stripe customers. Binds GET /v1/customers and /v1/customers/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/customers(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'stripe.read_charges',
    effect: 'read',
    description:
      'List or retrieve Stripe charges. Binds GET /v1/charges and /v1/charges/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/charges(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'stripe.create_refund',
    effect: 'write',
    description:
      'Issue a refund against an existing charge. Binds POST /v1/refunds. The charge_id is in the body — consider pinning it via raw constraint.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/refunds' },
    ],
  }),

  defineIntent({
    name: 'stripe.create_invoice',
    effect: 'write',
    description:
      'Create a Stripe invoice. Binds POST /v1/invoices.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/invoices' },
    ],
  }),

  defineIntent({
    name: 'stripe.create_customer',
    effect: 'write',
    description:
      'Create a new Stripe customer record. Binds POST /v1/customers.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/customers' },
    ],
  }),

  defineIntent({
    name: 'stripe.update_customer',
    effect: 'write',
    description:
      'Update an existing Stripe customer. Binds POST /v1/customers/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/customers/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'stripe.delete_customer',
    effect: 'destructive',
    description:
      'Permanently delete a Stripe customer. Binds DELETE /v1/customers/{id} and is destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/customers/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'stripe.capture_charge',
    effect: 'write',
    description:
      'Capture a previously authorized charge. Binds POST /v1/charges/{id}/capture. Money-moving, so add an amount cap via raw constraint on body.amount.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/charges/[^/]+/capture$' },
    ],
  }),

  defineIntent({
    name: 'stripe.create_payment_intent',
    effect: 'write',
    description:
      'Create a PaymentIntent for a charge flow. Binds POST /v1/payment_intents. Money-moving, so pair with an amount cap (body.amount) allowlist.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/payment_intents' },
    ],
  }),

  defineIntent({
    name: 'stripe.confirm_payment_intent',
    effect: 'write',
    description:
      'Confirm a PaymentIntent and move it toward capture. Binds POST /v1/payment_intents/{id}/confirm and is money-moving.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/payment_intents/[^/]+/confirm$' },
    ],
  }),

  defineIntent({
    name: 'stripe.cancel_payment_intent',
    effect: 'write',
    description:
      'Cancel an in-flight PaymentIntent. Binds POST /v1/payment_intents/{id}/cancel.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/payment_intents/[^/]+/cancel$' },
    ],
  }),

  defineIntent({
    name: 'stripe.create_subscription',
    effect: 'write',
    description:
      'Create a recurring subscription for a customer. Binds POST /v1/subscriptions. Money-moving, pair with allowlisted price IDs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/subscriptions' },
    ],
  }),

  defineIntent({
    name: 'stripe.cancel_subscription',
    effect: 'destructive',
    description:
      'Cancel an existing subscription. Binds DELETE /v1/subscriptions/{id} and is destructive for the customer.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/subscriptions/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'stripe.finalize_invoice',
    effect: 'write',
    description:
      'Finalize a draft invoice so it becomes payable. Binds POST /v1/invoices/{id}/finalize.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/invoices/[^/]+/finalize$' },
    ],
  }),

  defineIntent({
    name: 'stripe.pay_invoice',
    effect: 'write',
    description:
      'Trigger payment of a finalized invoice. Binds POST /v1/invoices/{id}/pay and is money-moving — scope to trusted customer IDs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/invoices/[^/]+/pay$' },
    ],
  }),

  defineIntent({
    name: 'stripe.void_invoice',
    effect: 'write',
    description:
      'Void a finalized invoice so it is not collectible. Binds POST /v1/invoices/{id}/void.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/invoices/[^/]+/void$' },
    ],
  }),

  defineIntent({
    name: 'stripe.create_transfer',
    effect: 'write',
    description:
      'Create a transfer to a connected account. Binds POST /v1/transfers. Money-moving, use an allowlisted destination account.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/transfers' },
    ],
  }),

  defineIntent({
    name: 'stripe.create_payout',
    effect: 'write',
    description:
      'Create a payout to an external bank account. Binds POST /v1/payouts and is money-moving — pair with an amount cap.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/payouts' },
    ],
  }),

  defineIntent({
    name: 'stripe.read_balance',
    effect: 'read',
    description:
      'Read the current Stripe account balance. Binds GET /v1/balance.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/balance' },
    ],
  }),

  defineIntent({
    name: 'stripe.read_disputes',
    effect: 'read',
    description:
      'List or retrieve payment disputes. Binds GET /v1/disputes and /v1/disputes/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/disputes(/[^/]+)?$' },
    ],
  }),
];
