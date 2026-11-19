import { z } from 'zod';
import { defineIntent } from './types.js';

// PayPal REST API — https://developer.paypal.com/api/rest/. Base:
// api-m.paypal.com. Mix of v1 and v2 endpoints. Intents gate on method
// plus pathname. Money-moving intents (capture, refund, payout) should
// be paired with raw amount-cap constraints on body.amount.value.

export const paypalIntents = [
  defineIntent({
    name: 'paypal.create_order',
    effect: 'write',
    description:
      'Create a Checkout order for a buyer to approve. Binds POST /v2/checkout/orders.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/checkout/orders' },
    ],
  }),

  defineIntent({
    name: 'paypal.capture_order',
    effect: 'write',
    description:
      'Capture funds on an approved Checkout order. Binds POST /v2/checkout/orders/{id}/capture. Money-moving; pair with an amount cap.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/checkout/orders/[^/]+/capture$' },
    ],
  }),

  defineIntent({
    name: 'paypal.authorize_order',
    effect: 'write',
    description:
      'Authorize a Checkout order without immediate capture. Binds POST /v2/checkout/orders/{id}/authorize.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/checkout/orders/[^/]+/authorize$' },
    ],
  }),

  defineIntent({
    name: 'paypal.void_order',
    effect: 'write',
    description:
      'Void an authorized but uncaptured payment. Binds POST /v2/payments/authorizations/{id}/void.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/payments/authorizations/[^/]+/void$' },
    ],
  }),

  defineIntent({
    name: 'paypal.refund_capture',
    effect: 'write',
    description:
      'Refund a captured payment. Binds POST /v2/payments/captures/{id}/refund. Money-moving; scope to known capture IDs and add an amount cap.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/payments/captures/[^/]+/refund$' },
    ],
  }),

  defineIntent({
    name: 'paypal.read_capture',
    effect: 'read',
    description:
      'Retrieve a specific payment capture. Binds GET /v2/payments/captures/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/payments/captures/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'paypal.create_invoice',
    effect: 'write',
    description:
      'Draft a new PayPal invoice. Binds POST /v2/invoicing/invoices.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/invoicing/invoices' },
    ],
  }),

  defineIntent({
    name: 'paypal.send_invoice',
    effect: 'send',
    description:
      'Send a drafted PayPal invoice to its recipient. Binds POST /v2/invoicing/invoices/{id}/send.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/invoicing/invoices/[^/]+/send$' },
    ],
  }),

  defineIntent({
    name: 'paypal.cancel_invoice',
    effect: 'write',
    description:
      'Cancel a sent PayPal invoice. Binds POST /v2/invoicing/invoices/{id}/cancel.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/invoicing/invoices/[^/]+/cancel$' },
    ],
  }),

  defineIntent({
    name: 'paypal.create_payout',
    effect: 'write',
    description:
      'Create a batch payout to one or more recipients. Binds POST /v1/payments/payouts. Money-moving; keep batch size and amount capped.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/payments/payouts' },
    ],
  }),

  defineIntent({
    name: 'paypal.read_payout',
    effect: 'read',
    description:
      'Retrieve a payout batch status. Binds GET /v1/payments/payouts/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/payments/payouts/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'paypal.create_subscription',
    effect: 'write',
    description:
      'Create a billing subscription against a pre-existing plan. Binds POST /v1/billing/subscriptions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/billing/subscriptions' },
    ],
  }),

  defineIntent({
    name: 'paypal.cancel_subscription',
    effect: 'write',
    description:
      'Cancel an active PayPal subscription. Binds POST /v1/billing/subscriptions/{id}/cancel.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/billing/subscriptions/[^/]+/cancel$' },
    ],
  }),

  defineIntent({
    name: 'paypal.suspend_subscription',
    effect: 'write',
    description:
      'Suspend an active PayPal subscription. Binds POST /v1/billing/subscriptions/{id}/suspend.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/billing/subscriptions/[^/]+/suspend$' },
    ],
  }),

  defineIntent({
    name: 'paypal.list_disputes',
    effect: 'read',
    description:
      'List disputes raised against the account. Binds GET /v1/customer/disputes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/customer/disputes' },
    ],
  }),

  defineIntent({
    name: 'paypal.read_dispute',
    effect: 'read',
    description:
      'Read a specific dispute record. Binds GET /v1/customer/disputes/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/customer/disputes/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'paypal.verify_webhook_signature',
    effect: 'read',
    description:
      'Verify a PayPal webhook signature. Binds POST /v1/notifications/verify-webhook-signature.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/notifications/verify-webhook-signature' },
    ],
  }),
];
