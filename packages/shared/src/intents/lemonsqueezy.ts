import { z } from 'zod';
import { defineIntent } from './types.js';

// Lemon Squeezy API — https://docs.lemonsqueezy.com/api. Base:
// api.lemonsqueezy.com/v1. JSON:API style. Most tenant scoping is done
// via store_id query filter; intents gate on method + pathname. Money-
// moving intents (cancel/resume/pause subscription) note the scope.

export const lemonsqueezyIntents = [
  defineIntent({
    name: 'lemonsqueezy.list_stores',
    effect: 'read',
    description:
      'List the Lemon Squeezy stores attached to the account. Binds GET /v1/stores.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/stores' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.list_products',
    effect: 'read',
    description:
      'List Lemon Squeezy products. Binds GET /v1/products.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/products' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.list_variants',
    effect: 'read',
    description:
      'List variants across products. Binds GET /v1/variants.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/variants' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.create_customer',
    effect: 'write',
    description:
      'Create a Lemon Squeezy customer record. Binds POST /v1/customers.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/customers' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.update_customer',
    effect: 'write',
    description:
      'Update a Lemon Squeezy customer record. Binds PATCH /v1/customers/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/customers/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.list_orders',
    effect: 'read',
    description:
      'List orders on the account. Binds GET /v1/orders.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/orders' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.read_order',
    effect: 'read',
    description:
      'Read a single order. Binds GET /v1/orders/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/orders/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.cancel_subscription',
    effect: 'destructive',
    description:
      'Cancel a Lemon Squeezy subscription. Binds DELETE /v1/subscriptions/{id}; destructive for the customer and revenue-affecting.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/subscriptions/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.update_subscription',
    effect: 'write',
    description:
      'Update a subscription (pause, resume, change plan). Binds PATCH /v1/subscriptions/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/subscriptions/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.list_subscriptions',
    effect: 'read',
    description:
      'List subscriptions on the account. Binds GET /v1/subscriptions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/subscriptions' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.create_checkout',
    effect: 'write',
    description:
      'Create a hosted checkout link. Binds POST /v1/checkouts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/checkouts' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.create_discount',
    effect: 'write',
    description:
      'Create a discount code. Binds POST /v1/discounts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/discounts' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.delete_discount',
    effect: 'destructive',
    description:
      'Delete a discount code. Binds DELETE /v1/discounts/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/discounts/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.activate_license',
    effect: 'write',
    description:
      'Activate a license key. Binds POST /v1/licenses/activate.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/licenses/activate' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.validate_license',
    effect: 'read',
    description:
      'Validate a license key without consuming activation. Binds POST /v1/licenses/validate.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/licenses/validate' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.create_webhook',
    effect: 'write',
    description:
      'Create a webhook subscription. Binds POST /v1/webhooks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/webhooks' },
    ],
  }),

  defineIntent({
    name: 'lemonsqueezy.create_usage_record',
    effect: 'write',
    description:
      'Record metered usage against a subscription item. Binds POST /v1/usage-records. Money-affecting via overage billing.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/usage-records' },
    ],
  }),
];
