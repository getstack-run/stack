import { z } from 'zod';
import { defineIntent } from './types.js';

// Gumroad API — https://gumroad.com/api. Base: api.gumroad.com/v2.
// Gumroad uses access tokens scoped to a single creator account; intents
// gate on method + pathname. Resource IDs are opaque strings in the path.

export const gumroadIntents = [
  defineIntent({
    name: 'gumroad.list_products',
    effect: 'read',
    description:
      'List all Gumroad products for the authenticated creator. Binds GET /v2/products.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/products' },
    ],
  }),

  defineIntent({
    name: 'gumroad.read_product',
    effect: 'read',
    description:
      'Read a single Gumroad product. Binds GET /v2/products/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/products/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'gumroad.enable_product',
    effect: 'write',
    description:
      'Enable a Gumroad product so it is available for sale. Binds PUT /v2/products/{id}/enable.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/products/[^/]+/enable$' },
    ],
  }),

  defineIntent({
    name: 'gumroad.disable_product',
    effect: 'write',
    description:
      'Disable a Gumroad product so it is hidden from sale. Binds PUT /v2/products/{id}/disable.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/products/[^/]+/disable$' },
    ],
  }),

  defineIntent({
    name: 'gumroad.delete_product',
    effect: 'destructive',
    description:
      'Delete a Gumroad product. Binds DELETE /v2/products/{id}; destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/products/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'gumroad.list_variants',
    effect: 'read',
    description:
      'List variant categories for a product. Binds GET /v2/products/{product_id}/variant_categories.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v2/products/[^/]+/variant_categories$',
      },
    ],
  }),

  defineIntent({
    name: 'gumroad.create_offer_code',
    effect: 'write',
    description:
      'Create a discount code for a specific product. Binds POST /v2/products/{product_id}/offer_codes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/products/[^/]+/offer_codes$' },
    ],
  }),

  defineIntent({
    name: 'gumroad.update_offer_code',
    effect: 'write',
    description:
      'Update an existing offer code. Binds PUT /v2/products/{product_id}/offer_codes/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v2/products/[^/]+/offer_codes/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'gumroad.delete_offer_code',
    effect: 'destructive',
    description:
      'Delete an offer code. Binds DELETE /v2/products/{product_id}/offer_codes/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v2/products/[^/]+/offer_codes/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'gumroad.list_sales',
    effect: 'read',
    description:
      'List sales for the creator. Binds GET /v2/sales.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/sales' },
    ],
  }),

  defineIntent({
    name: 'gumroad.list_subscribers',
    effect: 'read',
    description:
      'List subscribers for a specific product. Binds GET /v2/products/{product_id}/subscribers.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v2/products/[^/]+/subscribers$',
      },
    ],
  }),

  defineIntent({
    name: 'gumroad.cancel_subscriber',
    effect: 'destructive',
    description:
      'Cancel a subscription for a subscriber. Binds DELETE /v2/subscribers/{id}. Destructive for the customer.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/subscribers/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'gumroad.list_resource_subscriptions',
    effect: 'read',
    description:
      'List webhook resource subscriptions. Binds GET /v2/resource_subscriptions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/resource_subscriptions' },
    ],
  }),

  defineIntent({
    name: 'gumroad.verify_license',
    effect: 'read',
    description:
      'Verify a license key for a product. Binds POST /v2/licenses/verify.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/licenses/verify' },
    ],
  }),

  defineIntent({
    name: 'gumroad.enable_license',
    effect: 'write',
    description:
      'Enable a previously disabled license. Binds PUT /v2/licenses/enable.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'eq', value: '/v2/licenses/enable' },
    ],
  }),

  defineIntent({
    name: 'gumroad.disable_license',
    effect: 'write',
    description:
      'Disable a license so it stops validating. Binds PUT /v2/licenses/disable.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'eq', value: '/v2/licenses/disable' },
    ],
  }),

  defineIntent({
    name: 'gumroad.read_user',
    effect: 'read',
    description:
      'Read the authenticated Gumroad user profile. Binds GET /v2/user.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/user' },
    ],
  }),
];
