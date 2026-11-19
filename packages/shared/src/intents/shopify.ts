import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Shopify Admin REST API — https://shopify.dev/docs/api/admin-rest.
// Base: {shop}.myshopify.com/admin/api/{version}/{resource}.json. We pin
// to api/2024-10. Host is per-store, so allowlisting at url.host is the
// strongest scope; intents enforce method + path.

const shopFmt = z
  .string()
  .min(4)
  .max(64)
  .regex(/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/, 'shop host must be *.myshopify.com');
const shopList = z.union([shopFmt, z.array(shopFmt).min(1)]);
type ShopList = z.infer<typeof shopList>;
const toList = (v: ShopList): string[] => (Array.isArray(v) ? v : [v]);

function hostConstraint(shop: ShopList): Constraint {
  const list = toList(shop);
  return list.length === 1
    ? { path: 'url.host', op: 'eq', value: list[0]! }
    : { path: 'url.host', op: 'in', value: list };
}

export const shopifyIntents = [
  defineIntent({
    name: 'shopify.create_product',
    effect: 'write',
    description:
      'Create a product on allowlisted Shopify stores. Binds POST /admin/api/2024-10/products.json to the declared shop hosts.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/admin/api/2024-10/products.json' },
      hostConstraint(shop),
    ],
  }),

  defineIntent({
    name: 'shopify.update_product',
    effect: 'write',
    description:
      'Update an existing Shopify product. Binds PUT /admin/api/2024-10/products/{id}.json.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/admin/api/2024-10/products/[^/]+\\.json$' },
      hostConstraint(shop),
    ],
  }),

  defineIntent({
    name: 'shopify.delete_product',
    effect: 'destructive',
    description:
      'Delete a Shopify product. Binds DELETE /admin/api/2024-10/products/{id}.json; destructive.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/admin/api/2024-10/products/[^/]+\\.json$' },
      hostConstraint(shop),
    ],
  }),

  defineIntent({
    name: 'shopify.read_orders',
    effect: 'read',
    description:
      'List or read Shopify orders on allowlisted stores. Binds GET /admin/api/2024-10/orders.json and /orders/{id}.json.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/admin/api/2024-10/orders(/[^/]+)?\\.json$',
      },
      hostConstraint(shop),
    ],
  }),

  defineIntent({
    name: 'shopify.cancel_order',
    effect: 'write',
    description:
      'Cancel an existing Shopify order. Binds POST /admin/api/2024-10/orders/{id}/cancel.json. Destructive for the customer.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/admin/api/2024-10/orders/[^/]+/cancel\\.json$',
      },
      hostConstraint(shop),
    ],
  }),

  defineIntent({
    name: 'shopify.close_order',
    effect: 'write',
    description:
      'Close (archive) a Shopify order. Binds POST /admin/api/2024-10/orders/{id}/close.json.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/admin/api/2024-10/orders/[^/]+/close\\.json$',
      },
      hostConstraint(shop),
    ],
  }),

  defineIntent({
    name: 'shopify.fulfill_order',
    effect: 'write',
    description:
      'Create a fulfillment against a Shopify order. Binds POST /admin/api/2024-10/fulfillments.json.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/admin/api/2024-10/fulfillments.json' },
      hostConstraint(shop),
    ],
  }),

  defineIntent({
    name: 'shopify.refund_order',
    effect: 'write',
    description:
      'Issue a refund against a Shopify order. Binds POST /admin/api/2024-10/orders/{id}/refunds.json. Money-moving; pair with amount cap in body.refund.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/admin/api/2024-10/orders/[^/]+/refunds\\.json$',
      },
      hostConstraint(shop),
    ],
  }),

  defineIntent({
    name: 'shopify.create_customer',
    effect: 'write',
    description:
      'Create a Shopify customer. Binds POST /admin/api/2024-10/customers.json on the allowlisted store hosts.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/admin/api/2024-10/customers.json' },
      hostConstraint(shop),
    ],
  }),

  defineIntent({
    name: 'shopify.update_customer',
    effect: 'write',
    description:
      'Update a Shopify customer. Binds PUT /admin/api/2024-10/customers/{id}.json.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/admin/api/2024-10/customers/[^/]+\\.json$',
      },
      hostConstraint(shop),
    ],
  }),

  defineIntent({
    name: 'shopify.adjust_inventory',
    effect: 'write',
    description:
      'Adjust an inventory level on allowlisted Shopify stores. Binds POST /admin/api/2024-10/inventory_levels/adjust.json.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'eq',
        value: '/admin/api/2024-10/inventory_levels/adjust.json',
      },
      hostConstraint(shop),
    ],
  }),

  defineIntent({
    name: 'shopify.create_draft_order',
    effect: 'write',
    description:
      'Create a draft order on a Shopify store. Binds POST /admin/api/2024-10/draft_orders.json.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/admin/api/2024-10/draft_orders.json' },
      hostConstraint(shop),
    ],
  }),

  defineIntent({
    name: 'shopify.create_price_rule',
    effect: 'write',
    description:
      'Create a price rule (discount) on a Shopify store. Binds POST /admin/api/2024-10/price_rules.json.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/admin/api/2024-10/price_rules.json' },
      hostConstraint(shop),
    ],
  }),

  defineIntent({
    name: 'shopify.create_discount_code',
    effect: 'write',
    description:
      'Create a discount code under a price rule. Binds POST /admin/api/2024-10/price_rules/{rule_id}/discount_codes.json.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/admin/api/2024-10/price_rules/[^/]+/discount_codes\\.json$',
      },
      hostConstraint(shop),
    ],
  }),

  defineIntent({
    name: 'shopify.create_metafield',
    effect: 'write',
    description:
      'Create a metafield on a Shopify resource. Binds POST /admin/api/2024-10/metafields.json.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/admin/api/2024-10/metafields.json' },
      hostConstraint(shop),
    ],
  }),

  defineIntent({
    name: 'shopify.create_webhook',
    effect: 'write',
    description:
      'Subscribe a webhook to Shopify events. Binds POST /admin/api/2024-10/webhooks.json.',
    params: z.object({ shop: shopList }),
    expand: ({ shop }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/admin/api/2024-10/webhooks.json' },
      hostConstraint(shop),
    ],
  }),
];
