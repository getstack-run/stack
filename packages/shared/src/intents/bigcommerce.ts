import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// BigCommerce v3 API — https://developer.bigcommerce.com/docs/rest-catalog.
// Base: api.bigcommerce.com/stores/{store_hash}/v3/{resource}. Also v2
// for legacy order endpoints. store_hash scopes every call; pin it in
// the path so intents can't wander into sibling tenants.

const storeFmt = z
  .string()
  .min(4)
  .max(32)
  .regex(/^[a-z0-9]+$/i, 'store_hash is alphanumeric');
const storeList = z.union([storeFmt, z.array(storeFmt).min(1)]);
type StoreList = z.infer<typeof storeList>;
const toList = (v: StoreList): string[] => (Array.isArray(v) ? v : [v]);

function storePath(store: StoreList, suffix: string): Constraint {
  const list = toList(store);
  const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/stores/${alt}${suffix}$`,
  };
}

export const bigcommerceIntents = [
  defineIntent({
    name: 'bigcommerce.create_product',
    effect: 'write',
    description:
      'Create a product in an allowlisted BigCommerce store. Binds POST /stores/{hash}/v3/catalog/products.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      storePath(store, '/v3/catalog/products'),
    ],
  }),

  defineIntent({
    name: 'bigcommerce.update_product',
    effect: 'write',
    description:
      'Update a BigCommerce product. Binds PUT /stores/{hash}/v3/catalog/products/{id}.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      storePath(store, '/v3/catalog/products/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'bigcommerce.delete_product',
    effect: 'destructive',
    description:
      'Delete a BigCommerce product. Binds DELETE /stores/{hash}/v3/catalog/products/{id}; destructive.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      storePath(store, '/v3/catalog/products/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'bigcommerce.list_orders',
    effect: 'read',
    description:
      'List orders on an allowlisted store. Binds GET /stores/{hash}/v2/orders.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      storePath(store, '/v2/orders'),
    ],
  }),

  defineIntent({
    name: 'bigcommerce.update_order',
    effect: 'write',
    description:
      'Update a BigCommerce order status or fields. Binds PUT /stores/{hash}/v2/orders/{id}.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      storePath(store, '/v2/orders/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'bigcommerce.cancel_order',
    effect: 'write',
    description:
      'Cancel a BigCommerce order by updating its status. Binds PUT /stores/{hash}/v2/orders/{id} with body.status_id pinned at 5 (Cancelled) upstream.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      storePath(store, '/v2/orders/[^/]+'),
      { path: 'body.status_id', op: 'eq', value: 5 },
    ],
  }),

  defineIntent({
    name: 'bigcommerce.create_customer',
    effect: 'write',
    description:
      'Create a BigCommerce customer. Binds POST /stores/{hash}/v3/customers.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      storePath(store, '/v3/customers'),
    ],
  }),

  defineIntent({
    name: 'bigcommerce.update_customer',
    effect: 'write',
    description:
      'Update BigCommerce customers in bulk. Binds PUT /stores/{hash}/v3/customers.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      storePath(store, '/v3/customers'),
    ],
  }),

  defineIntent({
    name: 'bigcommerce.create_cart',
    effect: 'write',
    description:
      'Create a new cart on an allowlisted store. Binds POST /stores/{hash}/v3/carts.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      storePath(store, '/v3/carts'),
    ],
  }),

  defineIntent({
    name: 'bigcommerce.list_channels',
    effect: 'read',
    description:
      'List sales channels attached to a store. Binds GET /stores/{hash}/v3/channels.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      storePath(store, '/v3/channels'),
    ],
  }),

  defineIntent({
    name: 'bigcommerce.list_pricelists',
    effect: 'read',
    description:
      'List price lists on a store. Binds GET /stores/{hash}/v3/pricelists.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      storePath(store, '/v3/pricelists'),
    ],
  }),

  defineIntent({
    name: 'bigcommerce.create_promotion',
    effect: 'write',
    description:
      'Create a cart-level promotion on a store. Binds POST /stores/{hash}/v3/promotions.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      storePath(store, '/v3/promotions'),
    ],
  }),

  defineIntent({
    name: 'bigcommerce.create_webhook',
    effect: 'write',
    description:
      'Create a webhook subscription on a store. Binds POST /stores/{hash}/v3/hooks.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      storePath(store, '/v3/hooks'),
    ],
  }),

  defineIntent({
    name: 'bigcommerce.list_shipping_zones',
    effect: 'read',
    description:
      'List configured shipping zones. Binds GET /stores/{hash}/v2/shipping/zones.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      storePath(store, '/v2/shipping/zones'),
    ],
  }),

  defineIntent({
    name: 'bigcommerce.create_category',
    effect: 'write',
    description:
      'Create a catalog category. Binds POST /stores/{hash}/v3/catalog/categories.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      storePath(store, '/v3/catalog/categories'),
    ],
  }),

  defineIntent({
    name: 'bigcommerce.create_brand',
    effect: 'write',
    description:
      'Create a catalog brand. Binds POST /stores/{hash}/v3/catalog/brands.',
    params: z.object({ store: storeList }),
    expand: ({ store }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      storePath(store, '/v3/catalog/brands'),
    ],
  }),
];
