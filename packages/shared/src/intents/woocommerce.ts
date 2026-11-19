import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// WooCommerce REST API v3 — https://woocommerce.github.io/woocommerce-rest-api-docs/.
// Base: {site}/wp-json/wc/v3/{resource}. The WordPress site is the tenant,
// so allowlisting url.host is the primary scope. Intents also gate
// method + pathname under /wp-json/wc/v3/.

const hostFmt = z.string().min(3).max(128);
const hostList = z.union([hostFmt, z.array(hostFmt).min(1)]);
type HostList = z.infer<typeof hostList>;
const toList = (v: HostList): string[] => (Array.isArray(v) ? v : [v]);

function hostConstraint(host: HostList): Constraint {
  const list = toList(host);
  return list.length === 1
    ? { path: 'url.host', op: 'eq', value: list[0]! }
    : { path: 'url.host', op: 'in', value: list };
}

export const woocommerceIntents = [
  defineIntent({
    name: 'woocommerce.create_product',
    effect: 'write',
    description:
      'Create a WooCommerce product on an allowlisted site. Binds POST /wp-json/wc/v3/products scoped to the host allowlist.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wc/v3/products' },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.update_product',
    effect: 'write',
    description:
      'Update a WooCommerce product. Binds PUT /wp-json/wc/v3/products/{id}.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/wp-json/wc/v3/products/[0-9]+$' },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.delete_product',
    effect: 'destructive',
    description:
      'Delete a WooCommerce product. Binds DELETE /wp-json/wc/v3/products/{id}; destructive.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/wp-json/wc/v3/products/[0-9]+$' },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.create_order',
    effect: 'write',
    description:
      'Create a WooCommerce order. Binds POST /wp-json/wc/v3/orders.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wc/v3/orders' },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.update_order',
    effect: 'write',
    description:
      'Update a WooCommerce order (status, billing, etc.). Binds PUT /wp-json/wc/v3/orders/{id}.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/wp-json/wc/v3/orders/[0-9]+$' },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.read_orders',
    effect: 'read',
    description:
      'List or read WooCommerce orders. Binds GET /wp-json/wc/v3/orders and /wp-json/wc/v3/orders/{id}.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/wp-json/wc/v3/orders(/[0-9]+)?$' },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.create_customer',
    effect: 'write',
    description:
      'Create a WooCommerce customer. Binds POST /wp-json/wc/v3/customers.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wc/v3/customers' },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.update_customer',
    effect: 'write',
    description:
      'Update a WooCommerce customer. Binds PUT /wp-json/wc/v3/customers/{id}.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/wp-json/wc/v3/customers/[0-9]+$' },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.create_coupon',
    effect: 'write',
    description:
      'Create a WooCommerce coupon. Binds POST /wp-json/wc/v3/coupons.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wc/v3/coupons' },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.delete_coupon',
    effect: 'destructive',
    description:
      'Delete a WooCommerce coupon. Binds DELETE /wp-json/wc/v3/coupons/{id}.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/wp-json/wc/v3/coupons/[0-9]+$' },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.create_refund',
    effect: 'write',
    description:
      'Create a refund against a WooCommerce order. Binds POST /wp-json/wc/v3/orders/{order_id}/refunds. Money-moving; pair with an amount cap.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/wp-json/wc/v3/orders/[0-9]+/refunds$',
      },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.list_reviews',
    effect: 'read',
    description:
      'List product reviews. Binds GET /wp-json/wc/v3/products/reviews.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wc/v3/products/reviews' },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.list_shipping_zones',
    effect: 'read',
    description:
      'List shipping zones configured on the site. Binds GET /wp-json/wc/v3/shipping/zones.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wc/v3/shipping/zones' },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.list_tax_rates',
    effect: 'read',
    description:
      'List configured tax rates. Binds GET /wp-json/wc/v3/taxes.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wc/v3/taxes' },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.create_webhook',
    effect: 'write',
    description:
      'Create a WooCommerce webhook subscription. Binds POST /wp-json/wc/v3/webhooks.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wc/v3/webhooks' },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.list_reports',
    effect: 'read',
    description:
      'List WooCommerce sales and performance reports. Binds GET /wp-json/wc/v3/reports.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wc/v3/reports' },
      hostConstraint(host),
    ],
  }),

  defineIntent({
    name: 'woocommerce.list_payment_gateways',
    effect: 'read',
    description:
      'List configured payment gateways. Binds GET /wp-json/wc/v3/payment_gateways.',
    params: z.object({ host: hostList }),
    expand: ({ host }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wc/v3/payment_gateways' },
      hostConstraint(host),
    ],
  }),
];
