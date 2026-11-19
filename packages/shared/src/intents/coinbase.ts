import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Coinbase Advanced Trade API — https://docs.cdp.coinbase.com/advanced-trade/docs/welcome.
// Base: api.coinbase.com/api/v3/brokerage. Trading calls MUST be scoped
// to a product_id allowlist (e.g. BTC-USD) and order_configuration subtree
// to prevent market-order surprise fills. Pair with body.side ('BUY'/'SELL')
// and notional/size caps via raw constraints.

const productFmt = z
  .string()
  .min(3)
  .max(16)
  .regex(/^[A-Z0-9]+-[A-Z0-9]+$/, 'product_id must look like BTC-USD');
const productList = z.union([productFmt, z.array(productFmt).min(1)]);
type ProductList = z.infer<typeof productList>;
const toList = (v: ProductList): string[] => (Array.isArray(v) ? v : [v]);

function productBody(product: ProductList): Constraint {
  const list = toList(product);
  return list.length === 1
    ? { path: 'body.product_id', op: 'eq', value: list[0]! }
    : { path: 'body.product_id', op: 'in', value: list };
}

function productQuery(product: ProductList): Constraint {
  const list = toList(product);
  return list.length === 1
    ? { path: 'query.product_id', op: 'eq', value: list[0]! }
    : { path: 'query.product_id', op: 'in', value: list };
}

export const coinbaseIntents = [
  defineIntent({
    name: 'coinbase.list_accounts',
    effect: 'read',
    description:
      'List portfolio accounts and balances. Binds GET /api/v3/brokerage/accounts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/brokerage/accounts' },
    ],
  }),

  defineIntent({
    name: 'coinbase.read_account',
    effect: 'read',
    description:
      'Read a single brokerage account by UUID. Binds GET /api/v3/brokerage/accounts/{account_uuid}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v3/brokerage/accounts/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'coinbase.list_products',
    effect: 'read',
    description:
      'List available trading products. Binds GET /api/v3/brokerage/products.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/brokerage/products' },
    ],
  }),

  defineIntent({
    name: 'coinbase.read_product',
    effect: 'read',
    description:
      'Read a single product (market) detail. Binds GET /api/v3/brokerage/products/{product_id}.',
    params: z.object({ product: productList }),
    expand: ({ product }) => {
      const list = toList(product);
      const escaped = list.map((s) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? escaped[0]! : `(${escaped.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/api/v3/brokerage/products/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'coinbase.create_order',
    effect: 'write',
    description:
      'Place a new order on an allowlisted product. Binds POST /api/v3/brokerage/orders with body.product_id in the allowlist. Money-moving; pair with side and size caps.',
    params: z.object({ product: productList }),
    expand: ({ product }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/brokerage/orders' },
      productBody(product),
    ],
  }),

  defineIntent({
    name: 'coinbase.cancel_orders',
    effect: 'write',
    description:
      'Cancel a batch of open orders by ID. Binds POST /api/v3/brokerage/orders/batch_cancel.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/brokerage/orders/batch_cancel' },
    ],
  }),

  defineIntent({
    name: 'coinbase.list_orders',
    effect: 'read',
    description:
      'List historical or open orders. Binds GET /api/v3/brokerage/orders/historical/batch.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/brokerage/orders/historical/batch' },
    ],
  }),

  defineIntent({
    name: 'coinbase.read_order',
    effect: 'read',
    description:
      'Read a specific order by ID. Binds GET /api/v3/brokerage/orders/historical/{order_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v3/brokerage/orders/historical/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'coinbase.list_fills',
    effect: 'read',
    description:
      'List fills for historical orders. Binds GET /api/v3/brokerage/orders/historical/fills.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/brokerage/orders/historical/fills' },
    ],
  }),

  defineIntent({
    name: 'coinbase.read_candles',
    effect: 'read',
    description:
      'Read candle data for a specific product. Binds GET /api/v3/brokerage/products/{product_id}/candles.',
    params: z.object({ product: productList }),
    expand: ({ product }) => {
      const list = toList(product);
      const escaped = list.map((s) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? escaped[0]! : `(${escaped.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        {
          path: 'url.pathname',
          op: 'matches',
          value: `^/api/v3/brokerage/products/${alt}/candles$`,
        },
      ];
    },
  }),

  defineIntent({
    name: 'coinbase.read_market_trades',
    effect: 'read',
    description:
      'Read recent public trades for a product. Binds GET /api/v3/brokerage/products/{product_id}/ticker.',
    params: z.object({ product: productList }),
    expand: ({ product }) => {
      const list = toList(product);
      const escaped = list.map((s) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? escaped[0]! : `(${escaped.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        {
          path: 'url.pathname',
          op: 'matches',
          value: `^/api/v3/brokerage/products/${alt}/ticker$`,
        },
      ];
    },
  }),

  defineIntent({
    name: 'coinbase.read_best_bid_ask',
    effect: 'read',
    description:
      'Read best bid/ask for allowlisted products. Binds GET /api/v3/brokerage/best_bid_ask.',
    params: z.object({ product: productList }),
    expand: ({ product }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/brokerage/best_bid_ask' },
      productQuery(product),
    ],
  }),

  defineIntent({
    name: 'coinbase.list_portfolios',
    effect: 'read',
    description:
      'List portfolios on the Advanced Trade account. Binds GET /api/v3/brokerage/portfolios.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/brokerage/portfolios' },
    ],
  }),

  defineIntent({
    name: 'coinbase.read_fees',
    effect: 'read',
    description:
      'Read the current transaction fee summary. Binds GET /api/v3/brokerage/transaction_summary.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/brokerage/transaction_summary' },
    ],
  }),

  defineIntent({
    name: 'coinbase.preview_order',
    effect: 'read',
    description:
      'Preview an order before placing it. Binds POST /api/v3/brokerage/orders/preview with body.product_id in the allowlist.',
    params: z.object({ product: productList }),
    expand: ({ product }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/brokerage/orders/preview' },
      productBody(product),
    ],
  }),
];
