import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Square API — https://developer.squareup.com/reference/square. Base:
// connect.squareup.com/v2/{resource}. Most mutations are scoped to a
// location_id in the body; money-moving calls should pin location_id
// to a known allowlist and cap amounts in the request body.

const locationFmt = z.string().min(4).max(64);
const locationList = z.union([locationFmt, z.array(locationFmt).min(1)]);
type LocationList = z.infer<typeof locationList>;
const toList = (v: LocationList): string[] => (Array.isArray(v) ? v : [v]);

function locationConstraint(location: LocationList, path = 'body.location_id'): Constraint {
  const list = toList(location);
  return list.length === 1
    ? { path, op: 'eq', value: list[0]! }
    : { path, op: 'in', value: list };
}

export const squareIntents = [
  defineIntent({
    name: 'square.create_payment',
    effect: 'write',
    description:
      'Take a payment at a specific Square location. Binds POST /v2/payments with body.location_id in the allowlist. Money-moving; pair with amount_money cap.',
    params: z.object({ location: locationList }),
    expand: ({ location }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/payments' },
      locationConstraint(location),
    ],
  }),

  defineIntent({
    name: 'square.cancel_payment',
    effect: 'write',
    description:
      'Cancel an uncompleted Square payment. Binds POST /v2/payments/{payment_id}/cancel.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/payments/[^/]+/cancel$' },
    ],
  }),

  defineIntent({
    name: 'square.refund_payment',
    effect: 'write',
    description:
      'Refund a previously completed Square payment. Binds POST /v2/refunds. Money-moving; pair with amount_money cap.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/refunds' },
    ],
  }),

  defineIntent({
    name: 'square.create_order',
    effect: 'write',
    description:
      'Create an order at a specific Square location. Binds POST /v2/orders with body.order.location_id allowlist.',
    params: z.object({ location: locationList }),
    expand: ({ location }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/orders' },
      locationConstraint(location, 'body.order.location_id'),
    ],
  }),

  defineIntent({
    name: 'square.update_order',
    effect: 'write',
    description:
      'Update an existing Square order. Binds PUT /v2/orders/{order_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/orders/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'square.upsert_catalog_object',
    effect: 'write',
    description:
      'Create or update an object in the Square catalog. Binds POST /v2/catalog/object.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/catalog/object' },
    ],
  }),

  defineIntent({
    name: 'square.list_catalog',
    effect: 'read',
    description:
      'List catalog items or objects. Binds GET /v2/catalog/list.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/catalog/list' },
    ],
  }),

  defineIntent({
    name: 'square.create_customer',
    effect: 'write',
    description:
      'Create a Square customer. Binds POST /v2/customers.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/customers' },
    ],
  }),

  defineIntent({
    name: 'square.update_customer',
    effect: 'write',
    description:
      'Update a Square customer record. Binds PUT /v2/customers/{customer_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/customers/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'square.read_customers',
    effect: 'read',
    description:
      'List or read Square customers. Binds GET /v2/customers and /v2/customers/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/customers(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'square.create_invoice',
    effect: 'write',
    description:
      'Create a Square invoice draft. Binds POST /v2/invoices.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/invoices' },
    ],
  }),

  defineIntent({
    name: 'square.publish_invoice',
    effect: 'send',
    description:
      'Publish (send) a Square invoice to the customer. Binds POST /v2/invoices/{invoice_id}/publish.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/invoices/[^/]+/publish$' },
    ],
  }),

  defineIntent({
    name: 'square.list_locations',
    effect: 'read',
    description:
      'List all Square locations on the account. Binds GET /v2/locations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/locations' },
    ],
  }),

  defineIntent({
    name: 'square.create_booking',
    effect: 'write',
    description:
      'Create a Square Appointments booking. Binds POST /v2/bookings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/bookings' },
    ],
  }),

  defineIntent({
    name: 'square.cancel_booking',
    effect: 'write',
    description:
      'Cancel a Square booking. Binds POST /v2/bookings/{booking_id}/cancel.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/bookings/[^/]+/cancel$' },
    ],
  }),

  defineIntent({
    name: 'square.create_subscription',
    effect: 'write',
    description:
      'Create a recurring Square subscription. Binds POST /v2/subscriptions. Money-moving via scheduled charges.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/subscriptions' },
    ],
  }),

  defineIntent({
    name: 'square.cancel_subscription',
    effect: 'write',
    description:
      'Cancel a Square subscription. Binds POST /v2/subscriptions/{subscription_id}/cancel.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/subscriptions/[^/]+/cancel$' },
    ],
  }),

  defineIntent({
    name: 'square.activate_gift_card',
    effect: 'write',
    description:
      'Activate or load a Square gift card. Binds POST /v2/gift-cards/activities. Money-moving once linked to a purchase; pair with amount cap.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/gift-cards/activities' },
    ],
  }),
];
