import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Brex API — https://developer.brex.com/. Base: platform.brexapis.com.
// Money-moving endpoints (cards, transfers) should be scoped to known
// card_id or user_id allowlists. Transfers should additionally pin an
// amount cap via raw constraint on body.amount.amount.

const idFmt = z.string().min(4).max(128);
const idList = z.union([idFmt, z.array(idFmt).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function pathIdConstraint(ids: IdList, prefix: string): Constraint {
  const list = toList(ids);
  const escaped = list.map((s) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? escaped[0]! : `(${escaped.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^${prefix}/${alt}$`,
  };
}

export const brexIntents = [
  defineIntent({
    name: 'brex.list_cards',
    effect: 'read',
    description:
      'List cards issued to the Brex account. Binds GET /v2/cards.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/cards' },
    ],
  }),

  defineIntent({
    name: 'brex.create_card',
    effect: 'write',
    description:
      'Issue a new Brex card bound to a specific user. Binds POST /v2/cards. Keep user_id allowlist upstream and pair with spend controls.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/cards' },
    ],
  }),

  defineIntent({
    name: 'brex.lock_card',
    effect: 'write',
    description:
      'Lock a specific Brex card so it cannot be used. Binds POST /v2/cards/{card_id}/lock scoped to the allowlisted card IDs.',
    params: z.object({ card_id: idList }),
    expand: ({ card_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/v2/cards/(${toList(card_id).map((s) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&')).join('|')})/lock$`,
      },
    ],
  }),

  defineIntent({
    name: 'brex.terminate_card',
    effect: 'destructive',
    description:
      'Permanently terminate a Brex card. Binds POST /v2/cards/{card_id}/terminate to an allowlist; destructive.',
    params: z.object({ card_id: idList }),
    expand: ({ card_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/v2/cards/(${toList(card_id).map((s) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&')).join('|')})/terminate$`,
      },
    ],
  }),

  defineIntent({
    name: 'brex.list_transactions',
    effect: 'read',
    description:
      'List card transactions on the account. Binds GET /v2/transactions/card.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/transactions/card' },
    ],
  }),

  defineIntent({
    name: 'brex.categorize_transaction',
    effect: 'write',
    description:
      'Update the category of a specific transaction. Binds PUT /v2/transactions/card/primary/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/transactions/card/primary/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'brex.list_users',
    effect: 'read',
    description:
      'List users in the Brex organization. Binds GET /v2/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/users' },
    ],
  }),

  defineIntent({
    name: 'brex.create_user',
    effect: 'write',
    description:
      'Invite a new user to the Brex organization. Binds POST /v2/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/users' },
    ],
  }),

  defineIntent({
    name: 'brex.update_user',
    effect: 'write',
    description:
      'Update a Brex user record. Binds PUT /v2/users/{user_id} constrained to the allowlisted IDs.',
    params: z.object({ user_id: idList }),
    expand: ({ user_id }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      pathIdConstraint(user_id, '/v2/users'),
    ],
  }),

  defineIntent({
    name: 'brex.list_expenses',
    effect: 'read',
    description:
      'List card and out-of-pocket expenses. Binds GET /v1/expenses.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/expenses' },
    ],
  }),

  defineIntent({
    name: 'brex.update_expense',
    effect: 'write',
    description:
      'Update an expense memo, category, or compliance fields. Binds PUT /v1/expenses/card/{expense_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/expenses/card/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'brex.create_reimbursement',
    effect: 'write',
    description:
      'Submit a reimbursement request. Binds POST /v1/expenses/reimbursements. Money-moving once approved; pair with amount cap.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/expenses/reimbursements' },
    ],
  }),

  defineIntent({
    name: 'brex.list_vendors',
    effect: 'read',
    description:
      'List Brex vendors. Binds GET /v1/vendors.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/vendors' },
    ],
  }),

  defineIntent({
    name: 'brex.list_budgets',
    effect: 'read',
    description:
      'List spend budgets configured on the account. Binds GET /v2/budgets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/budgets' },
    ],
  }),

  defineIntent({
    name: 'brex.list_accounts',
    effect: 'read',
    description:
      'List Brex cash and card accounts. Binds GET /v2/accounts/cash and /v2/accounts/card.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/accounts/(cash|card)$' },
    ],
  }),

  defineIntent({
    name: 'brex.initiate_transfer',
    effect: 'write',
    description:
      'Initiate a cash transfer between Brex and an external account. Binds POST /v2/accounts/cash/transfers. Money-moving; pair with amount cap and destination allowlist.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/accounts/cash/transfers' },
    ],
  }),

  defineIntent({
    name: 'brex.list_statements',
    effect: 'read',
    description:
      'List monthly statements on the cash or card account. Binds GET /v2/accounts/cash/statements.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/accounts/cash/statements' },
    ],
  }),
];
