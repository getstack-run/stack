import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Wise API — https://docs.wise.com/api-docs/. Base: api.wise.com.
// Every money-moving call is scoped to a profile_id (business or personal).
// Intents pin profile_id wherever the API exposes it, and fund/cancel
// transfer intents are scoped to the minimal path + method. Pair transfer
// creates with a raw amount cap on body.sourceAmount or body.targetAmount.

const profileFmt = z.string().min(1).max(32).regex(/^[0-9]+$/, 'profile_id is numeric');
const profileList = z.union([profileFmt, z.array(profileFmt).min(1)]);
type ProfileList = z.infer<typeof profileList>;
const toList = (v: ProfileList): string[] => (Array.isArray(v) ? v : [v]);

function profilePath(profile: ProfileList, version: 'v1' | 'v2', suffix: string): Constraint {
  const list = toList(profile);
  const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/${version}/profiles/${alt}${suffix}$`,
  };
}

function profileBodyConstraint(profile: ProfileList): Constraint {
  const list = toList(profile);
  return list.length === 1
    ? { path: 'body.profile', op: 'eq', value: list[0]! }
    : { path: 'body.profile', op: 'in', value: list };
}

export const wiseIntents = [
  defineIntent({
    name: 'wise.list_profiles',
    effect: 'read',
    description:
      'List the personal and business profiles available to the token. Binds GET /v2/profiles.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/profiles' },
    ],
  }),

  defineIntent({
    name: 'wise.create_quote',
    effect: 'write',
    description:
      'Create a quote for a potential transfer under a specific profile. Binds POST /v3/profiles/{profile_id}/quotes.',
    params: z.object({ profile: profileList }),
    expand: ({ profile }) => {
      const list = toList(profile);
      const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v3/profiles/${alt}/quotes$` },
      ];
    },
  }),

  defineIntent({
    name: 'wise.create_recipient',
    effect: 'write',
    description:
      'Create a recipient account under a specific profile. Binds POST /v1/accounts with body.profile pinned to the allowlist.',
    params: z.object({ profile: profileList }),
    expand: ({ profile }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/accounts' },
      profileBodyConstraint(profile),
    ],
  }),

  defineIntent({
    name: 'wise.list_recipients',
    effect: 'read',
    description:
      'List recipient accounts visible to the token. Binds GET /v2/accounts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/accounts' },
    ],
  }),

  defineIntent({
    name: 'wise.delete_recipient',
    effect: 'destructive',
    description:
      'Delete a recipient account. Binds DELETE /v2/accounts/{id}. Destructive but non-monetary.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/accounts/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'wise.create_transfer',
    effect: 'write',
    description:
      'Create a transfer between accounts. Binds POST /v1/transfers. Money-moving; pair with amount cap and targetAccount allowlist.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/transfers' },
    ],
  }),

  defineIntent({
    name: 'wise.fund_transfer',
    effect: 'write',
    description:
      'Fund a created transfer from the profile balance. Binds POST /v3/profiles/{profile_id}/transfers/{transfer_id}/payments. Money-moving, scope to profile.',
    params: z.object({ profile: profileList }),
    expand: ({ profile }) => {
      const list = toList(profile);
      const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        {
          path: 'url.pathname',
          op: 'matches',
          value: `^/v3/profiles/${alt}/transfers/[^/]+/payments$`,
        },
      ];
    },
  }),

  defineIntent({
    name: 'wise.cancel_transfer',
    effect: 'write',
    description:
      'Cancel a not-yet-funded transfer. Binds PUT /v1/transfers/{transfer_id}/cancel.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/transfers/[^/]+/cancel$' },
    ],
  }),

  defineIntent({
    name: 'wise.list_balances',
    effect: 'read',
    description:
      'List balances for a specific profile. Binds GET /v4/profiles/{profile_id}/balances.',
    params: z.object({ profile: profileList }),
    expand: ({ profile }) => {
      const list = toList(profile);
      const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v4/profiles/${alt}/balances$` },
      ];
    },
  }),

  defineIntent({
    name: 'wise.convert_currency',
    effect: 'write',
    description:
      'Convert between two balances on a profile. Binds POST /v2/profiles/{profile_id}/balance-movements. Money-moving; pair with amount cap.',
    params: z.object({ profile: profileList }),
    expand: ({ profile }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      profilePath(profile, 'v2', '/balance-movements'),
    ],
  }),

  defineIntent({
    name: 'wise.list_transfers',
    effect: 'read',
    description:
      'List transfers visible under a profile. Binds GET /v1/transfers.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/transfers' },
    ],
  }),

  defineIntent({
    name: 'wise.read_statement',
    effect: 'read',
    description:
      'Download a statement for a balance under a specific profile. Binds GET /v1/profiles/{profile_id}/balance-statements/{id}/statement.json.',
    params: z.object({ profile: profileList }),
    expand: ({ profile }) => {
      const list = toList(profile);
      const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        {
          path: 'url.pathname',
          op: 'matches',
          value: `^/v1/profiles/${alt}/balance-statements/[^/]+/statement.json$`,
        },
      ];
    },
  }),

  defineIntent({
    name: 'wise.list_webhooks',
    effect: 'read',
    description:
      'List webhook subscriptions on a profile. Binds GET /v3/profiles/{profile_id}/subscriptions.',
    params: z.object({ profile: profileList }),
    expand: ({ profile }) => {
      const list = toList(profile);
      const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v3/profiles/${alt}/subscriptions$` },
      ];
    },
  }),

  defineIntent({
    name: 'wise.create_webhook',
    effect: 'write',
    description:
      'Create a webhook subscription on a profile. Binds POST /v3/profiles/{profile_id}/subscriptions.',
    params: z.object({ profile: profileList }),
    expand: ({ profile }) => {
      const list = toList(profile);
      const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v3/profiles/${alt}/subscriptions$` },
      ];
    },
  }),

  defineIntent({
    name: 'wise.delete_webhook',
    effect: 'destructive',
    description:
      'Delete a webhook subscription on a profile. Binds DELETE /v3/profiles/{profile_id}/subscriptions/{id}.',
    params: z.object({ profile: profileList }),
    expand: ({ profile }) => {
      const list = toList(profile);
      const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        {
          path: 'url.pathname',
          op: 'matches',
          value: `^/v3/profiles/${alt}/subscriptions/[^/]+$`,
        },
      ];
    },
  }),
];
