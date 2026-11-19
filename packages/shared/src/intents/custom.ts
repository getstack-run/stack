import { z } from 'zod';
import { defineIntent } from './types.js';

// Provider-agnostic intents. Useful for custom service connections that
// aren't in the first-party catalog, and as composable building blocks
// on top of provider-specific intents.

const hostList = z.array(z.string().min(1).max(253)).min(1);
const methodList = z.array(z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])).min(1);

export const customIntents = [
  defineIntent({
    name: 'custom.host_allowlist',
    effect: 'destructive',
    description:
      'Restrict calls to a set of hostnames. Binds url.host to the declared list (case-insensitive — all hosts are lowercased before match).',
    params: z.object({ hosts: hostList }),
    expand: ({ hosts }) => [
      {
        path: 'url.host',
        op: 'in',
        value: hosts.map((h) => h.toLowerCase()),
      },
    ],
  }),

  defineIntent({
    name: 'custom.path_prefix',
    effect: 'destructive',
    description:
      'Restrict calls to paths beginning with a prefix. Binds url.pathname starts_with prefix.',
    params: z.object({ prefix: z.string().min(1).max(128) }),
    expand: ({ prefix }) => [
      { path: 'url.pathname', op: 'starts_with', value: prefix },
    ],
  }),

  defineIntent({
    name: 'custom.methods',
    effect: 'destructive',
    description:
      'Restrict calls to a set of HTTP methods. Binds method to the declared allowlist.',
    params: z.object({ methods: methodList }),
    expand: ({ methods }) => [{ path: 'method', op: 'in', value: methods }],
  }),

  defineIntent({
    name: 'custom.read_only',
    effect: 'read',
    description:
      'Allow only safe / read-only HTTP methods (GET, HEAD). Shorthand for custom.methods with [GET, HEAD].',
    params: z.object({}),
    expand: () => [{ path: 'method', op: 'in', value: ['GET', 'HEAD'] }],
  }),

  defineIntent({
    name: 'custom.require_method',
    effect: 'destructive',
    description:
      'Require a single HTTP method for all proxied requests. Binds method eq value.',
    params: z.object({
      method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']),
    }),
    expand: ({ method }) => [{ path: 'method', op: 'eq', value: method }],
  }),

  defineIntent({
    name: 'custom.require_host',
    effect: 'destructive',
    description:
      'Require a single exact host for all proxied requests. Binds url.host eq value (lowercased).',
    params: z.object({ host: z.string().min(1).max(253) }),
    expand: ({ host }) => [
      { path: 'url.host', op: 'eq', value: host.toLowerCase() },
    ],
  }),

  defineIntent({
    name: 'custom.deny_methods',
    effect: 'destructive',
    description:
      'Block a set of HTTP methods. Binds method not_in the declared list, typically used to forbid destructive verbs.',
    params: z.object({ methods: methodList }),
    expand: ({ methods }) => [
      { path: 'method', op: 'not_in', value: methods },
    ],
  }),

  defineIntent({
    name: 'custom.require_pathname_prefix',
    effect: 'destructive',
    description:
      'Require the request pathname to start with a given prefix. Binds url.pathname starts_with prefix.',
    params: z.object({ prefix: z.string().min(1).max(128) }),
    expand: ({ prefix }) => [
      { path: 'url.pathname', op: 'starts_with', value: prefix },
    ],
  }),

  defineIntent({
    name: 'custom.require_pathname_regex',
    effect: 'destructive',
    description:
      'Require the request pathname to match a given RE2 regex. Binds url.pathname matches pattern (capped at 256 chars, compiled linear-time).',
    params: z.object({ pattern: z.string().min(1).max(256) }),
    expand: ({ pattern }) => [
      { path: 'url.pathname', op: 'matches', value: pattern },
    ],
  }),

  defineIntent({
    name: 'custom.require_pathname_equals',
    effect: 'destructive',
    description:
      'Require the request pathname to exactly match a value. Binds url.pathname eq pathname.',
    params: z.object({ pathname: z.string().min(1).max(1024) }),
    expand: ({ pathname }) => [
      { path: 'url.pathname', op: 'eq', value: pathname },
    ],
  }),

  defineIntent({
    name: 'custom.require_origin',
    effect: 'destructive',
    description:
      'Require the request origin (scheme + host + optional port) to match exactly. Binds url.origin eq origin.',
    params: z.object({ origin: z.string().min(1).max(1024) }),
    expand: ({ origin }) => [
      { path: 'url.origin', op: 'eq', value: origin },
    ],
  }),

  defineIntent({
    name: 'custom.require_query_equals',
    effect: 'destructive',
    description:
      'Require a specific query parameter to equal a value. Binds query.{name} eq value.',
    params: z.object({
      name: z.string().min(1).max(128),
      value: z.string().max(1024),
    }),
    expand: ({ name, value }) => [
      { path: `query.${name}`, op: 'eq', value },
    ],
  }),

  defineIntent({
    name: 'custom.require_query_in',
    effect: 'destructive',
    description:
      'Require a specific query parameter to be one of a fixed set of values. Binds query.{name} in values.',
    params: z.object({
      name: z.string().min(1).max(128),
      values: z.array(z.string().max(1024)).min(1),
    }),
    expand: ({ name, values }) => [
      { path: `query.${name}`, op: 'in', value: values },
    ],
  }),

  defineIntent({
    name: 'custom.require_query_absent',
    effect: 'destructive',
    description:
      'Require a specific query parameter to be absent. Binds query.{name} not_exists.',
    // Was `eq ''`, on the belief that the proxy normalises a missing param to
    // an empty string. It does not — resolvePath returns undefined for a
    // missing key, and every value operator fails on undefined. So this
    // intent denied exactly the request it existed to allow. Fixed by the
    // not_exists operator, which is what it always meant.
    params: z.object({ name: z.string().min(1).max(128) }),
    expand: ({ name }) => [{ path: `query.${name}`, op: 'not_exists', value: true }],
  }),

  defineIntent({
    name: 'custom.require_query_matches',
    effect: 'destructive',
    description:
      'Require a specific query parameter to match a RE2 regex. Binds query.{name} matches pattern.',
    params: z.object({
      name: z.string().min(1).max(128),
      pattern: z.string().min(1).max(256),
    }),
    expand: ({ name, pattern }) => [
      { path: `query.${name}`, op: 'matches', value: pattern },
    ],
  }),

  defineIntent({
    name: 'custom.require_body_field_equals',
    effect: 'destructive',
    description:
      'Require a specific JSON body field to equal a value. Binds body.{path} eq value using dotted JSON path (e.g. user.id).',
    params: z.object({
      field: z.string().min(1).max(128),
      value: z.union([z.string().max(1024), z.number(), z.boolean()]),
    }),
    expand: ({ field, value }) => [
      { path: `body.${field}`, op: 'eq', value },
    ],
  }),

  defineIntent({
    name: 'custom.require_body_field_starts_with',
    effect: 'destructive',
    description:
      'Require a specific JSON body field to start with a prefix. Binds body.{path} starts_with value.',
    params: z.object({
      field: z.string().min(1).max(128),
      value: z.string().min(1).max(1024),
    }),
    expand: ({ field, value }) => [
      { path: `body.${field}`, op: 'starts_with', value },
    ],
  }),

  defineIntent({
    name: 'custom.require_body_field_matches',
    effect: 'destructive',
    description:
      'Require a specific JSON body field to match a RE2 regex. Binds body.{path} matches pattern.',
    params: z.object({
      field: z.string().min(1).max(128),
      pattern: z.string().min(1).max(256),
    }),
    expand: ({ field, pattern }) => [
      { path: `body.${field}`, op: 'matches', value: pattern },
    ],
  }),

  defineIntent({
    name: 'custom.require_body_field_in',
    effect: 'destructive',
    description:
      'Require a specific JSON body field to be one of an allowlist of values. Binds body.{path} in values.',
    params: z.object({
      field: z.string().min(1).max(128),
      values: z.array(z.string().max(1024)).min(1),
    }),
    expand: ({ field, values }) => [
      { path: `body.${field}`, op: 'in', value: values },
    ],
  }),

  defineIntent({
    name: 'custom.deny_body_field_values',
    effect: 'destructive',
    description:
      'Forbid a set of values for a specific JSON body field. Binds body.{path} not_in values, useful for rejecting destructive flags.',
    params: z.object({
      field: z.string().min(1).max(128),
      values: z.array(z.string().max(1024)).min(1),
    }),
    expand: ({ field, values }) => [
      { path: `body.${field}`, op: 'not_in', value: values },
    ],
  }),
];
