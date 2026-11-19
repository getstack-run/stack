import { z } from 'zod';
import { defineIntent } from './types.js';

// Auth0 Management API v2 - https://auth0.com/docs/api/management/v2.
// Calls hit {tenant}.auth0.com/api/v2/…. The tenant lives in the host,
// not the path, so intents gate on method + path shape. User IDs are
// opaque (auth0|…, google-oauth2|…) and ride in URL segments.

export const auth0Intents = [
  defineIntent({
    name: 'auth0.list_users',
    effect: 'read',
    description:
      'Search or list users in the tenant. Binds GET /api/v2/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/users' },
    ],
  }),

  defineIntent({
    name: 'auth0.get_user',
    effect: 'read',
    description:
      'Fetch a single user by ID. Binds GET /api/v2/users/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'auth0.create_user',
    effect: 'write',
    description:
      'Create a new user in a database connection. Binds POST /api/v2/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/users' },
    ],
  }),

  defineIntent({
    name: 'auth0.update_user',
    effect: 'write',
    description:
      'Update profile fields on a user. Binds PATCH /api/v2/users/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'auth0.delete_user',
    effect: 'destructive',
    description:
      'Delete a user by ID. Binds DELETE /api/v2/users/{id} - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'auth0.assign_user_roles',
    effect: 'write',
    description:
      'Assign roles to a user. Binds POST /api/v2/users/{id}/roles.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/users/[^/]+/roles$' },
    ],
  }),

  defineIntent({
    name: 'auth0.remove_user_roles',
    effect: 'destructive',
    description:
      'Remove roles from a user. Binds DELETE /api/v2/users/{id}/roles.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/users/[^/]+/roles$' },
    ],
  }),

  defineIntent({
    name: 'auth0.list_roles',
    effect: 'read',
    description:
      'List roles defined in the tenant. Binds GET /api/v2/roles.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/roles' },
    ],
  }),

  defineIntent({
    name: 'auth0.create_role',
    effect: 'write',
    description:
      'Create a new role. Binds POST /api/v2/roles.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/roles' },
    ],
  }),

  defineIntent({
    name: 'auth0.delete_role',
    effect: 'destructive',
    description:
      'Delete a role by ID. Binds DELETE /api/v2/roles/{id} - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/roles/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'auth0.list_clients',
    effect: 'read',
    description:
      'List registered applications (clients). Binds GET /api/v2/clients.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/clients' },
    ],
  }),

  defineIntent({
    name: 'auth0.create_client',
    effect: 'write',
    description:
      'Register a new application client. Binds POST /api/v2/clients.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/clients' },
    ],
  }),

  defineIntent({
    name: 'auth0.delete_client',
    effect: 'destructive',
    description:
      'Delete an application client. Binds DELETE /api/v2/clients/{id} - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/clients/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'auth0.list_connections',
    effect: 'read',
    description:
      'List identity connections (DB, social, enterprise). Binds GET /api/v2/connections.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/connections' },
    ],
  }),

  defineIntent({
    name: 'auth0.update_connection',
    effect: 'write',
    description:
      'Update an identity connection. Binds PATCH /api/v2/connections/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/connections/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'auth0.list_rules',
    effect: 'read',
    description:
      'List rules (legacy). Binds GET /api/v2/rules.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/rules' },
    ],
  }),

  defineIntent({
    name: 'auth0.list_logs',
    effect: 'read',
    description:
      'Tail tenant logs for audit. Binds GET /api/v2/logs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/logs' },
    ],
  }),

  defineIntent({
    name: 'auth0.create_password_change_ticket',
    effect: 'write',
    description:
      'Issue a password-change ticket for a user. Binds POST /api/v2/tickets/password-change.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/tickets/password-change' },
    ],
  }),

  defineIntent({
    name: 'auth0.create_email_verification_ticket',
    effect: 'write',
    description:
      'Issue an email-verification ticket for a user. Binds POST /api/v2/tickets/email-verification.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/tickets/email-verification' },
    ],
  }),

  defineIntent({
    name: 'auth0.get_tenant_settings',
    effect: 'read',
    description:
      'Read tenant-level settings. Binds GET /api/v2/tenants/settings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/tenants/settings' },
    ],
  }),

  defineIntent({
    name: 'auth0.get_branding',
    effect: 'read',
    description:
      'Read branding settings (logo, colors, fonts). Binds GET /api/v2/branding.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/branding' },
    ],
  }),

  defineIntent({
    name: 'auth0.list_custom_domains',
    effect: 'read',
    description:
      'List configured custom domains. Binds GET /api/v2/custom-domains.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/custom-domains' },
    ],
  }),
];
