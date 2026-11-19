import { z } from 'zod';
import { defineIntent } from './types.js';

// Okta Management API - https://developer.okta.com/docs/reference/core-okta-api.
// Calls hit {yourOktaDomain}/api/v1/…. Users, groups, apps, factors,
// logs are the main resources. Intents gate on method + path shape.

export const oktaIntents = [
  defineIntent({
    name: 'okta.list_users',
    effect: 'read',
    description:
      'List users in the Okta org. Binds GET /api/v1/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/users' },
    ],
  }),

  defineIntent({
    name: 'okta.get_user',
    effect: 'read',
    description:
      'Fetch a single user by ID or login. Binds GET /api/v1/users/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'okta.create_user',
    effect: 'write',
    description:
      'Create a new user. Binds POST /api/v1/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/users' },
    ],
  }),

  defineIntent({
    name: 'okta.update_user',
    effect: 'write',
    description:
      'Update a user profile. Binds POST /api/v1/users/{id} (partial update).',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'okta.delete_user',
    effect: 'destructive',
    description:
      'Delete a user (must already be deactivated). Binds DELETE /api/v1/users/{id} - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'okta.activate_user',
    effect: 'write',
    description:
      'Activate a staged user. Binds POST /api/v1/users/{id}/lifecycle/activate.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/users/[^/]+/lifecycle/activate$' },
    ],
  }),

  defineIntent({
    name: 'okta.deactivate_user',
    effect: 'write',
    description:
      'Deactivate a user. Binds POST /api/v1/users/{id}/lifecycle/deactivate - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/users/[^/]+/lifecycle/deactivate$' },
    ],
  }),

  defineIntent({
    name: 'okta.suspend_user',
    effect: 'write',
    description:
      'Suspend a user (prevents sign-in, keeps data). Binds POST /api/v1/users/{id}/lifecycle/suspend.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/users/[^/]+/lifecycle/suspend$' },
    ],
  }),

  defineIntent({
    name: 'okta.reset_user_password',
    effect: 'write',
    description:
      'Force a user password reset. Binds POST /api/v1/users/{id}/lifecycle/reset_password.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/users/[^/]+/lifecycle/reset_password$' },
    ],
  }),

  defineIntent({
    name: 'okta.reset_user_factors',
    effect: 'write',
    description:
      'Reset all MFA factors for a user. Binds POST /api/v1/users/{id}/lifecycle/reset_factors - sensitive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/users/[^/]+/lifecycle/reset_factors$' },
    ],
  }),

  defineIntent({
    name: 'okta.list_groups',
    effect: 'read',
    description:
      'List groups in the Okta org. Binds GET /api/v1/groups.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/groups' },
    ],
  }),

  defineIntent({
    name: 'okta.create_group',
    effect: 'write',
    description:
      'Create a new group. Binds POST /api/v1/groups.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/groups' },
    ],
  }),

  defineIntent({
    name: 'okta.delete_group',
    effect: 'destructive',
    description:
      'Delete a group by ID. Binds DELETE /api/v1/groups/{id} - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/groups/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'okta.add_user_to_group',
    effect: 'write',
    description:
      'Add a user to a group. Binds PUT /api/v1/groups/{groupId}/users/{userId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/groups/[^/]+/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'okta.remove_user_from_group',
    effect: 'destructive',
    description:
      'Remove a user from a group. Binds DELETE /api/v1/groups/{groupId}/users/{userId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/groups/[^/]+/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'okta.list_apps',
    effect: 'read',
    description:
      'List applications configured in the org. Binds GET /api/v1/apps.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/apps' },
    ],
  }),

  defineIntent({
    name: 'okta.assign_user_to_app',
    effect: 'write',
    description:
      'Assign a user to an app. Binds POST /api/v1/apps/{appId}/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/apps/[^/]+/users$' },
    ],
  }),

  defineIntent({
    name: 'okta.unassign_user_from_app',
    effect: 'destructive',
    description:
      'Remove a user assignment from an app. Binds DELETE /api/v1/apps/{appId}/users/{userId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/apps/[^/]+/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'okta.list_policies',
    effect: 'read',
    description:
      'List policies (sign-on, password, MFA). Binds GET /api/v1/policies.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/policies' },
    ],
  }),

  defineIntent({
    name: 'okta.list_user_factors',
    effect: 'read',
    description:
      'List enrolled MFA factors for a user. Binds GET /api/v1/users/{id}/factors.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/users/[^/]+/factors$' },
    ],
  }),

  defineIntent({
    name: 'okta.revoke_user_sessions',
    effect: 'destructive',
    description:
      'Revoke all active sessions for a user. Binds DELETE /api/v1/users/{id}/sessions - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/users/[^/]+/sessions$' },
    ],
  }),

  defineIntent({
    name: 'okta.list_system_logs',
    effect: 'read',
    description:
      'Query system logs for audit. Binds GET /api/v1/logs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/logs' },
    ],
  }),

  defineIntent({
    name: 'okta.list_oauth2_scopes',
    effect: 'read',
    description:
      'List OAuth2 scopes defined on an authorization server. Binds GET /api/v1/authorizationServers/{id}/scopes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/api/v1/authorizationServers/[^/]+/scopes$',
      },
    ],
  }),
];
