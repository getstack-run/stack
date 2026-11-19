import { z } from 'zod';
import { defineIntent } from './types.js';

// Clerk Backend API - https://clerk.com/docs/reference/backend-api. Calls
// hit api.clerk.com/v1/… (legacy api.clerk.dev/v1/… also supported).
// Users, sessions, organizations are the main resources. Intents gate on
// method + path shape.

export const clerkIntents = [
  defineIntent({
    name: 'clerk.list_users',
    effect: 'read',
    description:
      'List users in the instance. Binds GET /v1/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/users' },
    ],
  }),

  defineIntent({
    name: 'clerk.get_user',
    effect: 'read',
    description:
      'Fetch a single user by ID. Binds GET /v1/users/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'clerk.create_user',
    effect: 'write',
    description:
      'Create a new user. Binds POST /v1/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/users' },
    ],
  }),

  defineIntent({
    name: 'clerk.update_user',
    effect: 'write',
    description:
      'Update a user\'s profile fields. Binds PATCH /v1/users/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'clerk.delete_user',
    effect: 'destructive',
    description:
      'Delete a user by ID. Binds DELETE /v1/users/{id} - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'clerk.ban_user',
    effect: 'write',
    description:
      'Ban a user, preventing sign-in. Binds POST /v1/users/{id}/ban.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/users/[^/]+/ban$' },
    ],
  }),

  defineIntent({
    name: 'clerk.unban_user',
    effect: 'write',
    description:
      'Lift a ban on a user. Binds POST /v1/users/{id}/unban.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/users/[^/]+/unban$' },
    ],
  }),

  defineIntent({
    name: 'clerk.lock_user',
    effect: 'write',
    description:
      'Lock a user account. Binds POST /v1/users/{id}/lock.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/users/[^/]+/lock$' },
    ],
  }),

  defineIntent({
    name: 'clerk.unlock_user',
    effect: 'write',
    description:
      'Unlock a user account. Binds POST /v1/users/{id}/unlock.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/users/[^/]+/unlock$' },
    ],
  }),

  defineIntent({
    name: 'clerk.list_sessions',
    effect: 'read',
    description:
      'List active sessions. Binds GET /v1/sessions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/sessions' },
    ],
  }),

  defineIntent({
    name: 'clerk.get_session',
    effect: 'read',
    description:
      'Fetch a session by ID. Binds GET /v1/sessions/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/sessions/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'clerk.revoke_session',
    effect: 'write',
    description:
      'Revoke an active session. Binds POST /v1/sessions/{id}/revoke.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/sessions/[^/]+/revoke$' },
    ],
  }),

  defineIntent({
    name: 'clerk.list_organizations',
    effect: 'read',
    description:
      'List organizations in the instance. Binds GET /v1/organizations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/organizations' },
    ],
  }),

  defineIntent({
    name: 'clerk.create_organization',
    effect: 'write',
    description:
      'Create a new organization. Binds POST /v1/organizations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/organizations' },
    ],
  }),

  defineIntent({
    name: 'clerk.delete_organization',
    effect: 'destructive',
    description:
      'Delete an organization. Binds DELETE /v1/organizations/{id} - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/organizations/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'clerk.list_organization_memberships',
    effect: 'read',
    description:
      'List memberships for an organization. Binds GET /v1/organizations/{id}/memberships.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/organizations/[^/]+/memberships$' },
    ],
  }),

  defineIntent({
    name: 'clerk.create_organization_membership',
    effect: 'write',
    description:
      'Add a user to an organization. Binds POST /v1/organizations/{id}/memberships.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/organizations/[^/]+/memberships$' },
    ],
  }),

  defineIntent({
    name: 'clerk.list_invitations',
    effect: 'read',
    description:
      'List instance-level invitations. Binds GET /v1/invitations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/invitations' },
    ],
  }),

  defineIntent({
    name: 'clerk.create_invitation',
    effect: 'send',
    recipient_paths: ['body.email_address'],
    description:
      'Send an instance-level invitation. Binds POST /v1/invitations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/invitations' },
    ],
  }),

  defineIntent({
    name: 'clerk.revoke_invitation',
    effect: 'write',
    description:
      'Revoke an outstanding invitation. Binds POST /v1/invitations/{id}/revoke.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/invitations/[^/]+/revoke$' },
    ],
  }),

  defineIntent({
    name: 'clerk.create_sign_in_token',
    effect: 'write',
    description:
      'Mint a single-use sign-in token for a user. Binds POST /v1/sign_in_tokens.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/sign_in_tokens' },
    ],
  }),

  defineIntent({
    name: 'clerk.list_jwt_templates',
    effect: 'read',
    description:
      'List JWT templates. Binds GET /v1/jwt_templates.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/jwt_templates' },
    ],
  }),

  defineIntent({
    name: 'clerk.create_actor_token',
    effect: 'write',
    description:
      'Mint an actor token for impersonation. Binds POST /v1/actor_tokens - sensitive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/actor_tokens' },
    ],
  }),
];
