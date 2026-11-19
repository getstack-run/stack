import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Sentry API — https://docs.sentry.io/api. Base: sentry.io/api/0/…
// (or self-hosted host). Resources are keyed by {organization_slug} and
// {project_slug}. Intents scope on organization slug; project-level
// scoping uses a nested path.

const slug = z.string().min(1).max(64).regex(/^[a-z0-9][a-z0-9-]*$/);
const slugList = z.union([slug, z.array(slug).min(1)]);
type SlugList = z.infer<typeof slugList>;
const toList = (v: SlugList): string[] => (Array.isArray(v) ? v : [v]);

function orgPathConstraint(org: SlugList, suffix: string): Constraint {
  const list = toList(org);
  const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/api/0/organizations/${alt}${suffix}$`,
  };
}

export const sentryIntents = [
  defineIntent({
    name: 'sentry.list_projects',
    effect: 'read',
    description:
      'List projects in specific organizations. Binds GET /api/0/organizations/{org}/projects/.',
    params: z.object({ organization_slug: slugList }),
    expand: ({ organization_slug }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      orgPathConstraint(organization_slug, '/projects/'),
    ],
  }),

  defineIntent({
    name: 'sentry.create_project',
    effect: 'write',
    description:
      'Create a project in a specific organization team. Binds POST /api/0/teams/{org}/{team}/projects/.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/api/0/teams/[a-z0-9-]+/[a-z0-9-]+/projects/$',
      },
    ],
  }),

  defineIntent({
    name: 'sentry.list_issues',
    effect: 'read',
    description:
      'List issues in specific organizations. Binds GET /api/0/organizations/{org}/issues/.',
    params: z.object({ organization_slug: slugList }),
    expand: ({ organization_slug }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      orgPathConstraint(organization_slug, '/issues/'),
    ],
  }),

  defineIntent({
    name: 'sentry.update_issue',
    effect: 'write',
    description:
      'Update an issue (status, assignee, etc.). Binds PUT /api/0/organizations/{org}/issues/{id}/.',
    params: z.object({ organization_slug: slugList }),
    expand: ({ organization_slug }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      orgPathConstraint(organization_slug, '/issues/\\d+/'),
    ],
  }),

  defineIntent({
    name: 'sentry.resolve_issue',
    effect: 'write',
    description:
      'Resolve an issue by setting status. Binds PUT /api/0/organizations/{org}/issues/{id}/ with body.status = resolved.',
    params: z.object({ organization_slug: slugList }),
    expand: ({ organization_slug }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      orgPathConstraint(organization_slug, '/issues/\\d+/'),
      { path: 'body.status', op: 'eq', value: 'resolved' },
    ],
  }),

  defineIntent({
    name: 'sentry.delete_issue',
    effect: 'destructive',
    description:
      'Permanently delete an issue. Binds DELETE /api/0/organizations/{org}/issues/{id}/ — destructive.',
    params: z.object({ organization_slug: slugList }),
    expand: ({ organization_slug }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      orgPathConstraint(organization_slug, '/issues/\\d+/'),
    ],
  }),

  defineIntent({
    name: 'sentry.get_event',
    effect: 'read',
    description:
      'Retrieve a single event by ID. Binds GET /api/0/projects/{org}/{project}/events/{event_id}/.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/api/0/projects/[a-z0-9-]+/[a-z0-9-]+/events/[0-9a-f]+/$',
      },
    ],
  }),

  defineIntent({
    name: 'sentry.list_releases',
    effect: 'read',
    description:
      'List releases in specific organizations. Binds GET /api/0/organizations/{org}/releases/.',
    params: z.object({ organization_slug: slugList }),
    expand: ({ organization_slug }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      orgPathConstraint(organization_slug, '/releases/'),
    ],
  }),

  defineIntent({
    name: 'sentry.create_release',
    effect: 'write',
    description:
      'Create a new release in specific organizations. Binds POST /api/0/organizations/{org}/releases/.',
    params: z.object({ organization_slug: slugList }),
    expand: ({ organization_slug }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      orgPathConstraint(organization_slug, '/releases/'),
    ],
  }),

  defineIntent({
    name: 'sentry.delete_release',
    effect: 'destructive',
    description:
      'Delete a release by version in specific organizations. Binds DELETE /api/0/organizations/{org}/releases/{version}/ — destructive.',
    params: z.object({ organization_slug: slugList }),
    expand: ({ organization_slug }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      orgPathConstraint(organization_slug, '/releases/[^/]+/'),
    ],
  }),

  defineIntent({
    name: 'sentry.list_teams',
    effect: 'read',
    description:
      'List teams in specific organizations. Binds GET /api/0/organizations/{org}/teams/.',
    params: z.object({ organization_slug: slugList }),
    expand: ({ organization_slug }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      orgPathConstraint(organization_slug, '/teams/'),
    ],
  }),

  defineIntent({
    name: 'sentry.list_organizations',
    effect: 'read',
    description:
      'List organizations the authenticated user belongs to. Binds GET /api/0/organizations/.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/0/organizations/' },
    ],
  }),

  defineIntent({
    name: 'sentry.list_alert_rules',
    effect: 'read',
    description:
      'List project alert rules. Binds GET /api/0/projects/{org}/{project}/rules/.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/api/0/projects/[a-z0-9-]+/[a-z0-9-]+/rules/$',
      },
    ],
  }),

  defineIntent({
    name: 'sentry.create_alert_rule',
    effect: 'write',
    description:
      'Create a project alert rule. Binds POST /api/0/projects/{org}/{project}/rules/.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/api/0/projects/[a-z0-9-]+/[a-z0-9-]+/rules/$',
      },
    ],
  }),

  defineIntent({
    name: 'sentry.list_tags',
    effect: 'read',
    description:
      'List tag keys for a project. Binds GET /api/0/projects/{org}/{project}/tags/.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/api/0/projects/[a-z0-9-]+/[a-z0-9-]+/tags/$',
      },
    ],
  }),

  defineIntent({
    name: 'sentry.list_user_feedback',
    effect: 'read',
    description:
      'List user feedback submissions for a project. Binds GET /api/0/projects/{org}/{project}/user-feedback/.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/api/0/projects/[a-z0-9-]+/[a-z0-9-]+/user-feedback/$',
      },
    ],
  }),

  defineIntent({
    name: 'sentry.upload_source_map',
    effect: 'write',
    description:
      'Upload a source map or release file. Binds POST /api/0/organizations/{org}/releases/{version}/files/.',
    params: z.object({ organization_slug: slugList }),
    expand: ({ organization_slug }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      orgPathConstraint(organization_slug, '/releases/[^/]+/files/'),
    ],
  }),

  defineIntent({
    name: 'sentry.list_release_files',
    effect: 'read',
    description:
      'List files attached to a release. Binds GET /api/0/organizations/{org}/releases/{version}/files/.',
    params: z.object({ organization_slug: slugList }),
    expand: ({ organization_slug }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      orgPathConstraint(organization_slug, '/releases/[^/]+/files/'),
    ],
  }),
];
