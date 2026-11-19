import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Snyk REST API — https://apidocs.snyk.io. Base: api.snyk.io/rest/…
// (and /v1/… for legacy endpoints). Most resources live under
// /rest/orgs/{org_id}/…. Intents scope on org_id where the API is
// org-scoped. org_id is a UUID.

const orgId = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, 'org_id must be UUID');
const orgList = z.union([orgId, z.array(orgId).min(1)]);
type OrgList = z.infer<typeof orgList>;
const toList = (v: OrgList): string[] => (Array.isArray(v) ? v : [v]);

function orgPathConstraint(org: OrgList, suffix: string): Constraint {
  const list = toList(org);
  const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/rest/orgs/${alt}${suffix}$`,
  };
}

export const snykIntents = [
  defineIntent({
    name: 'snyk.list_organizations',
    effect: 'read',
    description:
      'List organizations the user has access to. Binds GET /rest/orgs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/rest/orgs' },
    ],
  }),

  defineIntent({
    name: 'snyk.list_projects',
    effect: 'read',
    description:
      'List projects in specific organizations. Binds GET /rest/orgs/{org_id}/projects.',
    params: z.object({ org_id: orgList }),
    expand: ({ org_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      orgPathConstraint(org_id, '/projects'),
    ],
  }),

  defineIntent({
    name: 'snyk.get_project',
    effect: 'read',
    description:
      'Read a specific project within an org. Binds GET /rest/orgs/{org_id}/projects/{project_id}.',
    params: z.object({ org_id: orgList }),
    expand: ({ org_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      orgPathConstraint(
        org_id,
        '/projects/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
      ),
    ],
  }),

  defineIntent({
    name: 'snyk.delete_project',
    effect: 'destructive',
    description:
      'Delete a project from an org. Binds DELETE /rest/orgs/{org_id}/projects/{project_id} — destructive.',
    params: z.object({ org_id: orgList }),
    expand: ({ org_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      orgPathConstraint(
        org_id,
        '/projects/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
      ),
    ],
  }),

  defineIntent({
    name: 'snyk.list_issues',
    effect: 'read',
    description:
      'List issues across projects in an org. Binds GET /rest/orgs/{org_id}/issues.',
    params: z.object({ org_id: orgList }),
    expand: ({ org_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      orgPathConstraint(org_id, '/issues'),
    ],
  }),

  defineIntent({
    name: 'snyk.list_project_issues',
    effect: 'read',
    description:
      'List aggregated issues for a specific project. Binds GET /rest/orgs/{org_id}/projects/{project_id}/aggregated-issues.',
    params: z.object({ org_id: orgList }),
    expand: ({ org_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      orgPathConstraint(
        org_id,
        '/projects/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/aggregated-issues',
      ),
    ],
  }),

  defineIntent({
    name: 'snyk.test_package',
    effect: 'read',
    description:
      'Test an npm package for known vulnerabilities. Binds GET /v1/test/npm/{package}/{version}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/test/[^/]+/[^/]+/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'snyk.monitor_project',
    effect: 'write',
    description:
      'Submit a project manifest to be continuously monitored. Binds POST /v1/monitor/{package_manager}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/monitor/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'snyk.list_ignores',
    effect: 'read',
    description:
      'List configured issue ignores for a project. Binds GET /v1/org/{org_id}/project/{project_id}/ignores.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v1/org/[0-9a-f-]+/project/[0-9a-f-]+/ignores$',
      },
    ],
  }),

  defineIntent({
    name: 'snyk.create_ignore',
    effect: 'write',
    description:
      'Create an ignore rule for an issue in a project. Binds POST /v1/org/{org_id}/project/{project_id}/ignore/{issue_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v1/org/[0-9a-f-]+/project/[0-9a-f-]+/ignore/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'snyk.delete_ignore',
    effect: 'destructive',
    description:
      'Remove an ignore rule for an issue. Binds DELETE /v1/org/{org_id}/project/{project_id}/ignore/{issue_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v1/org/[0-9a-f-]+/project/[0-9a-f-]+/ignore/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'snyk.list_users',
    effect: 'read',
    description:
      'List members of specific organizations. Binds GET /rest/orgs/{org_id}/memberships.',
    params: z.object({ org_id: orgList }),
    expand: ({ org_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      orgPathConstraint(org_id, '/memberships'),
    ],
  }),

  defineIntent({
    name: 'snyk.list_integrations',
    effect: 'read',
    description:
      'List source-code and registry integrations for specific orgs. Binds GET /v1/org/{org_id}/integrations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/org/[0-9a-f-]+/integrations$' },
    ],
  }),

  defineIntent({
    name: 'snyk.list_targets',
    effect: 'read',
    description:
      'List monitored targets (repos) in specific orgs. Binds GET /rest/orgs/{org_id}/targets.',
    params: z.object({ org_id: orgList }),
    expand: ({ org_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      orgPathConstraint(org_id, '/targets'),
    ],
  }),

  defineIntent({
    name: 'snyk.generate_sbom',
    effect: 'read',
    description:
      'Generate an SBOM for a specific project. Binds GET /rest/orgs/{org_id}/projects/{project_id}/sbom.',
    params: z.object({ org_id: orgList }),
    expand: ({ org_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      orgPathConstraint(
        org_id,
        '/projects/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/sbom',
      ),
    ],
  }),

  defineIntent({
    name: 'snyk.generate_issues_report',
    effect: 'write',
    description:
      'Generate an issues report across an org. Binds POST /rest/orgs/{org_id}/reports.',
    params: z.object({ org_id: orgList }),
    expand: ({ org_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      orgPathConstraint(org_id, '/reports'),
    ],
  }),

  defineIntent({
    name: 'snyk.list_audit_logs',
    effect: 'read',
    description:
      'List audit log entries for specific orgs. Binds GET /rest/orgs/{org_id}/audit_logs/search.',
    params: z.object({ org_id: orgList }),
    expand: ({ org_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      orgPathConstraint(org_id, '/audit_logs/search'),
    ],
  }),
];
