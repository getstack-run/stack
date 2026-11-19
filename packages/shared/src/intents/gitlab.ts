import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// GitLab REST API v4 — https://gitlab.com/api/v4. Project-scoped operations
// live at /api/v4/projects/:id/… where :id is a numeric project ID or the
// URL-encoded "namespace/project" path. Intents bind method + pathname to
// the declared project allowlist.

const projectFmt = z.string().min(1).max(256);
const projectList = z.union([projectFmt, z.array(projectFmt).min(1)]);
type ProjectList = z.infer<typeof projectList>;
const toList = (v: ProjectList): string[] => (Array.isArray(v) ? v : [v]);

function projectPathPrefixConstraint(project: ProjectList, suffix: string): Constraint {
  const list = toList(project);
  if (list.length === 1) {
    return {
      path: 'url.pathname',
      op: 'eq',
      value: `/api/v4/projects/${list[0]!}${suffix}`,
    };
  }
  const escaped = list.map((p) => p.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/api/v4/projects/(${escaped.join('|')})${suffix.replace(/[.+*?^${}()|[\]\\]/g, '\\$&')}$`,
  };
}

function projectSubpathRegex(project: ProjectList, subpathRegex: string): Constraint {
  const list = toList(project);
  const escaped = list.map((p) => p.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? escaped[0]! : `(${escaped.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/api/v4/projects/${alt}${subpathRegex}$`,
  };
}

export const gitlabIntents = [
  defineIntent({
    name: 'gitlab.create_issue',
    effect: 'write',
    description:
      'Open a new issue in specific GitLab projects. Binds POST /api/v4/projects/:id/issues.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      projectPathPrefixConstraint(project, '/issues'),
    ],
  }),

  defineIntent({
    name: 'gitlab.update_issue',
    effect: 'write',
    description:
      'Update or close an existing issue. Binds PUT /api/v4/projects/:id/issues/:iid.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      projectSubpathRegex(project, '/issues/\\d+'),
    ],
  }),

  defineIntent({
    name: 'gitlab.comment_issue',
    effect: 'write',
    description:
      'Add a comment (note) to an issue. Binds POST /api/v4/projects/:id/issues/:iid/notes.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      projectSubpathRegex(project, '/issues/\\d+/notes'),
    ],
  }),

  defineIntent({
    name: 'gitlab.create_mr',
    effect: 'write',
    description:
      'Open a new merge request in specific projects. Binds POST /api/v4/projects/:id/merge_requests.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      projectPathPrefixConstraint(project, '/merge_requests'),
    ],
  }),

  defineIntent({
    name: 'gitlab.update_mr',
    effect: 'write',
    description:
      'Update an existing merge request (title, description, labels, state). Binds PUT /api/v4/projects/:id/merge_requests/:iid.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      projectSubpathRegex(project, '/merge_requests/\\d+'),
    ],
  }),

  defineIntent({
    name: 'gitlab.merge_mr',
    effect: 'write',
    description:
      'Merge a merge request. Binds PUT /api/v4/projects/:id/merge_requests/:iid/merge — destructive.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      projectSubpathRegex(project, '/merge_requests/\\d+/merge'),
    ],
  }),

  defineIntent({
    name: 'gitlab.create_pipeline',
    effect: 'write',
    description:
      'Trigger a new pipeline on a ref. Binds POST /api/v4/projects/:id/pipeline.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      projectPathPrefixConstraint(project, '/pipeline'),
    ],
  }),

  defineIntent({
    name: 'gitlab.cancel_pipeline',
    effect: 'write',
    description:
      'Cancel a running pipeline. Binds POST /api/v4/projects/:id/pipelines/:pid/cancel.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      projectSubpathRegex(project, '/pipelines/\\d+/cancel'),
    ],
  }),

  defineIntent({
    name: 'gitlab.retry_job',
    effect: 'write',
    description:
      'Retry a failed job. Binds POST /api/v4/projects/:id/jobs/:jid/retry.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      projectSubpathRegex(project, '/jobs/\\d+/retry'),
    ],
  }),

  defineIntent({
    name: 'gitlab.manage_releases',
    effect: 'destructive',
    description:
      'Create, update, and delete releases. Binds POST/PUT/DELETE /api/v4/projects/:id/releases(/:tag)?.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'in', value: ['POST', 'PUT', 'DELETE'] },
      projectSubpathRegex(project, '/releases(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'gitlab.manage_branches',
    effect: 'destructive',
    description:
      'Create or delete branches on a project. Binds POST/DELETE /api/v4/projects/:id/repository/branches(/:name)?.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      projectSubpathRegex(project, '/repository/branches(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'gitlab.manage_tags',
    effect: 'destructive',
    description:
      'Create or delete repository tags. Binds POST/DELETE /api/v4/projects/:id/repository/tags(/:name)?.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      projectSubpathRegex(project, '/repository/tags(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'gitlab.list_runners',
    effect: 'read',
    description:
      'Read-only listing of runners available to a project. Binds GET /api/v4/projects/:id/runners.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      projectPathPrefixConstraint(project, '/runners'),
    ],
  }),

  defineIntent({
    name: 'gitlab.manage_members',
    effect: 'destructive',
    description:
      'Add, update, and remove project members. Binds POST/PUT/DELETE /api/v4/projects/:id/members(/:user_id)?.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'in', value: ['POST', 'PUT', 'DELETE'] },
      projectSubpathRegex(project, '/members(/\\d+)?'),
    ],
  }),

  defineIntent({
    name: 'gitlab.manage_labels',
    effect: 'destructive',
    description:
      'Create, update, and delete project labels. Binds POST/PUT/DELETE /api/v4/projects/:id/labels(/:id)?.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'in', value: ['POST', 'PUT', 'DELETE'] },
      projectSubpathRegex(project, '/labels(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'gitlab.manage_milestones',
    effect: 'destructive',
    description:
      'Create, update, and delete project milestones. Binds POST/PUT/DELETE /api/v4/projects/:id/milestones(/:id)?.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'in', value: ['POST', 'PUT', 'DELETE'] },
      projectSubpathRegex(project, '/milestones(/\\d+)?'),
    ],
  }),

  defineIntent({
    name: 'gitlab.manage_variables',
    effect: 'destructive',
    description:
      'Create, update, and delete CI/CD variables. Binds POST/PUT/DELETE /api/v4/projects/:id/variables(/:key)? — sensitive.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'in', value: ['POST', 'PUT', 'DELETE'] },
      projectSubpathRegex(project, '/variables(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'gitlab.manage_webhooks',
    effect: 'destructive',
    description:
      'Create, update, and delete project webhooks. Binds POST/PUT/DELETE /api/v4/projects/:id/hooks(/:id)?.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'in', value: ['POST', 'PUT', 'DELETE'] },
      projectSubpathRegex(project, '/hooks(/\\d+)?'),
    ],
  }),

  defineIntent({
    name: 'gitlab.read_project',
    effect: 'read',
    description:
      'Read-only access to project metadata and subresources. Binds GET /api/v4/projects/:id/….',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      projectSubpathRegex(project, '(/.*)?'),
    ],
  }),
];
