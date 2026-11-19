import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Bitbucket Cloud REST 2.0 — https://api.bitbucket.org/2.0. Most resources
// live under /2.0/repositories/{workspace}/{repo_slug}/…. Intents bind
// method + pathname scoped to the declared workspace/repo allowlist.

const repoFmt = z
  .string()
  .min(3)
  .max(256)
  .regex(/^[^/]+\/[^/]+$/, 'repo must be "workspace/repo_slug"');
const repoList = z.union([repoFmt, z.array(repoFmt).min(1)]);
type RepoList = z.infer<typeof repoList>;
const toList = (v: RepoList): string[] => (Array.isArray(v) ? v : [v]);

function repoPathPrefixConstraint(repo: RepoList, suffix: string): Constraint {
  const list = toList(repo);
  if (list.length === 1) {
    return {
      path: 'url.pathname',
      op: 'eq',
      value: `/2.0/repositories/${list[0]!}${suffix}`,
    };
  }
  const escaped = list.map((r) => r.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/2\\.0/repositories/(${escaped.join('|')})${suffix.replace(/[.+*?^${}()|[\]\\]/g, '\\$&')}$`,
  };
}

function repoSubpathRegex(repo: RepoList, subpathRegex: string): Constraint {
  const list = toList(repo);
  const escaped = list.map((r) => r.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? escaped[0]! : `(${escaped.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/2\\.0/repositories/${alt}${subpathRegex}$`,
  };
}

export const bitbucketIntents = [
  defineIntent({
    name: 'bitbucket.create_issue',
    effect: 'write',
    description:
      'Open a new issue on a Bitbucket repo. Binds POST /2.0/repositories/{ws}/{repo}/issues.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoPathPrefixConstraint(repo, '/issues'),
    ],
  }),

  defineIntent({
    name: 'bitbucket.update_issue',
    effect: 'write',
    description:
      'Update an existing issue (title, state, assignee). Binds PUT /2.0/repositories/{ws}/{repo}/issues/{id}.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      repoSubpathRegex(repo, '/issues/\\d+'),
    ],
  }),

  defineIntent({
    name: 'bitbucket.comment_issue',
    effect: 'write',
    description:
      'Add a comment to an issue. Binds POST /2.0/repositories/{ws}/{repo}/issues/{id}/comments.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoSubpathRegex(repo, '/issues/\\d+/comments'),
    ],
  }),

  defineIntent({
    name: 'bitbucket.create_pr',
    effect: 'write',
    description:
      'Open a new pull request. Binds POST /2.0/repositories/{ws}/{repo}/pullrequests.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoPathPrefixConstraint(repo, '/pullrequests'),
    ],
  }),

  defineIntent({
    name: 'bitbucket.update_pr',
    effect: 'write',
    description:
      'Update an existing pull request (title, description, reviewers). Binds PUT /2.0/repositories/{ws}/{repo}/pullrequests/{id}.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      repoSubpathRegex(repo, '/pullrequests/\\d+'),
    ],
  }),

  defineIntent({
    name: 'bitbucket.merge_pr',
    effect: 'write',
    description:
      'Merge a pull request. Binds POST /2.0/repositories/{ws}/{repo}/pullrequests/{id}/merge — destructive.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoSubpathRegex(repo, '/pullrequests/\\d+/merge'),
    ],
  }),

  defineIntent({
    name: 'bitbucket.approve_pr',
    effect: 'destructive',
    description:
      'Approve or unapprove a pull request. Binds POST/DELETE /2.0/repositories/{ws}/{repo}/pullrequests/{id}/approve.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      repoSubpathRegex(repo, '/pullrequests/\\d+/approve'),
    ],
  }),

  defineIntent({
    name: 'bitbucket.comment_pr',
    effect: 'write',
    description:
      'Add a comment on a pull request. Binds POST /2.0/repositories/{ws}/{repo}/pullrequests/{id}/comments.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoSubpathRegex(repo, '/pullrequests/\\d+/comments'),
    ],
  }),

  defineIntent({
    name: 'bitbucket.trigger_pipeline',
    effect: 'write',
    description:
      'Trigger a new Bitbucket Pipelines run. Binds POST /2.0/repositories/{ws}/{repo}/pipelines/.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoSubpathRegex(repo, '/pipelines/?'),
    ],
  }),

  defineIntent({
    name: 'bitbucket.stop_pipeline',
    effect: 'write',
    description:
      'Stop a running pipeline. Binds POST /2.0/repositories/{ws}/{repo}/pipelines/{uuid}/stopPipeline.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoSubpathRegex(repo, '/pipelines/[^/]+/stopPipeline'),
    ],
  }),

  defineIntent({
    name: 'bitbucket.manage_branches',
    effect: 'destructive',
    description:
      'Create or delete branches via the refs endpoint. Binds POST/DELETE /2.0/repositories/{ws}/{repo}/refs/branches(/{name})?.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      repoSubpathRegex(repo, '/refs/branches(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'bitbucket.manage_tags',
    effect: 'destructive',
    description:
      'Create or delete tags via the refs endpoint. Binds POST/DELETE /2.0/repositories/{ws}/{repo}/refs/tags(/{name})?.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      repoSubpathRegex(repo, '/refs/tags(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'bitbucket.comment_commit',
    effect: 'write',
    description:
      'Post a comment on a specific commit. Binds POST /2.0/repositories/{ws}/{repo}/commit/{sha}/comments.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoSubpathRegex(repo, '/commit/[0-9a-f]+/comments'),
    ],
  }),

  defineIntent({
    name: 'bitbucket.manage_webhooks',
    effect: 'destructive',
    description:
      'Create, update, and delete repo webhooks. Binds POST/PUT/DELETE /2.0/repositories/{ws}/{repo}/hooks(/{uid})?.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'in', value: ['POST', 'PUT', 'DELETE'] },
      repoSubpathRegex(repo, '/hooks(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'bitbucket.manage_deployments',
    effect: 'write',
    description:
      'Create and update deployment environment entries. Binds POST/PUT /2.0/repositories/{ws}/{repo}/environments(/{uuid})?.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'in', value: ['POST', 'PUT'] },
      repoSubpathRegex(repo, '/environments(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'bitbucket.read_repo',
    effect: 'read',
    description:
      'Read-only access to repo contents and metadata. Binds GET /2.0/repositories/{ws}/{repo}/….',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      repoSubpathRegex(repo, '(/.*)?'),
    ],
  }),
];
