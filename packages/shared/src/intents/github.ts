import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// GitHub REST API — https://api.github.com. Most operations are scoped
// to a repo at /repos/{owner}/{repo}/…. Intents bind method + pathname
// so the agent can only touch the declared repo(s) and endpoint kind.

const repoFmt = z
  .string()
  .min(3)
  .max(128)
  .regex(/^[^/]+\/[^/]+$/, 'repo must be "owner/name"');
const repoList = z.union([repoFmt, z.array(repoFmt).min(1)]);
type RepoList = z.infer<typeof repoList>;
const toList = (v: RepoList): string[] => (Array.isArray(v) ? v : [v]);

function repoPathPrefixConstraint(repo: RepoList, suffix: string): Constraint {
  const list = toList(repo);
  if (list.length === 1) {
    return { path: 'url.pathname', op: 'eq', value: `/repos/${list[0]!}${suffix}` };
  }
  // Multiple repos: regex alternation. Repo name chars are [A-Za-z0-9._-].
  const escaped = list.map((r) => r.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/repos/(${escaped.join('|')})${suffix.replace(/[.+*?^${}()|[\]\\]/g, '\\$&')}$`,
  };
}

function repoSubpathRegex(repo: RepoList, subpathRegex: string): Constraint {
  const list = toList(repo);
  const escaped = list.map((r) => r.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const repoAlt = list.length === 1 ? escaped[0]! : `(${escaped.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/repos/${repoAlt}${subpathRegex}$`,
  };
}

export const githubIntents = [
  defineIntent({
    name: 'github.create_issue',
    effect: 'write',
    description:
      'Open a new issue in specific GitHub repos. Binds POST /repos/{owner}/{repo}/issues to the declared repo allowlist.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoPathPrefixConstraint(repo, '/issues'),
    ],
  }),

  defineIntent({
    name: 'github.comment_issue',
    effect: 'write',
    description:
      'Comment on any issue or PR in specific repos. Binds POST /repos/{owner}/{repo}/issues/{n}/comments.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoSubpathRegex(repo, '/issues/\\d+/comments'),
    ],
  }),

  defineIntent({
    name: 'github.create_pr',
    effect: 'write',
    description:
      'Open a new pull request in specific repos. Binds POST /repos/{owner}/{repo}/pulls to the declared repo allowlist.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoPathPrefixConstraint(repo, '/pulls'),
    ],
  }),

  defineIntent({
    name: 'github.merge_pr',
    effect: 'write',
    description:
      'Merge an existing pull request in specific repos. Binds PUT /repos/{owner}/{repo}/pulls/{n}/merge — destructive, use sparingly.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      repoSubpathRegex(repo, '/pulls/\\d+/merge'),
    ],
  }),

  defineIntent({
    name: 'github.read_repo',
    effect: 'read',
    description:
      'Read-only access to repo contents and metadata. Binds GET /repos/{owner}/{repo}/… to the declared repos.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      repoSubpathRegex(repo, '(/.*)?'),
    ],
  }),

  defineIntent({
    name: 'github.dispatch_workflow',
    effect: 'write',
    description:
      'Trigger a workflow_dispatch event on a named workflow. Binds POST /repos/{owner}/{repo}/actions/workflows/{id}/dispatches.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoSubpathRegex(repo, '/actions/workflows/[^/]+/dispatches'),
    ],
  }),

  defineIntent({
    name: 'github.list_workflow_runs',
    effect: 'read',
    description:
      'List Actions workflow runs for a repo. Binds GET /repos/{owner}/{repo}/actions/runs and per-workflow variants.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      repoSubpathRegex(repo, '/actions/(runs|workflows/[^/]+/runs)'),
    ],
  }),

  defineIntent({
    name: 'github.cancel_workflow_run',
    effect: 'write',
    description:
      'Cancel an in-progress Actions run. Binds POST /repos/{owner}/{repo}/actions/runs/{id}/cancel.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoSubpathRegex(repo, '/actions/runs/\\d+/cancel'),
    ],
  }),

  defineIntent({
    name: 'github.create_branch',
    effect: 'write',
    description:
      'Create a git ref (branch) via the refs endpoint. Binds POST /repos/{owner}/{repo}/git/refs.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoPathPrefixConstraint(repo, '/git/refs'),
    ],
  }),

  defineIntent({
    name: 'github.delete_branch',
    effect: 'destructive',
    description:
      'Delete a git ref (branch). Binds DELETE /repos/{owner}/{repo}/git/refs/heads/{branch} — destructive.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      repoSubpathRegex(repo, '/git/refs/heads/.+'),
    ],
  }),

  defineIntent({
    name: 'github.protect_branch',
    effect: 'write',
    description:
      'Set or update branch protection rules. Binds PUT /repos/{owner}/{repo}/branches/{branch}/protection.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      repoSubpathRegex(repo, '/branches/[^/]+/protection'),
    ],
  }),

  defineIntent({
    name: 'github.manage_releases',
    effect: 'destructive',
    description:
      'Create, update, and delete releases and release assets. Binds POST/PATCH/DELETE /repos/{owner}/{repo}/releases/….',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
      repoSubpathRegex(repo, '/releases(/.*)?'),
    ],
  }),

  defineIntent({
    name: 'github.create_deployment',
    effect: 'write',
    description:
      'Create deployments and deployment statuses. Binds POST /repos/{owner}/{repo}/deployments and /deployments/{id}/statuses.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoSubpathRegex(repo, '/deployments(/\\d+/statuses)?'),
    ],
  }),

  defineIntent({
    name: 'github.manage_checks',
    effect: 'write',
    description:
      'Create and update check runs for commits. Binds POST/PATCH /repos/{owner}/{repo}/check-runs(/{id})?.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH'] },
      repoSubpathRegex(repo, '/check-runs(/\\d+)?'),
    ],
  }),

  defineIntent({
    name: 'github.manage_labels',
    effect: 'destructive',
    description:
      'Create, update, delete, and attach labels on issues. Binds POST/PATCH/DELETE /repos/{owner}/{repo}/labels and /issues/{n}/labels.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
      repoSubpathRegex(repo, '/(labels(/.+)?|issues/\\d+/labels(/.+)?)'),
    ],
  }),

  defineIntent({
    name: 'github.manage_milestones',
    effect: 'destructive',
    description:
      'Create, update, and close milestones. Binds POST/PATCH/DELETE /repos/{owner}/{repo}/milestones(/{n})?.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
      repoSubpathRegex(repo, '/milestones(/\\d+)?'),
    ],
  }),

  defineIntent({
    name: 'github.submit_pr_review',
    effect: 'write',
    description:
      'Submit a review (approve, request changes, comment) on a pull request. Binds POST /repos/{owner}/{repo}/pulls/{n}/reviews.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      repoSubpathRegex(repo, '/pulls/\\d+/reviews'),
    ],
  }),

  defineIntent({
    name: 'github.request_pr_reviewers',
    effect: 'destructive',
    description:
      'Request or remove reviewers on a pull request. Binds POST/DELETE /repos/{owner}/{repo}/pulls/{n}/requested_reviewers.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      repoSubpathRegex(repo, '/pulls/\\d+/requested_reviewers'),
    ],
  }),

  defineIntent({
    name: 'github.dismiss_pr_review',
    effect: 'write',
    description:
      'Dismiss a previously submitted pull request review. Binds PUT /repos/{owner}/{repo}/pulls/{n}/reviews/{id}/dismissals.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      repoSubpathRegex(repo, '/pulls/\\d+/reviews/\\d+/dismissals'),
    ],
  }),

  defineIntent({
    name: 'github.read_collaborators',
    effect: 'read',
    description:
      'Read-only access to collaborator lists and permission levels. Binds GET /repos/{owner}/{repo}/collaborators(/…)?.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      repoSubpathRegex(repo, '/collaborators(/.*)?'),
    ],
  }),

  defineIntent({
    name: 'github.manage_gists',
    effect: 'destructive',
    description:
      'Create, update, and delete gists for the authenticated user. Binds POST/PATCH/DELETE /gists(/{id})? (not repo-scoped).',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
      { path: 'url.pathname', op: 'matches', value: '^/gists(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'github.manage_actions_secrets',
    effect: 'destructive',
    description:
      'Set or delete Actions repository secrets. Binds PUT/DELETE /repos/{owner}/{repo}/actions/secrets/{name} — sensitive.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'in', value: ['PUT', 'DELETE'] },
      repoSubpathRegex(repo, '/actions/secrets/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'github.manage_webhooks',
    effect: 'destructive',
    description:
      'Create, update, and delete repo webhooks. Binds POST/PATCH/DELETE /repos/{owner}/{repo}/hooks(/{id})?.',
    params: z.object({ repo: repoList }),
    expand: ({ repo }) => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
      repoSubpathRegex(repo, '/hooks(/\\d+)?'),
    ],
  }),
];
