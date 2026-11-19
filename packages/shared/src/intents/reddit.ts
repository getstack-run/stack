import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Reddit API - https://www.reddit.com/dev/api. OAuth traffic goes to
// oauth.reddit.com/api/…. Most write actions are POSTs to named endpoints
// with body params. Subreddit scoping rides on body.sr (submit) or the
// /r/{subreddit}/… path for reads.

const subredditList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type SubredditList = z.infer<typeof subredditList>;

function escapeRe(s: string): string {
  return s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&');
}

function subredditBodyConstraint(sr: SubredditList): Constraint {
  const list = Array.isArray(sr) ? sr : [sr];
  return list.length === 1
    ? { path: 'body.sr', op: 'eq', value: list[0]! }
    : { path: 'body.sr', op: 'in', value: list };
}

function subredditPathConstraint(sr: SubredditList, suffix: string): Constraint {
  const list = Array.isArray(sr) ? sr : [sr];
  if (list.length === 1) {
    return { path: 'url.pathname', op: 'eq', value: `/r/${list[0]!}${suffix}` };
  }
  const escaped = list.map((s) => escapeRe(s));
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/r/(${escaped.join('|')})${escapeRe(suffix)}$`,
  };
}

export const redditIntents = [
  defineIntent({
    name: 'reddit.submit_post',
    effect: 'send',
    recipient_paths: ['body.sr'],
    description:
      'Submit a link or self-text post to specific subreddits. Binds POST /api/submit with body.sr in the declared subreddit allowlist.',
    params: z.object({ subreddit: subredditList }),
    expand: ({ subreddit }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/submit' },
      subredditBodyConstraint(subreddit),
    ],
  }),

  defineIntent({
    name: 'reddit.comment',
    effect: 'send',
    recipient_paths: ['body.thing_id'],
    description:
      'Post a comment on a post or reply to another comment. Binds POST /api/comment.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/comment' },
    ],
  }),

  defineIntent({
    name: 'reddit.vote',
    effect: 'write',
    description:
      'Upvote, downvote, or clear a vote on a thing. Binds POST /api/vote.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/vote' },
    ],
  }),

  defineIntent({
    name: 'reddit.save',
    effect: 'write',
    description:
      'Save a post or comment for later. Binds POST /api/save.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/save' },
    ],
  }),

  defineIntent({
    name: 'reddit.unsave',
    effect: 'write',
    description:
      'Unsave a previously saved item. Binds POST /api/unsave.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/unsave' },
    ],
  }),

  defineIntent({
    name: 'reddit.hide',
    effect: 'write',
    description:
      'Hide a post from the authenticated user\'s listings. Binds POST /api/hide.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/hide' },
    ],
  }),

  defineIntent({
    name: 'reddit.report',
    effect: 'write',
    description:
      'Report a post or comment for moderator review. Binds POST /api/report.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/report' },
    ],
  }),

  defineIntent({
    name: 'reddit.delete_thing',
    effect: 'destructive',
    description:
      'Delete the authenticated user\'s own post or comment. Binds POST /api/del - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/del' },
    ],
  }),

  defineIntent({
    name: 'reddit.edit_thing',
    effect: 'write',
    description:
      'Edit the body of the authenticated user\'s own post or comment. Binds POST /api/editusertext.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/editusertext' },
    ],
  }),

  defineIntent({
    name: 'reddit.subscribe',
    effect: 'write',
    description:
      'Subscribe or unsubscribe to/from subreddits. Binds POST /api/subscribe.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/subscribe' },
    ],
  }),

  defineIntent({
    name: 'reddit.send_message',
    effect: 'send',
    recipient_paths: ['body.to'],
    description:
      'Send a private message to a user. Binds POST /api/compose.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/compose' },
    ],
  }),

  defineIntent({
    name: 'reddit.get_me',
    effect: 'read',
    description:
      'Fetch the authenticated user\'s identity. Binds GET /api/v1/me.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/me' },
    ],
  }),

  defineIntent({
    name: 'reddit.subreddit_about',
    effect: 'read',
    description:
      'Fetch metadata about specific subreddits. Binds GET /r/{subreddit}/about to the declared subreddit allowlist.',
    params: z.object({ subreddit: subredditList }),
    expand: ({ subreddit }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      subredditPathConstraint(subreddit, '/about'),
    ],
  }),

  defineIntent({
    name: 'reddit.subreddit_new',
    effect: 'read',
    description:
      'List new posts in specific subreddits. Binds GET /r/{subreddit}/new to the declared subreddit allowlist.',
    params: z.object({ subreddit: subredditList }),
    expand: ({ subreddit }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      subredditPathConstraint(subreddit, '/new'),
    ],
  }),

  defineIntent({
    name: 'reddit.subreddit_hot',
    effect: 'read',
    description:
      'List hot posts in specific subreddits. Binds GET /r/{subreddit}/hot to the declared subreddit allowlist.',
    params: z.object({ subreddit: subredditList }),
    expand: ({ subreddit }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      subredditPathConstraint(subreddit, '/hot'),
    ],
  }),

  defineIntent({
    name: 'reddit.search',
    effect: 'read',
    description:
      'Search the site for posts matching a query. Binds GET /search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/search' },
    ],
  }),

  defineIntent({
    name: 'reddit.subreddit_rules',
    effect: 'read',
    description:
      'Fetch rules for specific subreddits. Binds GET /r/{subreddit}/about/rules.',
    params: z.object({ subreddit: subredditList }),
    expand: ({ subreddit }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      subredditPathConstraint(subreddit, '/about/rules'),
    ],
  }),

  defineIntent({
    name: 'reddit.block_user',
    effect: 'write',
    description:
      'Block another user from contacting the authenticated user. Binds POST /api/block_user.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/block_user' },
    ],
  }),

  defineIntent({
    name: 'reddit.read_message',
    effect: 'write',
    description:
      'Mark private messages as read. Binds POST /api/read_message.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/read_message' },
    ],
  }),
];
