import { z } from 'zod';
import { defineIntent } from './types.js';

// Twitter/X API v2 - https://developer.x.com/en/docs/twitter-api. Calls
// hit api.twitter.com/2/…. User-scoped mutations embed the acting user's
// numeric ID in the pathname (/users/{id}/…). Intents gate on method +
// path shape; for binary actions on tweets, path carries the tweet ID.

export const twitterIntents = [
  defineIntent({
    name: 'twitter.create_tweet',
    effect: 'send',
    description:
      'Post a new tweet from the authenticated account. Binds POST /2/tweets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/2/tweets' },
    ],
  }),

  defineIntent({
    name: 'twitter.delete_tweet',
    effect: 'destructive',
    description:
      'Delete one of the authenticated user\'s tweets. Binds DELETE /2/tweets/{id} - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/2/tweets/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'twitter.follow_user',
    effect: 'write',
    description:
      'Follow another user as the authenticated user. Binds POST /2/users/{id}/following.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/2/users/[^/]+/following$' },
    ],
  }),

  defineIntent({
    name: 'twitter.unfollow_user',
    effect: 'destructive',
    description:
      'Unfollow a user. Binds DELETE /2/users/{source_id}/following/{target_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/2/users/[^/]+/following/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'twitter.block_user',
    effect: 'write',
    description:
      'Block a user. Binds POST /2/users/{id}/blocking.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/2/users/[^/]+/blocking$' },
    ],
  }),

  defineIntent({
    name: 'twitter.mute_user',
    effect: 'write',
    description:
      'Mute a user. Binds POST /2/users/{id}/muting.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/2/users/[^/]+/muting$' },
    ],
  }),

  defineIntent({
    name: 'twitter.like_tweet',
    effect: 'write',
    description:
      'Like a tweet as the authenticated user. Binds POST /2/users/{id}/likes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/2/users/[^/]+/likes$' },
    ],
  }),

  defineIntent({
    name: 'twitter.unlike_tweet',
    effect: 'destructive',
    description:
      'Remove a like from a tweet. Binds DELETE /2/users/{id}/likes/{tweet_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/2/users/[^/]+/likes/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'twitter.retweet',
    effect: 'write',
    description:
      'Retweet a tweet. Binds POST /2/users/{id}/retweets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/2/users/[^/]+/retweets$' },
    ],
  }),

  defineIntent({
    name: 'twitter.unretweet',
    effect: 'destructive',
    description:
      'Undo a retweet. Binds DELETE /2/users/{id}/retweets/{source_tweet_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/2/users/[^/]+/retweets/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'twitter.bookmark_tweet',
    effect: 'write',
    description:
      'Add a tweet to bookmarks. Binds POST /2/users/{id}/bookmarks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/2/users/[^/]+/bookmarks$' },
    ],
  }),

  defineIntent({
    name: 'twitter.remove_bookmark',
    effect: 'destructive',
    description:
      'Remove a tweet from bookmarks. Binds DELETE /2/users/{id}/bookmarks/{tweet_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/2/users/[^/]+/bookmarks/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'twitter.get_user_by_username',
    effect: 'read',
    description:
      'Look up a user by handle. Binds GET /2/users/by/username/{username}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/2/users/by/username/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'twitter.search_recent_tweets',
    effect: 'read',
    description:
      'Search tweets from the last 7 days. Binds GET /2/tweets/search/recent.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/2/tweets/search/recent' },
    ],
  }),

  defineIntent({
    name: 'twitter.counts_recent_tweets',
    effect: 'read',
    description:
      'Count tweets matching a query over the last 7 days. Binds GET /2/tweets/counts/recent.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/2/tweets/counts/recent' },
    ],
  }),

  defineIntent({
    name: 'twitter.create_list',
    effect: 'write',
    description:
      'Create a new list. Binds POST /2/lists.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/2/lists' },
    ],
  }),

  defineIntent({
    name: 'twitter.update_list',
    effect: 'write',
    description:
      'Update an existing list. Binds PUT /2/lists/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/2/lists/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'twitter.delete_list',
    effect: 'destructive',
    description:
      'Delete a list by ID. Binds DELETE /2/lists/{id} - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/2/lists/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'twitter.search_spaces',
    effect: 'read',
    description:
      'Search for Spaces by keyword. Binds GET /2/spaces/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/2/spaces/search' },
    ],
  }),

  defineIntent({
    name: 'twitter.get_tweet',
    effect: 'read',
    description:
      'Fetch a single tweet by ID. Binds GET /2/tweets/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/2/tweets/[^/]+$' },
    ],
  }),
];
