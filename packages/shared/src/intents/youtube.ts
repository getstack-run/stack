import { z } from 'zod';
import { defineIntent } from './types.js';

// YouTube Data API v3 - https://developers.google.com/youtube/v3. Calls
// hit www.googleapis.com/youtube/v3/…. Most resources are addressed by
// collection + id in query params (?id=…); writes POST/PUT/DELETE to the
// collection endpoint. Intents gate on method + path.

export const youtubeIntents = [
  defineIntent({
    name: 'youtube.list_videos',
    effect: 'read',
    description:
      'List videos by ID, chart, or my-uploads. Binds GET /youtube/v3/videos.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/videos' },
    ],
  }),

  defineIntent({
    name: 'youtube.insert_video',
    effect: 'send',
    description:
      'Upload a new video. Binds POST /upload/youtube/v3/videos - public content change.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/upload/youtube/v3/videos' },
    ],
  }),

  defineIntent({
    name: 'youtube.update_video',
    effect: 'write',
    description:
      'Update a video\'s metadata (title, description, tags, privacy). Binds PUT /youtube/v3/videos.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/videos' },
    ],
  }),

  defineIntent({
    name: 'youtube.delete_video',
    effect: 'destructive',
    description:
      'Delete a video owned by the authenticated channel. Binds DELETE /youtube/v3/videos - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/videos' },
    ],
  }),

  defineIntent({
    name: 'youtube.set_thumbnail',
    effect: 'write',
    description:
      'Upload a custom thumbnail for a video. Binds POST /upload/youtube/v3/thumbnails/set.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/upload/youtube/v3/thumbnails/set' },
    ],
  }),

  defineIntent({
    name: 'youtube.list_playlists',
    effect: 'read',
    description:
      'List playlists owned by the authenticated channel or by ID. Binds GET /youtube/v3/playlists.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/playlists' },
    ],
  }),

  defineIntent({
    name: 'youtube.insert_playlist',
    effect: 'write',
    description:
      'Create a new playlist on the authenticated channel. Binds POST /youtube/v3/playlists.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/playlists' },
    ],
  }),

  defineIntent({
    name: 'youtube.update_playlist',
    effect: 'write',
    description:
      'Update a playlist\'s metadata. Binds PUT /youtube/v3/playlists.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/playlists' },
    ],
  }),

  defineIntent({
    name: 'youtube.delete_playlist',
    effect: 'destructive',
    description:
      'Delete a playlist. Binds DELETE /youtube/v3/playlists - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/playlists' },
    ],
  }),

  defineIntent({
    name: 'youtube.list_playlist_items',
    effect: 'read',
    description:
      'List items in a playlist. Binds GET /youtube/v3/playlistItems.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/playlistItems' },
    ],
  }),

  defineIntent({
    name: 'youtube.insert_playlist_item',
    effect: 'write',
    description:
      'Add a video to a playlist. Binds POST /youtube/v3/playlistItems.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/playlistItems' },
    ],
  }),

  defineIntent({
    name: 'youtube.delete_playlist_item',
    effect: 'destructive',
    description:
      'Remove a video from a playlist. Binds DELETE /youtube/v3/playlistItems.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/playlistItems' },
    ],
  }),

  defineIntent({
    name: 'youtube.list_comment_threads',
    effect: 'read',
    description:
      'List top-level comments on a video or channel. Binds GET /youtube/v3/commentThreads.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/commentThreads' },
    ],
  }),

  defineIntent({
    name: 'youtube.insert_comment_thread',
    effect: 'send',
    recipient_paths: ['body.snippet.videoId'],
    description:
      'Post a new top-level comment. Binds POST /youtube/v3/commentThreads.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/commentThreads' },
    ],
  }),

  defineIntent({
    name: 'youtube.insert_comment',
    effect: 'send',
    recipient_paths: ['body.snippet.parentId'],
    description:
      'Post a reply to an existing comment. Binds POST /youtube/v3/comments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/comments' },
    ],
  }),

  defineIntent({
    name: 'youtube.delete_comment',
    effect: 'destructive',
    description:
      'Delete a comment owned by the authenticated channel. Binds DELETE /youtube/v3/comments - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/comments' },
    ],
  }),

  defineIntent({
    name: 'youtube.list_channels',
    effect: 'read',
    description:
      'Fetch channel metadata by ID or mine=true. Binds GET /youtube/v3/channels.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/channels' },
    ],
  }),

  defineIntent({
    name: 'youtube.update_channel',
    effect: 'write',
    description:
      'Update channel metadata (branding, localizations). Binds PUT /youtube/v3/channels.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/channels' },
    ],
  }),

  defineIntent({
    name: 'youtube.insert_subscription',
    effect: 'write',
    description:
      'Subscribe the authenticated channel to another channel. Binds POST /youtube/v3/subscriptions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/subscriptions' },
    ],
  }),

  defineIntent({
    name: 'youtube.delete_subscription',
    effect: 'destructive',
    description:
      'Unsubscribe from a channel. Binds DELETE /youtube/v3/subscriptions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/subscriptions' },
    ],
  }),

  defineIntent({
    name: 'youtube.insert_live_broadcast',
    effect: 'write',
    description:
      'Create a new live broadcast on the authenticated channel. Binds POST /youtube/v3/liveBroadcasts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/liveBroadcasts' },
    ],
  }),

  defineIntent({
    name: 'youtube.transition_live_broadcast',
    effect: 'write',
    description:
      'Transition a broadcast status (testing, live, complete). Binds POST /youtube/v3/liveBroadcasts/transition.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/liveBroadcasts/transition' },
    ],
  }),

  defineIntent({
    name: 'youtube.list_captions',
    effect: 'read',
    description:
      'List caption tracks for a video. Binds GET /youtube/v3/captions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/youtube/v3/captions' },
    ],
  }),

  defineIntent({
    name: 'youtube.insert_caption',
    effect: 'write',
    description:
      'Upload a caption track for a video. Binds POST /upload/youtube/v3/captions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/upload/youtube/v3/captions' },
    ],
  }),
];
