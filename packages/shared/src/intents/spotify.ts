import { z } from 'zod';
import { defineIntent } from './types.js';

// Spotify Web API — https://developer.spotify.com/documentation/web-api.
// All calls go to api.spotify.com/v1/…. Intents gate on method + pathname
// and, for playlist mutation, allowlist playlist IDs on the path.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);
const esc = (s: string) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&');
const alt = (list: string[]) => (list.length === 1 ? esc(list[0]!) : `(${list.map(esc).join('|')})`);

export const spotifyIntents = [
  defineIntent({
    name: 'spotify.get_me',
    effect: 'read',
    description:
      'Read the authenticated user profile. Binds GET /v1/me.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/me' },
    ],
  }),

  defineIntent({
    name: 'spotify.top_tracks',
    effect: 'read',
    description:
      'Fetch the authenticated user top tracks. Binds GET /v1/me/top/tracks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/me/top/tracks' },
    ],
  }),

  defineIntent({
    name: 'spotify.currently_playing',
    effect: 'read',
    description:
      'Read the currently-playing track for the user. Binds GET /v1/me/player/currently-playing.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/me/player/currently-playing' },
    ],
  }),

  defineIntent({
    name: 'spotify.player_play',
    effect: 'write',
    description:
      'Start or resume playback on the active device. Binds PUT /v1/me/player/play.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'eq', value: '/v1/me/player/play' },
    ],
  }),

  defineIntent({
    name: 'spotify.player_pause',
    effect: 'write',
    description:
      'Pause playback on the active device. Binds PUT /v1/me/player/pause.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'eq', value: '/v1/me/player/pause' },
    ],
  }),

  defineIntent({
    name: 'spotify.player_next',
    effect: 'write',
    description:
      'Skip to the next track in the queue. Binds POST /v1/me/player/next.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/me/player/next' },
    ],
  }),

  defineIntent({
    name: 'spotify.player_previous',
    effect: 'write',
    description:
      'Skip to the previous track. Binds POST /v1/me/player/previous.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/me/player/previous' },
    ],
  }),

  defineIntent({
    name: 'spotify.queue_add',
    effect: 'write',
    description:
      'Add a track URI to the playback queue. Binds POST /v1/me/player/queue.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/me/player/queue' },
    ],
  }),

  defineIntent({
    name: 'spotify.transfer_playback',
    effect: 'write',
    description:
      'Transfer playback to a different device. Binds PUT /v1/me/player.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'eq', value: '/v1/me/player' },
    ],
  }),

  defineIntent({
    name: 'spotify.create_playlist',
    effect: 'write',
    description:
      'Create a new playlist for the authenticated user. Binds POST /v1/me/playlists. Replaces the removed /v1/users/{user_id}/playlists endpoint (Feb 2026 Spotify API change).',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/me/playlists' },
    ],
  }),

  defineIntent({
    name: 'spotify.update_playlist_details',
    effect: 'write',
    description:
      'Rename or re-describe specific playlists. Binds PUT /v1/playlists/{playlist_id} to the declared playlist allowlist.',
    params: z.object({ playlist_id: idList }),
    expand: ({ playlist_id }) => {
      const list = toList(playlist_id);
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/playlists/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'spotify.add_playlist_tracks',
    effect: 'write',
    description:
      'Add tracks to specific playlists. Binds POST /v1/playlists/{playlist_id}/tracks to the declared playlist allowlist.',
    params: z.object({ playlist_id: idList }),
    expand: ({ playlist_id }) => {
      const list = toList(playlist_id);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/playlists/${alt(list)}/tracks$` },
      ];
    },
  }),

  defineIntent({
    name: 'spotify.remove_playlist_tracks',
    effect: 'destructive',
    description:
      'Remove tracks from specific playlists. Binds DELETE /v1/playlists/{playlist_id}/tracks. Destructive.',
    params: z.object({ playlist_id: idList }),
    expand: ({ playlist_id }) => {
      const list = toList(playlist_id);
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/playlists/${alt(list)}/tracks$` },
      ];
    },
  }),

  defineIntent({
    name: 'spotify.get_playlist',
    effect: 'read',
    description:
      'Read metadata and tracks for specific playlists. Binds GET /v1/playlists/{playlist_id}.',
    params: z.object({ playlist_id: idList }),
    expand: ({ playlist_id }) => {
      const list = toList(playlist_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/playlists/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'spotify.get_track',
    effect: 'read',
    description:
      'Fetch metadata for a specific track. Binds GET /v1/tracks/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/tracks/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'spotify.get_audio_features',
    effect: 'read',
    description:
      'Fetch audio-feature analysis for a specific track. Binds GET /v1/audio-features/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/audio-features/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'spotify.get_album',
    effect: 'read',
    description:
      'Fetch metadata for a specific album. Binds GET /v1/albums/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/albums/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'spotify.get_artist',
    effect: 'read',
    description:
      'Fetch metadata for a specific artist. Binds GET /v1/artists/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/artists/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'spotify.artist_top_tracks',
    effect: 'read',
    description:
      'List the top tracks for a specific artist. Binds GET /v1/artists/{id}/top-tracks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/artists/[^/]+/top-tracks$' },
    ],
  }),

  defineIntent({
    name: 'spotify.search',
    effect: 'read',
    description:
      'Search the Spotify catalog. Binds GET /v1/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/search' },
    ],
  }),

  defineIntent({
    name: 'spotify.save_tracks',
    effect: 'write',
    description:
      'Save tracks to the user library. Binds PUT /v1/me/tracks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'eq', value: '/v1/me/tracks' },
    ],
  }),

  defineIntent({
    name: 'spotify.remove_saved_tracks',
    effect: 'destructive',
    description:
      'Remove tracks from the user library. Binds DELETE /v1/me/tracks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'eq', value: '/v1/me/tracks' },
    ],
  }),

  defineIntent({
    name: 'spotify.list_saved_tracks',
    effect: 'read',
    description:
      'List tracks saved in the user library. Binds GET /v1/me/tracks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/me/tracks' },
    ],
  }),
];
