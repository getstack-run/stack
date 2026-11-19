import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// TikTok API — both TikTok API for Business (business-api.tiktok.com) and
// the Content Posting API (open.tiktokapis.com). Intents gate on host +
// pathname + body/query advertiser/user allowlists where applicable.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function eqOrIn(path: string, ids: IdList): Constraint {
  const list = toList(ids);
  return list.length === 1
    ? { path, op: 'eq', value: list[0]! }
    : { path, op: 'in', value: list };
}

export const tiktokIntents = [
  defineIntent({
    name: 'tiktok.init_video_upload',
    effect: 'send',
    description:
      'Initialize a direct-post video upload on the Content Posting API. Binds POST /v2/post/publish/video/init/.',
    params: z.object({}),
    expand: () => [
      { path: 'url.host', op: 'eq', value: 'open.tiktokapis.com' },
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/post/publish/video/init/' },
    ],
  }),

  defineIntent({
    name: 'tiktok.init_inbox_upload',
    effect: 'write',
    description:
      'Initialize an upload-to-inbox publish flow. Binds POST /v2/post/publish/inbox/video/init/.',
    params: z.object({}),
    expand: () => [
      { path: 'url.host', op: 'eq', value: 'open.tiktokapis.com' },
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/post/publish/inbox/video/init/' },
    ],
  }),

  defineIntent({
    name: 'tiktok.publish_status',
    effect: 'read',
    description:
      'Fetch the current status of a publish job. Binds POST /v2/post/publish/status/fetch/.',
    params: z.object({}),
    expand: () => [
      { path: 'url.host', op: 'eq', value: 'open.tiktokapis.com' },
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/post/publish/status/fetch/' },
    ],
  }),

  defineIntent({
    name: 'tiktok.list_videos',
    effect: 'read',
    description:
      'List videos owned by the authenticated user. Binds POST /v2/video/list/.',
    params: z.object({}),
    expand: () => [
      { path: 'url.host', op: 'eq', value: 'open.tiktokapis.com' },
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/video/list/' },
    ],
  }),

  defineIntent({
    name: 'tiktok.query_videos',
    effect: 'read',
    description:
      'Query specific videos by filters such as video IDs. Binds POST /v2/video/query/.',
    params: z.object({}),
    expand: () => [
      { path: 'url.host', op: 'eq', value: 'open.tiktokapis.com' },
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/video/query/' },
    ],
  }),

  defineIntent({
    name: 'tiktok.user_info',
    effect: 'read',
    description:
      'Read profile fields for the authenticated user. Binds GET /v2/user/info/.',
    params: z.object({}),
    expand: () => [
      { path: 'url.host', op: 'eq', value: 'open.tiktokapis.com' },
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/user/info/' },
    ],
  }),

  defineIntent({
    name: 'tiktok.list_comments',
    effect: 'read',
    description:
      'List comments on videos owned by the authenticated user. Binds POST /v2/video/comment/list/.',
    params: z.object({}),
    expand: () => [
      { path: 'url.host', op: 'eq', value: 'open.tiktokapis.com' },
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/video/comment/list/' },
    ],
  }),

  defineIntent({
    name: 'tiktok.reply_comment',
    effect: 'send',
    description:
      'Reply to a comment on a video. Binds POST /v2/video/comment/reply/create/.',
    params: z.object({}),
    expand: () => [
      { path: 'url.host', op: 'eq', value: 'open.tiktokapis.com' },
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/video/comment/reply/create/' },
    ],
  }),

  defineIntent({
    name: 'tiktok.list_captions',
    effect: 'read',
    description:
      'List available caption tracks for a video. Binds GET /v2/video/caption/list/.',
    params: z.object({}),
    expand: () => [
      { path: 'url.host', op: 'eq', value: 'open.tiktokapis.com' },
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/video/caption/list/' },
    ],
  }),

  defineIntent({
    name: 'tiktok.list_advertisers',
    effect: 'read',
    description:
      'List advertiser accounts the authenticated user can manage. Binds GET /open_api/v1.3/oauth2/advertiser/get/.',
    params: z.object({}),
    expand: () => [
      { path: 'url.host', op: 'eq', value: 'business-api.tiktok.com' },
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/open_api/v1.3/oauth2/advertiser/get/' },
    ],
  }),

  defineIntent({
    name: 'tiktok.campaign_create',
    effect: 'write',
    description:
      'Create a new campaign for a specific advertiser. Binds POST /open_api/v1.3/campaign/create/ with body.advertiser_id pinned.',
    params: z.object({ advertiser_id: idList }),
    expand: ({ advertiser_id }) => [
      { path: 'url.host', op: 'eq', value: 'business-api.tiktok.com' },
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/open_api/v1.3/campaign/create/' },
      eqOrIn('body.advertiser_id', advertiser_id),
    ],
  }),

  defineIntent({
    name: 'tiktok.campaign_update',
    effect: 'write',
    description:
      'Update campaign fields for a specific advertiser. Binds POST /open_api/v1.3/campaign/update/ with body.advertiser_id pinned.',
    params: z.object({ advertiser_id: idList }),
    expand: ({ advertiser_id }) => [
      { path: 'url.host', op: 'eq', value: 'business-api.tiktok.com' },
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/open_api/v1.3/campaign/update/' },
      eqOrIn('body.advertiser_id', advertiser_id),
    ],
  }),

  defineIntent({
    name: 'tiktok.adgroup_create',
    effect: 'write',
    description:
      'Create an ad group for a specific advertiser. Binds POST /open_api/v1.3/adgroup/create/ with body.advertiser_id pinned.',
    params: z.object({ advertiser_id: idList }),
    expand: ({ advertiser_id }) => [
      { path: 'url.host', op: 'eq', value: 'business-api.tiktok.com' },
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/open_api/v1.3/adgroup/create/' },
      eqOrIn('body.advertiser_id', advertiser_id),
    ],
  }),

  defineIntent({
    name: 'tiktok.ad_create',
    effect: 'write',
    description:
      'Create an ad for a specific advertiser. Binds POST /open_api/v1.3/ad/create/ with body.advertiser_id pinned.',
    params: z.object({ advertiser_id: idList }),
    expand: ({ advertiser_id }) => [
      { path: 'url.host', op: 'eq', value: 'business-api.tiktok.com' },
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/open_api/v1.3/ad/create/' },
      eqOrIn('body.advertiser_id', advertiser_id),
    ],
  }),

  defineIntent({
    name: 'tiktok.ad_update_status',
    effect: 'write',
    description:
      'Enable, pause, or delete ads for a specific advertiser. Binds POST /open_api/v1.3/ad/status/update/ with body.advertiser_id pinned.',
    params: z.object({ advertiser_id: idList }),
    expand: ({ advertiser_id }) => [
      { path: 'url.host', op: 'eq', value: 'business-api.tiktok.com' },
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/open_api/v1.3/ad/status/update/' },
      eqOrIn('body.advertiser_id', advertiser_id),
    ],
  }),

  defineIntent({
    name: 'tiktok.report_integrated',
    effect: 'read',
    description:
      'Fetch integrated ad performance reports for a specific advertiser. Binds GET /open_api/v1.3/report/integrated/get/ with query.advertiser_id pinned.',
    params: z.object({ advertiser_id: idList }),
    expand: ({ advertiser_id }) => [
      { path: 'url.host', op: 'eq', value: 'business-api.tiktok.com' },
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/open_api/v1.3/report/integrated/get/' },
      eqOrIn('query.advertiser_id', advertiser_id),
    ],
  }),
];
