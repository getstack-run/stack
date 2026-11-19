import { z } from 'zod';
import { defineIntent } from './types.js';

// Loom (Atlassian) does NOT publish a general-purpose public REST API
// as of 2026. The only developer-facing surface is:
//   - Record SDK + Embed SDK (client-side JS, not proxy-relevant)
//   - oEmbed endpoint at https://www.loom.com/v1/oembed (standard
//     oEmbed spec, follows the RFC discovery contract).
// Reference: https://dev.loom.com/
//
// We previously shipped 14 intents targeting a /v1/videos, /v1/folders
// REST surface that is not documented. Those were removed because the
// paths don't exist; leaving them would have resulted in guaranteed
// 404s at the proxy. The catalog now reflects what's actually
// reachable: oEmbed metadata fetches.

export const loomIntents = [
  defineIntent({
    name: 'loom.oembed_video',
    effect: 'read',
    description:
      'Fetch oEmbed metadata (embed HTML, thumbnail, title, duration) for a public Loom video URL. Binds GET /v1/oembed with a url query param carrying the Loom video URL.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'www.loom.com' },
      { path: 'url.pathname', op: 'eq', value: '/v1/oembed' },
    ],
  }),
];
