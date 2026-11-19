import { z } from 'zod';
import { defineIntent } from './types.js';

// LinkedIn API - https://learn.microsoft.com/en-us/linkedin/. Calls hit
// api.linkedin.com/v2/… (classic) and api.linkedin.com/rest/… (Versioned
// REST). Shares use /ugcPosts; profile actions use /me. Intents gate on
// method + path shape.

export const linkedinIntents = [
  defineIntent({
    name: 'linkedin.create_ugc_post',
    effect: 'send',
    description:
      'Create a share (text, article, or media) as the authenticated member or organization. Binds POST /v2/ugcPosts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/ugcPosts' },
    ],
  }),

  defineIntent({
    name: 'linkedin.get_ugc_post',
    effect: 'read',
    description:
      'Fetch a UGC post by URN. Binds GET /v2/ugcPosts/{urn}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/ugcPosts/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'linkedin.delete_ugc_post',
    effect: 'destructive',
    description:
      'Delete a previously published UGC post. Binds DELETE /v2/ugcPosts/{urn} - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/ugcPosts/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'linkedin.create_post',
    effect: 'send',
    description:
      'Create a post via the Versioned Posts API. Binds POST /rest/posts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/rest/posts' },
    ],
  }),

  defineIntent({
    name: 'linkedin.get_me',
    effect: 'read',
    description:
      'Fetch the authenticated member\'s profile (legacy). Binds GET /v2/me. Deprecated for new OIDC apps; use linkedin.get_userinfo instead.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/me' },
    ],
  }),

  defineIntent({
    name: 'linkedin.get_userinfo',
    effect: 'read',
    description:
      'Fetch the authenticated member\'s OpenID Connect user info. Binds GET /v2/userinfo. Preferred over get_me for new OIDC apps.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/userinfo' },
    ],
  }),

  defineIntent({
    name: 'linkedin.search_organizations',
    effect: 'read',
    description:
      'Search organizations (company pages) by name. Binds GET /v2/organizations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/organizations' },
    ],
  }),

  defineIntent({
    name: 'linkedin.list_organization_acls',
    effect: 'read',
    description:
      'List ACL roles on organizations the member can administer. Binds GET /v2/organizationAcls.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/organizationAcls' },
    ],
  }),

  defineIntent({
    name: 'linkedin.list_comments',
    effect: 'read',
    description:
      'List comments on a social object (post, article, comment). Binds GET /v2/socialActions/{urn}/comments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/socialActions/[^/]+/comments$' },
    ],
  }),

  defineIntent({
    name: 'linkedin.create_comment',
    effect: 'send',
    recipient_paths: ['url.pathname'],
    description:
      'Post a comment on a social object. Binds POST /v2/socialActions/{urn}/comments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/socialActions/[^/]+/comments$' },
    ],
  }),

  defineIntent({
    name: 'linkedin.list_likes',
    effect: 'read',
    description:
      'List likes on a social object. Binds GET /v2/socialActions/{urn}/likes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/socialActions/[^/]+/likes$' },
    ],
  }),

  defineIntent({
    name: 'linkedin.create_like',
    effect: 'write',
    description:
      'Like a social object. Binds POST /v2/socialActions/{urn}/likes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/socialActions/[^/]+/likes$' },
    ],
  }),

  defineIntent({
    name: 'linkedin.send_message',
    effect: 'send',
    recipient_paths: ['body.recipients'],
    description:
      'Send a member-to-member message via the Messages API. Binds POST /v2/messages.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/messages' },
    ],
  }),

  defineIntent({
    name: 'linkedin.list_invitations',
    effect: 'read',
    description:
      'List connection invitations sent or received. Binds GET /v2/invitations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/invitations' },
    ],
  }),

  defineIntent({
    name: 'linkedin.send_invitation',
    effect: 'send',
    description:
      'Send a connection invitation. Binds POST /v2/invitations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/invitations' },
    ],
  }),

  defineIntent({
    name: 'linkedin.list_ad_campaign_groups',
    effect: 'read',
    description:
      'List ad campaign groups the member can manage. Binds GET /rest/adCampaignGroups.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/rest/adCampaignGroups' },
    ],
  }),

  defineIntent({
    name: 'linkedin.create_ad_campaign_group',
    effect: 'write',
    description:
      'Create a new ad campaign group. Binds POST /rest/adCampaignGroups.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/rest/adCampaignGroups' },
    ],
  }),

  defineIntent({
    name: 'linkedin.list_ad_campaigns',
    effect: 'read',
    description:
      'List ad campaigns the member can manage. Binds GET /rest/adCampaigns.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/rest/adCampaigns' },
    ],
  }),

  defineIntent({
    name: 'linkedin.create_ad_campaign',
    effect: 'write',
    description:
      'Create a new ad campaign. Binds POST /rest/adCampaigns.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/rest/adCampaigns' },
    ],
  }),

  defineIntent({
    name: 'linkedin.read_organization_statistics',
    effect: 'read',
    description:
      'Read follower + engagement statistics for an organization page. Binds GET /v2/organizationPageStatistics.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/organizationPageStatistics' },
    ],
  }),
];
