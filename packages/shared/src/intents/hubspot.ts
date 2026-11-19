import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// HubSpot CRM v3 — https://developers.hubspot.com/docs/api/crm. Base:
// api.hubapi.com/crm/v3/objects/{type}. Intents gate on method +
// pathname — no per-record binding at v1 (record IDs assigned by HubSpot).

export const hubspotIntents = [
  defineIntent({
    name: 'hubspot.create_contact',
    effect: 'write',
    description:
      'Create a new HubSpot contact. Binds POST /crm/v3/objects/contacts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/crm/v3/objects/contacts' },
    ],
  }),

  defineIntent({
    name: 'hubspot.update_contact',
    effect: 'write',
    description:
      'Update an existing HubSpot contact. Binds PATCH /crm/v3/objects/contacts/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/crm/v3/objects/contacts/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'hubspot.create_deal',
    effect: 'write',
    description:
      'Create a new HubSpot deal. Binds POST /crm/v3/objects/deals.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/crm/v3/objects/deals' },
    ],
  }),

  defineIntent({
    name: 'hubspot.read_contacts',
    effect: 'read',
    description:
      'Read-only access to HubSpot contacts. Binds GET /crm/v3/objects/contacts and /crm/v3/objects/contacts/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/crm/v3/objects/contacts(/[^/]+)?$',
      },
    ],
  }),

  defineIntent({
    name: 'hubspot.delete_contact',
    effect: 'destructive',
    description:
      'Archive (soft-delete) a HubSpot contact. Binds DELETE /crm/v3/objects/contacts/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/crm/v3/objects/contacts/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'hubspot.search_contacts',
    effect: 'read',
    description:
      'Search HubSpot contacts with filter groups. Binds POST /crm/v3/objects/contacts/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/crm/v3/objects/contacts/search' },
    ],
  }),

  defineIntent({
    name: 'hubspot.batch_upsert_contacts',
    effect: 'write',
    description:
      'Batch upsert HubSpot contacts by unique property. Binds POST /crm/v3/objects/contacts/batch/upsert.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/crm/v3/objects/contacts/batch/upsert' },
    ],
  }),

  defineIntent({
    name: 'hubspot.create_company',
    effect: 'write',
    description:
      'Create a new HubSpot company. Binds POST /crm/v3/objects/companies.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/crm/v3/objects/companies' },
    ],
  }),

  defineIntent({
    name: 'hubspot.update_company',
    effect: 'write',
    description:
      'Update an existing HubSpot company. Binds PATCH /crm/v3/objects/companies/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/crm/v3/objects/companies/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'hubspot.read_companies',
    effect: 'read',
    description:
      'Read-only access to HubSpot companies. Binds GET /crm/v3/objects/companies and /crm/v3/objects/companies/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/crm/v3/objects/companies(/[^/]+)?$',
      },
    ],
  }),

  defineIntent({
    name: 'hubspot.update_deal',
    effect: 'write',
    description:
      'Update an existing HubSpot deal. Binds PATCH /crm/v3/objects/deals/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/crm/v3/objects/deals/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'hubspot.read_deals',
    effect: 'read',
    description:
      'Read-only access to HubSpot deals. Binds GET /crm/v3/objects/deals and /crm/v3/objects/deals/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/crm/v3/objects/deals(/[^/]+)?$',
      },
    ],
  }),

  defineIntent({
    name: 'hubspot.search_deals',
    effect: 'read',
    description:
      'Search HubSpot deals with filter groups. Binds POST /crm/v3/objects/deals/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/crm/v3/objects/deals/search' },
    ],
  }),

  defineIntent({
    name: 'hubspot.associate_objects',
    effect: 'write',
    description:
      'Create an association between two CRM objects (e.g. contact to company). Binds PUT /crm/v3/objects/{fromType}/{fromId}/associations/{toType}/{toId}/{assocType}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/crm/v3/objects/[^/]+/[^/]+/associations/[^/]+/[^/]+/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'hubspot.create_ticket',
    effect: 'write',
    description:
      'Create a new HubSpot support ticket. Binds POST /crm/v3/objects/tickets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/crm/v3/objects/tickets' },
    ],
  }),

  defineIntent({
    name: 'hubspot.update_ticket',
    effect: 'write',
    description:
      'Update an existing HubSpot ticket. Binds PATCH /crm/v3/objects/tickets/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/crm/v3/objects/tickets/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'hubspot.create_note',
    effect: 'write',
    description:
      'Create a HubSpot note engagement. Binds POST /crm/v3/objects/notes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/crm/v3/objects/notes' },
    ],
  }),

  defineIntent({
    name: 'hubspot.list_owners',
    effect: 'read',
    description:
      'List HubSpot CRM owners (users who can own records). Binds GET /crm/v3/owners.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/crm/v3/owners(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'hubspot.list_pipelines',
    effect: 'read',
    description:
      'List HubSpot deal or ticket pipelines. Binds GET /crm/v3/pipelines/{objectType}.',
    params: z.object({
      object_type: z.enum(['deals', 'tickets']).optional(),
    }),
    expand: (p) => {
      const constraints: Constraint[] = [
        { path: 'method', op: 'eq', value: 'GET' },
      ];
      if (p.object_type) {
        constraints.push({
          path: 'url.pathname',
          op: 'matches',
          value: `^/crm/v3/pipelines/${p.object_type}(/[^/]+)?$`,
        });
      } else {
        constraints.push({
          path: 'url.pathname',
          op: 'matches',
          value: '^/crm/v3/pipelines/[^/]+(/[^/]+)?$',
        });
      }
      return constraints;
    },
  }),

  defineIntent({
    name: 'hubspot.send_marketing_email',
    effect: 'send',
    recipient_paths: ['body.message.to', 'body.message.cc', 'body.message.bcc'],
    description:
      'Send a single transactional marketing email via HubSpot. Binds POST /marketing/v3/transactional/single-email/send.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/marketing/v3/transactional/single-email/send' },
    ],
  }),

  defineIntent({
    name: 'hubspot.read_products',
    effect: 'read',
    description:
      'Read-only access to the HubSpot product library. Binds GET /crm/v3/objects/products and /crm/v3/objects/products/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/crm/v3/objects/products(/[^/]+)?$',
      },
    ],
  }),
];
