import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Salesforce REST API — https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/.
// Base host is per-org (e.g. https://acme.my.salesforce.com). Intents gate
// on method + pathname against the versioned /services/data/v{n}/ prefix.
// API version is captured as a single path segment `v\d+\.\d+` so the
// catalog survives minor version bumps without needing per-version intents.

const VERSION = 'v[0-9]+\\.[0-9]+';

export const salesforceIntents = [
  defineIntent({
    name: 'salesforce.create_account',
    effect: 'write',
    description:
      'Create a Salesforce Account record. Binds POST /services/data/v*/sobjects/Account.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/sobjects/Account$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.update_account',
    effect: 'write',
    description:
      'Update an existing Salesforce Account record. Binds PATCH /services/data/v*/sobjects/Account/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/sobjects/Account/[^/]+$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.read_accounts',
    effect: 'read',
    description:
      'Retrieve Salesforce Account records. Binds GET /services/data/v*/sobjects/Account/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/sobjects/Account(/[^/]+)?$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.create_contact',
    effect: 'write',
    description:
      'Create a Salesforce Contact record. Binds POST /services/data/v*/sobjects/Contact.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/sobjects/Contact$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.update_contact',
    effect: 'write',
    description:
      'Update an existing Salesforce Contact record. Binds PATCH /services/data/v*/sobjects/Contact/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/sobjects/Contact/[^/]+$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.create_lead',
    effect: 'write',
    description:
      'Create a Salesforce Lead record. Binds POST /services/data/v*/sobjects/Lead.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/sobjects/Lead$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.update_lead',
    effect: 'write',
    description:
      'Update an existing Salesforce Lead record. Binds PATCH /services/data/v*/sobjects/Lead/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/sobjects/Lead/[^/]+$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.convert_lead',
    effect: 'write',
    description:
      'Convert a Salesforce Lead into Account, Contact, and Opportunity via the built-in Apex action. Binds POST /services/data/v*/actions/standard/convertLead.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/actions/standard/convertLead$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.create_opportunity',
    effect: 'write',
    description:
      'Create a Salesforce Opportunity record. Binds POST /services/data/v*/sobjects/Opportunity.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/sobjects/Opportunity$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.update_opportunity_stage',
    effect: 'write',
    description:
      'Update an Opportunity (typically StageName) via PATCH. Binds PATCH /services/data/v*/sobjects/Opportunity/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/sobjects/Opportunity/[^/]+$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.create_case',
    effect: 'write',
    description:
      'Create a Salesforce Case record. Binds POST /services/data/v*/sobjects/Case.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/sobjects/Case$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.close_case',
    effect: 'write',
    description:
      'Close or update a Salesforce Case (typically Status=Closed). Binds PATCH /services/data/v*/sobjects/Case/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/sobjects/Case/[^/]+$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.create_task',
    effect: 'write',
    description:
      'Create a Salesforce Task activity. Binds POST /services/data/v*/sobjects/Task.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/sobjects/Task$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.create_event',
    effect: 'write',
    description:
      'Create a Salesforce Event (calendar activity). Binds POST /services/data/v*/sobjects/Event.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/sobjects/Event$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.run_soql_query',
    effect: 'read',
    description:
      'Execute a SOQL query. Binds GET /services/data/v*/query. Query string is in ?q= and is not constrained by this intent.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/query$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.run_report',
    effect: 'read',
    description:
      'Execute a Salesforce Analytics report synchronously. Binds GET /services/data/v*/analytics/reports/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/analytics/reports/[^/]+$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.read_dashboards',
    effect: 'read',
    description:
      'Read Salesforce Analytics dashboards. Binds GET /services/data/v*/analytics/dashboards and /analytics/dashboards/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/analytics/dashboards(/[^/]+)?$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.post_chatter_feed',
    effect: 'write',
    description:
      'Post a Chatter feed item (e.g. to a record or group). Binds POST /services/data/v*/chatter/feed-elements.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/chatter/feed-elements$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.upload_content',
    effect: 'write',
    description:
      'Create a ContentVersion (file upload) in Salesforce Files. Binds POST /services/data/v*/sobjects/ContentVersion.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/services/data/${VERSION}/sobjects/ContentVersion$`,
      },
    ],
  }),

  defineIntent({
    name: 'salesforce.create_custom_object_record',
    effect: 'write',
    description:
      'Create a record on any custom sObject (names end with __c). Binds POST /services/data/v*/sobjects/{Object__c}.',
    params: z.object({
      object_name: z
        .string()
        .regex(/^[A-Za-z0-9_]+__c$/)
        .optional(),
    }),
    expand: (p) => {
      const constraints: Constraint[] = [
        { path: 'method', op: 'eq', value: 'POST' },
      ];
      if (p.object_name) {
        constraints.push({
          path: 'url.pathname',
          op: 'matches',
          value: `^/services/data/${VERSION}/sobjects/${p.object_name}$`,
        });
      } else {
        constraints.push({
          path: 'url.pathname',
          op: 'matches',
          value: `^/services/data/${VERSION}/sobjects/[A-Za-z0-9_]+__c$`,
        });
      }
      return constraints;
    },
  }),
];
