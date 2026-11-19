import { z } from 'zod';
import { defineIntent } from './types.js';

// Typeform API — https://www.typeform.com/developers/create/reference/.
// All calls go to api.typeform.com/…. Form IDs and workspace IDs are
// allowlisted on the path where relevant.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);
const esc = (s: string) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&');
const alt = (list: string[]) => (list.length === 1 ? esc(list[0]!) : `(${list.map(esc).join('|')})`);

export const typeformIntents = [
  defineIntent({
    name: 'typeform.list_forms',
    effect: 'read',
    description:
      'List forms available to the token. Binds GET /forms.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/forms' },
    ],
  }),

  defineIntent({
    name: 'typeform.create_form',
    effect: 'write',
    description:
      'Create a new form. Binds POST /forms.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/forms' },
    ],
  }),

  defineIntent({
    name: 'typeform.get_form',
    effect: 'read',
    description:
      'Read a specific form definition. Binds GET /forms/{form_id} to the declared form allowlist.',
    params: z.object({ form_id: idList }),
    expand: ({ form_id }) => {
      const list = toList(form_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/forms/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'typeform.update_form',
    effect: 'write',
    description:
      'Replace a specific form definition. Binds PUT /forms/{form_id}.',
    params: z.object({ form_id: idList }),
    expand: ({ form_id }) => {
      const list = toList(form_id);
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.pathname', op: 'matches', value: `^/forms/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'typeform.patch_form',
    effect: 'write',
    description:
      'Patch fields on a specific form definition. Binds PATCH /forms/{form_id}.',
    params: z.object({ form_id: idList }),
    expand: ({ form_id }) => {
      const list = toList(form_id);
      return [
        { path: 'method', op: 'eq', value: 'PATCH' },
        { path: 'url.pathname', op: 'matches', value: `^/forms/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'typeform.delete_form',
    effect: 'destructive',
    description:
      'Delete a specific form. Binds DELETE /forms/{form_id}. Destructive.',
    params: z.object({ form_id: idList }),
    expand: ({ form_id }) => {
      const list = toList(form_id);
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.pathname', op: 'matches', value: `^/forms/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'typeform.list_responses',
    effect: 'read',
    description:
      'List responses for a specific form. Binds GET /forms/{form_id}/responses.',
    params: z.object({ form_id: idList }),
    expand: ({ form_id }) => {
      const list = toList(form_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/forms/${alt(list)}/responses$` },
      ];
    },
  }),

  defineIntent({
    name: 'typeform.delete_responses',
    effect: 'destructive',
    description:
      'Delete responses from a specific form. Binds DELETE /forms/{form_id}/responses. Destructive.',
    params: z.object({ form_id: idList }),
    expand: ({ form_id }) => {
      const list = toList(form_id);
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.pathname', op: 'matches', value: `^/forms/${alt(list)}/responses$` },
      ];
    },
  }),

  defineIntent({
    name: 'typeform.list_webhooks',
    effect: 'read',
    description:
      'List webhooks registered on a specific form. Binds GET /forms/{form_id}/webhooks.',
    params: z.object({ form_id: idList }),
    expand: ({ form_id }) => {
      const list = toList(form_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/forms/${alt(list)}/webhooks$` },
      ];
    },
  }),

  defineIntent({
    name: 'typeform.create_webhook',
    effect: 'write',
    description:
      'Create or replace a tagged webhook on a specific form. Binds PUT /forms/{form_id}/webhooks/{tag}.',
    params: z.object({ form_id: idList }),
    expand: ({ form_id }) => {
      const list = toList(form_id);
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.pathname', op: 'matches', value: `^/forms/${alt(list)}/webhooks/[^/]+$` },
      ];
    },
  }),

  defineIntent({
    name: 'typeform.delete_webhook',
    effect: 'destructive',
    description:
      'Delete a tagged webhook on a specific form. Binds DELETE /forms/{form_id}/webhooks/{tag}.',
    params: z.object({ form_id: idList }),
    expand: ({ form_id }) => {
      const list = toList(form_id);
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.pathname', op: 'matches', value: `^/forms/${alt(list)}/webhooks/[^/]+$` },
      ];
    },
  }),

  defineIntent({
    name: 'typeform.list_webhook_deliveries',
    effect: 'read',
    description:
      'List recent webhook delivery attempts for a specific form + tag. Binds GET /forms/{form_id}/webhooks/{tag}/deliveries.',
    params: z.object({ form_id: idList }),
    expand: ({ form_id }) => {
      const list = toList(form_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/forms/${alt(list)}/webhooks/[^/]+/deliveries$` },
      ];
    },
  }),

  defineIntent({
    name: 'typeform.form_insights',
    effect: 'read',
    description:
      'Fetch insights / summary metrics for a specific form. Binds GET /insights/{form_id}/summary.',
    params: z.object({ form_id: idList }),
    expand: ({ form_id }) => {
      const list = toList(form_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/insights/${alt(list)}/summary$` },
      ];
    },
  }),

  defineIntent({
    name: 'typeform.list_workspaces',
    effect: 'read',
    description:
      'List workspaces available to the token. Binds GET /workspaces.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/workspaces' },
    ],
  }),

  defineIntent({
    name: 'typeform.create_workspace',
    effect: 'write',
    description:
      'Create a new workspace. Binds POST /workspaces.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/workspaces' },
    ],
  }),

  defineIntent({
    name: 'typeform.list_images',
    effect: 'read',
    description:
      'List uploaded images in the account. Binds GET /images.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/images' },
    ],
  }),

  defineIntent({
    name: 'typeform.upload_image',
    effect: 'write',
    description:
      'Upload a new image. Binds POST /images.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/images' },
    ],
  }),

  defineIntent({
    name: 'typeform.list_themes',
    effect: 'read',
    description:
      'List form themes in the account. Binds GET /themes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/themes' },
    ],
  }),

  defineIntent({
    name: 'typeform.create_theme',
    effect: 'write',
    description:
      'Create a new form theme. Binds POST /themes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/themes' },
    ],
  }),

  defineIntent({
    name: 'typeform.get_me',
    effect: 'read',
    description:
      'Read the authenticated Typeform account. Binds GET /me.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/me' },
    ],
  }),
];
