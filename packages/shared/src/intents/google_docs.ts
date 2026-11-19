import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Google Docs API v1 — https://developers.google.com/docs/api.
// All operations live at docs.googleapis.com/v1/documents/{id}. Most
// edits flow through a single batchUpdate endpoint whose body carries a
// `requests` array; intents scope both the document and the request type.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function docAlt(ids: IdList): string {
  const list = toList(ids);
  const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  return list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
}

function docPath(ids: IdList, suffix: string): Constraint {
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v1/documents/${docAlt(ids)}${suffix}$`,
  };
}

export const googleDocsIntents = [
  defineIntent({
    name: 'google_docs.get_document',
    effect: 'read',
    description:
      'Read the content and structure of specific Google Docs. Binds GET /v1/documents/{id} to the declared document allowlist.',
    params: z.object({ document_id: idList }),
    expand: ({ document_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      docPath(document_id, ''),
    ],
  }),

  defineIntent({
    name: 'google_docs.create_document',
    effect: 'write',
    description:
      'Create a new blank document owned by the authenticated user. Binds POST /v1/documents.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/documents' },
    ],
  }),

  defineIntent({
    name: 'google_docs.batch_update',
    effect: 'write',
    description:
      'Apply any batchUpdate request to specific documents. Binds POST /v1/documents/{id}:batchUpdate to the declared document allowlist.',
    params: z.object({ document_id: idList }),
    expand: ({ document_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      docPath(document_id, ':batchUpdate'),
    ],
  }),

  defineIntent({
    name: 'google_docs.insert_text',
    effect: 'write',
    description:
      'Insert text into specific documents. Binds POST /v1/documents/{id}:batchUpdate with body.requests.0.insertText pinned.',
    params: z.object({ document_id: idList }),
    expand: ({ document_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      docPath(document_id, ':batchUpdate'),
      { path: 'body.requests.0.insertText', op: 'not_eq', value: '' },
    ],
  }),

  defineIntent({
    name: 'google_docs.delete_content',
    effect: 'destructive',
    description:
      'Delete a content range in specific documents. Binds POST /v1/documents/{id}:batchUpdate with body.requests.0.deleteContentRange pinned. Destructive.',
    params: z.object({ document_id: idList }),
    expand: ({ document_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      docPath(document_id, ':batchUpdate'),
      { path: 'body.requests.0.deleteContentRange', op: 'not_eq', value: '' },
    ],
  }),

  defineIntent({
    name: 'google_docs.replace_all_text',
    effect: 'write',
    description:
      'Perform find-and-replace across specific documents. Binds POST /v1/documents/{id}:batchUpdate with body.requests.0.replaceAllText pinned.',
    params: z.object({ document_id: idList }),
    expand: ({ document_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      docPath(document_id, ':batchUpdate'),
      { path: 'body.requests.0.replaceAllText', op: 'not_eq', value: '' },
    ],
  }),

  defineIntent({
    name: 'google_docs.update_text_style',
    effect: 'write',
    description:
      'Update character formatting in specific documents. Binds POST /v1/documents/{id}:batchUpdate with body.requests.0.updateTextStyle pinned.',
    params: z.object({ document_id: idList }),
    expand: ({ document_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      docPath(document_id, ':batchUpdate'),
      { path: 'body.requests.0.updateTextStyle', op: 'not_eq', value: '' },
    ],
  }),

  defineIntent({
    name: 'google_docs.update_paragraph_style',
    effect: 'write',
    description:
      'Update paragraph formatting in specific documents. Binds POST /v1/documents/{id}:batchUpdate with body.requests.0.updateParagraphStyle pinned.',
    params: z.object({ document_id: idList }),
    expand: ({ document_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      docPath(document_id, ':batchUpdate'),
      { path: 'body.requests.0.updateParagraphStyle', op: 'not_eq', value: '' },
    ],
  }),

  defineIntent({
    name: 'google_docs.insert_table',
    effect: 'write',
    description:
      'Insert a table into specific documents. Binds POST /v1/documents/{id}:batchUpdate with body.requests.0.insertTable pinned.',
    params: z.object({ document_id: idList }),
    expand: ({ document_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      docPath(document_id, ':batchUpdate'),
      { path: 'body.requests.0.insertTable', op: 'not_eq', value: '' },
    ],
  }),

  defineIntent({
    name: 'google_docs.insert_table_row',
    effect: 'write',
    description:
      'Insert a new row into an existing table in specific documents. Binds POST /v1/documents/{id}:batchUpdate with body.requests.0.insertTableRow pinned.',
    params: z.object({ document_id: idList }),
    expand: ({ document_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      docPath(document_id, ':batchUpdate'),
      { path: 'body.requests.0.insertTableRow', op: 'not_eq', value: '' },
    ],
  }),

  defineIntent({
    name: 'google_docs.insert_page_break',
    effect: 'write',
    description:
      'Insert a page break in specific documents. Binds POST /v1/documents/{id}:batchUpdate with body.requests.0.insertPageBreak pinned.',
    params: z.object({ document_id: idList }),
    expand: ({ document_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      docPath(document_id, ':batchUpdate'),
      { path: 'body.requests.0.insertPageBreak', op: 'not_eq', value: '' },
    ],
  }),

  defineIntent({
    name: 'google_docs.insert_inline_image',
    effect: 'write',
    description:
      'Insert an inline image into specific documents. Binds POST /v1/documents/{id}:batchUpdate with body.requests.0.insertInlineImage pinned.',
    params: z.object({ document_id: idList }),
    expand: ({ document_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      docPath(document_id, ':batchUpdate'),
      { path: 'body.requests.0.insertInlineImage', op: 'not_eq', value: '' },
    ],
  }),

  defineIntent({
    name: 'google_docs.create_named_range',
    effect: 'write',
    description:
      'Create a named range in specific documents. Binds POST /v1/documents/{id}:batchUpdate with body.requests.0.createNamedRange pinned.',
    params: z.object({ document_id: idList }),
    expand: ({ document_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      docPath(document_id, ':batchUpdate'),
      { path: 'body.requests.0.createNamedRange', op: 'not_eq', value: '' },
    ],
  }),

  defineIntent({
    name: 'google_docs.delete_named_range',
    effect: 'destructive',
    description:
      'Delete a named range in specific documents. Binds POST /v1/documents/{id}:batchUpdate with body.requests.0.deleteNamedRange pinned. Destructive.',
    params: z.object({ document_id: idList }),
    expand: ({ document_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      docPath(document_id, ':batchUpdate'),
      { path: 'body.requests.0.deleteNamedRange', op: 'not_eq', value: '' },
    ],
  }),

  defineIntent({
    name: 'google_docs.create_header',
    effect: 'write',
    description:
      'Create a document header in specific documents. Binds POST /v1/documents/{id}:batchUpdate with body.requests.0.createHeader pinned.',
    params: z.object({ document_id: idList }),
    expand: ({ document_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      docPath(document_id, ':batchUpdate'),
      { path: 'body.requests.0.createHeader', op: 'not_eq', value: '' },
    ],
  }),

  defineIntent({
    name: 'google_docs.create_footer',
    effect: 'write',
    description:
      'Create a document footer in specific documents. Binds POST /v1/documents/{id}:batchUpdate with body.requests.0.createFooter pinned.',
    params: z.object({ document_id: idList }),
    expand: ({ document_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      docPath(document_id, ':batchUpdate'),
      { path: 'body.requests.0.createFooter', op: 'not_eq', value: '' },
    ],
  }),
];
