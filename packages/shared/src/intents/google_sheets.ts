import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Google Sheets API v4 — https://developers.google.com/sheets/api.
// All operations live at sheets.googleapis.com/v4/spreadsheets/{id}…;
// intents scope on spreadsheetId and bind specific verbs.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function sheetAlt(ids: IdList): string {
  const list = toList(ids);
  const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  return list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
}

function sheetPath(ids: IdList, suffix: string): Constraint {
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v4/spreadsheets/${sheetAlt(ids)}${suffix}$`,
  };
}

export const googleSheetsIntents = [
  defineIntent({
    name: 'google_sheets.get_spreadsheet',
    effect: 'read',
    description:
      'Read spreadsheet metadata and structure for specific spreadsheets. Binds GET /v4/spreadsheets/{id}.',
    params: z.object({ spreadsheet_id: idList }),
    expand: ({ spreadsheet_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      sheetPath(spreadsheet_id, ''),
    ],
  }),

  defineIntent({
    name: 'google_sheets.create_spreadsheet',
    effect: 'write',
    description:
      'Create a new spreadsheet owned by the authenticated user. Binds POST /v4/spreadsheets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v4/spreadsheets' },
    ],
  }),

  defineIntent({
    name: 'google_sheets.get_values',
    effect: 'read',
    description:
      'Read cell values from a specific range in specific spreadsheets. Binds GET /v4/spreadsheets/{id}/values/{range}.',
    params: z.object({ spreadsheet_id: idList }),
    expand: ({ spreadsheet_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      sheetPath(spreadsheet_id, '/values/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'google_sheets.update_values',
    effect: 'write',
    description:
      'Overwrite cell values in a specific range in specific spreadsheets. Binds PUT /v4/spreadsheets/{id}/values/{range}.',
    params: z.object({ spreadsheet_id: idList }),
    expand: ({ spreadsheet_id }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      sheetPath(spreadsheet_id, '/values/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'google_sheets.append_values',
    effect: 'write',
    description:
      'Append rows to a specific range in specific spreadsheets. Binds POST /v4/spreadsheets/{id}/values/{range}:append.',
    params: z.object({ spreadsheet_id: idList }),
    expand: ({ spreadsheet_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sheetPath(spreadsheet_id, '/values/[^/]+:append'),
    ],
  }),

  defineIntent({
    name: 'google_sheets.clear_values',
    effect: 'write',
    description:
      'Clear cell values in a specific range in specific spreadsheets. Binds POST /v4/spreadsheets/{id}/values/{range}:clear. Destructive.',
    params: z.object({ spreadsheet_id: idList }),
    expand: ({ spreadsheet_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sheetPath(spreadsheet_id, '/values/[^/]+:clear'),
    ],
  }),

  defineIntent({
    name: 'google_sheets.batch_get_values',
    effect: 'read',
    description:
      'Read multiple ranges from specific spreadsheets in one call. Binds GET /v4/spreadsheets/{id}/values:batchGet.',
    params: z.object({ spreadsheet_id: idList }),
    expand: ({ spreadsheet_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      sheetPath(spreadsheet_id, '/values:batchGet'),
    ],
  }),

  defineIntent({
    name: 'google_sheets.batch_update_values',
    effect: 'write',
    description:
      'Update multiple ranges in specific spreadsheets in one call. Binds POST /v4/spreadsheets/{id}/values:batchUpdate.',
    params: z.object({ spreadsheet_id: idList }),
    expand: ({ spreadsheet_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sheetPath(spreadsheet_id, '/values:batchUpdate'),
    ],
  }),

  defineIntent({
    name: 'google_sheets.batch_clear_values',
    effect: 'write',
    description:
      'Clear multiple ranges in specific spreadsheets in one call. Binds POST /v4/spreadsheets/{id}/values:batchClear. Destructive.',
    params: z.object({ spreadsheet_id: idList }),
    expand: ({ spreadsheet_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sheetPath(spreadsheet_id, '/values:batchClear'),
    ],
  }),

  defineIntent({
    name: 'google_sheets.batch_update_spreadsheet',
    effect: 'write',
    description:
      'Apply structural spreadsheet changes (add sheets, formatting, charts, etc.) in specific spreadsheets. Binds POST /v4/spreadsheets/{id}:batchUpdate.',
    params: z.object({ spreadsheet_id: idList }),
    expand: ({ spreadsheet_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sheetPath(spreadsheet_id, ':batchUpdate'),
    ],
  }),

  defineIntent({
    name: 'google_sheets.copy_sheet_to',
    effect: 'write',
    description:
      'Copy a single sheet tab from one spreadsheet to another. Binds POST /v4/spreadsheets/{id}/sheets/{sheetId}:copyTo.',
    params: z.object({ spreadsheet_id: idList }),
    expand: ({ spreadsheet_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sheetPath(spreadsheet_id, '/sheets/\\d+:copyTo'),
    ],
  }),

  defineIntent({
    name: 'google_sheets.get_by_data_filter',
    effect: 'read',
    description:
      'Fetch sheet metadata using DataFilter selectors. Binds POST /v4/spreadsheets/{id}:getByDataFilter.',
    params: z.object({ spreadsheet_id: idList }),
    expand: ({ spreadsheet_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sheetPath(spreadsheet_id, ':getByDataFilter'),
    ],
  }),

  defineIntent({
    name: 'google_sheets.get_values_by_data_filter',
    effect: 'read',
    description:
      'Read cell values matching DataFilter selectors across specific spreadsheets. Binds POST /v4/spreadsheets/{id}/values:batchGetByDataFilter.',
    params: z.object({ spreadsheet_id: idList }),
    expand: ({ spreadsheet_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sheetPath(spreadsheet_id, '/values:batchGetByDataFilter'),
    ],
  }),

  defineIntent({
    name: 'google_sheets.update_values_by_data_filter',
    effect: 'write',
    description:
      'Update cell values matching DataFilter selectors across specific spreadsheets. Binds POST /v4/spreadsheets/{id}/values:batchUpdateByDataFilter.',
    params: z.object({ spreadsheet_id: idList }),
    expand: ({ spreadsheet_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sheetPath(spreadsheet_id, '/values:batchUpdateByDataFilter'),
    ],
  }),

  defineIntent({
    name: 'google_sheets.clear_values_by_data_filter',
    effect: 'write',
    description:
      'Clear cell values matching DataFilter selectors across specific spreadsheets. Binds POST /v4/spreadsheets/{id}/values:batchClearByDataFilter. Destructive.',
    params: z.object({ spreadsheet_id: idList }),
    expand: ({ spreadsheet_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sheetPath(spreadsheet_id, '/values:batchClearByDataFilter'),
    ],
  }),

  defineIntent({
    name: 'google_sheets.read_only',
    effect: 'read',
    description:
      'Allow any GET under the Sheets API for specific spreadsheets. Binds GET /v4/spreadsheets/{id}(/.*)?, useful for pure reporting agents.',
    params: z.object({ spreadsheet_id: idList }),
    expand: ({ spreadsheet_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      sheetPath(spreadsheet_id, '(/.*)?'),
    ],
  }),
];
