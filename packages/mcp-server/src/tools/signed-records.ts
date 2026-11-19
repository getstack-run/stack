import { createHash } from 'node:crypto';
import { z } from 'zod';
import { throwApiError } from '../api-client.js';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const SIGNED_RECORDS_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  stack_export_signed_record: hint.write('Export Signed record'),
  stack_list_signed_records: hint.read('List Signed records'),
  stack_get_signed_record: hint.read('Get Signed record'),
  stack_download_signed_record: hint.read('Download Signed record'),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const SIGNED_RECORDS_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  stack_download_signed_record: 'Returns a whole Signed record as text. Kept out of the directory profile, whose reviewed tool set does not change.',
};

/** Signed evidence records. */
export function registerSignedRecordsTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api, apiRaw } = ctx;
  server.tool(
    'stack_export_signed_record',
    'Create one portable Signed record for a Mission, session or period and return it. The immutable JSON snapshot contains the signed claims and verification material that exist at export time. Signed records are a controls feature: without controls the API answers 402 CONTROLS_REQUIRED, and a self-managed install also needs a licence that covers signed exports.',
    {
      scope_kind: z
        .enum(['mission', 'session', 'incident', 'period'])
        .describe(
          'Scope kind. mission and session take an id ref; period takes period:YYYY-Qn, period:YYYY-MM or period:YYYY-MM-DD/YYYY-MM-DD. incident is reserved and currently refused.',
        ),
      scope_ref: z
        .string()
        .min(1)
        .max(256)
        .describe('Reference matching scope_kind: ms_* / ses_* / incident:<id> / period:<range>.'),
      supersedes: z
        .string()
        .optional()
        .describe(
          'Optional prior pack id (pck_*) when re-exporting the same scope; supersedes pointer surfaces on the new pack.',
        ),
      air_gap: z
        .boolean()
        .optional()
        .describe(
          'Marks the record as intended for offline verification. Every record already embeds the JWKS and schemas.',
        ),
    },
    async ({ scope_kind, scope_ref, supersedes, air_gap }) => {
      const body: Record<string, unknown> = {
        scope: { kind: scope_kind, ref: scope_ref },
      };
      if (supersedes !== undefined) body.supersedes = supersedes;
      if (air_gap !== undefined) body.air_gap = air_gap;
      const result = await api('POST', '/v1/evidence-packs', body);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_list_signed_records',
    "List the account's Signed records, newest first, optionally filtered by scope as <kind>:<ref>. Reading the record is a controls feature: without controls the API answers 402 CONTROLS_REQUIRED.",
    {
      scope: z
        .string()
        .optional()
        .describe("Scope filter '<kind>:<ref>'. Omitted: every record."),
    },
    async ({ scope }) => {
      const params = new URLSearchParams();
      if (scope) params.set('scope', scope);
      const suffix = params.toString();
      const result = await api('GET', `/v1/evidence-packs${suffix ? `?${suffix}` : ''}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_get_signed_record',
    'Get one Signed record receipt by id. The response includes the signed envelope bytes and parsed record claim. Reading the record is a controls feature: without controls the API answers 402 CONTROLS_REQUIRED.',
    {
      pack_id: z.string().describe('The Signed record id (pack_*).'),
    },
    async ({ pack_id }) => {
      const result = await api('GET', `/v1/evidence-packs/${encodeURIComponent(pack_id)}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_download_signed_record',
    "Download the exact stored bytes of one Signed record (pack_*) as JSON, with their sha256 and size so the copy can be checked against the signed claim. A record larger than one call carries is saved to the account's drive and the call answers with the file. Reading the record is a controls feature: without controls the API answers 402 CONTROLS_REQUIRED.",
    {
      pack_id: z.string().describe('The Signed record id (pack_*).'),
    },
    async ({ pack_id }) => {
      const res = await apiRaw('GET', `/v1/evidence-packs/${encodeURIComponent(pack_id)}/download`);
      if (!res.ok) throwApiError(res);
      const body = res.text ?? '';
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({ pack_id, sha256: createHash('sha256').update(body, 'utf8').digest('hex'), byte_size: Buffer.byteLength(body, 'utf8') }, null, 2),
          },
          { type: 'resource' as const, resource: { uri: `stack://signed-records/${encodeURIComponent(pack_id)}.json`, mimeType: 'application/json', text: body } },
        ],
      };
    },
  );
}
