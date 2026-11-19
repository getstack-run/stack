import { z } from 'zod';
import { throwApiError } from '../api-client.js';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const AUDIT_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // Audit and LLM usage
  stack_audit_list: hint.read('List audit entries'),
  stack_audit_chain_head: hint.read('Get audit chain head'),
  stack_audit_verify_chain: hint.read('Verify audit chain'),
  stack_audit_export: hint.read('Export audit log'),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const AUDIT_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  stack_audit_export: 'Returns the whole audit log as text, up to 3 MB at a time. Kept out of the directory profile, whose reviewed tool set does not change.',
};

/** Audit log listing, chain head and chain verification. */
export function registerAuditTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api, apiRaw } = ctx;
  // ─── Audit Tools ────────────────────────────────────────────────────

  server.tool(
    'stack_audit_list',
    "List the account's recent audit log entries, newest first. agent_id and passport_jti narrow the list to one agent or Passport; since (epoch ms) returns only newer entries. Each entry has layer, action, outcome, duration_ms, error_code, error_message and the hash-chain fields entry_hash and prev_entry_hash. A cascade revoke appears as one passport.revoke entry plus one passport.revoke_cascade entry per child. Reading the record is a controls feature: without controls the API answers 402 CONTROLS_REQUIRED.",
    {
      limit: z
        .number()
        .int()
        .min(1)
        .max(100)
        .optional()
        .describe('Number of entries (default 20, max 100)'),
      since: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe('Epoch ms watermark — only return entries newer than this timestamp'),
      agent_id: z.string().optional().describe('Filter to a single agent'),
      passport_jti: z.string().optional().describe('Filter to a single passport jti'),
    },
    async ({ limit, since, agent_id, passport_jti }) => {
      const params = new URLSearchParams();
      if (limit != null) params.set('limit', String(limit));
      if (since != null) params.set('since', String(since));
      if (agent_id) params.set('agent_id', agent_id);
      if (passport_jti) params.set('passport_jti', passport_jti);
      const qs = params.toString();
      const result = await api('GET', `/v1/audit${qs ? `?${qs}` : ''}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_audit_chain_head',
    "Get the account's audit chain head: latest entry hash, total count and latest timestamp. A recorded head lets a third party later confirm, from an export, that no earlier entry was altered. Reading the record is a controls feature: without controls the API answers 402 CONTROLS_REQUIRED.",
    {},
    async () => {
      const result = await api('GET', '/v1/audit/chain-head');
      return toolJson(result);
    },
  );

  server.tool(
    'stack_audit_verify_chain',
    "Verify the integrity of the account's audit chain. Returns valid: true when every entry's hash matches its content and links to the previous entry; otherwise returns the first break and its reason. Reading the record is a controls feature: without controls the API answers 402 CONTROLS_REQUIRED.",
    {
      from: z.string().optional().describe('ISO 8601 datetime — walk only entries from this point'),
      to: z.string().optional().describe('ISO 8601 datetime — walk only entries up to this point'),
      limit: z
        .number()
        .int()
        .min(1)
        .max(100_000)
        .optional()
        .describe('Most entries to walk, 1 to 100,000. Leave out to walk the whole chain (or the whole from-to range)'),
    },
    async ({ from, to, limit }) => {
      const params = new URLSearchParams();
      if (from) params.set('from', from);
      if (to) params.set('to', to);
      if (limit != null) params.set('limit', String(limit));
      const qs = params.toString();
      const result = await api('GET', `/v1/audit/verify-chain${qs ? `?${qs}` : ''}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_audit_export',
    "Export the account's audit log as json, ndjson or csv, newest first, with each entry's hash. Never metered. An export larger than one call carries is saved to the account's drive and the call answers with the file; narrow it with from and to, or page it with limit and offset, to read it here. Reading the record is a controls feature: without controls the API answers 402 CONTROLS_REQUIRED.",
    {
      from: z.string().datetime().optional().describe('ISO 8601 datetime: first entry included'),
      to: z.string().datetime().optional().describe('ISO 8601 datetime: last entry included'),
      format: z.enum(['json', 'ndjson', 'csv']).optional().describe('Default json'),
      limit: z.number().int().min(1).max(50_000).optional().describe('Most entries to return, 1 to 50,000'),
      offset: z.number().int().min(0).optional().describe('Entries to skip, for paging'),
    },
    async ({ from, to, format, limit, offset }) => {
      const params = new URLSearchParams();
      if (from) params.set('from', from);
      if (to) params.set('to', to);
      if (format) params.set('format', format);
      if (limit != null) params.set('limit', String(limit));
      if (offset != null) params.set('offset', String(offset));
      const qs = params.toString();
      const res = await apiRaw('GET', `/v1/audit/export${qs ? `?${qs}` : ''}`);
      if (!res.ok) throwApiError(res);
      // A result larger than one call carries goes through the session's hand-off (the drive), like any tool's.
      return { content: [{ type: 'text' as const, text: res.text ?? '' }] };
    },
  );
}
