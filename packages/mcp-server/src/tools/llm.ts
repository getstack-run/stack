import { z } from 'zod';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const LLM_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  stack_llm_usage_list: hint.read('List LLM usage'),
  stack_llm_usage_summary: hint.read('Summarize LLM usage'),
};

/** LLM gateway usage. */
export function registerLlmTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  // ─── LLM Usage ──────────────────────────────────────────────────────

  server.tool(
    'stack_llm_usage_list',
    'List per-call LLM usage records for the customer-key gateway and STACK-key product calls. Each row names the product surface, provider payer, STACK-fee payer, model, tokens, provider cost, STACK fee, total cost, wallet hold, streaming flag, and mission binding. Cursor-paginated, newest first. Returns only the calling account\'s records.',
    {
      limit: z
        .number()
        .int()
        .min(1)
        .max(100)
        .optional()
        .describe('Page size (default 20, max 100)'),
      cursor: z.string().optional().describe('Pagination cursor from prior response next_cursor'),
      provider: z
        .enum(['anthropic', 'openai', 'openrouter'])
        .optional()
        .describe('Filter by provider'),
      passport_jti: z.string().optional().describe('Filter to a single passport'),
      mission_id: z.string().optional().describe('Filter to calls bound to a specific mission'),
      agent_id: z.string().optional().describe('Filter to a single agent'),
      since: z.string().optional().describe('ISO timestamp lower bound on created_at (inclusive)'),
      until: z.string().optional().describe('ISO timestamp upper bound on created_at (exclusive)'),
    },
    async ({ limit, cursor, provider, passport_jti, mission_id, agent_id, since, until }) => {
      const params = new URLSearchParams();
      if (limit != null) params.set('limit', String(limit));
      if (cursor) params.set('cursor', cursor);
      if (provider) params.set('provider', provider);
      if (passport_jti) params.set('passport_jti', passport_jti);
      if (mission_id) params.set('mission_id', mission_id);
      if (agent_id) params.set('agent_id', agent_id);
      if (since) params.set('since', since);
      if (until) params.set('until', until);
      const qs = params.toString();
      const result = await api('GET', `/v1/llm/usage${qs ? `?${qs}` : ''}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_llm_usage_summary',
    'Aggregate LLM usage by product surface, payer, provider, optional model, and UTC day. Returns calls, tokens, provider cost and STACK fee as separate values for the calling account. group_by_model=false collapses models while keeping surface and payer separate.',
    {
      provider: z.enum(['anthropic', 'openai', 'openrouter']).optional(),
      passport_jti: z.string().optional(),
      mission_id: z.string().optional(),
      agent_id: z.string().optional(),
      since: z.string().optional().describe('ISO timestamp lower bound (inclusive)'),
      until: z.string().optional().describe('ISO timestamp upper bound (exclusive)'),
      group_by_model: z
        .boolean()
        .optional()
        .describe('Default true. false collapses models per provider.'),
    },
    async ({ provider, passport_jti, mission_id, agent_id, since, until, group_by_model }) => {
      const params = new URLSearchParams();
      if (provider) params.set('provider', provider);
      if (passport_jti) params.set('passport_jti', passport_jti);
      if (mission_id) params.set('mission_id', mission_id);
      if (agent_id) params.set('agent_id', agent_id);
      if (since) params.set('since', since);
      if (until) params.set('until', until);
      if (group_by_model !== undefined) params.set('group_by_model', String(group_by_model));
      const qs = params.toString();
      const result = await api('GET', `/v1/llm/usage/summary${qs ? `?${qs}` : ''}`);
      return toolJson(result);
    },
  );
}
