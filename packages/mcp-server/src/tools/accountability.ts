import { z } from 'zod';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson, approvalFlow } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const ACCOUNTABILITY_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // Accountability
  stack_checkpoint: hint.write('Submit Passport checkpoint'),
  stack_checkout: hint.write('Submit Passport checkout'),
  stack_get_passport_report: hint.read('Get Passport report'),
  stack_list_pending_reviews: hint.read('List pending reviews'),
  stack_decide_review: hint.destructive('Decide checkout review'),
};

/** Passport checkpoints, checkouts, reports and operator review decisions. */
export function registerAccountabilityTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  // ─── Accountability Tools ────────────────────────────────────────────

  server.tool(
    'stack_checkpoint',
    "Record a progress checkpoint for an active Passport: services used, action count and a summary since the last checkpoint. Agents in standard accountability mode have no checkpoints and the call is refused. Returns checkpoint_id, passport_jti and flags for services the Passport did not declare. For an enforced agent it also moves the stored monitoring deadline (new_expires_at) to now plus the checkpoint interval; the signed Passport token's own expiry does not change.",
    {
      passport_jti: z.string().describe('Passport JTI'),
      services_used: z
        .array(z.string())
        .describe('Service providers accessed since last checkpoint'),
      actions_count: z.number().describe('Number of actions taken since last checkpoint'),
      summary: z.string().optional().describe('Brief narrative of progress'),
      delegated_to: z.array(z.string()).optional().describe('Agent IDs delegated to, if any'),
    },
    async ({ passport_jti, services_used, actions_count, summary, delegated_to }) => {
      const result = await api('POST', `/v1/passports/${encodeURIComponent(passport_jti)}/checkpoint`, {
        services_used,
        actions_count,
        summary,
        delegated_to,
      });
      return toolJson(result);
    },
  );

  server.tool(
    'stack_checkout',
    "Record the final report for a Passport's work and check it out. STACK's review engine evaluates the checkout and may flag it for operator review.",
    {
      passport_jti: z.string().describe('Passport JTI'),
      services_used: z.array(z.string()).describe('All service providers used during the mission'),
      actions_count: z.number().describe('Total actions taken during the mission'),
      summary: z.string().optional().describe('Summary of what was accomplished'),
      delegated_to: z
        .array(z.string())
        .optional()
        .describe('Agent IDs delegated to during the mission'),
    },
    async ({ passport_jti, services_used, actions_count, summary, delegated_to }) => {
      const result = await api('POST', `/v1/passports/${encodeURIComponent(passport_jti)}/checkout`, {
        services_used,
        actions_count,
        summary,
        delegated_to,
      });
      return toolJson(result);
    },
  );

  server.tool(
    'stack_get_passport_report',
    'Get the accountability report for a Passport: intent, checkpoints, checkout and review decision. Reading the record is a controls feature: without controls the API answers 402 CONTROLS_REQUIRED.',
    {
      passport_jti: z.string().describe('Passport JTI'),
    },
    async ({ passport_jti }) => {
      const result = await api('GET', `/v1/passports/${encodeURIComponent(passport_jti)}/report`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_list_pending_reviews',
    'List flagged or blocked Passport checkouts pending operator review.',
    {
      status: z
        .enum(['flagged', 'blocked'])
        .optional()
        .describe('Filter by review status (default: flagged)'),
      page: z.number().optional().describe('Page number'),
      limit: z.number().optional().describe('Results per page (default 20)'),
    },
    async ({ status, page, limit }) => {
      const params = new URLSearchParams();
      if (status) params.set('status', status);
      if (page) params.set('page', String(page));
      if (limit) params.set('limit', String(limit));
      const qs = params.toString();
      const result = await api('GET', `/v1/passports/reviews${qs ? `?${qs}` : ''}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_decide_review',
    `Record an operator decision on a flagged Passport checkout. approved clears the flag; blocked stops future Passport issuance to the agent. A block applies immediately. An approval from an MCP or API-key session requires human approval. ${approvalFlow}`,
    {
      checkout_id: z.string().describe('Checkout ID to decide on'),
      decision: z.enum(['approved', 'blocked']).describe('Operator decision'),
      notes: z.string().optional().describe('Operator notes explaining the decision'),
      block_future: z
        .boolean()
        .optional()
        .describe('Block this agent from future passport issuance'),
      governance_approval_id: z
        .string()
        .optional()
        .describe('Approval id (gvr_*) from a prior 403, after human approval in the dashboard'),
    },
    async ({ checkout_id, decision, notes, block_future, governance_approval_id }) => {
      const result = await api(
        'POST',
        `/v1/passports/reviews/${encodeURIComponent(checkout_id)}/decide`,
        { decision, notes, block_future },
        governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined,
      );
      return toolJson(result);
    },
  );
}
