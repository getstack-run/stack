import { z } from 'zod';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

const APPROVAL_FIELDS = [
  'id', 'action', 'resource_id', 'summary', 'status', 'requested_via', 'expires_at', 'created_at', 'decided_at',
] as const;

const APPROVAL_STATUSES = ['pending', 'approved', 'rejected', 'consumed', 'expired'] as const;

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const APPROVALS_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // Approvals
  stack_get_approval: hint.read('Get approval'),
  stack_list_approvals: hint.read('List approvals'),
};

/** Governance approvals: listing and reading them. Deciding is the person's, in the chat or on the approval page. */
export function registerApprovalsTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  server.tool(
    'stack_get_approval',
    'Read one pending or decided governance approval of this account: its action, summary, status, expiry and the link to its page. Statuses are pending, approved, rejected, consumed and expired. An approval lasts 24 hours. Returns the approval and approval_url; it does not decide it.',
    {
      approval_id: z.string().regex(/^gvr_[A-Za-z0-9_-]{1,64}$/).describe('Approval id (gvr_*) from a GOVERNANCE_APPROVAL_REQUIRED response'),
    },
    async ({ approval_id }) => {
      const detail = await api('GET', `/v1/governance/approvals/${encodeURIComponent(approval_id)}`) as {
        approval?: Record<string, unknown>;
        approval_url?: unknown;
      };
      const approval = Object.fromEntries(
        APPROVAL_FIELDS.flatMap((key) => (detail.approval && key in detail.approval ? [[key, detail.approval[key]]] : [])),
      );
      return toolJson({ approval, approval_url: typeof detail.approval_url === 'string' ? detail.approval_url : null });
    },
  );

  server.tool(
    'stack_list_approvals',
    'List the governance approvals of this account, newest first, up to 100 held by the API: each with its id, action, summary, status, expiry and decision time. Statuses are pending, approved, rejected, consumed and expired; an approval lasts 24 hours. Use status to list only one kind, for example pending. The list carries no link: stack_get_approval returns one approval with the link to its page. It does not decide anything.',
    {
      status: z.enum(APPROVAL_STATUSES).optional().describe('Only approvals in this status'),
      limit: z.number().int().min(1).max(100).optional().describe('Most approvals to return (default 20)'),
    },
    async ({ status, limit }) => {
      const result = await api('GET', '/v1/governance/approvals') as { approvals?: Array<Record<string, unknown>> };
      const rows = Array.isArray(result.approvals) ? result.approvals : [];
      const approvals = rows
        .filter((row) => status === undefined || row['status'] === status)
        .slice(0, limit ?? 20)
        .map((row) => Object.fromEntries(
          [...APPROVAL_FIELDS, 'tenant'].flatMap((key) => (key in row ? [[key, row[key]]] : [])),
        ));
      return toolJson({ approvals });
    },
  );
}
