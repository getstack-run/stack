// The step between a 403 GOVERNANCE_APPROVAL_REQUIRED and the retry: ask the
// person, never the model. See elicitation.ts for the trust model. Fails
// closed: anything unexpected is 'unavailable', and the caller then returns the
// approval link instead.

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ApiFn } from './api-client.js';
import {
  currentToolCall,
  type ApprovalDetail,
  type ChatConfirmationOptions,
  type ChatDecision,
  type Elicitor,
} from './elicitation.js';

/**
 * Decides a pending governance approval for the person who is in the middle of
 * a tool call. `unavailable` means no confirmation happened here: the caller
 * falls back to the approval link, and nothing is ever approved without the
 * person's answer.
 */
export interface ToolCallConfirmer {
  /** Whether this session's client can be asked at all; when it cannot, nothing is fetched or asked. */
  canConfirm(): boolean;
  confirm(detail: ApprovalDetail): Promise<ChatDecision>;
}

/** What a deployment's confirmer is built from, once per MCP session. */
export interface ConfirmationSession {
  mcp: McpServer;
  /** The server's requests of its client. */
  elicitor: Elicitor;
  /** A client of the API without this hook, so a confirmation never asks for a confirmation. */
  api: ApiFn;
  /** What the transport knows of the session (its id, its principal, the attestation key). */
  options: ChatConfirmationOptions;
  /** The engine's own confirmer, for what a deployment's does not decide. */
  engine: ToolCallConfirmer;
}

/** Builds the confirmer of one MCP session. */
export type ConfirmerFactory = (session: ConfirmationSession) => ToolCallConfirmer;

/**
 * The engine's confirmer: it opens the approval page in the person's browser
 * when their client can show a page, and reports what was decided there. The
 * decision is the page's; nothing is approved here.
 */
export class ElicitationConfirmer implements ToolCallConfirmer {
  constructor(
    private readonly elicitor: Elicitor,
    private readonly api: ApiFn,
  ) {}

  canConfirm(): boolean {
    return this.elicitor.canOpenUrl();
  }

  async confirm(detail: ApprovalDetail): Promise<ChatDecision> {
    if (!this.canConfirm() || !detail.approval_url) return 'unavailable';
    try {
      if (!await this.elicitor.openApprovalPage({ id: detail.approval.id, approval_url: detail.approval_url })) return 'unavailable';
      const approvalPath = `/v1/governance/approvals/${encodeURIComponent(detail.approval.id)}`;
      const after = await this.api('GET', approvalPath) as ApprovalDetail;
      if (after.approval.status === 'approved') return 'approved';
      if (after.approval.status === 'rejected') return 'rejected';
    } catch {
      // Fall back to the approval link. Nothing is applied without approval.
    }
    return 'unavailable';
  }
}

/**
 * Ask the person to decide a pending governance approval. 'unavailable' means
 * no confirmation happened here: no tool call in progress, a client that
 * cannot ask, or a failure. `api` must be a client without the confirmation
 * hook.
 */
export async function confirmGovernance(
  confirmer: ToolCallConfirmer,
  api: ApiFn,
  approvalId: string,
  approvalUrl?: string,
): Promise<ChatDecision> {
  if (!currentToolCall() || !confirmer.canConfirm()) return 'unavailable';
  try {
    const fetched = await api('GET', `/v1/governance/approvals/${encodeURIComponent(approvalId)}`) as ApprovalDetail;
    // The link the API named with the refusal is the one the person is shown.
    const detail: ApprovalDetail = approvalUrl ? { ...fetched, approval_url: approvalUrl } : fetched;
    return await confirmer.confirm(detail);
  } catch {
    // Fall back to the approval link. Nothing is applied without approval.
    return 'unavailable';
  }
}
