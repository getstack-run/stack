import type { HttpClient } from '../client.js';

// A governance step-up asks a person to approve one exact change. The chat or
// the program that raised it reads the approval to describe the change before
// it asks, and to follow its status afterwards. Reading is all this does: the
// decision itself is made by a person in the dashboard, or confirmed in an MCP
// chat client, never by a call from here.

export type GovernanceApprovalStatus = 'pending' | 'approved' | 'rejected' | 'consumed' | 'expired';

export interface GovernanceApproval {
  id: string;
  /** What the approval is for, for example `billing_mutate` or `service_grant_expand`. */
  action: string;
  resource_id: string;
  summary: string;
  requested_via: 'operator_key' | 'member_session' | 'oauth' | 'member_key';
  status: GovernanceApprovalStatus;
  expires_at: string;
  created_at: string;
  decided_at: string | null;
  /** Present on an `account_open` approval: what the person is asked to open. */
  account_preview?: { name: string; monthly_budget_cents: number | null; pieces: string[] } | null;
  /** Present on a policy approval. */
  policy_preview?: Record<string, unknown> | null;
  /** Present only when a partner reads an approval of one of its white-label tenants. */
  tenant?: { operator_id: string; name: string };
}

export interface GovernanceApprovalDetail {
  approval: GovernanceApproval;
  /** SHA-256 of the exact change this approval covers. A chat confirmation binds to it. */
  payload_hash: string;
  /** The approval's own page in the Console, where a person decides. */
  approval_url: string;
}

/**
 * Governance approvals.
 *
 * @example
 * ```ts
 * try {
 *   await stack.billing.subscribePlatform();
 * } catch (error) {
 *   if (error instanceof GovernanceApprovalRequiredError) {
 *     const { approval, approval_url } = await stack.governance.getApproval(error.approvalId);
 *     console.log(approval.summary, approval_url);
 *   }
 * }
 * ```
 */
export class GovernanceService {
  constructor(private readonly client: HttpClient) {}

  /**
   * One approval: its status, the hash of the change it covers and the link to
   * its own page. An approval of another account is a 404, never revealed. A
   * pending approval past its expiry reads as `expired`. An agent context is
   * refused: an agent never reads or decides its own approvals.
   */
  async getApproval(approvalId: string): Promise<GovernanceApprovalDetail> {
    return this.client.get<GovernanceApprovalDetail>(`/v1/governance/approvals/${encodeURIComponent(approvalId)}`);
  }

  /**
   * The account's approvals, newest first, up to the 100 the API holds, with their status (a pending
   * approval past its expiry reads as `expired`). A list carries no link: `getApproval` returns one
   * approval with its page. An agent context is refused.
   */
  async listApprovals(): Promise<{ approvals: GovernanceApproval[] }> {
    return this.client.get<{ approvals: GovernanceApproval[] }>('/v1/governance/approvals');
  }
}
