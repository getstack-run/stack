import type { HttpClient } from '../client.js';

/** `ask_first`: what needs a person waits for one. `trust_agents`: nothing waits for a person. */
export type TrustValue = 'ask_first' | 'trust_agents';

/** What is set at one scope, and what is in force there. */
export interface TrustSetting {
  /** The agent this is for, or null for the account. */
  agent_id: string | null;
  /** What is set at this scope: null when it has no value of its own (an agent following its account, an account on STACK's default). */
  trust: TrustValue | null;
  /** What is in force here: the agent's value, else the account's, else STACK's default (`trust_agents`). */
  effective: TrustValue;
  /** Which of those the effective value is. */
  source: 'agent' | 'account' | 'default';
}

/**
 * The trust switch: whether the account's agents ask first or are trusted to act. With `trust_agents` nothing waits for
 * a person on card purchases, orders on the customer's own supplier account, and governance changes made with the
 * owner's own API key; with `ask_first` they wait, as they always have. In both, a wallet balance or spend limit, a
 * revoked or suspended agent, a control policy's review rule and the browser-only actions still apply. A new account
 * starts on `trust_agents`. Owner or admin only; an agent is refused. It is not part of any control policy. A change that
 * makes a scope trust where it asked first before needs a person's approval (`trust_widen`: 403
 * `GOVERNANCE_APPROVAL_REQUIRED` with the approval link; retry with `governanceApprovalId` once it is approved); a
 * change to `ask_first` applies at once. Every change is recorded in the audit log.
 */
export class TrustService {
  constructor(private readonly client: HttpClient) {}

  /** The account's value, or one agent's own value over the account's. */
  async get(agentId?: string): Promise<TrustSetting> {
    return this.client.get<TrustSetting>(trustPath(agentId));
  }

  /** Set the account's value, or one agent's (it wins over the account's). */
  async set(trust: TrustValue, agentId?: string, opts?: { governanceApprovalId?: string }): Promise<TrustSetting> {
    return this.client.put<TrustSetting>(trustPath(agentId), { trust }, approvalHeaders(opts));
  }

  /** Remove an agent's own value, so it follows the account again. */
  async clear(agentId: string, opts?: { governanceApprovalId?: string }): Promise<TrustSetting> {
    return this.client.put<TrustSetting>(trustPath(agentId), { trust: null }, approvalHeaders(opts));
  }
}

function trustPath(agentId: string | undefined): string {
  return agentId === undefined ? '/v1/trust' : `/v1/agents/${encodeURIComponent(agentId)}/trust`;
}

function approvalHeaders(opts: { governanceApprovalId?: string } | undefined): { headers: Record<string, string> } | undefined {
  return opts?.governanceApprovalId ? { headers: { 'X-Governance-Approval': opts.governanceApprovalId } } : undefined;
}
