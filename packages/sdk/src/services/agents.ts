import type { HttpClient } from '../client.js';
import type {
  Agent,
  AgentSetupInput,
  AgentSetupResult,
  DismissWarningsResult,
  RegisterAgentInput,
  UpdateAgentInput,
} from '../types.js';

/** What an agent is: revoked, else blocked (its Passports are blocked), else paused (suspended by the owner), else active. */
export type AgentOverviewStatus = 'active' | 'paused' | 'blocked' | 'revoked';

/** The other agent of a drop-off and how many there were with it this month. */
export interface AgentOverviewHandoff {
  agent_id: string;
  name: string;
  count: number;
}

/** One agent of the account in the agents overview. */
export interface AgentOverviewRow {
  agent_id: string;
  name: string;
  status: AgentOverviewStatus;
  /** The trust value in force and where it comes from: `agent` is the agent's own, `account` follows the account, `default` is STACK's. */
  trust: { value: 'ask_first' | 'trust_agents'; source: 'agent' | 'account' | 'default' };
  /** The agent's account, or null for an agent with none. */
  account: { id: string; status: string } | null;
  /** The account's pieces and their states (pending, ready, paused, failed, closing, closed). */
  pieces: Array<{ kind: string; state: string }>;
  /** Items waiting on a person for this agent: held control reviews, approvals that name it, orders and card purchases waiting for approval, intent checks, flagged checkouts. */
  held: number;
  /** The agent's wake-ups: waiting to be delivered, and delivered and not yet acknowledged. */
  wakes: { queued: number; running: number };
  /** When the agent was last issued a Passport, or null. */
  last_passport_at: string | null;
  /** Drop-offs of this calendar month (UTC): to the agents it sent to, from the agents it received from. */
  handoffs_this_month: { sent: AgentOverviewHandoff[]; received: AgentOverviewHandoff[] };
  /** What the agent's account was charged this calendar month (UTC), in cents; null for an agent with no account. */
  spend_this_month_cents: number | null;
}

export interface AgentsOverviewPage {
  agents: AgentOverviewRow[];
  /** Pass as `cursor` for the next page; null on the last. */
  next_cursor: string | null;
}

export class AgentService {
  constructor(private client: HttpClient) {}

  async register(input: RegisterAgentInput): Promise<Agent> {
    return this.client.post<Agent>('/v1/agents/register', input);
  }

  /**
   * Register an agent, give it its first grants and declare the hosts its connections' credentials may go to, as
   * one human approval whose card lists all of it. Pass governanceApprovalId (gvr_*) when retrying after a 403
   * GOVERNANCE_APPROVAL_REQUIRED, once a person approved it in the chat or on the approval page (the approval_url).
   */
  async setup(input: AgentSetupInput, opts?: { governanceApprovalId?: string }): Promise<AgentSetupResult> {
    return this.client.post<AgentSetupResult>(
      '/v1/agents/setup',
      { agent: input.agent, grants: input.grants ?? [], allowed_hosts: input.allowed_hosts ?? [] },
      opts?.governanceApprovalId ? { headers: { 'X-Governance-Approval': opts.governanceApprovalId } } : undefined,
    );
  }

  /**
   * Resolve every open warning of one agent and keep new ones of the same kinds from coming back for a day.
   * Criticals are never dismissed. It needs no approval; `opts.governanceApprovalId` is accepted for callers written
   * before and has no effect.
   */
  async dismissWarnings(agentId: string, opts?: { governanceApprovalId?: string }): Promise<DismissWarningsResult> {
    return this.client.post<DismissWarningsResult>(
      `/v1/agents/${encodeURIComponent(agentId)}/dismiss-warnings`,
      {},
      opts?.governanceApprovalId ? { headers: { 'X-Governance-Approval': opts.governanceApprovalId } } : undefined,
    );
  }

  async list(): Promise<Agent[]> {
    return this.client.get<Agent[]>('/v1/agents');
  }

  /**
   * One page of every agent of the account with its status, trust, pieces, what waits on a person for it, its queued
   * wake-ups, its handoffs and its spend this month. Owner, admin or read-only; an agent is refused. Nothing from the audit
   * record. Up to 200 agents a page (the default); pass `next_cursor` back as `cursor` for the next.
   */
  async overview(opts?: { limit?: number; cursor?: string }): Promise<AgentsOverviewPage> {
    return this.client.get<AgentsOverviewPage>('/v1/agents/overview', {
      limit: opts?.limit !== undefined ? String(opts.limit) : undefined,
      cursor: opts?.cursor,
    });
  }

  async get(id: string): Promise<Agent> {
    return this.client.get<Agent>(`/v1/agents/${id}`);
  }

  async update(id: string, input: UpdateAgentInput): Promise<Agent> {
    return this.client.patch<Agent>(`/v1/agents/${id}`, input);
  }

  async delete(id: string): Promise<{ deleted: boolean }> {
    return this.client.delete<{ deleted: boolean }>(`/v1/agents/${id}`);
  }

  /** pass governanceApprovalId (gvr_*) when retrying after a
   * 403 GOVERNANCE_APPROVAL_REQUIRED, once a human approved it on the
   * approval page (the approval_url). */
  async unblock(id: string, opts?: { governanceApprovalId?: string }): Promise<{ unblocked: boolean }> {
    return this.client.post<{ unblocked: boolean }>(
      `/v1/agents/${id}/unblock`,
      undefined,
      opts?.governanceApprovalId ? { headers: { 'X-Governance-Approval': opts.governanceApprovalId } } : undefined,
    );
  }

  async getPermissions(agentId: string): Promise<unknown> {
    return this.client.get(`/v1/agents/${agentId}/permissions`);
  }
}
