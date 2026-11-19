// IntentsService TS SDK wrapper.
//
// Three groupings:
//   1. simulate dry-run dispatcher.
//   2. submit pre-execution gate. Registers the
//                    intent_claim, runs simulation, persists a pending
//                    intent_approvals row, returns an approval id.
//      submitAndWait() Polls /v1/intents/:id until status leaves
//                      'pending' or the deadline passes.
//   3. listPending() / approve() / reject() — operator-side surface.
//
// Every shape stays a plain interface mirroring the wire JSON so
// consumers can compose without TypeScript reaching for our internals.

import type { HttpClient } from '../client.js';

// ─── Shared ─────────────────────────────────────────────────────────

/** Subset of the IntentClaim payload — kept loose so SDK consumers
 *  can ship through whatever they've assembled without us shipping
 *  the entire Zod schema as a peer dependency. */
export interface IntentInput {
  type: 'intent_claim';
  intent_type: 'http_call' | 'mcp_tool' | 'skill_invocation' | 'onchain_tx' | 'task_complete';
  agent_id: string;
  named_intent: string;
  target: string;
  action: string;
  parameters: Record<string, unknown>;
  estimated_cost: { wallet_cents: number | null; tokens: number | null; gas_gwei: number | null };
  accountability: 'enforced' | 'logged' | 'standard';
  reason: string | null;
  requires: string[];
  user_subject: string | null;
  mission_ref: string | null;
  submitted_at: number;
}

export interface SimulationCost {
  wallet_cents: number | null;
  tokens: number | null;
  gas_gwei: number | null;
}

export interface SimulationDiagnostics {
  failed_constraint?: { path: string; op: string };
  scope_missing_service?: string;
  accountability_passport?: 'enforced' | 'logged' | 'standard';
  accountability_intent?: 'enforced' | 'logged' | 'standard';
  tier_limit?: {
    meter: string;
    cap: number | null;
    used: number;
    wallet_balance_cents: number;
    overage_price_cents: number;
  };
}

// ─── 2.1 — simulate ─────────────────────────────────────────────────

export interface SimulateInput {
  intent: IntentInput;
  intent_claim_ref?: string;
  persist?: boolean;
}

export interface SimulateResult {
  allowed: boolean;
  denial_reasons: string[];
  simulated_cost: SimulationCost;
  predicted_detector_fires: Array<{ detector_key: string; severity: string }>;
  simulated_at: number;
  claim_id?: string;
  diagnostics: SimulationDiagnostics;
}

// ─── 2.2 — submit / approval flow ───────────────────────────────────

export interface SubmitInput {
  intent: IntentInput;
  expires_in_seconds?: number;
  skip_simulation?: boolean;
}

export interface SubmitResult {
  approval_id: string;
  intent_claim_id: string;
  simulated_claim_id?: string;
  status: 'pending';
  expires_at: string;
  simulation?: SimulateResult;
}

export interface PendingApproval {
  id: string;
  operator_id: string;
  agent_id: string;
  passport_jti: string;
  intent_claim_id: string;
  simulated_claim_id: string | null;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  requested_at: string;
  expires_at: string;
  decided_at: string | null;
  decided_by_member_id: string | null;
  notes: string | null;
  block_future: boolean;
}

export interface DecisionResult {
  approval_id: string;
  status: 'approved' | 'rejected';
  decided_at: string;
}

export interface DecideInput {
  notes?: string;
  block_future?: boolean;
}

/**
 * Result of `submitAndWait` — either the row reached a terminal status
 * within the deadline (`status` is one of approved / rejected /
 * expired) or polling timed out (`timed_out: true`).
 */
export type SubmitAndWaitResult =
  | { timed_out: false; row: PendingApproval; initial: SubmitResult }
  | { timed_out: true; row: PendingApproval; initial: SubmitResult };

export class IntentsService {
  constructor(private client: HttpClient) {}

  /**
   * Dry-run an Intent against a passport WITHOUT registering an
   * approval. surface.
   */
  async simulate(input: SimulateInput, options: { passportToken: string }): Promise<SimulateResult> {
    return this.client.post<SimulateResult>('/v1/intents/simulate', input, {
      headers: { 'X-Passport-Token': options.passportToken },
    });
  }

  /**
   * Submit an Intent for pre-execution operator approval. Registers
   * the intent_claim, runs simulation (unless `skip_simulation=true`),
   * persists a pending intent_approvals row, and notifies the operator
   * via their configured channels. Returns the approval id; callers
   * poll `/v1/intents/:id` (via `listPending` + custom filter, or via
   * `submitAndWait`) until status leaves 'pending'.
   */
  async submit(input: SubmitInput, options: { passportToken: string }): Promise<SubmitResult> {
    return this.client.post<SubmitResult>('/v1/intents/submit', input, {
      headers: { 'X-Passport-Token': options.passportToken },
    });
  }

  /**
   * Convenience: submit + poll. Polls the operator's pending list at
   * `intervalMs` until either the approval reaches a terminal status
   * or `timeoutMs` elapses. The poll uses listPending which is
   * operator-scope — the SDK caller must be authenticated as the
   * operator (or a member with role=admin) for this to work end-to-end.
   *
   * Practical use: in batch / CI scripts where the agent and operator
   * are the same identity. For agent-runtime mode where the operator
   * approves async via dashboard, callers should subscribe to
   * notifications or poll `listPending` themselves.
   */
  async submitAndWait(
    input: SubmitInput,
    options: { passportToken: string; timeoutMs?: number; intervalMs?: number },
  ): Promise<SubmitAndWaitResult> {
    const initial = await this.submit(input, options);
    const timeoutMs = options.timeoutMs ?? 60_000;
    const intervalMs = options.intervalMs ?? 1_000;
    const deadline = Date.now() + timeoutMs;
    let last: PendingApproval | null = null;
    // Poll the per-id endpoint so we can read the actual terminal
    // status (approved | rejected | expired) — listPending alone can't
    // distinguish "no longer pending" from "approved", which made the
    // 0.5.0 implementation silently treat rejections as approvals.
    while (Date.now() < deadline) {
      const row = await this.get(initial.approval_id);
      last = row;
      if (row.status !== 'pending') {
        return { timed_out: false, row, initial };
      }
      await sleep(intervalMs);
    }
    return {
      timed_out: true,
      row: last ?? ({ id: initial.approval_id, status: 'pending' } as PendingApproval),
      initial,
    };
  }

  /**
   * Fetch a single approval row by id, regardless of status. Returns
   * the full row when the calling operator owns it; 404s when the row
   * doesn't exist OR belongs to a different operator (existence is
   * hidden cross-tenant). Used by `submitAndWait` to distinguish
   * approved from rejected reliably.
   */
  async get(approvalId: string): Promise<PendingApproval> {
    return this.client.get<PendingApproval>(`/v1/intents/${encodeURIComponent(approvalId)}`);
  }

  /** List pending approvals scoped to the calling operator. */
  async listPending(opts?: { page?: number; limit?: number }): Promise<{ items: PendingApproval[]; total: number }> {
    const query: Record<string, string | undefined> = {};
    if (opts?.page !== undefined) query['page'] = String(opts.page);
    if (opts?.limit !== undefined) query['limit'] = String(opts.limit);
    return this.client.get<{ items: PendingApproval[]; total: number }>('/v1/intents/pending', query);
  }

  /**
   * Transition a pending approval → approved. From an API key or an OAuth token this answers 403
   * GOVERNANCE_APPROVAL_REQUIRED with an approval_url: a person confirms this intent in the chat or on that page, and
   * the retry carries `governanceApprovalId` (gvr_*). The Console's own session needs none.
   */
  async approve(approvalId: string, input?: DecideInput, opts?: { governanceApprovalId?: string }): Promise<DecisionResult> {
    return this.client.post<DecisionResult>(
      `/v1/intents/${encodeURIComponent(approvalId)}/approve`,
      input ?? {},
      opts?.governanceApprovalId ? { headers: { 'X-Governance-Approval': opts.governanceApprovalId } } : undefined,
    );
  }

  /**
   * Transition a pending approval → rejected. Auto-revokes the
   * passport; `block_future=true` additionally suspends the agent.
   */
  async reject(approvalId: string, input?: DecideInput): Promise<DecisionResult> {
    return this.client.post<DecisionResult>(`/v1/intents/${encodeURIComponent(approvalId)}/reject`, input ?? {});
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
