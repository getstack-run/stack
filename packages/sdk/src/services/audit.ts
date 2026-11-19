import type { HttpClient } from '../client.js';

export interface AuditEntry {
  entry_id: string;
  trace_id: string;
  timestamp: number;
  operator_id: string;
  agent_id: string;
  passport_jti: string;
  layer: 'vault' | 'dropoff' | 'skills' | 'hire' | 'system' | 'billing';
  action: string;
  outcome: 'success' | 'denied' | 'failure';
  duration_ms: number | null;
  error_code: string | null;
  error_message: string | null;
  entry_hash: string;
  prev_entry_hash: string;
}

export interface ChainHead {
  operator_id: string;
  latest_entry_hash: string | null;
  latest_timestamp: number | null;
  total_entries: number;
  observed_at: string;
}

export interface ChainVerification {
  operator_id: string;
  verified_at: string;
  valid: boolean;
  total_checked: number;
  head_entry_hash: string | null;
  first_break?: {
    entry_id: string;
    timestamp: number;
    reason: 'hash_mismatch' | 'prev_hash_mismatch';
    expected: string;
    actual: string;
  };
}

/**
 * The audit record. STACK writes it for every account; reading it is a controls feature, so without controls every
 * call here throws `ControlsRequiredError` (402 `CONTROLS_REQUIRED`). Switching controls on shows all of it, including
 * what came before. A self-managed install has every controls feature.
 */
export class AuditService {
  constructor(private client: HttpClient) {}

  async list(options?: {
    limit?: number;
    since?: number;
    agentId?: string;
    passportJti?: string;
  }): Promise<{
    entries: AuditEntry[];
    max_timestamp: number | null;
  }> {
    return this.client.get('/v1/audit', {
      limit: options?.limit?.toString(),
      since: options?.since?.toString(),
      agent_id: options?.agentId,
      passport_jti: options?.passportJti,
    });
  }

  async chainHead(): Promise<ChainHead> {
    return this.client.get<ChainHead>('/v1/audit/chain-head');
  }

  async verifyChain(options?: {
    from?: string;
    to?: string;
    limit?: number;
  }): Promise<ChainVerification> {
    return this.client.get('/v1/audit/verify-chain', {
      from: options?.from,
      to: options?.to,
      limit: options?.limit?.toString(),
    });
  }
}
