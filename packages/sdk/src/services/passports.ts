import type { HttpClient } from '../client.js';
import { delegationScopesFromToken } from '../delegation-scopes.js';
import type {
  IssuedPassport,
  IssuePassportInput,
  DelegatePassportInput,
  VerifyPassportResult,
  ActivePassport,
  CheckpointInput,
  CheckoutInput,
} from '../types.js';

export class PassportService {
  constructor(private client: HttpClient) {}

  async issue(input: IssuePassportInput): Promise<IssuedPassport> {
    return this.client.post<IssuedPassport>('/v1/passports/issue', input);
  }

  async verify(token: string, serviceId?: string): Promise<VerifyPassportResult> {
    return this.client.post<VerifyPassportResult>('/v1/passports/verify', {
      token,
      ...(serviceId ? { service_id: serviceId } : {}),
    });
  }

  async revoke(jti: string, reason?: string): Promise<{ success: boolean }> {
    return this.client.post<{ success: boolean }>('/v1/passports/revoke', { jti, reason });
  }

  async delegate(input: DelegatePassportInput): Promise<IssuedPassport> {
    const { parent_token, ...rest } = input;
    return this.client.post<IssuedPassport>('/v1/passports/delegate', { ...rest,
      parent_passport_token: parent_token, scopes: input.scopes ?? delegationScopesFromToken(parent_token) });
  }

  async refresh(token: string, ttlSeconds?: number): Promise<IssuedPassport> {
    return this.client.post<IssuedPassport>('/v1/passports/refresh', {
      token,
      ttl_seconds: ttlSeconds,
    });
  }

  async listActive(options?: { agentId?: string; sessionId?: string }): Promise<ActivePassport[]> {
    return this.client.get<ActivePassport[]>('/v1/passports/active', {
      agent_id: options?.agentId,
      session_id: options?.sessionId,
    });
  }

  async revokeAgent(agentId: string, reason?: string): Promise<{ success: boolean; revoked_count: number }> {
    return this.client.post(`/v1/passports/revoke-agent/${agentId}`, { reason });
  }

  async revokeSession(sessionId: string, reason?: string): Promise<{ success: boolean; revoked_count: number }> {
    return this.client.post(`/v1/passports/revoke-session/${sessionId}`, { reason });
  }

  async revokeAll(reason?: string): Promise<{ success: boolean; revoked_count: number }> {
    return this.client.post('/v1/passports/revoke-all', { confirm: true, reason });
  }

  // ─── Accountability ─────────────────────────────────────────────
  async checkpoint(jti: string, input: CheckpointInput): Promise<unknown> {
    return this.client.post(`/v1/passports/${jti}/checkpoint`, input);
  }

  async checkout(jti: string, input: CheckoutInput): Promise<unknown> {
    return this.client.post(`/v1/passports/${jti}/checkout`, input);
  }

  /** The passport's report. It reads the record, a controls feature: `ControlsRequiredError` (402) without controls. */
  async getReport(jti: string): Promise<unknown> {
    return this.client.get(`/v1/passports/${jti}/report`);
  }

  async listReviews(options?: { status?: string; page?: string; limit?: string }): Promise<unknown> {
    return this.client.get('/v1/passports/reviews', options);
  }

  /** pass governanceApprovalId (gvr_*) when retrying after a
   * 403 GOVERNANCE_APPROVAL_REQUIRED, once a human approved it on the
   * approval page (the approval_url). */
  async decideReview(
    checkoutId: string,
    decision: { decision: 'approved' | 'blocked'; notes?: string; block_future?: boolean },
    opts?: { governanceApprovalId?: string },
  ): Promise<unknown> {
    return this.client.post(
      `/v1/passports/reviews/${checkoutId}/decide`,
      decision,
      opts?.governanceApprovalId ? { headers: { 'X-Governance-Approval': opts.governanceApprovalId } } : undefined,
    );
  }
}
