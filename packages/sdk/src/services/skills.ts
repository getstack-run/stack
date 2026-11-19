import type { HttpClient } from '../client.js';
import type {
  Skill,
  PublishSkillInput,
  BrowseSkillsQuery,
  SkillInvocation,
  InvokeSkillInput,
  SkillRequest,
  PostSkillRequestInput,
} from '../types.js';
import { authorityRequestHeaders } from '../authority-request.js';

export interface InvokeSkillOptions {
  approvalId?: string;
  /** Stable, high-entropy runtime correlation id. Reuse it for exact retries. */
  authorityRequestId?: string;
  /** Required for paid calls unless authorityRequestId supplies the same role. */
  idempotencyKey?: string;
}

export class SkillService {
  constructor(private client: HttpClient) {}

  // ─── Publishing ───────────────────────────────────────────────────
  async publish(input: PublishSkillInput): Promise<Skill> {
    return this.client.post<Skill>('/v1/skills', input);
  }

  async get(id: string): Promise<Skill> {
    return this.client.get<Skill>(`/v1/skills/${id}`);
  }

  async browse(query?: BrowseSkillsQuery): Promise<Skill[]> {
    return this.client.get<Skill[]>('/v1/skills', query as Record<string, string | undefined>);
  }

  async listOwned(): Promise<Skill[]> {
    return this.client.get<Skill[]>('/v1/skills/mine');
  }

  async update(id: string, input: Partial<PublishSkillInput>): Promise<Skill> {
    return this.client.patch<Skill>(`/v1/skills/${id}`, input);
  }

  async suspend(id: string): Promise<Skill> {
    return this.client.post<Skill>(`/v1/skills/${id}/suspend`);
  }

  async activate(id: string): Promise<Skill> {
    return this.client.post<Skill>(`/v1/skills/${id}/activate`);
  }

  async checkTrust(id: string): Promise<unknown> {
    return this.client.post(`/v1/skills/${id}/check-trust`, {});
  }

  // ─── Invocations ──────────────────────────────────────────────────
  /**
   * Invoke a skill.
   *
   * @param skillId - target skill (sk_*)
   * @param input - skill input (validated server-side against the
   *   skill's schema), plus optional `payment_token` for one-shot
   *   paid invocations.
   * @param options - per-call options:
   *   - `approvalId`: approval id from `intents.submitAndWait`
   *     . Sent as `X-Intent-Approval-Id`. Required
   *     when the calling agent is in enforced mode.
   */
  async invoke(
    skillId: string,
    input: InvokeSkillInput & { payment_token?: string },
    options?: InvokeSkillOptions,
  ): Promise<SkillInvocation> {
    const headers: Record<string, string> = authorityRequestHeaders(options?.authorityRequestId);
    if (options?.approvalId) headers['X-Intent-Approval-Id'] = options.approvalId;
    if (options?.idempotencyKey) headers['Idempotency-Key'] = options.idempotencyKey;
    return this.client.post<SkillInvocation>(
      `/v1/skills/${skillId}/invoke`,
      input,
      Object.keys(headers).length > 0 ? { headers } : undefined,
    );
  }

  async getInvocation(invocationId: string): Promise<SkillInvocation> {
    return this.client.get<SkillInvocation>(`/v1/skills/invocations/${invocationId}`);
  }

  async listInvocations(): Promise<SkillInvocation[]> {
    return this.client.get<SkillInvocation[]>('/v1/skills/invocations/mine');
  }

  async listPendingInvocations(skillId?: string): Promise<SkillInvocation[]> {
    return this.client.get<SkillInvocation[]>('/v1/skills/invocations/pending', {
      skill_id: skillId,
    });
  }

  async claimInvocation(invocationId: string): Promise<{ id: string; skill_id: string; input: Record<string, unknown> }> {
    return this.client.post(`/v1/skills/invocations/${invocationId}/claim`);
  }

  async completeInvocation(invocationId: string, output: Record<string, unknown>): Promise<unknown> {
    return this.client.post(`/v1/skills/invocations/${invocationId}/complete`, { output });
  }

  async failInvocation(
    invocationId: string,
    error: { code: string; message: string },
  ): Promise<unknown> {
    return this.client.post(`/v1/skills/invocations/${invocationId}/fail`, { error });
  }

  // ─── Polling helper ───────────────────────────────────────────────
  async poll(invocationId: string, options?: { intervalMs?: number; timeoutMs?: number }): Promise<SkillInvocation> {
    const interval = options?.intervalMs ?? 1000;
    const timeout = options?.timeoutMs ?? 60_000;
    const start = Date.now();

    while (Date.now() - start < timeout) {
      const result = await this.getInvocation(invocationId);
      if (result.status === 'completed' || result.status === 'failed' || result.status === 'expired') {
        return result;
      }
      await new Promise(resolve => setTimeout(resolve, interval));
    }

    throw new Error(`Invocation ${invocationId} timed out after ${timeout}ms`);
  }

  // ─── Requests ─────────────────────────────────────────────────────
  async postRequest(input: PostSkillRequestInput): Promise<SkillRequest> {
    return this.client.post<SkillRequest>('/v1/skill-requests', input);
  }

  async listRequests(query?: { status?: string; limit?: string; offset?: string }): Promise<SkillRequest[]> {
    return this.client.get<SkillRequest[]>('/v1/skill-requests', query);
  }

  async getRequest(id: string): Promise<SkillRequest> {
    return this.client.get<SkillRequest>(`/v1/skill-requests/${id}`);
  }

  async getRequestMatches(id: string): Promise<unknown> {
    return this.client.get(`/v1/skill-requests/${id}/matches`);
  }

  async suggestComposition(id: string): Promise<unknown> {
    return this.client.get(`/v1/skill-requests/${id}/suggest`);
  }
}
