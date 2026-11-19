import type { HttpClient } from '../client.js';
import type { DeliveryMethod, AddDeliveryMethodInput } from '../types.js';

export class DeliveryMethodService {
  constructor(private client: HttpClient) {}

  private approvalOptions(governanceApprovalId?: string) {
    return governanceApprovalId
      ? { headers: { 'X-Governance-Approval': governanceApprovalId } }
      : undefined;
  }

  async add(
    input: AddDeliveryMethodInput,
    opts?: { governanceApprovalId?: string },
  ): Promise<DeliveryMethod> {
    return this.client.post<DeliveryMethod>(
      '/v1/notifications/destinations',
      input,
      this.approvalOptions(opts?.governanceApprovalId),
    );
  }

  async list(): Promise<DeliveryMethod[]> {
    return this.client.get<DeliveryMethod[]>('/v1/notifications/destinations');
  }

  async delete(
    id: string,
    opts?: { governanceApprovalId?: string },
  ): Promise<{ deleted: boolean }> {
    return this.client.delete<{ deleted: boolean }>(
      `/v1/notifications/destinations/${id}`,
      this.approvalOptions(opts?.governanceApprovalId),
    );
  }

  async rotateSecret(
    id: string,
    opts?: { governanceApprovalId?: string },
  ): Promise<DeliveryMethod & { webhook_secret: string }> {
    return this.client.post<DeliveryMethod & { webhook_secret: string }>(
      `/v1/notifications/destinations/${id}/rotate-secret`,
      undefined,
      this.approvalOptions(opts?.governanceApprovalId),
    );
  }

  async sendVerificationCode(
    id: string,
    opts?: { governanceApprovalId?: string },
  ): Promise<{ sent: boolean }> {
    return this.client.post(
      `/v1/notifications/destinations/${id}/send-code`,
      undefined,
      this.approvalOptions(opts?.governanceApprovalId),
    );
  }

  async verify(
    id: string,
    code: string,
    opts?: { governanceApprovalId?: string },
  ): Promise<{ verified: boolean; error?: string }> {
    return this.client.post(
      `/v1/notifications/destinations/${id}/verify`,
      { code },
      this.approvalOptions(opts?.governanceApprovalId),
    );
  }

  async test(
    id: string,
    opts?: { governanceApprovalId?: string },
  ): Promise<{ sent: boolean; error?: string }> {
    return this.client.post(
      `/v1/notifications/destinations/${id}/test`,
      undefined,
      this.approvalOptions(opts?.governanceApprovalId),
    );
  }
}
