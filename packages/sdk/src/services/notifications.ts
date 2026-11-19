import type { HttpClient } from '../client.js';
import type { NotificationRule, CreateNotificationRuleInput, UpdateNotificationRuleInput } from '../types.js';

export class NotificationService {
  constructor(private client: HttpClient) {}

  async createRule(input: CreateNotificationRuleInput): Promise<NotificationRule> {
    return this.client.post<NotificationRule>('/v1/notifications/channels', input);
  }

  async listRules(): Promise<NotificationRule[]> {
    return this.client.get<NotificationRule[]>('/v1/notifications/channels');
  }

  async updateRule(id: string, input: UpdateNotificationRuleInput): Promise<NotificationRule> {
    return this.client.patch<NotificationRule>(`/v1/notifications/channels/${id}`, input);
  }

  async deleteRule(id: string): Promise<{ deleted: boolean }> {
    return this.client.delete<{ deleted: boolean }>(`/v1/notifications/channels/${id}`);
  }

  /** @deprecated Use DeliveryMethodService instead */
  async sendVerificationCode(id: string): Promise<{ sent: boolean }> {
    return this.client.post(`/v1/notifications/channels/${id}/send-code`);
  }

  /** @deprecated Use DeliveryMethodService instead */
  async verify(id: string, code: string): Promise<{ verified: boolean; error?: string }> {
    return this.client.post(`/v1/notifications/channels/${id}/verify`, { code });
  }

  /** @deprecated Use DeliveryMethodService instead */
  async test(id: string): Promise<{ sent: boolean; error?: string }> {
    return this.client.post(`/v1/notifications/channels/${id}/test`);
  }
}
