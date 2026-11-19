import type { HttpClient } from '../client.js';
import type { SecurityEvent } from '../types.js';

export class SecurityEventService {
  constructor(private client: HttpClient) {}

  async list(options?: { agentId?: string; page?: string; limit?: string }): Promise<{
    events: SecurityEvent[];
    unresolved_count: number;
    page: number;
    limit: number;
  }> {
    return this.client.get('/v1/security-events', {
      agent_id: options?.agentId,
      page: options?.page,
      limit: options?.limit,
    });
  }

  async get(id: string): Promise<SecurityEvent> {
    return this.client.get<SecurityEvent>(`/v1/security-events/${id}`);
  }

  async resolve(id: string): Promise<{ resolved: boolean; id: string }> {
    return this.client.post(`/v1/security-events/${id}/resolve`);
  }
}
