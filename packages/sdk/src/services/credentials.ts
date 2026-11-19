import type { HttpClient } from '../client.js';
import type { CredentialResult } from '../types.js';

export class CredentialService {
  constructor(private client: HttpClient) {}

  /** The credential of a provider. When the provider has several connections, `connection` (a name, any case, or an `scon_` id) picks one. */
  async get(provider: string, connection?: string): Promise<CredentialResult> {
    return this.client.get<CredentialResult>(`/v1/credentials/${provider}`, connection !== undefined ? { connection } : undefined);
  }

  async getByConnection(connectionId: string): Promise<CredentialResult> {
    return this.client.get<CredentialResult>(`/v1/credentials/by-connection/${connectionId}`);
  }
}
