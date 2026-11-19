// The rows of the inbound webhooks a deployment manages itself (a provider whose deliveries it takes: RentAHuman's events). Made, given
// their provider's signing secret and ended without the receiver, the entitlements or the detector, so a process that only keeps those
// rows (the worker, which registers an endpoint again after RentAHuman refused it) builds this and not the whole inbound service.

import { Buffer } from 'node:buffer';
import { NotFoundError, generateWebhookSecret, ids } from '@stack/shared';
import type { KmsService } from '../crypto/kms.js';
import type { InboundWebhookRepository } from '../repositories/inbound-webhook-repo.js';

export interface ManagedInboundWebhooksDeps {
  repo: Pick<InboundWebhookRepository, 'insert' | 'findByIdScoped' | 'setProviderSigningSecret' | 'revoke'>;
  kms: Pick<KmsService, 'encryptDirect'>;
  /** Base URL of the public receiver. Eg. https://api.getstack.run */
  baseUrl: string;
}

export class ManagedInboundWebhooks {
  constructor(private readonly deps: ManagedInboundWebhooksDeps) {}

  /** A row for a provider the deployment takes the deliveries of. Returns the URL to register with the provider. */
  async create(operatorId: string, provider: string): Promise<{ id: string; slug: string; webhook_url: string }> {
    const id = ids.inboundWebhook();
    const slug = ids.inboundWebhookSlug();
    const downstream = generateWebhookSecret();
    const sealed = await this.deps.kms.encryptDirect(Buffer.from(downstream, 'utf8'), {
      operatorId,
      context: { operator_id: operatorId, webhook_id: id, purpose: 'inbound_webhook_downstream_secret' },
    });
    const row = await this.deps.repo.insert({
      id, operator_id: operatorId, provider, slug, forward_url: null,
      webhook_secret_encrypted: sealed.toString('base64'), provider_signing_secret_encrypted: null, agent_id: null,
    });
    return { id: row.id, slug: row.slug, webhook_url: `${this.deps.baseUrl}/v1/inbound/${row.provider}/${row.slug}` };
  }

  /** The secret the provider signs this row's deliveries with, sealed under the row's own context. */
  async setSecret(id: string, operatorId: string, secret: string): Promise<void> {
    const row = await this.deps.repo.findByIdScoped(id, operatorId);
    if (!row || row.revoked_at) throw new NotFoundError('inbound_webhook', id);
    const sealed = await this.deps.kms.encryptDirect(Buffer.from(secret, 'utf8'), {
      operatorId,
      context: { operator_id: operatorId, webhook_id: id, purpose: 'inbound_provider_signing_secret' },
    });
    if (!await this.deps.repo.setProviderSigningSecret(id, operatorId, sealed.toString('base64'), row.provider)) {
      throw new NotFoundError('inbound_webhook', id);
    }
  }

  /** End a row: deliveries to it are 404 from now on. Idempotent. */
  async revoke(id: string, operatorId: string): Promise<void> {
    const row = await this.deps.repo.findByIdScoped(id, operatorId);
    if (!row) throw new NotFoundError('inbound_webhook', id);
    await this.deps.repo.revoke(id, operatorId);
  }
}
