import { ids, NotFoundError, ConflictError, InvalidRequestError } from '@stack/shared';
import type { OauthAppRepository } from '../repositories/oauth-app-repo.js';
import type { KmsService } from '../crypto/kms.js';

/**
 * A directory tenant: an id (GUID), a verified domain, or one of Microsoft's
 * own words. It is put into a URL path, so nothing else is accepted.
 */
const TENANT = /^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$/;

/**
 * An app's tenant has no column of its own, so it travels inside the secret's
 * KMS envelope: the plaintext of an app with one is this marker followed by a
 * JSON object, and the plaintext of an app without one is the bare secret, as
 * every row made before the tenant existed.
 */
const SECRET_WITH_TENANT = 'stack-oauth-app/v1:';

function sealSecret(secret: string, tenant: string | undefined): string {
  return tenant ? `${SECRET_WITH_TENANT}${JSON.stringify({ secret, tenant })}` : secret;
}

function openSecret(plaintext: string): { secret: string; tenant?: string } {
  if (!plaintext.startsWith(SECRET_WITH_TENANT)) return { secret: plaintext };
  try {
    const parsed = JSON.parse(plaintext.slice(SECRET_WITH_TENANT.length)) as { secret?: unknown; tenant?: unknown };
    if (typeof parsed.secret === 'string' && typeof parsed.tenant === 'string' && TENANT.test(parsed.tenant)) {
      return { secret: parsed.secret, tenant: parsed.tenant };
    }
  } catch {
    // A secret that merely begins with the marker is a secret.
  }
  return { secret: plaintext };
}

export class OauthAppService {
  constructor(
    private oauthAppRepo: OauthAppRepository,
    private kms: KmsService,
  ) {}

  async create(
    operatorId: string,
    input: { provider: string; client_id: string; client_secret: string; scopes?: string; tenant?: string },
  ) {
    // Check for existing app for this provider
    const existing = await this.oauthAppRepo.findByOperatorAndProvider(operatorId, input.provider);
    if (existing) {
      throw new ConflictError(`OAuth app already configured for provider '${input.provider}'. Delete it first to reconfigure.`);
    }
    if (input.tenant !== undefined && !TENANT.test(input.tenant)) {
      throw new InvalidRequestError('tenant must be a directory id or domain, such as a GUID or contoso.onmicrosoft.com');
    }

    // Encrypt client_secret via KMS. Bind the envelope to operator+provider so
    // it cannot be transplanted onto another operator's OAuth app row.
    const { ciphertext } = await this.kms.encrypt(sealSecret(input.client_secret, input.tenant), {
      operator_id: operatorId,
      provider: input.provider,
      kind: 'oauth_app',
    });

    const app = await this.oauthAppRepo.create({
      id: ids.oauthApp(),
      operator_id: operatorId,
      provider: input.provider,
      client_id: input.client_id,
      client_secret_encrypted: ciphertext,
      scopes: input.scopes ?? null,
    });

    return {
      id: app.id,
      provider: app.provider,
      client_id: app.client_id,
      scopes: app.scopes,
      created_at: app.created_at,
    };
  }

  async list(operatorId: string) {
    const apps = await this.oauthAppRepo.findByOperator(operatorId);
    return apps.map((app) => ({
      id: app.id,
      provider: app.provider,
      client_id: app.client_id,
      scopes: app.scopes,
      created_at: app.created_at,
      updated_at: app.updated_at,
    }));
  }

  async delete(operatorId: string, provider: string) {
    const deleted = await this.oauthAppRepo.deleteByOperatorAndProvider(operatorId, provider);
    if (!deleted) throw new NotFoundError('OauthApp', provider);
    return { success: true };
  }

  /**
   * Get decrypted OAuth app credentials for a provider.
   * API-internal only. Browser-facing routes must never serialize this value.
   */
  async getDecrypted(operatorId: string, provider: string) {
    const app = await this.oauthAppRepo.findByOperatorAndProvider(operatorId, provider);
    if (!app) return null;

    const plaintext = await this.kms.decrypt(app.client_secret_encrypted, {
      operator_id: operatorId,
      provider,
      kind: 'oauth_app',
    });
    const { secret, tenant } = openSecret(plaintext);
    return {
      id: app.id,
      client_id: app.client_id,
      client_secret: secret,
      ...(tenant ? { tenant } : {}),
      scopes: app.scopes,
    };
  }
}
