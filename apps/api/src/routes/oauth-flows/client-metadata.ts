import { eq } from 'drizzle-orm';
import { oauthClients } from '@stack/shared';
import type { Services } from '../../config/services.js';
import type { ClientMetadataDocument } from '../../lib/oauth-cimd.js';

// ─── Client ID Metadata Document persistence ────────────────────────

/**
 * Store (or refresh) the oauth_clients row for a validated metadata-document
 * client. Authorization codes and refresh tokens reference oauth_clients by
 * foreign key, so URL clients need a row like any other. Returns undefined
 * when a row with this id exists but was not created from a metadata
 * document; such a row is never overwritten.
 */
export async function persistMetadataClient(
  db: Services['db'],
  doc: ClientMetadataDocument,
): Promise<{ redirect_uris: string[] } | undefined> {
  const existing = await db.query.oauthClients.findFirst({ where: eq(oauthClients.id, doc.client_id) });
  if (existing && existing.metadata_url !== doc.client_id) return undefined;
  const values = {
    client_secret_hash: null,
    client_type: 'public',
    client_name: doc.client_name,
    redirect_uris: doc.redirect_uris,
    grant_types: doc.grant_types,
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    metadata_url: doc.client_id,
    updated_at: new Date(),
  };
  if (existing) {
    await db.update(oauthClients).set(values).where(eq(oauthClients.id, doc.client_id));
  } else {
    await db
      .insert(oauthClients)
      .values({ id: doc.client_id, operator_id: null, scope: null, software_id: null, software_version: null, ...values })
      .onConflictDoUpdate({ target: oauthClients.id, set: values, where: eq(oauthClients.metadata_url, doc.client_id) });
  }
  return { redirect_uris: doc.redirect_uris };
}
