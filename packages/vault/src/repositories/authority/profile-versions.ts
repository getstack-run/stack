import { and, eq, inArray, isNull, or, sql } from 'drizzle-orm';
import { authorityProfileVersions, authorityReceivers } from '@stack/shared';
import type {
  AuthorityProofProfileVersionRecord,
  AuthorityReceiverProfileRecord,
} from '../../services/authority/records.js';
import { AuthorityAggregateRepository } from './context.js';

/** Versioned proof, domain and receiver profiles, and activation of a profile version. */
export class AuthorityProfileVersionRepository extends AuthorityAggregateRepository {
  async findProofProfileVersion(operatorId: string, id: string) {
    const [row] = await this.db.select().from(authorityProfileVersions).where(and(
      eq(authorityProfileVersions.id, id), eq(authorityProfileVersions.profile_kind, 'proof'),
      or(eq(authorityProfileVersions.owner_operator_id, operatorId), isNull(authorityProfileVersions.owner_operator_id)),
    )).limit(1);
    if (!row) return null;
    const config = row.config_json;
    return {
      id: row.id, operator_id: row.owner_operator_id, proof_kind: String(config.proof_kind),
      schema_uri: row.schema_uri, schema_version: row.schema_version, adapter_key: row.adapter_key,
      adapter_version: row.adapter_version, accepted_native_formats: config.accepted_native_formats as string[],
      status: row.status as AuthorityProofProfileVersionRecord['status'], content_hash: row.content_hash, config_json: config,
    };
  }

  async findReceiverProfile(operatorId: string, profileId: string) {
    const [row] = await this.db.select().from(authorityProfileVersions).where(and(
      eq(authorityProfileVersions.id, profileId), eq(authorityProfileVersions.profile_kind, 'receiver'),
      eq(authorityProfileVersions.owner_operator_id, operatorId),
    )).limit(1);
    if (!row || !row.receiver_id) return null;
    const config = row.config_json;
    return {
      id: row.id, receiver_id: row.receiver_id, status: row.status as AuthorityReceiverProfileRecord['status'],
      content_hash: row.content_hash, audience: String(config.audience),
      delivery_endpoint: config.delivery && typeof config.delivery === 'object'
        ? String((config.delivery as Record<string, unknown>).endpoint)
        : null,
      config_json: config,
      profile_key: row.profile_key, version: row.version, schema_uri: row.schema_uri, schema_version: row.schema_version,
      adapter_key: row.adapter_key, adapter_version: row.adapter_version,
    };
  }

  async insertProfileVersion(row: typeof authorityProfileVersions.$inferInsert) {
    const [created] = await this.db.insert(authorityProfileVersions).values(row).returning();
    return created!;
  }

  async findProfileVersion(operatorId: string, kind: 'proof' | 'domain' | 'receiver', id: string) {
    const [row] = await this.db.select().from(authorityProfileVersions).where(and(
      eq(authorityProfileVersions.id, id), eq(authorityProfileVersions.profile_kind, kind),
      or(eq(authorityProfileVersions.owner_operator_id, operatorId), isNull(authorityProfileVersions.owner_operator_id)),
    )).limit(1);
    return row ?? null;
  }

  async activateProfileVersion(operatorId: string, kind: 'proof' | 'domain' | 'receiver', id: string, now: Date) {
    return this.db.transaction(async (tx) => {
      const [profile] = await tx.select().from(authorityProfileVersions).where(and(
        eq(authorityProfileVersions.id, id), eq(authorityProfileVersions.profile_kind, kind),
        eq(authorityProfileVersions.owner_operator_id, operatorId), inArray(authorityProfileVersions.status, ['draft', 'active']),
      )).limit(1);
      if (!profile) return null;
      await tx.update(authorityProfileVersions).set({ status: 'retired', retired_at: now }).where(and(
        eq(authorityProfileVersions.owner_operator_id, operatorId), eq(authorityProfileVersions.profile_kind, kind),
        eq(authorityProfileVersions.profile_key, profile.profile_key), eq(authorityProfileVersions.status, 'active'),
        sql`${authorityProfileVersions.id} <> ${id}`,
      ));
      const [active] = await tx.update(authorityProfileVersions).set({ status: 'active', activated_at: now })
        .where(and(
          eq(authorityProfileVersions.id, id), eq(authorityProfileVersions.profile_kind, kind),
          eq(authorityProfileVersions.owner_operator_id, operatorId),
        )).returning();
      if (kind === 'receiver' && profile.receiver_id) await tx.update(authorityReceivers).set({
        current_profile_version_id: id,
        status: sql`case when ${authorityReceivers.verified_at} is null then 'pending' else 'active' end`,
      }).where(and(eq(authorityReceivers.id, profile.receiver_id), eq(authorityReceivers.managed_by_operator_id, operatorId)));
      return active ?? null;
    });
  }
}
