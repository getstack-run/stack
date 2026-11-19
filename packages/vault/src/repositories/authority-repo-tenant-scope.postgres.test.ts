import { randomUUID } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { describe, expect, it } from 'vitest';
import { authorityProfileVersions, createDb, operators, type Database } from '@stack/shared';
import { AuthorityRepository } from './authority-repo.js';
import { isDedicatedVaultTestDatabase } from '../test/dedicated-test-database.js';

const databaseUrl = process.env['DATABASE_URL'];
const suite = isDedicatedVaultTestDatabase(databaseUrl) ? describe : describe.skip;

/**
 * Thrown at the end of the transaction so everything the test wrote is rolled
 * back. Authority profile versions are immutable at the database level (the
 * guard trigger refuses DELETE outside an operator erasure), so a test cannot
 * clean up by deleting its rows; it must never commit them.
 */
const ROLLBACK = Symbol('rollback');

suite('authority repository tenant scoping in PostgreSQL', () => {
  it('activates a profile version only for the operator that owns it', async () => {
    const db = createDb(databaseUrl!);
    const suffix = randomUUID();
    const owner = `op_profile_owner_${suffix}`;
    const other = `op_profile_other_${suffix}`;
    const profileId = `apv_scope_${suffix}`;
    try {
      const outcome = await db
        .transaction(async (tx) => {
          await tx.insert(operators).values([
            { id: owner, email: `${owner}@test.invalid`, api_key_hash: randomUUID() },
            { id: other, email: `${other}@test.invalid`, api_key_hash: randomUUID() },
          ]);
          await tx.insert(authorityProfileVersions).values({
            id: profileId,
            owner_operator_id: owner,
            profile_kind: 'proof',
            profile_key: `scope_${suffix}`,
            version: 1,
            schema_uri: 'https://example.test/schema',
            schema_version: '1',
            adapter_key: 'test',
            adapter_version: 1,
            config_json: {},
            content_hash: `sha256:${suffix}`,
            status: 'draft',
          });
          const repo = new AuthorityRepository(tx as unknown as Database, tx);
          const now = new Date();
          await expect(repo.activateProfileVersion(other, 'proof', profileId, now)).resolves.toBeNull();
          await expect(repo.activateProfileVersion(owner, 'domain', profileId, now)).resolves.toBeNull();
          const [untouched] = await tx.select().from(authorityProfileVersions)
            .where(eq(authorityProfileVersions.id, profileId));
          expect(untouched?.status).toBe('draft');
          expect(untouched?.activated_at).toBeNull();

          const activated = await repo.activateProfileVersion(owner, 'proof', profileId, now);
          expect(activated?.status).toBe('active');
          expect(activated?.owner_operator_id).toBe(owner);
          throw ROLLBACK;
        })
        .catch((error: unknown) => error);
      expect(outcome).toBe(ROLLBACK);
      const [leftover] = await db.select().from(authorityProfileVersions)
        .where(eq(authorityProfileVersions.id, profileId));
      expect(leftover).toBeUndefined();
    } finally {
      await db.$client.end();
    }
  });
});
