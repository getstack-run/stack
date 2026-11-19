import { afterAll, describe, expect, it } from 'vitest';
import { sql } from 'drizzle-orm';
import { createDb } from '@stack/shared';
import { DropoffRepository } from '../repositories/dropoff-repo.js';
import { DropoffService } from './dropoff-service.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDatabase = DATABASE_URL ? describe : describe.skip;

class ExpectedRollback extends Error {}

describeWithDatabase('pre-0069 drop-off expiry compatibility', () => {
  const db = createDb(DATABASE_URL!);
  afterAll(async () => db.$client.end({ timeout: 5 }));

  it('expires and purges a legacy row without selecting or decrypting its payload', async () => {
    let cryptoCalls = 0;
    const crypto = {
      async encrypt() { cryptoCalls += 1; throw new Error('must not encrypt'); },
      async decrypt() { cryptoCalls += 1; throw new Error('must not decrypt'); },
    };
    const suffix = Math.random().toString(36).slice(2);
    const schemaName = `dropoff_pre0069_${suffix}`;

    await expect(db.transaction(async (tx) => {
      await tx.execute(sql.raw(`CREATE SCHEMA "${schemaName}"`));
      await tx.execute(sql.raw(`SET LOCAL search_path TO "${schemaName}"`));
      await tx.execute(sql.raw(`
        CREATE TABLE dropoffs (
          id text PRIMARY KEY,
          operator_id text NOT NULL,
          from_agent_id text NOT NULL,
          to_agent_id text NOT NULL,
          schema jsonb NOT NULL,
          status text NOT NULL,
          on_expire text NOT NULL,
          payload_hash text,
          payload_encrypted text,
          deposited_bytes bigint NOT NULL DEFAULT 0,
          created_at timestamptz NOT NULL DEFAULT now(),
          deposited_at timestamptz,
          collected_at timestamptz,
          expires_at timestamptz NOT NULL,
          mission_id text
        )
      `));
      await tx.execute(sql.raw(`
        INSERT INTO dropoffs (
          id, operator_id, from_agent_id, to_agent_id, schema, status,
          on_expire, payload_hash, payload_encrypted, deposited_at, expires_at
        ) VALUES (
          'dof_synthetic', 'op_synthetic', 'agt_from_synthetic', 'agt_to_synthetic',
          '{"type":"object"}', 'deposited', 'notify', 'synthetic-hash',
          'synthetic-envelope', now() - interval '2 hours', now() - interval '1 hour'
        )
      `));

      const service = new DropoffService(new DropoffRepository(db), crypto);
      const expired = await service.expireOverdue(tx, 10);
      expect(expired).toHaveLength(1);
      expect(expired[0]).toMatchObject({ id: 'dof_synthetic', status: 'expired' });
      expect(cryptoCalls).toBe(0);
      const result = await tx.execute(sql.raw(
        `SELECT status, payload_encrypted FROM dropoffs WHERE id = 'dof_synthetic'`,
      ));
      expect([...result]).toEqual([{ status: 'expired', payload_encrypted: null }]);
      throw new ExpectedRollback('rollback isolated compatibility fixture');
    })).rejects.toBeInstanceOf(ExpectedRollback);
  });
});
