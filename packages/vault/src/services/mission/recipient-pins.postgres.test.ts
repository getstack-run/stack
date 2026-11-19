import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq, inArray } from 'drizzle-orm';
import { createDb, mergeRecipientPins, missions, operators, passportClaims, readRecipientPins, type Database } from '@stack/shared';
import { MissionRepository } from '../../repositories/mission-repo.js';
import { resolveVaultFixtureDatabaseUrl } from '../../test/dedicated-test-database.js';
import { rowToView } from './helpers.js';
import { MissionRecipientPinReader } from './recipient-pins.js';

// Only the dedicated test database: these fixtures write and delete rows.
const DATABASE_URL = resolveVaultFixtureDatabaseUrl();
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('a Mission\'s recipient pins in PostgreSQL', () => {
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_pins_${suffix}`;
  const otherOperatorId = `op_pins_other_${suffix}`;
  const pinned = `ms_pins_${suffix}`;
  const unpinned = `ms_pins_none_${suffix}`;
  const claimIds = [`pc_pins_${suffix}`, `pc_pins_none_${suffix}`];
  const pins = [{ path: '*', op: 'in' as const, value: ['ana@example.com'] }, { path: 'url.pathname', op: 'eq' as const, value: '/api/v10/channels/1/messages' }];
  let db: Database;
  let repo: MissionRepository;

  beforeAll(async () => {
    db = createDb(DATABASE_URL!);
    repo = new MissionRepository(db);
    for (const id of [operatorId, otherOperatorId]) {
      await db.insert(operators).values({ id, email: `${id}@example.test`, api_key_hash: `hash_${id}` });
    }
    for (const [missionId, claimId, recipientPins] of [[pinned, claimIds[0]!, pins], [unpinned, claimIds[1]!, null]] as const) {
      await db.insert(passportClaims).values({ claim_id: claimId, operator_id: operatorId, type: 'mission', body_json: {}, claim_hash: `hash_${claimId}`, signature: 'fixture-signature' });
      await db.insert(missions).values({
        mission_id: missionId, operator_id: operatorId, claim_id: claimId, intent_summary: 'Pins fixture',
        recipient_pins: recipientPins, expires_at: new Date(Date.now() + 600_000),
      });
    }
  });

  afterAll(async () => {
    await db.delete(missions).where(inArray(missions.mission_id, [pinned, unpinned]));
    await db.delete(passportClaims).where(inArray(passportClaims.claim_id, claimIds));
    await db.delete(operators).where(inArray(operators.id, [operatorId, otherOperatorId]));
  });

  it('keeps the pins as jsonb and reads them back on the view, null for a Mission with none', async () => {
    expect(rowToView((await repo.findById(pinned))!).recipient_pins).toEqual(pins);
    expect(rowToView((await repo.findById(unpinned))!).recipient_pins).toBeNull();
  });

  it('reads them for the operator that owns the Mission and for no other', async () => {
    const reader = new MissionRecipientPinReader(repo);
    const nobody = { pins: null, assignedAgentId: null };
    expect(await reader.read(operatorId, pinned)).toEqual({ pins, assignedAgentId: null });
    expect(await reader.read(operatorId, unpinned)).toEqual(nobody);
    expect(await reader.read(otherOperatorId, pinned)).toEqual(nobody);
    expect(await reader.read(operatorId, `ms_missing_${suffix}`)).toEqual(nobody);
  });

  it('adds recipients to a live Mission by merging them into its pins, and a reader that forgets reads them again', async () => {
    const reader = new MissionRecipientPinReader(repo);
    expect((await reader.read(operatorId, unpinned)).pins).toBeNull();
    const added = await repo.updateRecipientPins(operatorId, unpinned, (current) =>
      mergeRecipientPins(readRecipientPins(current), [{ path: '*', op: 'in', value: ['bob@example.com'] }]));
    expect(added.status).toBe('updated');
    const again = await repo.updateRecipientPins(operatorId, unpinned, (current) =>
      mergeRecipientPins(readRecipientPins(current), [{ path: '*', op: 'in', value: ['cy@example.com'] }, { path: 'body.cc', op: 'eq', value: 'dee@example.com' }]));
    expect(again.status === 'updated' ? again.row.recipient_pins : null).toEqual([
      { path: '*', op: 'in', value: ['bob@example.com', 'cy@example.com'] },
      { path: 'body.cc', op: 'eq', value: 'dee@example.com' },
    ]);
    // What this machine read before is kept until it is told the pins changed.
    expect((await reader.read(operatorId, unpinned)).pins).toBeNull();
    reader.forget(operatorId, unpinned);
    expect((await reader.read(operatorId, unpinned)).pins).toHaveLength(2);
    // Another operator's Mission reads as missing, and changes nothing.
    expect(await repo.updateRecipientPins(otherOperatorId, unpinned, () => [])).toEqual({ status: 'missing' });
  });

  it('is not touched by a Mission\'s lifecycle: completing it leaves the pins as they were', async () => {
    await db.update(missions).set({ completed_at: new Date(), terminal_state: 'completed_successful' }).where(eq(missions.mission_id, pinned));
    expect(rowToView((await repo.findById(pinned))!).recipient_pins).toEqual(pins);
  });

  it('refuses to change the pins of a Mission that has ended', async () => {
    expect(await repo.updateRecipientPins(operatorId, pinned, () => [])).toEqual({ status: 'ended' });
  });
});
