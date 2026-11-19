import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { DATA_TRAIL_WINDOW_SECONDS, createDb, operators, passportClaims, type Database } from '@stack/shared';
import { PassportClaimsRepository, MAX_OBSERVED_SOURCES } from './passport-claims-repo.js';
import { resolveVaultFixtureDatabaseUrl } from '../test/dedicated-test-database.js';

// Only the dedicated test database: these fixtures write and delete rows.
const DATABASE_URL = resolveVaultFixtureDatabaseUrl();
const describeWithDb = DATABASE_URL ? describe : describe.skip;

const DAY = 86_400_000;

describeWithDb('what a Mission has read, by Mission and inside the rolling window', () => {
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_flow_${suffix}`;
  const standing = `ms_flow_standing_${suffix}`;
  const other = `ms_flow_other_${suffix}`;
  const now = Date.now();
  let db: Database;
  let repo: PassportClaimsRepository;
  let n = 0;

  const observe = (mission: string, source: string, entity: string, issuedAt: number) =>
    db.insert(passportClaims).values({
      claim_id: `pc_flow_${suffix}_${n++}`, operator_id: operatorId, type: 'entity_observation',
      body_json: { type: 'entity_observation', entities: [entity], content_fingerprints: [`fp_${entity}`], source_service: source, mission_ref: mission },
      claim_hash: `hash_${suffix}_${n}`, signature: 'fixture-signature', issued_at_ms: issuedAt,
    });
  const read = (missionId: string | null, extra: Partial<Parameters<PassportClaimsRepository['findObservedContentForFlow']>[0]> = {}) =>
    repo.findObservedContentForFlow({ operatorId, passportId: null, missionId, now, ...extra });
  const entitiesBySource = (rows: Awaited<ReturnType<typeof read>>) =>
    Object.fromEntries([...new Set(rows.map((r) => r.sourceService))].map((s) => [s, rows.filter((r) => r.sourceService === s).flatMap((r) => r.entities ?? [])]));

  beforeAll(async () => {
    db = createDb(DATABASE_URL!);
    repo = new PassportClaimsRepository(db);
    await db.insert(operators).values({ id: operatorId, email: `${operatorId}@example.test`, api_key_hash: `hash_${operatorId}` });
  });

  afterAll(async () => {
    if (!db) return;
    await db.delete(passportClaims).where(eq(passportClaims.operator_id, operatorId));
    await db.delete(operators).where(eq(operators.id, operatorId));
    await db.$client.end();
  });

  it('reads by Mission, with no Passport, and not another Mission\'s observations', async () => {
    await observe(standing, 'gmail', 'a@x.test', now - 1000);
    await observe(other, 'slack', 'b@x.test', now - 1000);
    expect(entitiesBySource(await read(standing))).toEqual({ gmail: ['a@x.test'] });
  });

  it('drops what was recorded before the window and keeps what is inside it', async () => {
    const windowMs = DATA_TRAIL_WINDOW_SECONDS * 1000;
    await observe(standing, 'old-source', 'old@x.test', now - windowMs - DAY);
    await observe(standing, 'mercury', 'inside@x.test', now - windowMs + DAY);
    await observe(standing, 'mercury', 'older@x.test', now - windowMs - 1000);
    const rows = entitiesBySource(await read(standing));
    expect(rows['old-source']).toBeUndefined();
    expect(rows['mercury']).toEqual(['inside@x.test']);
    expect(rows['gmail']).toEqual(['a@x.test']);
  });

  it('is rolling: reading a source again puts it back on the trail', async () => {
    const windowMs = DATA_TRAIL_WINDOW_SECONDS * 1000;
    await observe(standing, 'old-source', 'old@x.test', now - 1000);
    expect(entitiesBySource(await read(standing))['old-source']).toContain('old@x.test');
    // And it ages out again one window later.
    const later = now + windowMs + 2000;
    expect(entitiesBySource(await read(standing, { now: later }))['old-source']).toBeUndefined();
  });

  it('keeps the newest observations per source, so a busy source cannot evict a quiet one', async () => {
    for (let i = 0; i < 5; i++) await observe(standing, 'chatty', `c${i}@x.test`, now - 5000 + i);
    const rows = await read(standing, { perSourceLimit: 3 });
    expect(rows.filter((r) => r.sourceService === 'chatty').flatMap((r) => r.entities)).toEqual(['c4@x.test', 'c3@x.test', 'c2@x.test']);
    expect(rows.some((r) => r.sourceService === 'gmail')).toBe(true);
  });

  it('counts only sources inside the window toward the source cap, however many went quiet', async () => {
    const windowMs = DATA_TRAIL_WINDOW_SECONDS * 1000;
    const mission = `ms_flow_many_${suffix}`;
    for (let i = 0; i < MAX_OBSERVED_SOURCES + 5; i++) await observe(mission, `quiet-${String(i).padStart(3, '0')}`, `q${i}@x.test`, now - windowMs - DAY);
    await observe(mission, 'live', 'live@x.test', now - 1000);
    expect(entitiesBySource(await read(mission))).toEqual({ live: ['live@x.test'] });
  });

  it('refuses rather than silently dropping when more sources than the cap are inside the window', async () => {
    const mission = `ms_flow_cap_${suffix}`;
    for (let i = 0; i < 4; i++) await observe(mission, `live-${i}`, `l${i}@x.test`, now - 1000);
    await expect(read(mission, { maxSources: 3 })).rejects.toThrow(/more than 3 sources/);
  });

  it('keys an operator-scoped claim on its producer, so a retry returns the claim already written', async () => {
    const claim = (id: string, key: string, role = 'data_trail') => ({
      claim_id: id, passport_id: null, operator_id: operatorId, type: 'entity_observation',
      body_json: { type: 'entity_observation', entities: ['h:00'], source_service: 'stack:account-messages', mission_ref: standing },
      claim_hash: `hash_${id}`, signature: '', subject: `stack://operator/${operatorId}`,
      envelope_version: 1, claim_version: 1, envelope_cose: 'fixture', issuer: operatorId, issued_at_ms: now,
      receipt: null, source_operation_id: key, source_role: role,
    });
    const first = await repo.insertFromSource(claim(`pc_op_${suffix}_a`, `account_message:${suffix}`));
    const retried = await repo.insertFromSource(claim(`pc_op_${suffix}_b`, `account_message:${suffix}`));
    expect(retried.claim_id).toBe(first.claim_id);
    const other = await repo.insertFromSource(claim(`pc_op_${suffix}_c`, `account_message:${suffix}:2`));
    expect(other.claim_id).toBe(`pc_op_${suffix}_c`);
    expect(first.passport_id).toBeNull();
    const rows = await db.select().from(passportClaims).where(eq(passportClaims.operator_id, operatorId));
    expect(rows.filter((row) => row.source_operation_id?.startsWith(`account_message:${suffix}`))).toHaveLength(2);
  });

  it('hands back which entities of an observation are only the request\'s own URL, and null for a row recorded before that', async () => {
    const mission = `ms_flow_own_${suffix}`;
    await db.insert(passportClaims).values({
      claim_id: `pc_flow_${suffix}_own`, operator_id: operatorId, type: 'entity_observation',
      body_json: { type: 'entity_observation', entities: ['h:aa', 'h:bb'], request_entities: ['h:aa'], content_fingerprints: [], source_service: 'openai', mission_ref: mission },
      claim_hash: `hash_${suffix}_own`, signature: 'fixture-signature', issued_at_ms: now - 2000,
    });
    await observe(mission, 'anthropic', 'old-row@x.test', now - 1000);
    const rows = await read(mission);
    expect(rows.find((r) => r.sourceService === 'openai')).toMatchObject({ entities: ['h:aa', 'h:bb'], requestEntities: ['h:aa'] });
    // An old row has none, so every entity of it still counts as read.
    expect(rows.find((r) => r.sourceService === 'anthropic')).toMatchObject({ entities: ['old-row@x.test'], requestEntities: null });
  });

  it('with no Mission falls back to the Passport\'s own observations, or nothing', async () => {
    expect(await read(null)).toEqual([]);
  });
});
