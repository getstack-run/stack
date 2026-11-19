import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { auditLog, createDb, hashApiKey, operators, securityEvents } from '@stack/shared';
// The kit is plain JavaScript with no declarations.
// @ts-expect-error TS7016
import * as conformanceKit from '../../../../spec/conformance/src/index.mjs';
import { isDedicatedStackTestDatabase } from '../test/dedicated-test-database.js';
import { SiemExporter, createSinks, dbSiemReader, readSiemConfig } from './siem-export.js';

/**
 * The engine's security-monitoring exporter against the `siem-exporter` suite of the conformance kit
 * (spec/siem-export/SPEC.md): the real exporter, the real reader over a real database and the real sinks send to the
 * collectors the kit plays (a UDP socket, a TCP server, a TLS server and an HTTPS server with a certificate of their
 * own). The harness fills the two tables with rows built from the records the suite hands it, with a planted value in
 * every column the export does not carry, and runs one pass at a time.
 *
 * Needs a dedicated test database (DATABASE_URL, migrated). Redis is stood in for in memory: the exporter keeps its
 * position and its hold on a stream there, and nothing else reads them.
 */

const databaseUrl = process.env['DATABASE_URL'];
const enabled = isDedicatedStackTestDatabase(databaseUrl);

type Report = { results: Array<{ id: string; status: string; level: string; detail?: string }>; conforms: boolean };
type Kit = { runSiemExporterSuite(options: unknown): Promise<Report>; formatReport(report: unknown): string };

class MemoryRedis {
  store = new Map<string, string>();
  async get(key: string) { return this.store.get(key) ?? null; }
  async set(key: string, value: string, ...rest: unknown[]) {
    if (rest.includes('NX') && this.store.has(key)) return null;
    this.store.set(key, value);
    return 'OK';
  }
  async eval(_script: string, _n: number, key: string, token: string) {
    if (this.store.get(key) === token) { this.store.delete(key); return 1; }
    return 0;
  }
}

interface Config { syslog: { url: string } | null; http: { url: string; token: string | null } | null; caPem: string | null; streams: string[]; canary: string }
interface SourceRecord { stream: 'security' | 'audit'; id: string; time: string; severity: string; operator_id: string; agent_id: string; event: string; fields: Record<string, unknown> }

describe.runIf(enabled)('the engine exporter against the siem-exporter conformance suite', { timeout: 600_000 }, () => {
  const db = createDb(databaseUrl!);
  const quiet = { log: vi.fn(), warn: vi.fn() };
  const folder = mkdtempSync(join(tmpdir(), 'siem-conformance-'));
  const kit = conformanceKit as unknown as Kit;

  beforeAll(async () => {
    await db.insert(operators).values({
      id: 'op_conformance', email: `siem-conformance-${Date.now()}@corp.example`, api_key_hash: hashApiKey(`sk_live_${Date.now()}`), tier: 'enterprise', status: 'active',
    } as never).onConflictDoNothing();
  });

  afterAll(async () => {
    await db.execute(sql`delete from security_events where operator_id = 'op_conformance'`);
    await db.execute(sql`delete from audit_log where operator_id = 'op_conformance'`);
    await db.execute(sql`delete from operators where id = 'op_conformance'`);
    rmSync(folder, { recursive: true, force: true });
  });

  async function harness(config: Config) {
    // Nothing of an earlier scenario is in the tables when a new exporter starts.
    await db.execute(sql`delete from security_events where operator_id = 'op_conformance'`);
    await db.execute(sql`delete from audit_log where operator_id = 'op_conformance'`);
    const env: Record<string, string> = { STACK_SIEM_STREAMS: config.streams.join(',') };
    if (config.syslog) env['STACK_SIEM_SYSLOG_URL'] = config.syslog.url;
    if (config.http) {
      env['STACK_SIEM_HTTP_URL'] = config.http.url;
      if (config.http.token) env['STACK_SIEM_HTTP_TOKEN'] = config.http.token;
    }
    if (config.caPem) {
      const file = join(folder, `ca-${Math.random().toString(36).slice(2)}.pem`);
      writeFileSync(file, config.caPem);
      env['STACK_SIEM_TLS_CA_FILE'] = file;
    }
    const siemConfig = readSiemConfig(env)!;
    const exporter = new SiemExporter({
      config: siemConfig,
      reader: dbSiemReader(db),
      redis: new MemoryRedis() as never,
      features: { has: () => true },
      sinks: createSinks(siemConfig),
      // The settling delay is read against a clock an hour on, so a row written after the first pass is old enough at the next.
      now: () => new Date(Date.now() + 3_600_000),
      log: quiet,
    });
    return {
      async emit(records: SourceRecord[]) {
        // The rows stand for what the engine wrote. The Mission and the claims they point at are not the point of this test, so
        // the harness writes them with the database's foreign key checks off for the one transaction.
        await db.transaction(async (tx) => {
          await tx.execute(sql`set local session_replication_role = replica`);
          for (const record of records) {
            if (record.stream === 'security') {
              await tx.insert(securityEvents).values({
                id: record.id,
                operator_id: record.operator_id,
                agent_id: record.agent_id,
                passport_jti: record.fields['passport_jti'] as string | null,
                mission_id: record.fields['mission_id'] as string | null,
                signal_type: record.event,
                severity: record.severity,
                message: record.fields['message'] as string,
                metadata: record.fields['metadata'] as Record<string, unknown> | null,
                resolved: record.fields['resolved'] as boolean,
                resolved_by: config.canary,
                created_at: new Date(record.time),
              });
            } else {
              await tx.insert(auditLog).values({
                entry_id: record.id,
                trace_id: record.fields['trace_id'] as string,
                span_id: 'span_conformance',
                timestamp: Date.parse(record.time),
                operator_id: record.operator_id,
                agent_id: record.agent_id,
                passport_jti: record.fields['passport_jti'] as string,
                layer: record.fields['layer'] as string,
                action: record.event,
                outcome: record.fields['outcome'] as string,
                error_code: record.fields['error_code'] as string | null,
                prev_entry_hash: 'prev_conformance',
                entry_hash: record.fields['entry_hash'] as string,
                claim_binding_status: 'not_applicable',
                // The columns the export does not carry, each with the planted value.
                payload_hash: config.canary,
                error_message: config.canary,
              });
            }
          }
        });
      },
      async pass() { await exporter.pass(); },
    };
  }

  it('conforms: a record is one RFC 5424 message or one line, framed as the specification says, delivered at least once and in order, with nothing a row holds outside the public fields', async () => {
    const report = await kit.runSiemExporterSuite({ exporter: harness });
    const notPassed = report.results.filter((r) => r.status !== 'pass');
    expect(notPassed, kit.formatReport(report)).toEqual([]);
    expect(report.results.length).toBe(15);
    expect(report.conforms).toBe(true);
  });
});
