import { createSocket } from 'node:dgram';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect as netConnect, isIP, type Socket } from 'node:net';
import { connect as tlsConnect, rootCertificates } from 'node:tls';
import {
  SIEM_BATCH_SIZE,
  SIEM_DEFAULT_SYSLOG_PORT,
  SIEM_DEFAULT_SYSLOG_TLS_PORT,
  SIEM_HTTP_CONTENT_TYPE,
  SIEM_LOCK_SECONDS,
  SIEM_PASS_INTERVAL_SECONDS,
  SIEM_SETTLE_SECONDS,
  SIEM_SINK_TIMEOUT_SECONDS,
  SIEM_SYSLOG_APP_NAME,
  SIEM_SYSLOG_FACILITY,
  SIEM_SYSLOG_HOSTNAME,
  SIEM_SYSLOG_MAX_BYTES,
  SIEM_SYSLOG_SD_ID,
  SIEM_SYSLOG_SEVERITY,
  auditLog,
  securityEvents,
  type Database,
  type SiemStream,
} from '@stack/shared';
import { asc, sql } from 'drizzle-orm';
import type { FeatureGate } from './licence-service.js';
import type { RedisClient } from './wiring/infra.js';

/**
 * Security-monitoring connector: STACK's own record, sent to the customer's
 * collector. A licensed feature of a self-managed install (`siem`).
 *
 * Two streams can be exported, each as it happens:
 *
 *   security  the security events the detectors and signals raise
 *   audit     the audit log's rows (the hash-chained record of what ran)
 *
 * and each can go to a syslog collector (RFC 5424 over UDP, TCP or TLS) and/or
 * an HTTPS endpoint (newline-delimited JSON). Delivery is at least once: a
 * stream's position advances only after every sink took the batch, so a
 * collector that is down is caught up when it returns, and every record
 * carries its id so a collector can drop a repeat. Records older than the
 * moment export first ran are not sent (a connector turned on today does not
 * replay history).
 *
 *   STACK_SIEM_SYSLOG_URL   udp://host:514 | tcp://host:514 | tls://host:6514
 *   STACK_SIEM_HTTP_URL     https://collector.example/ingest
 *   STACK_SIEM_HTTP_TOKEN   bearer token for the HTTP sink (optional)
 *   STACK_SIEM_STREAMS      security (default) | audit | security,audit
 *   STACK_SIEM_TLS_CA_FILE  extra CA certificate (PEM) for tls:// and https://
 *
 * Only the public fields of a row are sent (see the `record` functions): never
 * a credential, an input body or a payload.
 *
 * The wire contract (records, frames, delivery, what a collector must do) is the
 * open specification `spec/siem-export/SPEC.md`, judged by the `siem-exporter`
 * and `siem-collector` suites of `spec/conformance`; its constants are in
 * `packages/shared/src/constants/siem-export.ts`.
 */

export type { SiemStream };

export interface SiemConfig {
  syslog: { protocol: 'udp' | 'tcp' | 'tls'; host: string; port: number } | null;
  http: { url: string; token: string | null } | null;
  streams: SiemStream[];
  caPem: string | null;
}

export function readSiemConfig(env: Record<string, string | undefined>): SiemConfig | null {
  const syslogUrl = env['STACK_SIEM_SYSLOG_URL']?.trim();
  const httpUrl = env['STACK_SIEM_HTTP_URL']?.trim();
  if (!syslogUrl && !httpUrl) return null;

  let syslog: SiemConfig['syslog'] = null;
  if (syslogUrl) {
    let parsed: URL;
    try {
      parsed = new URL(syslogUrl);
    } catch {
      throw new Error('[BOOT] STACK_SIEM_SYSLOG_URL is not a valid URL');
    }
    const protocol = parsed.protocol.replace(':', '');
    if (protocol !== 'udp' && protocol !== 'tcp' && protocol !== 'tls') {
      throw new Error('[BOOT] STACK_SIEM_SYSLOG_URL must start with udp://, tcp:// or tls://');
    }
    syslog = {
      protocol,
      host: parsed.hostname,
      port: parsed.port ? Number(parsed.port) : protocol === 'tls' ? SIEM_DEFAULT_SYSLOG_TLS_PORT : SIEM_DEFAULT_SYSLOG_PORT,
    };
  }

  let http: SiemConfig['http'] = null;
  if (httpUrl) {
    let parsed: URL;
    try {
      parsed = new URL(httpUrl);
    } catch {
      throw new Error('[BOOT] STACK_SIEM_HTTP_URL is not a valid URL');
    }
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
    if ((parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) || parsed.username || parsed.password) {
      throw new Error('[BOOT] STACK_SIEM_HTTP_URL must be an https URL');
    }
    http = { url: parsed.toString(), token: env['STACK_SIEM_HTTP_TOKEN']?.trim() || null };
  }

  const requested = (env['STACK_SIEM_STREAMS'] ?? 'security')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const streams: SiemStream[] = [];
  for (const name of requested) {
    if (name !== 'security' && name !== 'audit') {
      throw new Error('[BOOT] STACK_SIEM_STREAMS lists security and/or audit');
    }
    if (!streams.includes(name)) streams.push(name);
  }
  if (streams.length === 0) throw new Error('[BOOT] STACK_SIEM_STREAMS lists security and/or audit');

  const caFile = env['STACK_SIEM_TLS_CA_FILE']?.trim();
  let caPem: string | null = null;
  if (caFile) {
    try {
      caPem = readFileSync(caFile, 'utf8');
    } catch {
      throw new Error('[BOOT] STACK_SIEM_TLS_CA_FILE cannot be read');
    }
  }
  return { syslog, http, streams, caPem };
}

// ─── Records ─────────────────────────────────────────────────────────────

export interface SiemRecord {
  stream: SiemStream;
  /** Unique within its stream: a collector drops a repeat by it. */
  id: string;
  time: string;
  severity: 'info' | 'warning' | 'critical';
  operator_id: string;
  agent_id: string;
  /** What happened, in the stream's own words (a signal type, an action). */
  event: string;
  fields: Record<string, unknown>;
}

interface SecurityRow {
  id: string;
  operator_id: string;
  agent_id: string;
  passport_jti: string | null;
  mission_id: string | null;
  signal_type: string;
  severity: string;
  message: string;
  metadata: Record<string, unknown> | null;
  resolved: boolean;
  created_at: Date;
}

export function securityRecord(row: SecurityRow): SiemRecord {
  return {
    stream: 'security',
    id: row.id,
    time: row.created_at.toISOString(),
    severity: row.severity === 'critical' ? 'critical' : row.severity === 'info' ? 'info' : 'warning',
    operator_id: row.operator_id,
    agent_id: row.agent_id,
    event: row.signal_type,
    fields: {
      passport_jti: row.passport_jti,
      mission_id: row.mission_id,
      message: row.message,
      metadata: row.metadata,
      resolved: row.resolved,
    },
  };
}

interface AuditRow {
  entry_id: string;
  trace_id: string;
  timestamp: number;
  operator_id: string;
  agent_id: string;
  passport_jti: string;
  layer: string;
  action: string;
  outcome: string;
  error_code: string | null;
  entry_hash: string;
}

export function auditRecord(row: AuditRow): SiemRecord {
  return {
    stream: 'audit',
    id: row.entry_id,
    time: new Date(row.timestamp).toISOString(),
    severity: row.outcome === 'failure' || row.outcome === 'blocked' ? 'warning' : 'info',
    operator_id: row.operator_id,
    agent_id: row.agent_id,
    event: row.action,
    fields: {
      passport_jti: row.passport_jti,
      layer: row.layer,
      outcome: row.outcome,
      error_code: row.error_code,
      trace_id: row.trace_id,
      entry_hash: row.entry_hash,
    },
  };
}

// ─── Formats ─────────────────────────────────────────────────────────────

/** One datagram must fit; a UDP collector may drop anything bigger. */
const MAX_SYSLOG_BYTES = SIEM_SYSLOG_MAX_BYTES;

function sdEscape(value: string): string {
  return value.replace(/[\\"\]]/g, (c) => `\\${c}`);
}

function sdName(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 32) || '_';
}

/** RFC 5424: `<PRI>1 TIME HOST APP PROCID MSGID [SD] MSG`, the record as JSON in MSG. */
export function formatSyslog(record: SiemRecord, host = SIEM_SYSLOG_HOSTNAME): string {
  const pri = SIEM_SYSLOG_FACILITY * 8 + SIEM_SYSLOG_SEVERITY[record.severity];
  const sd = `[${SIEM_SYSLOG_SD_ID} stream="${record.stream}" id="${sdEscape(record.id)}" operator="${sdEscape(record.operator_id)}" agent="${sdEscape(record.agent_id)}" event="${sdEscape(sdName(record.event))}"]`;
  const header = `<${pri}>1 ${record.time} ${host.replace(/\s+/g, '-') || '-'} ${SIEM_SYSLOG_APP_NAME} - ${sdName(record.stream)} ${sd} `;
  let body = JSON.stringify(record);
  if (Buffer.byteLength(header + body, 'utf8') > MAX_SYSLOG_BYTES) {
    // Too big for one datagram: keep the identifying fields, drop the detail.
    body = JSON.stringify({ ...record, fields: { truncated: true } });
  }
  return header + body;
}

export function formatNdjson(records: SiemRecord[]): string {
  return records.map((r) => JSON.stringify(r)).join('\n') + '\n';
}

// ─── Sinks ───────────────────────────────────────────────────────────────

export interface SiemSink {
  readonly name: string;
  send(records: SiemRecord[]): Promise<void>;
}

const SINK_TIMEOUT_MS = SIEM_SINK_TIMEOUT_SECONDS * 1000;

/**
 * The certificate authorities a TLS sink trusts: the system's, and the customer's own when one is given
 * (`STACK_SIEM_TLS_CA_FILE` names an extra authority, so it adds to the system's and never replaces them).
 */
function trustedAuthorities(caPem: string | null): string[] | undefined {
  return caPem ? [...rootCertificates, caPem] : undefined;
}

export class SyslogSink implements SiemSink {
  readonly name = 'syslog';

  constructor(
    private readonly target: NonNullable<SiemConfig['syslog']>,
    private readonly caPem: string | null = null,
    private readonly hostname = SIEM_SYSLOG_HOSTNAME,
    private readonly timeoutMs = SINK_TIMEOUT_MS,
  ) {}

  async send(records: SiemRecord[]): Promise<void> {
    const messages = records.map((r) => formatSyslog(r, this.hostname));
    if (this.target.protocol === 'udp') {
      await this.sendUdp(messages);
      return;
    }
    // RFC 6587 octet counting: `<length> <message>`, the length in bytes, so a collector reads a message by its length
    // and never by a delimiter.
    const framed = Buffer.concat(
      messages.map((m) => {
        const bytes = Buffer.from(m, 'utf8');
        return Buffer.concat([Buffer.from(`${bytes.length} `, 'ascii'), bytes]);
      }),
    );
    await this.sendStream(framed);
  }

  private sendUdp(messages: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = createSocket(this.target.host.includes(':') ? 'udp6' : 'udp4');
      let pending = messages.length;
      const done = (err?: Error | null) => {
        if (err) {
          socket.close();
          reject(err);
          return;
        }
        if (--pending === 0) {
          socket.close();
          resolve();
        }
      };
      if (pending === 0) {
        socket.close();
        resolve();
        return;
      }
      for (const message of messages) {
        socket.send(Buffer.from(message, 'utf8'), this.target.port, this.target.host, done);
      }
    });
  }

  private sendStream(payload: Buffer): Promise<void> {
    return new Promise((resolve, reject) => {
      let socket: Socket;
      const onError = (err: Error) => {
        socket?.destroy();
        reject(err);
      };
      const connected = () => {
        socket.write(payload, (err) => {
          if (err) return onError(err);
          socket.end(() => resolve());
        });
      };
      const ca = trustedAuthorities(this.caPem);
      socket =
        this.target.protocol === 'tls'
          ? tlsConnect(
              {
                host: this.target.host,
                port: this.target.port,
                // An address carries no server name (RFC 6066): the certificate is then checked against the address itself.
                ...(isIP(this.target.host) ? {} : { servername: this.target.host }),
                rejectUnauthorized: true,
                minVersion: 'TLSv1.2',
                ...(ca ? { ca } : {}),
              },
              connected,
            )
          : netConnect({ host: this.target.host, port: this.target.port }, connected);
      // From the first moment: a collector that accepts the connection and never answers the handshake must not hold the pass.
      socket.setTimeout(this.timeoutMs, () => onError(new Error('syslog sink timed out')));
      socket.once('error', onError);
    });
  }
}

export class HttpSink implements SiemSink {
  readonly name = 'http';

  constructor(
    private readonly target: NonNullable<SiemConfig['http']>,
    private readonly caPem: string | null = null,
    private readonly timeoutMs = SINK_TIMEOUT_MS,
  ) {}

  /**
   * One POST of newline-delimited JSON. Any answer but a 2xx is a failure, a redirect included: it is not followed, and
   * a collector that moved is a collector that has not taken the batch.
   */
  send(records: SiemRecord[]): Promise<void> {
    const url = new URL(this.target.url);
    const body = Buffer.from(formatNdjson(records), 'utf8');
    const ca = trustedAuthorities(this.caPem);
    return new Promise((resolve, reject) => {
      const send = url.protocol === 'https:' ? httpsRequest : httpRequest;
      const request = send(
        url,
        {
          method: 'POST',
          headers: {
            'content-type': SIEM_HTTP_CONTENT_TYPE,
            'content-length': String(body.length),
            ...(this.target.token ? { authorization: `Bearer ${this.target.token}` } : {}),
          },
          signal: AbortSignal.timeout(this.timeoutMs),
          ...(url.protocol === 'https:' ? { minVersion: 'TLSv1.2' as const, ...(ca ? { ca } : {}) } : {}),
        },
        (response) => {
          response.resume();
          response.on('error', reject);
          response.on('end', () => {
            const status = response.statusCode ?? 0;
            if (status >= 200 && status < 300) resolve();
            else reject(new Error(`HTTP sink answered ${status}`));
          });
        },
      );
      request.on('error', reject);
      request.end(body);
    });
  }
}

export function createSinks(config: SiemConfig, hostname?: string): SiemSink[] {
  return [
    ...(config.syslog ? [new SyslogSink(config.syslog, config.caPem, hostname)] : []),
    ...(config.http ? [new HttpSink(config.http, config.caPem)] : []),
  ];
}

// ─── The exporter ────────────────────────────────────────────────────────

const BATCH = SIEM_BATCH_SIZE;
/** Rows newer than this are left for the next pass: a transaction that committed late must not be skipped. */
const SETTLE_MS = SIEM_SETTLE_SECONDS * 1000;
const PASS_INTERVAL_MS = SIEM_PASS_INTERVAL_SECONDS * 1000;
const LOCK_SECONDS = SIEM_LOCK_SECONDS;

interface Cursor {
  t: string;
  id: string;
}

export interface SiemReader {
  read(stream: SiemStream, after: Cursor, before: Date, limit: number): Promise<Array<{ record: SiemRecord; cursor: Cursor }>>;
  /** Where a stream stands now, for a first run that must not replay history. */
  now(stream: SiemStream): Cursor;
}

export function dbSiemReader(db: Database): SiemReader {
  return {
    now: () => ({ t: String(Date.now()), id: '' }),
    async read(stream, after, before, limit) {
      if (stream === 'security') {
        const rows = await db
          .select()
          .from(securityEvents)
          .where(
            // The times go as ISO text with a cast: the driver does not serialise a Date it is given inside a raw fragment.
            sql`(${securityEvents.created_at}, ${securityEvents.id}) > (${new Date(Number(after.t)).toISOString()}::timestamptz, ${after.id}) AND ${securityEvents.created_at} < ${before.toISOString()}::timestamptz`,
          )
          .orderBy(asc(securityEvents.created_at), asc(securityEvents.id))
          .limit(limit);
        return rows.map((row) => ({
          record: securityRecord(row),
          cursor: { t: String(row.created_at.getTime()), id: row.id },
        }));
      }
      const rows = await db
        .select()
        .from(auditLog)
        .where(
          sql`(${auditLog.timestamp}, ${auditLog.entry_id}) > (${Number(after.t)}, ${after.id}) AND ${auditLog.timestamp} < ${before.getTime()}`,
        )
        .orderBy(asc(auditLog.timestamp), asc(auditLog.entry_id))
        .limit(limit);
      return rows.map((row) => ({
        record: auditRecord(row),
        cursor: { t: String(row.timestamp), id: row.entry_id },
      }));
    },
  };
}

export interface SiemExporterDeps {
  config: SiemConfig;
  reader: SiemReader;
  redis: Pick<RedisClient, 'get' | 'set' | 'eval'>;
  features: Pick<FeatureGate, 'has'>;
  sinks?: SiemSink[];
  now?: () => Date;
  log?: Pick<Console, 'log' | 'warn'>;
}

export class SiemExporter {
  private readonly sinks: SiemSink[];
  private readonly token = randomUUID();
  private lastLine: string | undefined;

  constructor(private readonly deps: SiemExporterDeps) {
    this.sinks = deps.sinks ?? createSinks(deps.config);
  }

  private key(stream: SiemStream, what: 'cursor' | 'lock'): string {
    return `stack:siem:${what}:${stream}`;
  }

  /**
   * One pass over every stream: send what is new, then move on. Returns how
   * many records it delivered. Does nothing while the feature is off, and when
   * another API machine holds the stream.
   */
  async pass(): Promise<number> {
    if (!this.deps.features.has('siem')) return 0;
    let delivered = 0;
    for (const stream of this.deps.config.streams) {
      const locked = await this.deps.redis.set(this.key(stream, 'lock'), this.token, 'EX', LOCK_SECONDS, 'NX');
      if (locked !== 'OK') continue;
      try {
        delivered += await this.passStream(stream);
      } finally {
        // Release only our own lock.
        await this.deps.redis
          .eval(
            "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end",
            1,
            this.key(stream, 'lock'),
            this.token,
          )
          .catch(() => undefined);
      }
    }
    return delivered;
  }

  private async passStream(stream: SiemStream): Promise<number> {
    const now = (this.deps.now ?? (() => new Date()))();
    const stored = await this.deps.redis.get(this.key(stream, 'cursor'));
    let cursor: Cursor;
    if (stored) {
      cursor = JSON.parse(stored) as Cursor;
    } else {
      // First run: start from now. History is not replayed.
      cursor = this.deps.reader.now(stream);
      await this.deps.redis.set(this.key(stream, 'cursor'), JSON.stringify(cursor));
    }
    let delivered = 0;
    for (;;) {
      const rows = await this.deps.reader.read(stream, cursor, new Date(now.getTime() - SETTLE_MS), BATCH);
      if (rows.length === 0) return delivered;
      const records = rows.map((r) => r.record);
      try {
        for (const sink of this.sinks) await sink.send(records);
      } catch (err) {
        this.report(`[siem] Export of the ${stream} stream paused: ${(err as Error).message}; it will resume where it stopped.`);
        return delivered;
      }
      cursor = rows[rows.length - 1]!.cursor;
      await this.deps.redis.set(this.key(stream, 'cursor'), JSON.stringify(cursor));
      delivered += rows.length;
      this.lastLine = undefined;
      if (rows.length < BATCH) return delivered;
    }
  }

  private report(line: string): void {
    if (line === this.lastLine) return;
    this.lastLine = line;
    (this.deps.log ?? console).warn(line);
  }

  /** Run a pass every few seconds. Returns the function that stops it. */
  start(): () => void {
    let running = false;
    const tick = () => {
      if (running) return;
      running = true;
      this.pass()
        .catch((err) => this.report(`[siem] Export pass failed: ${(err as Error).message}`))
        .finally(() => {
          running = false;
        });
    };
    const timer = setInterval(tick, PASS_INTERVAL_MS);
    timer.unref();
    return () => clearInterval(timer);
  }
}

/** The connector for this install, or null when none is configured. */
export function createSiemExporter(
  env: Record<string, string | undefined>,
  deps: { db: Database; redis: RedisClient; features: FeatureGate },
  log: Pick<Console, 'log' | 'warn'> = console,
): SiemExporter | null {
  const config = readSiemConfig(env);
  if (!config) return null;
  log.log(
    `[siem] Exporting the ${config.streams.join(' and ')} stream(s) to ${[config.syslog && `syslog ${config.syslog.protocol}://${config.syslog.host}`, config.http && 'an HTTPS endpoint'].filter(Boolean).join(' and ')}${deps.features.has('siem') ? '.' : ' once a licence with security-monitoring connectors is installed.'}`,
  );
  return new SiemExporter({ config, reader: dbSiemReader(deps.db), redis: deps.redis, features: deps.features, log });
}
