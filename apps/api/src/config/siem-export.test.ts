import { createServer as createTcpServer, type Server } from 'node:net';
import { createSocket } from 'node:dgram';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { createServer as createTlsServer } from 'node:tls';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SiemRecord as SiemRecordSchema } from '@stack/shared';
// The kit is plain JavaScript with no declarations; its certificate maker is what the suites' own TLS collectors use.
// @ts-expect-error TS7016
import { selfSignedCertificate } from '../../../../spec/conformance/src/x509.mjs';
import {
  HttpSink,
  SiemExporter,
  SyslogSink,
  auditRecord,
  formatNdjson,
  formatSyslog,
  readSiemConfig,
  securityRecord,
  type SiemConfig,
  type SiemReader,
  type SiemRecord,
  type SiemSink,
} from './siem-export.js';

const quiet = { log: vi.fn(), warn: vi.fn() };

const RECORD: SiemRecord = securityRecord({
  id: 'sev_1',
  operator_id: 'op_a',
  agent_id: 'agt_1',
  passport_jti: 'pp_1',
  mission_id: null,
  signal_type: 'prompt_injection',
  severity: 'critical',
  message: 'Prompt injection pattern matched',
  metadata: { pattern_id: 'override_ignore_previous' },
  resolved: false,
  created_at: new Date('2026-10-21T12:00:00.000Z'),
});

class FakeRedis {
  store = new Map<string, string>();
  async get(key: string) {
    return this.store.get(key) ?? null;
  }
  async set(key: string, value: string, ..._rest: unknown[]) {
    if (_rest.includes('NX') && this.store.has(key)) return null;
    this.store.set(key, value);
    return 'OK';
  }
  async eval(_script: string, _n: number, key: string, token: string) {
    if (this.store.get(key) === token) {
      this.store.delete(key);
      return 1;
    }
    return 0;
  }
}

function config(overrides: Partial<SiemConfig> = {}): SiemConfig {
  return { syslog: null, http: null, streams: ['security'], caPem: null, ...overrides };
}

/** Rows 1..n as one stream; the reader honours the cursor and the settle bound like the database reader. */
function readerOf(rows: Array<{ n: number; at: number }>): SiemReader {
  return {
    now: () => ({ t: '0', id: '' }),
    async read(_stream, after, before, limit) {
      return rows
        .filter((r) => r.n > Number(after.id || 0) && r.at < before.getTime())
        .slice(0, limit)
        .map((r) => ({
          record: { ...RECORD, id: `sev_${r.n}` },
          cursor: { t: String(r.at), id: String(r.n) },
        }));
    },
  };
}

const closers: Array<() => Promise<void>> = [];
afterEach(async () => {
  await Promise.all(closers.splice(0).map((c) => c()));
  vi.clearAllMocks();
});

describe('configuration', () => {
  it('is off unless a sink is named', () => {
    expect(readSiemConfig({})).toBeNull();
  });

  it('reads a syslog and an HTTP sink, and refuses unsafe or unknown settings', () => {
    const c = readSiemConfig({
      STACK_SIEM_SYSLOG_URL: 'tls://siem.corp.example',
      STACK_SIEM_HTTP_URL: 'https://collector.corp.example/ingest',
      STACK_SIEM_HTTP_TOKEN: 'tok',
      STACK_SIEM_STREAMS: 'security,audit',
    })!;
    expect(c.syslog).toEqual({ protocol: 'tls', host: 'siem.corp.example', port: 6514 });
    expect(c.http).toEqual({ url: 'https://collector.corp.example/ingest', token: 'tok' });
    expect(c.streams).toEqual(['security', 'audit']);
    expect(() => readSiemConfig({ STACK_SIEM_SYSLOG_URL: 'ftp://x' })).toThrow(/udp:\/\//);
    expect(() => readSiemConfig({ STACK_SIEM_HTTP_URL: 'http://collector.corp.example' })).toThrow(/https/);
    expect(() => readSiemConfig({ STACK_SIEM_HTTP_URL: 'https://u:p@collector.corp.example' })).toThrow(/https/);
    expect(() => readSiemConfig({ STACK_SIEM_HTTP_URL: 'https://c.example', STACK_SIEM_STREAMS: 'everything' })).toThrow(/streams/i);
    expect(() => readSiemConfig({ STACK_SIEM_SYSLOG_URL: 'udp://x', STACK_SIEM_TLS_CA_FILE: '/nope/ca.pem' })).toThrow(/CA/);
  });
});

describe('record formats', () => {
  it('writes RFC 5424 with the record as JSON and the right priority', () => {
    const line = formatSyslog(RECORD, 'stack-1');
    // facility 4 (security) * 8 + severity 2 (critical) = 34
    expect(line.startsWith('<34>1 2026-10-21T12:00:00.000Z stack-1 stack-engine - security [stack@32473 ')).toBe(true);
    expect(line).toContain('stream="security"');
    expect(line).toContain('id="sev_1"');
    expect(JSON.parse(line.slice(line.indexOf('] ') + 2))).toMatchObject({ id: 'sev_1', event: 'prompt_injection' });
  });

  it('escapes what structured data cannot carry and shrinks a record too big for one datagram', () => {
    const nasty = { ...RECORD, id: 'a"b]c\\d', operator_id: 'op"x' };
    const line = formatSyslog(nasty);
    expect(line).toContain('id="a\\"b\\]c\\\\d"');
    const huge = { ...RECORD, fields: { blob: 'x'.repeat(20_000) } };
    expect(Buffer.byteLength(formatSyslog(huge))).toBeLessThan(8_000);
  });

  it('writes one JSON object per line for an HTTP sink', () => {
    const out = formatNdjson([RECORD, { ...RECORD, id: 'sev_2' }]);
    expect(out.trim().split('\n').map((l) => JSON.parse(l).id)).toEqual(['sev_1', 'sev_2']);
  });

  it('exports the public fields of an audit row and nothing that carries a payload', () => {
    const record = auditRecord({
      entry_id: 'aud_1',
      trace_id: 't',
      timestamp: Date.parse('2026-10-21T12:00:00Z'),
      operator_id: 'op_a',
      agent_id: 'agt_1',
      passport_jti: 'pp_1',
      layer: 'vault',
      action: 'proxy.call',
      outcome: 'blocked',
      error_code: 'CONTROL_DENIED',
      entry_hash: 'h',
      ...({ payload_hash: 'must-not-appear', error_message: 'must-not-appear' } as object),
    } as never);
    expect(record.severity).toBe('warning');
    expect(JSON.stringify(record)).not.toContain('must-not-appear');
  });
});

describe('sinks', () => {
  it('delivers over TCP with octet counting', async () => {
    const received: Buffer[] = [];
    const server: Server = createTcpServer((socket) => socket.on('data', (d) => received.push(d)));
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    closers.push(() => new Promise((r) => server.close(() => r())));
    const port = (server.address() as { port: number }).port;
    await new SyslogSink({ protocol: 'tcp', host: '127.0.0.1', port }).send([RECORD, { ...RECORD, id: 'sev_2' }]);
    await new Promise((r) => setTimeout(r, 50));
    const text = Buffer.concat(received).toString('utf8');
    const first = /^(\d+) /.exec(text)!;
    const body = text.slice(first[0].length, first[0].length + Number(first[1]));
    expect(body.startsWith('<34>1 ')).toBe(true);
    expect(text.slice(first[0].length + Number(first[1]))).toMatch(/^\d+ <34>1 /);
  });

  it('delivers over UDP, one datagram a record', async () => {
    const socket = createSocket('udp4');
    const got: string[] = [];
    socket.on('message', (m) => got.push(m.toString('utf8')));
    await new Promise<void>((r) => socket.bind(0, '127.0.0.1', r));
    closers.push(async () => void socket.close());
    await new SyslogSink({ protocol: 'udp', host: '127.0.0.1', port: socket.address().port }).send([RECORD, { ...RECORD, id: 'sev_2' }]);
    await new Promise((r) => setTimeout(r, 100));
    expect(got).toHaveLength(2);
    expect(got[0]).toContain('id="sev_1"');
  });

  it('delivers over HTTP with a bearer token, and fails the batch when the collector refuses it', async () => {
    const seen: Array<{ auth: string | undefined; body: string }> = [];
    let status = 200;
    const server = createHttpServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        seen.push({ auth: req.headers.authorization, body });
        res.statusCode = status;
        res.end();
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    closers.push(() => new Promise((r) => server.close(() => r())));
    const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/ingest`;
    const sink = new HttpSink({ url, token: 'tok' });
    await sink.send([RECORD]);
    expect(seen[0]!.auth).toBe('Bearer tok');
    expect(JSON.parse(seen[0]!.body.trim()).id).toBe('sev_1');
    status = 503;
    await expect(sink.send([RECORD])).rejects.toThrow(/503/);
  });
});

describe('the exporter', () => {
  const NOW = new Date('2026-10-21T12:00:00Z');
  const old = NOW.getTime() - 60_000;

  function exporter(opts: { sinks: SiemSink[]; rows: Array<{ n: number; at: number }>; redis?: FakeRedis; licensed?: boolean }) {
    const redis = opts.redis ?? new FakeRedis();
    return {
      redis,
      exporter: new SiemExporter({
        config: config(),
        reader: readerOf(opts.rows),
        redis: redis as never,
        features: { has: () => opts.licensed ?? true },
        sinks: opts.sinks,
        now: () => NOW,
        log: quiet,
      }),
    };
  }

  it('sends what is new once, in order, and not again', async () => {
    const sent: string[] = [];
    const sink: SiemSink = { name: 't', send: async (rs) => void sent.push(...rs.map((r) => r.id)) };
    const { exporter: e, redis } = exporter({ sinks: [sink], rows: [{ n: 1, at: old }, { n: 2, at: old + 1 }] });
    // The first pass starts from now: history is not replayed.
    redis.store.set('stack:siem:cursor:security', JSON.stringify({ t: '0', id: '0' }));
    expect(await e.pass()).toBe(2);
    expect(sent).toEqual(['sev_1', 'sev_2']);
    expect(await e.pass()).toBe(0);
    expect(sent).toHaveLength(2);
  });

  it('does not replay history on its first run', async () => {
    const sink: SiemSink = { name: 't', send: vi.fn(async () => {}) };
    const reader: SiemReader = { ...readerOf([{ n: 1, at: old }]), now: () => ({ t: String(NOW.getTime()), id: '99' }) };
    const redis = new FakeRedis();
    const e = new SiemExporter({ config: config(), reader, redis: redis as never, features: { has: () => true }, sinks: [sink], now: () => NOW, log: quiet });
    expect(await e.pass()).toBe(0);
    expect(sink.send).not.toHaveBeenCalled();
    expect(JSON.parse(redis.store.get('stack:siem:cursor:security')!)).toEqual({ t: String(NOW.getTime()), id: '99' });
  });

  it('keeps its place when a sink is down and delivers the same records when it returns', async () => {
    let up = false;
    const sent: string[] = [];
    const sink: SiemSink = {
      name: 't',
      send: async (rs) => {
        if (!up) throw new Error('connect ECONNREFUSED');
        sent.push(...rs.map((r) => r.id));
      },
    };
    const { exporter: e, redis } = exporter({ sinks: [sink], rows: [{ n: 1, at: old }, { n: 2, at: old + 1 }] });
    redis.store.set('stack:siem:cursor:security', JSON.stringify({ t: '0', id: '0' }));
    expect(await e.pass()).toBe(0);
    expect(quiet.warn).toHaveBeenCalledWith(expect.stringContaining('paused'));
    up = true;
    expect(await e.pass()).toBe(2);
    expect(sent).toEqual(['sev_1', 'sev_2']);
  });

  it('waits for a row that is too new to be sure of (a late commit must not be skipped)', async () => {
    const sink: SiemSink = { name: 't', send: vi.fn(async () => {}) };
    const { exporter: e, redis } = exporter({ sinks: [sink], rows: [{ n: 1, at: NOW.getTime() - 1_000 }] });
    redis.store.set('stack:siem:cursor:security', JSON.stringify({ t: '0', id: '0' }));
    expect(await e.pass()).toBe(0);
  });

  it('does nothing without the licence, and one machine at a time', async () => {
    const sink: SiemSink = { name: 't', send: vi.fn(async () => {}) };
    const off = exporter({ sinks: [sink], rows: [{ n: 1, at: old }], licensed: false });
    off.redis.store.set('stack:siem:cursor:security', JSON.stringify({ t: '0', id: '0' }));
    expect(await off.exporter.pass()).toBe(0);
    expect(sink.send).not.toHaveBeenCalled();

    const held = exporter({ sinks: [sink], rows: [{ n: 1, at: old }] });
    held.redis.store.set('stack:siem:cursor:security', JSON.stringify({ t: '0', id: '0' }));
    held.redis.store.set('stack:siem:lock:security', 'another-machine');
    expect(await held.exporter.pass()).toBe(0);
    expect(held.redis.store.get('stack:siem:lock:security')).toBe('another-machine');
  });
});

describe('the records are the ones the specification publishes', () => {
  it('parses a security record and an audit record with the shared schema, and a syslog body is the same record', () => {
    const audit = auditRecord({
      entry_id: 'aud_1', trace_id: 't', timestamp: Date.parse('2026-10-21T12:00:00Z'), operator_id: 'op_a', agent_id: 'agt_1',
      passport_jti: 'pp_1', layer: 'vault', action: 'proxy.call', outcome: 'success', error_code: null, entry_hash: 'h',
    });
    for (const record of [RECORD, audit]) {
      expect(SiemRecordSchema.safeParse(record).success).toBe(true);
      const line = formatSyslog(record);
      expect(JSON.parse(line.slice(line.indexOf('] ') + 2))).toEqual(record);
    }
    expect(SiemRecordSchema.safeParse({ ...RECORD, severity: 'fatal' }).success).toBe(false);
  });
});

describe('TLS to a collector', () => {
  const certificate = selfSignedCertificate() as { cert: string; key: string };

  it("trusts the customer's authority in addition to the system's, and refuses a certificate nobody vouches for", async () => {
    const received: Buffer[] = [];
    const server = createTlsServer({ cert: certificate.cert, key: certificate.key }, (socket) => socket.on('data', (d) => received.push(d)));
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    closers.push(() => new Promise((r) => server.close(() => r())));
    const port = (server.address() as { port: number }).port;

    await expect(new SyslogSink({ protocol: 'tls', host: '127.0.0.1', port }).send([RECORD])).rejects.toThrow(/self[- ]signed|unable to verify/i);
    await new SyslogSink({ protocol: 'tls', host: '127.0.0.1', port }, certificate.cert).send([RECORD]);
    await new Promise((r) => setTimeout(r, 50));
    expect(Buffer.concat(received).toString('utf8')).toMatch(/^\d+ <34>1 /);
  });

  it('gives up on a collector that accepts the connection and never answers the handshake', async () => {
    const open: Array<{ destroy(): void }> = [];
    const silent: Server = createTcpServer((socket) => void open.push(socket));
    await new Promise<void>((r) => silent.listen(0, '127.0.0.1', r));
    closers.push(() => new Promise((r) => { silent.close(() => r()); for (const socket of open) socket.destroy(); }));
    const port = (silent.address() as { port: number }).port;
    await expect(new SyslogSink({ protocol: 'tls', host: '127.0.0.1', port }, certificate.cert, 'stack', 200).send([RECORD])).rejects.toThrow(/timed out/);
  });

  it("sends to an HTTPS collector under the customer's authority, and not to one nobody vouches for", async () => {
    const seen: string[] = [];
    const server = createHttpsServer({ cert: certificate.cert, key: certificate.key }, (req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        seen.push(body);
        res.statusCode = 204;
        res.end();
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    closers.push(() => new Promise((r) => { server.close(() => r()); server.closeAllConnections(); }));
    const url = `https://127.0.0.1:${(server.address() as { port: number }).port}/ingest`;
    await expect(new HttpSink({ url, token: null }).send([RECORD])).rejects.toThrow();
    await new HttpSink({ url, token: null }, certificate.cert).send([RECORD]);
    expect(JSON.parse(seen[0]!.trim()).id).toBe('sev_1');
  });

  it('treats a redirect as a failure and does not follow it', async () => {
    let followed = false;
    const server = createHttpServer((req, res) => {
      if (req.url === '/moved') followed = true;
      res.statusCode = 302;
      res.setHeader('location', '/moved');
      res.end();
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    closers.push(() => new Promise((r) => { server.close(() => r()); server.closeAllConnections(); }));
    const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/ingest`;
    await expect(new HttpSink({ url, token: null }).send([RECORD])).rejects.toThrow(/302/);
    expect(followed).toBe(false);
  });
});
