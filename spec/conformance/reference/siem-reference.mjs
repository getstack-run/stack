// A reference EXPORTER and a reference COLLECTOR of the security-monitoring export (spec/siem-export/SPEC.md), written
// from the specification with node:crypto, node:net, node:tls, node:dgram and node:https alone. The exporter keeps its
// source in memory (`emit` puts records there); the collector listens on UDP, TCP, TLS and HTTPS and keeps what it
// receives in memory. They are the public references the `siem-exporter` and `siem-collector` suites run against in
// continuous integration, and the starting point for an implementation of your own.
//
// `quirk` turns on ONE deliberate defect, for the tests of the suites themselves (siem-reference.test.mjs): a
// conformance kit that cannot fail a broken implementation would certify anything.

import { createSocket } from 'node:dgram';
import { createServer as createHttpsServer, request as httpsRequest } from 'node:https';
import { connect as netConnect, createServer as createNetServer } from 'node:net';
import { connect as tlsConnect, createServer as createTlsServer, rootCertificates } from 'node:tls';
import { selfSignedCertificate } from '../src/x509.mjs';

export const EXPORTER_QUIRKS = [
  'none',
  'wrong-pri', // the facility is 1, not 4
  'sd-unescaped', // structured data values are not escaped
  'newline-framing', // TCP messages are separated by newlines, not counted
  'char-count', // the octet count is a number of characters
  'no-truncate', // a record too big for a datagram is sent as it is
  'udp-batch', // one datagram carries a whole batch
  'replays-history', // what came before the first pass is sent
  'no-bearer', // the token is not sent
  'no-final-newline', // the last line of a batch has no newline
  'one-request', // a batch is not cut at 200 records
  'tls-insecure', // a certificate is not checked
  'follows-redirects', // a redirect is followed (and the token with it)
  'drops-on-failure', // the position moves when the collector failed
  'leaks-canary', // a field of the source that is not public is sent
  'reorders', // records go in reverse
  'duplicates', // every record is sent twice
  'ignores-streams', // every stream is exported
  'extra-fields', // a record has a member the specification does not name
];

export const COLLECTOR_QUIRKS = [
  'none',
  'no-dedupe', // a repeat is stored again
  'dedupe-by-id', // the stream is left out of the identity of a record
  'newline-split', // TCP messages are split on newlines
  'char-count', // the octet count is read as characters
  'no-auth', // the bearer token is not checked
  'sd-parse', // the record is read from the structured data
  'ack-before-store', // 2xx before the batch is stored
  'rejects-unknown', // a member it does not know is refused
  'rejects-truncated', // a record with truncated fields is refused
  'redirect', // answers a redirect
  'body-limit', // a body over 1 MiB is refused
  'accepts-bad-body', // a body that is not JSON is answered 2xx
];

const FACILITY = 4;
const SEVERITY = { critical: 2, warning: 4, info: 6 };
const SD_ID = 'stack@32473';
const BATCH = 200;
const MAX_MESSAGE = 8000;
const SETTLE_MS = 5000;

const sdEscape = (value) => value.replace(/[\\"\]]/g, (c) => `\\${c}`);
const sdName = (event) => event.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 32) || '_';
const order = (a, b) => (a.time < b.time ? -1 : a.time > b.time ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

// ─── The exporter ──────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * @param {{ syslog: { url: string } | null, http: { url: string, token: string | null } | null, caPem: string | null, streams: string[], canary?: string }} config
 * @param {{ quirk?: string, now?: () => number }} [options] `now` is the clock the settling delay is read against, in milliseconds.
 */
export function createReferenceExporter(config, { quirk = 'none', now = () => Date.now() } = {}) {
  if (!EXPORTER_QUIRKS.includes(quirk)) throw new Error(`unknown quirk ${quirk}`);
  const q = (name) => quirk === name;
  const source = [];
  const positions = new Map(); // stream -> { time, id }
  let started = false;
  const syslog = config.syslog ? new URL(config.syslog.url) : null;
  const protocol = syslog ? syslog.protocol.replace(':', '') : null;
  const authorities = config.caPem ? [...rootCertificates, config.caPem] : undefined;

  const publicRecord = (row) => {
    const { _private, ...record } = row;
    void _private;
    return record;
  };

  function message(record) {
    const priority = (q('wrong-pri') ? 1 : FACILITY) * 8 + SEVERITY[record.severity];
    const esc = q('sd-unescaped') ? (v) => v : sdEscape;
    const sd = `[${SD_ID} stream="${esc(record.stream)}" id="${esc(record.id)}" operator="${esc(record.operator_id)}" agent="${esc(record.agent_id)}" event="${esc(sdName(record.event))}"]`;
    const header = `<${priority}>1 ${record.time} stack stack-engine - ${record.stream} ${sd} `;
    let body = JSON.stringify(record);
    if (!q('no-truncate') && Buffer.byteLength(header + body, 'utf8') > MAX_MESSAGE) body = JSON.stringify({ ...record, fields: { truncated: true } });
    return header + body;
  }

  function sendUdp(messages) {
    return new Promise((resolve, reject) => {
      const socket = createSocket('udp4');
      const datagrams = q('udp-batch') ? [messages.join('\n')] : messages;
      let pending = datagrams.length;
      for (const datagram of datagrams) {
        socket.send(Buffer.from(datagram, 'utf8'), Number(syslog.port), syslog.hostname, (error) => {
          if (error) { socket.close(); reject(error); } else if (--pending === 0) { socket.close(); resolve(); }
        });
      }
    });
  }

  function sendStream(messages) {
    const payload = q('newline-framing')
      ? Buffer.from(`${messages.join('\n')}\n`, 'utf8')
      : Buffer.concat(messages.map((m) => {
        const bytes = Buffer.from(m, 'utf8');
        const count = q('char-count') ? m.length : bytes.length;
        return Buffer.concat([Buffer.from(`${count} `, 'ascii'), bytes]);
      }));
    return new Promise((resolve, reject) => {
      const done = () => { socket.write(payload, (error) => (error ? reject(error) : socket.end(() => resolve()))); };
      const host = syslog.hostname;
      const port = Number(syslog.port);
      const socket = protocol === 'tls'
        ? tlsConnect({ host, port, ...(/^\d+\.\d+\.\d+\.\d+$/.test(host) ? {} : { servername: host }), rejectUnauthorized: !q('tls-insecure'), minVersion: 'TLSv1.2', ca: authorities }, done)
        : netConnect({ host, port }, done);
      socket.setTimeout(10_000, () => socket.destroy(new Error('timed out')));
      socket.once('error', reject);
    });
  }

  function post(records, url = config.http.url, redirects = 0) {
    const lines = records.map((r) => JSON.stringify(r));
    const body = Buffer.from(q('no-final-newline') ? lines.join('\n') : `${lines.join('\n')}\n`, 'utf8');
    const target = new URL(url);
    return new Promise((resolve, reject) => {
      const headers = { 'content-type': 'application/x-ndjson', 'content-length': body.length };
      if (config.http.token && !q('no-bearer')) headers.authorization = `Bearer ${config.http.token}`;
      const request = httpsRequest(target, { method: 'POST', headers, ca: authorities, rejectUnauthorized: !q('tls-insecure'), minVersion: 'TLSv1.2', timeout: 10_000 }, (response) => {
        response.resume();
        response.on('end', () => {
          const status = response.statusCode;
          if (q('follows-redirects') && status >= 300 && status < 400 && response.headers.location && redirects < 3) {
            resolve(post(records, new URL(response.headers.location, target).toString(), redirects + 1));
          } else if (status >= 200 && status < 300) resolve();
          else reject(new Error(`the collector answered ${status}`));
        });
      });
      request.on('timeout', () => request.destroy(new Error('timed out')));
      request.on('error', reject);
      request.end(body);
    });
  }

  async function sendBatch(records) {
    const out = q('duplicates') ? records.flatMap((r) => [r, r]) : q('reorders') ? [...records].reverse() : records;
    if (syslog) {
      const messages = out.map(message);
      if (protocol === 'udp') await sendUdp(messages);
      else await sendStream(messages);
    }
    if (config.http) await post(out);
  }

  return {
    async emit(records) {
      for (const record of records) {
        const row = q('leaks-canary') ? { ...record, fields: { ...record.fields, ...(record.fields.truncated ? {} : { password_hash: config.canary }) } } : record;
        source.push(q('extra-fields') ? { ...row, source_row_id: 1 } : row);
      }
    },
    /** One pass: what is new, a batch at a time, stream by stream. Rejects when a collector did not take a batch. */
    async pass() {
      if (!started) {
        started = true;
        // The first pass is the moment the exporter starts: what is in the source now is history.
        if (!q('replays-history')) for (const stream of config.streams) positions.set(stream, { time: new Date().toISOString(), id: '' });
        else for (const stream of config.streams) positions.set(stream, { time: '', id: '' });
      }
      for (const stream of q('ignores-streams') ? ['security', 'audit'] : config.streams) {
        const position = positions.get(stream) ?? { time: new Date().toISOString(), id: '' };
        const cutoff = new Date(now() - SETTLE_MS).toISOString();
        for (;;) {
          const batch = source
            .filter((r) => r.stream === stream && (r.time > position.time || (r.time === position.time && r.id > position.id)) && r.time < cutoff)
            .sort(order)
            .slice(0, q('one-request') ? 1000 : BATCH);
          if (batch.length === 0) break;
          try {
            await sendBatch(batch.map(publicRecord));
          } catch (error) {
            if (q('drops-on-failure')) { positions.set(stream, { time: batch.at(-1).time, id: batch.at(-1).id }); }
            throw error;
          }
          positions.set(stream, { time: batch.at(-1).time, id: batch.at(-1).id });
          position.time = batch.at(-1).time;
          position.id = batch.at(-1).id;
          if (batch.length < BATCH) break;
        }
        positions.set(stream, position);
      }
    },
    async close() {},
  };
}

// ─── The collector ─────────────────────────────────────────────────────────────────────────────────────────────────

/** Read octet-counted frames from `buffer`; what is left over is an incomplete frame. */
function readFrames(buffer) {
  const frames = [];
  let at = 0;
  while (at < buffer.length) {
    const space = buffer.indexOf(0x20, at);
    if (space < 0) break;
    const count = Number(buffer.subarray(at, space).toString('ascii'));
    if (!Number.isInteger(count) || count < 1) throw new Error('a frame does not start with a byte count');
    const end = space + 1 + count;
    if (buffer.length < end) break;
    frames.push(buffer.subarray(space + 1, end));
    at = end;
  }
  return { frames, rest: buffer.subarray(at) };
}

/** The same, for a collector that reads the count as a number of characters, which is wrong for text that is not ASCII. */
function readFramesByCharacters(buffer) {
  const text = buffer.toString('utf8');
  const frames = [];
  let at = 0;
  while (at < text.length) {
    const space = text.indexOf(' ', at);
    if (space < 0) break;
    const count = Number(text.slice(at, space));
    if (!Number.isInteger(count) || count < 1) throw new Error('a frame does not start with a count');
    if (text.length < space + 1 + count) break;
    frames.push(Buffer.from(text.slice(space + 1, space + 1 + count), 'utf8'));
    at = space + 1 + count;
  }
  return { frames, rest: Buffer.from(text.slice(at), 'utf8') };
}

function parseMessage(text, { fromStructuredData = false } = {}) {
  const header = /^<(\d{1,3})>(\d+) (\S+) (\S+) (\S+) (\S+) (\S+) /.exec(text);
  if (!header) throw new Error('not a syslog message');
  let at = header[0].length;
  const params = {};
  if (text[at] === '[') {
    at += 1;
    at = text.indexOf(' ', at) + 1;
    for (;;) {
      const eq = text.indexOf('="', at);
      const name = text.slice(at, eq);
      let value = '';
      let i = eq + 2;
      for (; i < text.length; i += 1) {
        if (text[i] === '\\' && '\\"]'.includes(text[i + 1])) { value += text[i + 1]; i += 1; } else if (text[i] === '"') break; else value += text[i];
      }
      params[name] = value;
      at = i + 1;
      if (text[at] === ']') { at += 1; break; }
      at += 1;
    }
  } else {
    at += 1;
  }
  const record = JSON.parse(text.slice(at + 1));
  if (fromStructuredData) return { ...record, id: params.id ?? record.id, operator_id: params.operator ?? record.operator_id, severity: Number(header[1]) % 8 === 6 ? 'info' : record.severity };
  return record;
}

/**
 * @param {{ token: string, quirk?: string }} options
 * @returns {Promise<{ udp: object, tcp: object, tls: object, https: object, records: () => Promise<object[]>, close: () => Promise<void> }>}
 */
export async function startReferenceCollector({ token, quirk = 'none' }) {
  if (!COLLECTOR_QUIRKS.includes(quirk)) throw new Error(`unknown quirk ${quirk}`);
  const q = (name) => quirk === name;
  const certificate = selfSignedCertificate();
  const store = [];
  const seen = new Set();
  const identity = (record) => (q('dedupe-by-id') ? record.id : `${record.stream}/${record.id}`);

  function accept(record) {
    if (typeof record?.stream !== 'string' || typeof record.id !== 'string') throw new Error('not a record');
    if (q('rejects-unknown') && Object.keys(record).some((k) => !['stream', 'id', 'time', 'severity', 'operator_id', 'agent_id', 'event', 'fields'].includes(k))) throw new Error('unknown member');
    if (q('rejects-truncated') && record.fields?.truncated) throw new Error('truncated');
    const key = identity(record);
    if (!q('no-dedupe') && seen.has(key)) return;
    seen.add(key);
    store.push(record);
  }
  const takeMessage = (text) => {
    try { accept(parseMessage(text, { fromStructuredData: q('sd-parse') })); } catch { /* a message it cannot read is dropped */ }
  };

  const udp = createSocket('udp4');
  udp.on('message', (m) => takeMessage(m.toString('utf8')));
  await new Promise((resolve) => udp.bind(0, '127.0.0.1', resolve));

  const onStream = (socket) => {
    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (q('newline-split')) {
        let at;
        while ((at = buffer.indexOf(0x0a)) >= 0) {
          const line = buffer.subarray(0, at).toString('utf8');
          buffer = buffer.subarray(at + 1);
          // a line holds "<count> <message>"
          takeMessage(line.slice(line.indexOf(' ') + 1));
        }
        return;
      }
      try {
        const { frames, rest } = q('char-count') ? readFramesByCharacters(buffer) : readFrames(buffer);
        buffer = rest;
        for (const frame of frames) takeMessage(frame.toString('utf8'));
      } catch { socket.destroy(); }
    });
    socket.on('error', () => undefined);
  };
  const tcp = createNetServer(onStream);
  const tls = createTlsServer({ cert: certificate.cert, key: certificate.key }, onStream);
  tls.on('tlsClientError', () => undefined);
  await Promise.all([new Promise((resolve) => tcp.listen(0, '127.0.0.1', resolve)), new Promise((resolve) => tls.listen(0, '127.0.0.1', resolve))]);

  const https = createHttpsServer({ cert: certificate.cert, key: certificate.key }, (req, res) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => { size += c.length; chunks.push(c); });
    req.on('end', () => {
      const reply = (status, headers = {}) => { res.writeHead(status, headers); res.end(); };
      if (q('redirect')) return reply(307, { location: '/elsewhere' });
      if (!q('no-auth') && req.headers.authorization !== `Bearer ${token}`) return reply(401);
      if (q('body-limit') && size > 1_048_576) return reply(413);
      const lines = Buffer.concat(chunks).toString('utf8').split('\n').filter((l) => l.length > 0);
      let parsed;
      try { parsed = lines.map((l) => JSON.parse(l)); } catch {
        if (q('accepts-bad-body')) return reply(204);
        return reply(400);
      }
      if (q('ack-before-store')) {
        reply(204);
        setTimeout(() => { for (const record of parsed) { try { accept(record); } catch { /* skip */ } } }, 600);
        return undefined;
      }
      try { for (const record of parsed) accept(record); } catch { return reply(400); }
      return reply(204);
    });
  });
  await new Promise((resolve) => https.listen(0, '127.0.0.1', resolve));

  return {
    udp: { host: '127.0.0.1', port: udp.address().port },
    tcp: { host: '127.0.0.1', port: tcp.address().port },
    tls: { host: '127.0.0.1', port: tls.address().port, ca: certificate.cert },
    https: { url: `https://127.0.0.1:${https.address().port}/ingest`, ca: certificate.cert },
    records: async () => store.map((r) => structuredClone(r)),
    close: async () => {
      udp.close();
      https.closeAllConnections();
      await Promise.all([tcp, tls, https].map((s) => new Promise((resolve) => s.close(() => resolve()))));
    },
  };
}
