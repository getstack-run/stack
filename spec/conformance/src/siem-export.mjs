// Conformance suites for the security-monitoring export (spec/siem-export/SPEC.md). Two halves, one for each side of
// the wire:
//
//   runSiemExporterSuite   the kit plays the COLLECTOR (a UDP socket, a TCP server, a TLS server and an HTTPS server it
//                          starts itself) and judges an EXPORTER that a harness of yours drives.
//   runSiemCollectorSuite  the kit plays the EXPORTER (it sends the frames of sections 5 to 7) and judges a COLLECTOR
//                          that a harness of yours starts.
//
// The exporter harness is a function `exporter(config)` that resolves with `{ emit(records), pass(), close() }`:
//   config  { syslog: { url } | null, http: { url, token } | null, caPem: string | null, streams: string[], canary: string }
//           the collectors to send to (the kit's), the certificate authority to trust for TLS and HTTPS (or none),
//           the streams to export, and a string to put in every field of a source row that is not public: it must
//           never arrive.
//   emit    makes these records appear in the exporter's source (a database, a queue), as records of the
//           specification's model; the `time` of each is after the first pass.
//   pass    runs one delivery pass: sends what is new. It may reject when a collector fails; the kit does not mind. The
//           first pass of a harness is the moment the exporter starts (history before it is not sent); a harness whose
//           exporter waits for a record to settle lets one emitted after the first pass be sent at the next.
//
// The collector harness is a function `collector({ token })` that resolves with
//   { udp?: { host, port }, tcp?: { host, port }, tls?: { host, port, ca }, https?: { url, ca }, records(), close() }
// the addresses it listens on (the HTTPS collector requires `Authorization: Bearer <token>`), the certificate
// authority a client must trust for its TLS and HTTPS addresses, and `records()`, which resolves with the records it
// holds now, as objects. A check that needs a transport the harness does not offer is skipped.

import { createSocket } from 'node:dgram';
import { createServer as createHttpsServer, request as httpsRequest } from 'node:https';
import { createServer as createNetServer, connect as netConnect } from 'node:net';
import { createServer as createTlsServer, connect as tlsConnect } from 'node:tls';
import { randomBytes } from 'node:crypto';
import { assert, runChecks, skip } from './harness.mjs';
import { selfSignedCertificate } from './x509.mjs';

// ─── The wire format, from the specification ───────────────────────────────────────────────────────────────────────

export const SIEM = Object.freeze({
  facility: 4,
  syslogSeverity: { critical: 2, warning: 4, info: 6 },
  sdId: 'stack@32473',
  appName: 'stack-engine',
  hostname: 'stack',
  maxSyslogBytes: 8000,
  batchSize: 200,
  contentType: 'application/x-ndjson',
  members: ['stream', 'id', 'time', 'severity', 'operator_id', 'agent_id', 'event', 'fields'],
  fieldMembers: {
    security: ['passport_jti', 'mission_id', 'message', 'metadata', 'resolved'],
    audit: ['passport_jti', 'layer', 'outcome', 'error_code', 'trace_id', 'entry_hash'],
  },
});

const sdEscape = (value) => value.replace(/[\\"\]]/g, (c) => `\\${c}`);
/** The `event` as a structured data value (section 5.1): safe characters, 32 at most, `_` when nothing is left. */
export const sdEvent = (event) => event.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 32) || '_';

/** One syslog message for a record, exactly as section 5 says. */
export function formatSyslogMessage(record, { pri } = {}) {
  const priority = pri ?? SIEM.facility * 8 + SIEM.syslogSeverity[record.severity];
  const sd = `[${SIEM.sdId} stream="${sdEscape(record.stream)}" id="${sdEscape(record.id)}" operator="${sdEscape(record.operator_id)}" agent="${sdEscape(record.agent_id)}" event="${sdEscape(sdEvent(record.event))}"]`;
  const header = `<${priority}>1 ${record.time} ${SIEM.hostname} ${SIEM.appName} - ${record.stream} ${sd} `;
  let body = JSON.stringify(record);
  if (Buffer.byteLength(header + body, 'utf8') > SIEM.maxSyslogBytes) body = JSON.stringify({ ...record, fields: { truncated: true } });
  return header + body;
}

/** Octet counting (RFC 6587 section 3.4.1): the byte count, a space, the message, for each message. */
export function octetFrames(messages) {
  return Buffer.concat(messages.map((m) => {
    const bytes = Buffer.from(m, 'utf8');
    return Buffer.concat([Buffer.from(`${bytes.length} `, 'ascii'), bytes]);
  }));
}

/** A batch for an HTTPS collector: each record on a line of its own, each line ended by a newline. */
export const ndjson = (records) => `${records.map((r) => JSON.stringify(r)).join('\n')}\n`;

/** Read octet-counted frames from bytes. Returns the messages and what is left over (an incomplete frame). Throws on a bad count. */
export function readOctetFrames(buffer) {
  const frames = [];
  let at = 0;
  while (at < buffer.length) {
    const space = buffer.indexOf(0x20, at);
    if (space < 0) break;
    const digits = buffer.subarray(at, space).toString('ascii');
    if (!/^[1-9][0-9]*$/.test(digits)) throw new Error(`a frame starts with ${JSON.stringify(digits.slice(0, 20))}, which is not a byte count`);
    const length = Number(digits);
    if (buffer.length < space + 1 + length) break;
    frames.push(buffer.subarray(space + 1, space + 1 + length));
    at = space + 1 + length;
  }
  return { frames, rest: buffer.subarray(at) };
}

/** Parse the RFC 5424 message of section 5. Throws with what is wrong. */
export function parseSyslogMessage(text) {
  const header = /^<(\d{1,3})>(\d+) (\S+) (\S+) (\S+) (\S+) (\S+) /.exec(text);
  if (!header) throw new Error('the message does not start with <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID');
  const [, pri, version, timestamp, hostname, appName, procId, msgId] = header;
  let at = header[0].length;
  const params = [];
  let sdId = null;
  if (text[at] === '-') {
    at += 1;
  } else {
    if (text[at] !== '[') throw new Error('the structured data does not start with [');
    at += 1;
    const idEnd = text.indexOf(' ', at);
    sdId = text.slice(at, idEnd);
    at = idEnd + 1;
    for (;;) {
      const eq = text.indexOf('="', at);
      if (eq < 0) throw new Error('a structured data parameter has no =" ');
      const name = text.slice(at, eq);
      let value = '';
      let i = eq + 2;
      for (;; i += 1) {
        if (i >= text.length) throw new Error('a structured data value is not closed');
        const c = text[i];
        if (c === '\\' && '\\"]'.includes(text[i + 1])) { value += text[i + 1]; i += 1; } else if (c === '"') break; else value += c;
      }
      params.push([name, value]);
      at = i + 1;
      if (text[at] === ']') { at += 1; break; }
      if (text[at] !== ' ') throw new Error('a structured data parameter is not followed by a space or ]');
      at += 1;
    }
  }
  if (text[at] !== ' ') throw new Error('there is no space before the message body');
  return { pri: Number(pri), version: Number(version), timestamp, hostname, appName, procId, msgId, sdId, params, msg: text.slice(at + 1) };
}

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** What is wrong with a record, by section 3, or undefined. */
export function recordProblem(record) {
  if (!isObject(record)) return 'it is not an object';
  const keys = Object.keys(record);
  if (JSON.stringify(keys) !== JSON.stringify(SIEM.members)) return `its members are ${JSON.stringify(keys)}, not ${JSON.stringify(SIEM.members)}`;
  if (!['security', 'audit'].includes(record.stream)) return `stream is ${JSON.stringify(record.stream)}`;
  for (const name of ['id', 'operator_id', 'agent_id', 'event']) if (typeof record[name] !== 'string' || record[name].length === 0) return `${name} is not a non-empty string`;
  if (typeof record.time !== 'string' || !ISO.test(record.time)) return `time is ${JSON.stringify(record.time)}, not an ISO 8601 UTC time with milliseconds`;
  if (!['info', 'warning', 'critical'].includes(record.severity)) return `severity is ${JSON.stringify(record.severity)}`;
  if (!isObject(record.fields)) return 'fields is not an object';
  if (record.fields.truncated === true) return undefined;
  const fieldKeys = Object.keys(record.fields);
  if (JSON.stringify(fieldKeys) !== JSON.stringify(SIEM.fieldMembers[record.stream])) return `its fields are ${JSON.stringify(fieldKeys)}, not ${JSON.stringify(SIEM.fieldMembers[record.stream])}`;
  return undefined;
}

// ─── Records the suites make ───────────────────────────────────────────────────────────────────────────────────────

let counter = 0;
/**
 * Records of one stream with strictly increasing times and ids, so that the order of (time, id) is the order made.
 * `at` is the time of the first one.
 */
export function makeRecords(stream, count, { at = Date.now() + 2000, tag = randomBytes(3).toString('hex'), severities = stream === 'audit' ? ['info', 'warning'] : ['info', 'warning', 'critical'], over = () => ({}) } = {}) {
  const run = (counter += 1);
  return Array.from({ length: count }, (_, i) => {
    const severity = severities[i % severities.length];
    const id = `${stream === 'security' ? 'sevt' : 'aud'}_${tag}${run}_${String(i).padStart(4, '0')}`;
    const common = { stream, id, time: new Date(at + i).toISOString(), severity, operator_id: 'op_conformance', agent_id: 'agt_conformance' };
    const record = stream === 'security'
      ? { ...common, event: 'prompt_injection', fields: { passport_jti: 'pas_conformance', mission_id: i % 2 ? null : 'ms_conformance', message: `Body caught injection ${i}`, metadata: { pattern_id: 'override_ignore_previous', blocked: true }, resolved: false } }
      : { ...common, event: 'proxy.call', fields: { passport_jti: 'pas_conformance', layer: 'vault', outcome: severity === 'info' ? 'success' : 'blocked', error_code: severity === 'info' ? null : 'CONTROL_DENIED', trace_id: `trace_${id}`, entry_hash: `h_${id}` } };
    return { ...record, ...over(i, record) };
  });
}

const sortKeys = (v) => (Array.isArray(v) ? v.map(sortKeys) : isObject(v) ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])])) : v);
const same = (a, b) => JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b));
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function until(predicate, ms = 4000, quiet = 0) {
  const deadline = Date.now() + ms;
  let ok = false;
  while (Date.now() < deadline) {
    if (predicate()) { ok = true; break; }
    await sleep(25);
  }
  if (ok && quiet > 0) await sleep(quiet);
  return ok;
}

// ─── The collectors the kit plays (the exporter suite) ─────────────────────────────────────────────────────────────

async function udpCollector() {
  const socket = createSocket('udp4');
  const datagrams = [];
  socket.on('message', (m) => datagrams.push(Buffer.from(m)));
  await new Promise((resolve) => socket.bind(0, '127.0.0.1', resolve));
  return { port: socket.address().port, datagrams, close: async () => { socket.close(); } };
}

/** A TCP server, with TLS when given a certificate. `refuse()` stops it listening and `accept()` starts it on the same port again. */
async function streamCollector(certificate) {
  const connections = [];
  const sockets = new Set();
  const onConnection = (socket) => {
    const connection = { bytes: Buffer.alloc(0), ended: false, protocol: certificate ? socket.getProtocol?.() ?? null : null };
    connections.push(connection);
    sockets.add(socket);
    socket.on('data', (d) => { connection.bytes = Buffer.concat([connection.bytes, d]); });
    socket.on('end', () => { connection.ended = true; socket.end(); });
    socket.on('error', () => undefined);
    socket.on('close', () => sockets.delete(socket));
  };
  const server = certificate ? createTlsServer({ cert: certificate.cert, key: certificate.key, minVersion: 'TLSv1' }, onConnection) : createNetServer(onConnection);
  if (certificate) server.on('tlsClientError', () => undefined);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  let listening = true;
  return {
    port,
    connections,
    refuse: () => new Promise((resolve) => { listening = false; server.close(() => resolve()); }),
    accept: () => new Promise((resolve) => { if (listening) return resolve(); server.listen(port, '127.0.0.1', () => { listening = true; resolve(); }); }),
    close: async () => { for (const socket of sockets) socket.destroy(); if (listening) await new Promise((resolve) => server.close(() => resolve())); },
  };
}

async function httpsCollector(certificate) {
  const requests = [];
  let answer = () => ({ status: 200 });
  const server = createHttpsServer({ cert: certificate.cert, key: certificate.key }, (req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const entry = { method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8'), status: 0 };
      requests.push(entry);
      const reply = answer(entry, requests.length);
      entry.status = reply.status;
      res.writeHead(reply.status, reply.headers ?? {});
      res.end();
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  return {
    port,
    url: `https://127.0.0.1:${port}/siem/ingest?source=conformance`,
    requests,
    answer: (fn) => { answer = fn; },
    close: async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(() => resolve())); },
  };
}

/**
 * Everything one scenario needs: the collectors it asks for, an exporter driven by the harness, and what arrived.
 * `trust` is 'ca' (the exporter is given the collectors' certificate authority), 'none' (it is given none) or 'other-host'
 * (the certificate names a host the collector is not at).
 */
async function rig(options, { syslog = null, http = false, streams = ['security'], token = 'siem-test-token', trust = 'ca', history = [] } = {}) {
  const certificate = trust === 'other-host' ? selfSignedCertificate({ commonName: 'collector.invalid', dns: ['collector.invalid'], ips: [] }) : selfSignedCertificate();
  const canary = `CANARY-${randomBytes(6).toString('hex')}`;
  const collectors = {};
  const closers = [];
  if (syslog === 'udp') closers.push((collectors.udp = await udpCollector()).close);
  if (syslog === 'tcp') closers.push((collectors.tcp = await streamCollector(null)).close);
  if (syslog === 'tls') closers.push((collectors.tls = await streamCollector(certificate)).close);
  if (http) closers.push((collectors.https = await httpsCollector(certificate)).close);
  const config = {
    syslog: syslog ? { url: `${syslog}://127.0.0.1:${collectors[syslog].port}` } : null,
    http: http ? { url: collectors.https.url, token } : null,
    caPem: trust === 'none' ? null : certificate.cert,
    streams,
    canary,
  };
  if (http && token === null) config.http.token = null;
  const exporter = await options.exporter(config);
  closers.push(async () => exporter.close?.());
  if (history.length > 0) await exporter.emit(history);
  const attempt = async () => { try { await exporter.pass(); return null; } catch (error) { return error; } };
  await attempt(); // the exporter starts: what came before is history
  return {
    collectors, canary, token, attempt,
    emit: (records) => exporter.emit(records),
    close: async () => { for (const close of closers.reverse()) await close().catch(() => undefined); },
    /** The messages that arrived at the syslog collector, parsed, with the raw text. */
    messages() {
      const out = [];
      if (collectors.udp) for (const d of collectors.udp.datagrams) out.push({ raw: d.toString('utf8'), bytes: d.length });
      for (const c of [collectors.tcp, collectors.tls]) {
        if (!c) continue;
        for (const connection of c.connections) for (const frame of readOctetFrames(connection.bytes).frames) out.push({ raw: frame.toString('utf8'), bytes: frame.length });
      }
      return out;
    },
    /** The raw bytes of everything that arrived, anywhere. */
    everything() {
      const parts = [];
      if (collectors.udp) parts.push(...collectors.udp.datagrams);
      for (const c of [collectors.tcp, collectors.tls]) if (c) parts.push(...c.connections.map((x) => x.bytes));
      if (collectors.https) parts.push(...collectors.https.requests.map((r) => Buffer.from(`${JSON.stringify(r.headers)}\n${r.url}\n${r.body}`)));
      return Buffer.concat(parts).toString('utf8');
    },
  };
}

const bodyRecords = (request) => request.body.split('\n').filter((line) => line.length > 0).map((line) => JSON.parse(line));
const syslogRecord = (message) => JSON.parse(parseSyslogMessage(message.raw).msg);
const idsOf = (records) => records.map((r) => r.id);

// ─── The exporter suite ────────────────────────────────────────────────────────────────────────────────────────────

/**
 * @param {{ exporter: (config: object) => Promise<{ emit: (records: object[]) => Promise<void>, pass: () => Promise<void>, close?: () => Promise<void> }>, transports?: string[] }} options
 */
export async function runSiemExporterSuite(options) {
  const offered = options.transports ?? ['udp', 'tcp', 'tls', 'https'];
  const syslogs = offered.filter((t) => t !== 'https');
  const https = offered.includes('https');
  const settle = async (r, expected, extra) => until(() => expected(), 4000, extra ?? 150);
  const noTransport = (name) => skip(`the harness does not offer ${name}`);

  /** Run a scenario and always clean up. */
  const withRig = async (rigOptions, body) => {
    const r = await rig(options, rigOptions);
    try { return await body(r); } finally { await r.close(); }
  };
  /** Send these records through one transport and return what arrived there. */
  const through = async (transport, records, { expected = records.length, ...extra } = {}) => withRig(transport === 'https' ? { http: true, ...extra } : { syslog: transport, ...extra }, async (r) => {
    await r.emit(records);
    await r.attempt();
    const arrived = () => (transport === 'https'
      ? r.collectors.https.requests.filter((q) => q.status >= 200 && q.status < 300).flatMap(bodyRecords)
      : r.messages().map(syslogRecord));
    await settle(r, () => arrived().length >= expected);
    return { records: arrived(), r, rawMessages: transport === 'https' ? [] : r.messages(), requests: r.collectors.https?.requests ?? [], connections: (r.collectors.tcp ?? r.collectors.tls)?.connections ?? [], datagrams: r.collectors.udp?.datagrams ?? [] };
  });

  const mixed = () => [
    ...makeRecords('security', 3, { severities: ['critical', 'warning', 'info'] }),
    ...makeRecords('audit', 3, { at: Date.now() + 2500, severities: ['warning', 'info'] }),
  ];

  const checks = [
    {
      id: 'X01', level: 'MUST', title: 'does not send what came before it started: a connector switched on today sends what happens from today',
      async run() {
        const transport = offered[0];
        const old = makeRecords('security', 3, { at: Date.now() - 3_600_000 });
        const fresh = makeRecords('security', 2);
        const seen = await withRig(transport === 'https' ? { http: true, history: old } : { syslog: transport, history: old }, async (r) => {
          await r.emit(fresh);
          await r.attempt();
          const arrived = () => (transport === 'https' ? r.collectors.https.requests.flatMap((q) => (q.status < 300 ? bodyRecords(q) : [])) : r.messages().map(syslogRecord));
          await settle(r, () => arrived().length >= fresh.length, 300);
          return idsOf(arrived());
        });
        assert(old.every((o) => !seen.includes(o.id)), 'a record from before the first pass was sent');
        assert(fresh.every((f) => seen.includes(f.id)), 'a record emitted after the first pass was not sent');
      },
    },
    {
      id: 'X10', level: 'MUST', title: 'sends each record as one RFC 5424 message: PRI 34, 36 or 38 by severity, version 1, the record\'s time, host stack, app stack-engine, the stream as the message id, and the record as the body',
      async run() {
        if (syslogs.length === 0) return noTransport('a syslog transport');
        for (const transport of syslogs) {
          const records = mixed();
          const { records: got, rawMessages } = await through(transport, records, { streams: ['security', 'audit'] });
          assert(rawMessages.length >= records.length, `${transport}: ${rawMessages.length} messages arrived for ${records.length} records`);
          for (const record of records) {
            const message = rawMessages.find((m) => { try { return syslogRecord(m).id === record.id; } catch { return false; } });
            assert(message, `${transport}: no message for ${record.id}`);
            let parsed;
            try { parsed = parseSyslogMessage(message.raw); } catch (error) { throw new Error(`${transport}: ${error.message}: ${message.raw.slice(0, 120)}`, { cause: error }); }
            const where = `${transport} ${record.id}`;
            assert(parsed.pri === SIEM.facility * 8 + SIEM.syslogSeverity[record.severity], `${where}: PRI is ${parsed.pri} for severity ${record.severity}`);
            assert(parsed.version === 1, `${where}: version is ${parsed.version}`);
            assert(parsed.timestamp === record.time, `${where}: the timestamp is ${parsed.timestamp}, not the record's time ${record.time}`);
            assert(parsed.hostname === SIEM.hostname && parsed.appName === SIEM.appName && parsed.procId === '-', `${where}: the host, app or process is ${parsed.hostname} ${parsed.appName} ${parsed.procId}`);
            assert(parsed.msgId === record.stream, `${where}: the message id is ${parsed.msgId}`);
            assert(parsed.sdId === SIEM.sdId, `${where}: the structured data id is ${parsed.sdId}`);
            assert(JSON.stringify(parsed.params.map((p) => p[0])) === JSON.stringify(['stream', 'id', 'operator', 'agent', 'event']), `${where}: the structured data parameters are ${JSON.stringify(parsed.params.map((p) => p[0]))}`);
            const value = Object.fromEntries(parsed.params);
            assert(value.stream === record.stream && value.id === record.id && value.operator === record.operator_id && value.agent === record.agent_id && value.event === sdEvent(record.event), `${where}: the structured data does not say what the record says`);
            assert(!parsed.msg.startsWith('﻿'), `${where}: the body starts with a byte order mark`);
            const body = JSON.parse(parsed.msg);
            const problem = recordProblem(body);
            assert(!problem, `${where}: the body is not a record: ${problem}`);
            assert(same(body, record), `${where}: the body is not the record that was emitted`);
          }
          assert(got.length >= records.length, `${transport}: records are missing`);
        }
      },
    },
    {
      id: 'X11', level: 'MUST', title: 'escapes the three characters structured data cannot carry (backslash, quote and closing bracket) and makes the event a safe name, cut to 32 characters, leaving the whole event in the body',
      async run() {
        if (syslogs.length === 0) return noTransport('a syslog transport');
        const record = makeRecords('security', 1, { over: () => ({ id: 'sevt_a"b]c\\d_e', event: 'weird event/name with.dots and a very long tail 0123456789', agent_id: 'agt "q"' }) })[0];
        const { rawMessages } = await through(syslogs[0], [record]);
        assert(rawMessages.length === 1, `${rawMessages.length} messages arrived`);
        const parsed = parseSyslogMessage(rawMessages[0].raw);
        const value = Object.fromEntries(parsed.params);
        assert(value.id === record.id, `the id came back as ${JSON.stringify(value.id)}`);
        assert(value.agent === record.agent_id, `the agent came back as ${JSON.stringify(value.agent)}`);
        assert(value.event === sdEvent(record.event) && value.event.length <= 32, `the event came back as ${JSON.stringify(value.event)}`);
        assert(JSON.parse(parsed.msg).event === record.event, 'the body does not carry the whole event');
        assert(/id="sevt_a\\"b\\\]c\\\\d_e"/.test(rawMessages[0].raw), 'the id is not escaped as RFC 5424 says');
      },
    },
    {
      id: 'X12', level: 'MUST', title: 'sends a record too big for one datagram without its detail (fields {"truncated":true}) in a message of at most 8000 bytes, and an HTTPS line whole',
      async run() {
        if (offered.length === 0) return noTransport('a transport');
        const big = makeRecords('security', 1, { over: (_i, r) => ({ fields: { ...r.fields, metadata: { blob: 'x'.repeat(20_000) } } }) })[0];
        for (const transport of syslogs) {
          const { rawMessages } = await through(transport, [big]);
          assert(rawMessages.length === 1, `${transport}: ${rawMessages.length} messages arrived`);
          assert(rawMessages[0].bytes <= SIEM.maxSyslogBytes, `${transport}: the message is ${rawMessages[0].bytes} bytes`);
          const body = JSON.parse(parseSyslogMessage(rawMessages[0].raw).msg);
          assert(body.id === big.id && body.time === big.time && body.severity === big.severity && body.event === big.event, `${transport}: the identifying members changed`);
          assert(same(body.fields, { truncated: true }), `${transport}: the fields are ${JSON.stringify(body.fields).slice(0, 80)}, not {"truncated":true}`);
        }
        if (https) {
          const { records } = await through('https', [big]);
          assert(records.length === 1 && same(records[0], big), 'the HTTPS line is not the whole record');
        }
      },
    },
    {
      id: 'X13', level: 'MUST', title: 'frames TCP and TLS messages by octet counting in bytes (with text that is not ASCII), one connection for a batch of at most 200 that it closes, nothing after the last frame',
      async run() {
        const streams = syslogs.filter((t) => t !== 'udp');
        if (streams.length === 0) return noTransport('TCP or TLS');
        for (const transport of streams) {
          const records = makeRecords('security', 3, { over: (i, r) => ({ fields: { ...r.fields, message: `héllo — 日本語 ✓ ${i}` } }) });
          const { rawMessages, connections } = await through(transport, records);
          assert(connections.length === 1, `${transport}: ${connections.length} connections were made for one batch`);
          const bytes = connections[0].bytes;
          const { frames, rest } = readOctetFrames(bytes);
          assert(frames.length === 3 && rest.length === 0, `${transport}: ${frames.length} frames and ${rest.length} bytes left over`);
          let length = 0;
          for (const frame of frames) length += frame.length + `${frame.length} `.length;
          assert(length === bytes.length, `${transport}: the frames are not the whole stream`);
          for (const message of rawMessages) assert(Buffer.byteLength(message.raw, 'utf8') === message.bytes, `${transport}: a count is not a number of bytes`);
          assert(rawMessages.some((m) => m.raw.includes('日本語')), `${transport}: the text that is not ASCII did not arrive`);
          assert(connections[0].ended, `${transport}: the exporter did not close the connection`);
        }
        const transport = streams[0];
        const many = makeRecords('security', 250);
        const { connections } = await withRig({ syslog: transport }, async (r) => {
          await r.emit(many);
          await r.attempt();
          const c = (r.collectors.tcp ?? r.collectors.tls).connections;
          await settle(r, () => c.reduce((n, x) => n + readOctetFrames(x.bytes).frames.length, 0) >= 250);
          return { connections: c.map((x) => readOctetFrames(x.bytes).frames.length) };
        });
        assert(JSON.stringify(connections) === JSON.stringify([200, 50]), `250 records went in connections of ${JSON.stringify(connections)} messages, not [200,50]`);
      },
    },
    {
      id: 'X14', level: 'MUST', title: 'sends each UDP message as a datagram of its own, with no framing',
      async run() {
        if (!syslogs.includes('udp')) return noTransport('UDP');
        const records = makeRecords('security', 4);
        const { datagrams } = await through('udp', records);
        assert(datagrams.length === 4, `${datagrams.length} datagrams arrived for 4 records`);
        for (const d of datagrams) {
          const parsed = parseSyslogMessage(d.toString('utf8'));
          assert(!/^\d+ </.test(d.toString('utf8')), 'a datagram starts with a byte count');
          JSON.parse(parsed.msg);
        }
      },
    },
    {
      id: 'X20', level: 'MUST', title: 'sends syslog over TLS 1.2 or later to a collector whose certificate chains to the authority it was given',
      async run() {
        if (!syslogs.includes('tls')) return noTransport('TLS');
        const records = makeRecords('security', 2);
        const { records: got, connections } = await through('tls', records);
        assert(got.length === 2, `${got.length} of 2 records arrived over TLS`);
        assert(connections.every((c) => c.protocol === null || /^TLSv1\.[23]$/.test(c.protocol)), `a connection used ${connections.map((c) => c.protocol)}`);
      },
    },
    {
      id: 'X21', level: 'MUST', title: 'never sends to a TLS or HTTPS collector whose certificate it does not trust, or whose certificate names another host',
      async run() {
        const targets = [...(syslogs.includes('tls') ? ['tls'] : []), ...(https ? ['https'] : [])];
        if (targets.length === 0) return noTransport('TLS or HTTPS');
        for (const trust of ['none', 'other-host']) {
          for (const transport of targets) {
            const records = makeRecords('security', 2);
            await withRig(transport === 'https' ? { http: true, trust } : { syslog: transport, trust }, async (r) => {
              await r.emit(records);
              await r.attempt();
              await sleep(400);
              await r.attempt();
              await sleep(400);
              const connections = r.collectors.tls?.connections ?? [];
              const requests = r.collectors.https?.requests ?? [];
              assert(connections.every((c) => c.bytes.length === 0) && requests.length === 0, `${transport} with ${trust === 'none' ? 'an authority it was not given' : 'a certificate for another host'}: data reached the collector`);
              assert(!r.everything().includes('sevt_'), `${transport} with ${trust}: a record reached the collector`);
            });
          }
        }
      },
    },
    {
      id: 'X30', level: 'MUST', title: 'POSTs a batch to the configured address as newline-delimited JSON with the content type and the bearer token, one record to a line, each line ended by a newline, at most 200 to a request, never compressed',
      async run() {
        if (!https) return noTransport('HTTPS');
        const records = makeRecords('security', 250);
        const { requests } = await through('https', records);
        const taken = requests.filter((q) => q.status >= 200 && q.status < 300);
        assert(taken.length === 2, `${taken.length} requests carried 250 records, not 2`);
        for (const request of requests) {
          assert(request.method === 'POST', `the method is ${request.method}`);
          assert(request.url === '/siem/ingest?source=conformance', `the request went to ${request.url}`);
          assert(request.headers['content-type'] === SIEM.contentType, `the content type is ${request.headers['content-type']}`);
          assert(request.headers.authorization === 'Bearer siem-test-token', `the authorization is ${request.headers.authorization}`);
          assert(!request.headers['content-encoding'], 'the body is compressed');
          assert(request.body.endsWith('\n') && !request.body.includes('\n\n'), 'the body is not lines each ended by a newline');
          const sent = bodyRecords(request);
          assert(sent.length >= 1 && sent.length <= SIEM.batchSize, `a request carries ${sent.length} records`);
          for (const record of sent) assert(!recordProblem(record), `a line is not a record: ${recordProblem(record)}`);
        }
        assert(JSON.stringify(taken.map((q) => bodyRecords(q).length)) === JSON.stringify([200, 50]), `the requests carried ${taken.map((q) => bodyRecords(q).length)} records, not [200,50]`);
        assert(JSON.stringify(idsOf(taken.flatMap(bodyRecords))) === JSON.stringify(idsOf(records)), 'the records are not in the order of their time');
      },
    },
    {
      id: 'X31', level: 'MUST', title: 'sends no Authorization header when it has no token',
      async run() {
        if (!https) return noTransport('HTTPS');
        const { requests } = await through('https', makeRecords('security', 1), { token: null });
        assert(requests.length >= 1, 'no request arrived');
        assert(requests.every((q) => q.headers.authorization === undefined), `an Authorization header was sent: ${requests[0].headers.authorization}`);
      },
    },
    {
      id: 'X32', level: 'MUST', title: 'sends each record once when nothing fails, in the order of time and id, only for the streams it was told to export',
      async run() {
        const transport = https ? 'https' : offered[0];
        for (const streams of [['security'], ['audit'], ['security', 'audit']]) {
          const records = [...makeRecords('security', 30), ...makeRecords('audit', 30)];
          const want = records.filter((r) => streams.includes(r.stream));
          const { records: got } = await through(transport, records, { streams, expected: want.length });
          const key = (r) => `${r.stream}/${r.id}`;
          assert(new Set(got.map(key)).size === got.length, `${streams}: a record arrived twice`);
          assert(JSON.stringify([...got.map(key)].sort()) === JSON.stringify(want.map(key).sort()), `${streams}: the records that arrived are not the records of those streams (${got.length} of ${want.length})`);
          if (transport !== 'udp') {
            for (const stream of streams) {
              const order = got.filter((r) => r.stream === stream).map((r) => r.id);
              assert(JSON.stringify(order) === JSON.stringify(order.slice().sort()), `${streams}: the ${stream} records are not in order`);
            }
          }
        }
      },
    },
    {
      id: 'X33', level: 'MUST', title: 'sends the same record to the syslog collector and the HTTPS collector, and keeps from both what the source did not mean to be public',
      async run() {
        if (!https || syslogs.length === 0) return noTransport('a syslog transport and HTTPS together');
        const transport = syslogs.includes('tcp') ? 'tcp' : syslogs[0];
        const records = mixed();
        await withRig({ syslog: transport, http: true, streams: ['security', 'audit'] }, async (r) => {
          await r.emit(records);
          await r.attempt();
          const viaHttp = () => r.collectors.https.requests.filter((q) => q.status < 300).flatMap(bodyRecords);
          await settle(r, () => viaHttp().length >= records.length && r.messages().length >= records.length);
          assert(viaHttp().length === records.length, `${viaHttp().length} records arrived by HTTPS, not ${records.length}`);
          for (const record of records) {
            const a = viaHttp().find((x) => x.id === record.id);
            const b = r.messages().map(syslogRecord).find((x) => x.id === record.id);
            assert(a && b && same(a, b) && same(a, record), `${record.id}: the two collectors did not receive the same record`);
          }
          assert(!r.everything().includes(r.canary), 'a value the source holds in a field that is not public reached a collector');
        });
      },
    },
    {
      id: 'X40', level: 'MUST', title: 'keeps its place when an HTTPS collector fails it (503, 401, 400 or a redirect it does not follow) and sends the same records, none lost, in order, when it recovers',
      async run() {
        if (!https) return noTransport('HTTPS');
        for (const status of [503, 401, 400, 302]) {
          const first = makeRecords('security', 5);
          const later = makeRecords('security', 3, { at: Date.now() + 3000 });
          await withRig({ http: true }, async (r) => {
            const c = r.collectors.https;
            c.answer(() => (status === 302 ? { status, headers: { location: `https://127.0.0.1:${c.port}/moved` } } : { status }));
            await r.emit(first);
            await r.attempt();
            await r.attempt();
            await r.emit(later);
            await r.attempt();
            assert(!c.requests.some((q) => q.url === '/moved'), `a ${status} redirect was followed`);
            assert(!c.requests.some((q) => q.status < 300), `a record was taken while the collector answered ${status}`);
            c.answer(() => ({ status: 200 }));
            await r.attempt();
            const arrived = () => c.requests.filter((q) => q.status === 200).flatMap(bodyRecords);
            await settle(r, () => arrived().length >= 8);
            assert(JSON.stringify(idsOf(arrived())) === JSON.stringify(idsOf([...first, ...later])), `after ${status}, ${arrived().length} records arrived in the order ${idsOf(arrived()).map((id) => id.slice(-4))}, not all 8 in order`);
          });
        }
      },
    },
    {
      id: 'X41', level: 'MUST', title: 'keeps its place when a TCP or TLS collector refuses the connection, and sends the same records, none lost, when it listens again',
      async run() {
        const streams = syslogs.filter((t) => t !== 'udp');
        if (streams.length === 0) return noTransport('TCP or TLS');
        for (const transport of streams) {
          const records = makeRecords('security', 6);
          await withRig({ syslog: transport }, async (r) => {
            const c = r.collectors[transport];
            await c.refuse();
            await r.emit(records);
            await r.attempt();
            await r.attempt();
            assert(c.connections.every((x) => x.bytes.length === 0), `${transport}: records reached a collector that was not listening`);
            await c.accept();
            await r.attempt();
            const arrived = () => r.messages().map(syslogRecord);
            await settle(r, () => arrived().length >= 6);
            assert(JSON.stringify(idsOf(arrived())) === JSON.stringify(idsOf(records)), `${transport}: ${arrived().length} records arrived after the collector came back, not the 6 sent in order`);
          });
        }
      },
    },
    {
      id: 'X50', level: 'MUST', title: 'sends nothing a source row holds outside the public fields: a value planted in every other field never arrives, and a record has exactly the members and fields of the specification',
      async run() {
        if (offered.length === 0) return noTransport('a transport');
        const records = mixed();
        const transports = [...syslogs.slice(0, 1), ...(https ? ['https'] : [])];
        for (const transport of transports) {
          const { records: got, r } = await through(transport, records, { streams: ['security', 'audit'] });
          assert(got.length >= records.length, `${transport}: ${got.length} records arrived`);
          assert(!r.everything().includes(r.canary), `${transport}: a planted value arrived`);
          for (const record of got) assert(!recordProblem(record), `${transport} ${record.id}: ${recordProblem(record)}`);
        }
      },
    },
  ];
  return runChecks('security monitoring export: exporter', checks);
}

// ─── The collector suite ───────────────────────────────────────────────────────────────────────────────────────────

function sendUdp({ host, port }, messages) {
  return new Promise((resolve, reject) => {
    const socket = createSocket('udp4');
    let pending = messages.length;
    for (const message of messages) {
      socket.send(Buffer.from(message, 'utf8'), port, host, (error) => {
        if (error) { socket.close(); reject(error); } else if (--pending === 0) { socket.close(); resolve(); }
      });
    }
  });
}

/** Write `chunks` (buffers) on one connection, one after the other, then close it. */
function sendStream({ host, port, ca = null, tls = false }, chunks, { gap = 5 } = {}) {
  return new Promise((resolve, reject) => {
    const socket = tls ? tlsConnect({ host, port, ca, ...(/^\d+\.\d+\.\d+\.\d+$/.test(host) ? {} : { servername: host }), minVersion: 'TLSv1.2' }) : netConnect({ host, port });
    socket.on('error', reject);
    socket.on('close', () => resolve());
    socket.on(tls ? 'secureConnect' : 'connect', async () => {
      for (const chunk of chunks) {
        socket.write(chunk);
        if (gap > 0) await sleep(gap);
      }
      socket.end();
    });
    socket.resume();
  });
}

function postBatch({ url, ca }, { headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const request = httpsRequest(url, { method: 'POST', ca, headers: { 'content-type': SIEM.contentType, 'content-length': Buffer.byteLength(body), ...headers }, timeout: 10_000 }, (response) => {
      const chunks = [];
      response.on('data', (c) => chunks.push(c));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, text: Buffer.concat(chunks).toString('utf8') }));
    });
    request.on('error', reject);
    request.on('timeout', () => request.destroy(new Error('the collector did not answer in 10 seconds')));
    request.end(body);
  });
}

/** Cut a buffer at the given offsets. */
const cutAt = (buffer, offsets) => {
  const out = [];
  let last = 0;
  for (const offset of [...offsets, buffer.length]) { if (offset > last) out.push(buffer.subarray(last, offset)); last = Math.max(last, offset); }
  return out;
};

/**
 * @param {{ collector: (options: { token: string }) => Promise<{ udp?: object, tcp?: object, tls?: object, https?: object, records: () => Promise<object[]>, close?: () => Promise<void> }> }} options
 */
export async function runSiemCollectorSuite(options) {
  const token = `siem-${randomBytes(12).toString('base64url')}`;
  const handle = await options.collector({ token });
  const held = async () => handle.records();
  const keyOf = (r) => `${r.stream}/${r.id}`;
  const has = async (records) => {
    const stored = await held();
    return records.every((record) => stored.some((s) => s.stream === record.stream && s.id === record.id));
  };
  const count = async (record) => (await held()).filter((s) => s.stream === record.stream && s.id === record.id).length;
  const waitHeld = async (records, ms = 3000) => { const deadline = Date.now() + ms; while (Date.now() < deadline) { if (await has(records)) return true; await sleep(30); } return false; };
  const needs = (name) => (handle[name] ? null : skip(`the collector offers no ${name} address`));
  const auth = { authorization: `Bearer ${token}` };
  const streamTransports = ['tcp', 'tls'].filter((name) => handle[name]);

  const result = await runChecks('security monitoring export: collector', [
    {
      id: 'C01', level: 'MUST', title: 'takes each UDP datagram as one syslog message and stores its record, as it is',
      async run() {
        const unsupported = needs('udp');
        if (unsupported) return unsupported;
        const records = makeRecords('security', 3, { severities: ['critical', 'warning', 'info'] });
        await sendUdp(handle.udp, records.map((r) => formatSyslogMessage(r)));
        assert(await waitHeld(records), 'the records were not stored');
        const stored = await held();
        for (const record of records) assert(same(stored.find((s) => s.id === record.id), record), `${record.id} was stored changed`);
      },
    },
    {
      id: 'C02', level: 'MUST', title: 'reads TCP frames by octet counting: frames split at any byte, text that is not ASCII counted in bytes, and a message with a newline in its structured data',
      async run() {
        if (streamTransports.length === 0) return skip('the collector offers no TCP or TLS address');
        for (const name of streamTransports) {
          const records = makeRecords('security', 4, {
            over: (i, r) => ({
              ...(i === 1 ? { id: `${r.id}_line\nbreak` } : {}),
              fields: { ...r.fields, message: i === 2 ? 'héllo — 日本語 ✓' : r.fields.message },
            }),
          });
          const bytes = octetFrames(records.map((r) => formatSyslogMessage(r)));
          const target = { ...handle[name], tls: name === 'tls' };
          await sendStream(target, cutAt(bytes, [1, 2, 3, 40, Math.floor(bytes.length / 2), Math.floor(bytes.length / 2) + 7, bytes.length - 2]));
          assert(await waitHeld(records), `${name}: the records were not all stored`);
          const stored = await held();
          for (const record of records) assert(same(stored.find((s) => s.id === record.id), record), `${name}: ${JSON.stringify(record.id)} was stored changed`);
        }
      },
    },
    {
      id: 'C03', level: 'MUST', title: 'takes a batch of 200 messages on one TCP or TLS connection and a message of 7000 bytes',
      async run() {
        if (streamTransports.length === 0) return skip('the collector offers no TCP or TLS address');
        for (const name of streamTransports) {
          const records = makeRecords('audit', 200);
          const large = makeRecords('security', 1, { over: (_i, r) => ({ fields: { ...r.fields, message: 'y'.repeat(6000) } }) })[0];
          await sendStream({ ...handle[name], tls: name === 'tls' }, [octetFrames([...records, large].map((r) => formatSyslogMessage(r)))], { gap: 0 });
          assert(await waitHeld([...records, large], 5000), `${name}: not all 201 records were stored`);
        }
      },
    },
    {
      id: 'C04', level: 'MUST', title: 'takes a batch of newline-delimited JSON with the bearer token, answers 2xx only after it has stored the whole batch, and takes 200 records and a body of 8 MiB',
      async run() {
        const unsupported = needs('https');
        if (unsupported) return unsupported;
        const records = makeRecords('security', 5);
        const response = await postBatch(handle.https, { headers: auth, body: ndjson(records) });
        assert(response.status >= 200 && response.status < 300, `the collector answered ${response.status}`);
        assert(await has(records), 'the collector answered before it stored the batch');
        const batch = makeRecords('audit', 200);
        const second = await postBatch(handle.https, { headers: auth, body: ndjson(batch) });
        assert(second.status >= 200 && second.status < 300, `a batch of 200 records was answered ${second.status}`);
        assert(await has(batch), 'the batch of 200 was not stored');
        const heavy = makeRecords('security', 8, { over: (_i, r) => ({ fields: { ...r.fields, metadata: { blob: 'z'.repeat(1_100_000) } } }) });
        const third = await postBatch(handle.https, { headers: auth, body: ndjson(heavy) });
        assert(third.status >= 200 && third.status < 300, `a body of about 8.8 MiB was answered ${third.status}`);
        assert(await has(heavy), 'the body of 8 MiB was not stored');
      },
    },
    {
      id: 'C05', level: 'MUST', title: 'refuses a batch with no bearer token or a wrong one (401 or 403) and stores nothing from it',
      async run() {
        const unsupported = needs('https');
        if (unsupported) return unsupported;
        for (const [why, headers] of [['no token', {}], ['a wrong token', { authorization: `Bearer ${token}x` }], ['another scheme', { authorization: `Basic ${Buffer.from(`x:${token}`).toString('base64')}` }]]) {
          const records = makeRecords('security', 2);
          const response = await postBatch(handle.https, { headers, body: ndjson(records) });
          assert([401, 403].includes(response.status), `${why}: the collector answered ${response.status}`);
          await sleep(100);
          assert(!(await held()).some((s) => records.some((r) => r.id === s.id)), `${why}: a record was stored`);
        }
      },
    },
    {
      id: 'C06', level: 'MUST', title: 'drops a repeat by stream and id, over one transport and across two, and keeps two records that have the same id in different streams',
      async run() {
        const records = makeRecords('security', 3);
        const twin = { ...makeRecords('audit', 1)[0], id: records[0].id };
        const via = [];
        if (handle.https) via.push(async (rs) => postBatch(handle.https, { headers: auth, body: ndjson(rs) }));
        if (handle.udp) via.push((rs) => sendUdp(handle.udp, rs.map((r) => formatSyslogMessage(r))));
        if (streamTransports[0]) via.push((rs) => sendStream({ ...handle[streamTransports[0]], tls: streamTransports[0] === 'tls' }, [octetFrames(rs.map((r) => formatSyslogMessage(r)))], { gap: 0 }));
        if (via.length === 0) return skip('the collector offers no transport');
        for (const send of via) await send(records);
        await send2(via, records);
        await send2(via.slice().reverse(), [twin]);
        assert(await waitHeld([...records, twin]), 'the records were not stored');
        await sleep(200);
        for (const record of records) assert((await count(record)) === 1, `${record.id} is stored ${await count(record)} times`);
        assert((await count(twin)) === 1 && (await count(records[0])) === 1, 'two records with one id in two streams were not both kept');
        assert((await held()).filter((s) => s.id === records[0].id).length === 2, 'the records of the two streams are not kept apart');
        void keyOf;
        async function send2(senders, rs) { for (const send of senders) await send(rs); }
      },
    },
    {
      id: 'C07', level: 'MUST', title: 'takes the record from the body, not from the structured data or the priority: a message whose structured data names another id and whose priority says another severity is stored as its body says',
      async run() {
        const transport = handle.udp ? 'udp' : streamTransports[0];
        if (!transport) return skip('the collector offers no syslog transport');
        const [record] = makeRecords('security', 1, { severities: ['critical'] });
        const message = formatSyslogMessage(record, { pri: 38 }).replace(`id="${record.id}"`, 'id="sevt_not_the_one"').replace('operator="op_conformance"', 'operator="op_other"');
        if (transport === 'udp') await sendUdp(handle.udp, [message]);
        else await sendStream({ ...handle[transport], tls: transport === 'tls' }, [octetFrames([message])], { gap: 0 });
        assert(await waitHeld([record]), 'the record named in the body was not stored');
        const stored = (await held()).find((s) => s.id === record.id);
        assert(same(stored, record), 'the stored record is not the body of the message');
        assert(!(await held()).some((s) => s.id === 'sevt_not_the_one'), 'the collector took the id from the structured data');
      },
    },
    {
      id: 'C08', level: 'MUST', title: 'accepts members it does not know (in the record, in its fields and in the structured data) and a record with truncated fields',
      async run() {
        const [known] = makeRecords('security', 1);
        const future = { ...known, id: `${known.id}_future`, x_future_member: { a: 1 }, fields: { ...known.fields, future_field: [1, 2] } };
        const truncated = { ...makeRecords('security', 1)[0], fields: { truncated: true } };
        const records = [future, truncated];
        const transport = handle.https ? 'https' : handle.udp ? 'udp' : streamTransports[0];
        if (!transport) return skip('the collector offers no transport');
        if (transport === 'https') {
          const response = await postBatch(handle.https, { headers: auth, body: ndjson(records) });
          assert(response.status >= 200 && response.status < 300, `the collector answered ${response.status}`);
        } else {
          const messages = records.map((r) => formatSyslogMessage(r).replace(']', ' x_future="1"]'));
          if (transport === 'udp') await sendUdp(handle.udp, messages);
          else await sendStream({ ...handle[transport], tls: transport === 'tls' }, [octetFrames(messages)], { gap: 0 });
        }
        assert(await waitHeld(records), 'a record with a member the collector does not know, or with truncated fields, was not stored');
      },
    },
    {
      id: 'C09', level: 'MUST', title: 'never answers with a redirect',
      async run() {
        const unsupported = needs('https');
        if (unsupported) return unsupported;
        const answers = [];
        answers.push(await postBatch(handle.https, { headers: auth, body: ndjson(makeRecords('security', 1)) }));
        answers.push(await postBatch(handle.https, { headers: {}, body: ndjson(makeRecords('security', 1)) }));
        answers.push(await postBatch(handle.https, { headers: auth, body: 'not json\n' }));
        for (const a of answers) assert(a.status < 300 || a.status >= 400, `the collector answered ${a.status}`);
      },
    },
    {
      id: 'C10', level: 'SHOULD', title: 'refuses a body that is not newline-delimited JSON of records with a 4xx, and takes a body whose last line has no newline',
      async run() {
        const unsupported = needs('https');
        if (unsupported) return unsupported;
        const bad = await postBatch(handle.https, { headers: auth, body: `${JSON.stringify(makeRecords('security', 1)[0])}\nthis is not json\n` });
        assert(bad.status >= 400 && bad.status < 500, `a body with a line that is not JSON was answered ${bad.status}`);
        const records = makeRecords('audit', 2);
        const bare = await postBatch(handle.https, { headers: auth, body: ndjson(records).trimEnd() });
        assert(bare.status >= 200 && bare.status < 300 && (await waitHeld(records)), `a body with no final newline was answered ${bare.status}`);
      },
    },
  ]);
  await handle.close?.();
  return result;
}
