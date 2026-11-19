# STACK Security Monitoring Export

**Specification:** STACK Security Monitoring Export
**Version:** 1.0.0
**Status:** Stable
**Licence:** Apache-2.0

An install of the STACK engine can send its own record to the customer's security tooling as it happens: the security events its detectors and signals raise, and the rows of its audit log. This document defines what is sent (the record), how it is framed for each way of sending it (RFC 5424 syslog over UDP, TCP and TLS, and newline-delimited JSON over HTTPS with a bearer token), when it is sent and what delivery promises, and what a collector must do with it.

Contents: 1 Conventions, 2 Overview, 3 Records, 4 Delivery, 5 Syslog messages, 6 Syslog transports, 7 HTTPS, 8 Configuration, 9 What a collector must do, 10 Failures and retries, 11 Security considerations, 12 Machine-readable schemas, 13 Conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. Two roles are used. The **exporter** is the STACK engine, which finds new records and sends them. The **collector** is the customer's server or service (a syslog receiver, a SIEM, a log pipeline, an HTTPS ingest endpoint) that receives them. A collector implementation conforms to this specification if it satisfies every MUST in section 9. An exporter implementation conforms if it satisfies sections 3 to 8 and 10. The conformance kit in [`../conformance/`](../conformance/README.md) tests both: the `siem-exporter` suite plays a collector and judges an exporter, and the `siem-collector` suite plays an exporter and judges a collector.

All times are ISO 8601 in UTC with milliseconds (`2026-10-21T12:00:00.000Z`). All JSON is UTF-8. Identifiers are opaque: the prefixes in the examples are conventions of the reference implementation.

## 2. Overview

- The export is a feature of the engine that runs on the customer's own infrastructure, switched on by the install's configuration (section 8) and licensed: it is the `siem` feature of the install's licence key, listed there as "security-monitoring connectors". Without the feature the exporter sends nothing, even when it is configured; it starts from the moment the feature is first on (section 4.2). How a licence is issued and checked is not part of this specification.
- Two **streams** can be exported, each on its own: `security` and `audit` (section 3). The default is `security`.
- Each stream can go to one **syslog collector** (RFC 5424 messages over UDP, TCP or TLS) and to one **HTTPS collector** (newline-delimited JSON), together or alone. Both carry the same record: a syslog message holds it as the JSON text of its body, and a line of an HTTPS batch is that same text.
- Delivery is by batches, in order, from a position the exporter keeps. A position moves only after every collector took the batch, so a collector that was down is caught up when it returns, and a record can arrive more than once: every record carries an identifier so that a collector can drop a repeat (section 4).
- Only the public fields of a row are sent (section 3.4): never a credential, a Passport, or the body of a request or a response.

## 3. Records

### 3.1 The record

A record is a JSON object, described by [`schemas/SiemRecord.json`](schemas/SiemRecord.json). A record has exactly these members, in this order:

| Member | Value |
|---|---|
| `stream` | `security` or `audit` (3.2 and 3.3). |
| `id` | Unique within its stream. A collector identifies a record by the pair of `stream` and `id`. |
| `time` | When it happened: the row's creation time (security) or its timestamp (audit). |
| `severity` | `info`, `warning` or `critical`. |
| `operator_id` | The customer account the record belongs to. |
| `agent_id` | The agent it concerns. The engine uses the word `system` for an audit row it writes itself. |
| `event` | What happened, in the stream's own words: the signal type of a security event, the action of an audit row. |
| `fields` | The stream's own members (3.2, 3.3). |

A collector MUST ignore members it does not know, in the record and in `fields`: a later minor version of this specification may add them.

The streams:

| Stream | What it carries |
|---|---|
| `security` | The security events the detectors and signals raise, for example a prompt injection caught in an input, a burst of credential use, or a drift from what an agent declared. |
| `audit` | The rows of the audit log, the hash-chained record of what ran. |

### 3.2 The `security` stream

`id` is the security event's id. `severity` is the event's: `critical` and `info` as they are, anything else `warning`. `fields` is [`schemas/SiemSecurityFields.json`](schemas/SiemSecurityFields.json):

| Member | Value |
|---|---|
| `passport_jti` | The Passport the event was raised under, or `null`. |
| `mission_id` | The Mission it was raised under, or `null`. |
| `message` | The detector's own sentence about what it saw. |
| `metadata` | The detector's structured detail as stored on the event, or `null`: the pattern that matched and the field it matched in, whether the call was blocked, the classifier's verdict and cost. For text an agent itself sent, it can also carry a short excerpt of what matched (at most 80 characters) and the classifier's reasoning; for text that came from a third party it carries the length of the match and no excerpt. |
| `resolved` | Whether the event had been resolved when it was read. A record is exported once; a later resolution is not sent again. |

### 3.3 The `audit` stream

`id` is the audit row's entry id. `severity` is `warning` for a row whose outcome is `failure` or `blocked` and `info` for every other. `fields` is [`schemas/SiemAuditFields.json`](schemas/SiemAuditFields.json):

| Member | Value |
|---|---|
| `passport_jti` | The Passport the action ran under (`none` for an action that ran under none). |
| `layer` | Which part of the engine wrote the row (`vault`, `dropoff`, `skills`, `hire`, `system`). |
| `outcome` | `success`, `failure`, `pending` or `blocked`. |
| `error_code` | The error code of a failure or a refusal, or `null`. |
| `trace_id` | The identifier that ties the rows of one request together. |
| `entry_hash` | The row's hash in the operator's audit chain ([Record Format](../record/SPEC.md), section 5). It lets a collector tie an exported row to a record export; it is not enough to verify the chain, because the row's other fields are not sent. |

### 3.4 What is not sent

The exporter builds each record from a fixed list of fields; it never forwards a row. For an audit row, the digest of its payload, its error text, its durations and byte counts, its span identifiers, the hash of the row before it and the claims it was bound to are not sent. Neither stream carries a credential, a Passport token, an input or output body, a payload, or any personal data. The one place the text of a call can appear is `metadata` of a security event (3.2), and then only as the detector's own bounded excerpt.

A collector MUST treat `message` and `metadata`, and every value in a record that an agent or a third party can influence, as data and never as instructions (section 11).

### 3.5 Example

```json
{
  "stream": "security",
  "id": "sevt_3k9d8f2a",
  "time": "2026-10-21T12:00:00.000Z",
  "severity": "critical",
  "operator_id": "op_41aa",
  "agent_id": "agt_8f2c",
  "event": "prompt_injection",
  "fields": {
    "passport_jti": "pas_3k9d",
    "mission_id": null,
    "message": "Body caught injection: pattern",
    "metadata": { "blocked": true, "pattern_id": "override_ignore_previous", "field_path": "body.text" },
    "resolved": false
  }
}
```

## 4. Delivery

### 4.1 Passes

The exporter looks for new records every few seconds. For each stream it exports, in the order the configuration lists them, one **pass** does this, repeating while a batch was full:

1. Read the next records of the stream: those after the stream's **position**, in the order of `time` and then `id`, no newer than a settling delay before now, at most one batch.
2. Send the batch to every collector, the syslog collector first and then the HTTPS collector. All of a batch goes to one collector in one connection, one request or one run of datagrams.
3. When every collector took the batch (4.3), move the position to the last record of the batch. When one did not, stop: the stream is **paused** and the next pass starts again from the same position (section 10).

<!-- spec:generated:siem-constants -->

| Constant | Value |
|---|---|
| Streams | `security`, `audit` |
| Severities | `info`, `warning`, `critical` |
| Syslog facility | 4 (security and authorization messages) |
| Syslog severity of `critical`, `warning`, `info` | 2, 4, 6 |
| PRI of `critical`, `warning`, `info` | 34, 36, 38 |
| Structured data identifier (SD-ID) | `stack@32473` |
| APP-NAME | `stack-engine` |
| HOSTNAME | `stack` |
| Longest syslog message | 8000 bytes |
| Content type of a batch to an HTTPS collector | `application/x-ndjson` |
| Records in a batch, at most | 200 |
| A record is left alone until it is | 5 s old |
| How often the exporter looks for new records | 5 s |
| Time allowed for one connection or request | 10 s |
| A machine holds a stream for at most | 30 s |
| Default syslog port over UDP and TCP, over TLS | 514, 6514 |

<!-- /spec:generated -->

The exporter leaves a record alone until it is the settling delay old, so that a transaction that committed late is not skipped. The delay makes a late row rare; it does not make it impossible. A row that commits more than the delay after its own `time`, behind a position that has moved past that time, is never exported. A collector that needs every row reconciles against a record export ([Record Format](../record/SPEC.md)).

Only one machine of an install exports a stream at a time: it takes the stream for at most the time in the table and gives it back at the end of the pass. A pass that outlasts the hold can overlap another machine's; the effect is repeats, never losses.

### 4.2 Where it starts

The first time a stream is exported (the first pass with the feature on and a collector configured) the position is set to that moment. **History is not replayed**: a connector switched on today sends what happens from today. A stream whose position is lost starts again from the moment it is next read.

### 4.3 What "took" means

The exporter treats a batch as taken, and moves on, when:

| Transport | The batch is taken when |
|---|---|
| HTTPS | the collector answers with a `2xx` status. |
| TCP and TLS | every frame has been written to the connection and the exporter has closed it without an error. The collector never answers: there is no acknowledgement. |
| UDP | every datagram has been handed to the network. Nothing acknowledges it. |

Delivery is therefore **at least once** up to the point the transport says so: a failure the exporter sees (a refused connection, a timeout, a non-`2xx` answer) is retried, without loss, until it passes. A datagram the network drops, and bytes that a TCP collector accepted into its socket and then lost before it stored them, are not seen by the exporter and are not retried. A collector that must not lose a record uses HTTPS, the only transport that is acknowledged, or reconciles against a record export.

### 4.4 Repeats

A record can arrive more than once. Repeats arise when a batch is sent again after another collector refused it (the batch goes to every collector again), when the exporter stopped between sending a batch and saving the position, and when two machines overlapped. A collector MUST drop a repeat by the pair of `stream` and `id`. A repeat carries the same record, byte for byte in its JSON, except that a record is built again when it is read again, so its `fields.resolved` may differ.

### 4.5 Order

Within a stream records are sent in the order of `time` and then `id`. Between streams there is no order. A UDP collector can receive the datagrams of one batch in any order, and a collector that merges the two collectors' copies sees both orders: a collector SHOULD order by `time`, not by arrival.

## 5. Syslog messages

A syslog message is an RFC 5424 message, built as

```
<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
```

with one space between the parts and these values:

| Part | Value |
|---|---|
| `PRI` | Facility 4 times 8, plus the syslog severity of the record: 34 for `critical`, 36 for `warning`, 38 for `info`. |
| `VERSION` | `1`. |
| `TIMESTAMP` | The record's `time`. |
| `HOSTNAME` | `stack`. |
| `APP-NAME` | `stack-engine`. |
| `PROCID` | `-`. |
| `MSGID` | The record's `stream`: `security` or `audit`. |
| `SD` | One structured data element, `[stack@32473 stream="…" id="…" operator="…" agent="…" event="…"]`, the five parameters in this order (5.1). |
| `MSG` | The record as JSON text (section 3.1), UTF-8, with no byte order mark. |

The `SD-ID` `stack@32473` follows the form of RFC 5424 section 7 for an identifier with an enterprise number. The number 32473 is the one RFC 5612 reserves for documentation, so no registration stands behind the name; a collector identifies the message by the identifier and by `APP-NAME`, and MUST NOT take the identifier as proof of who sent it.

### 5.1 The structured data

The parameter values are the record's `stream`, `id`, `operator_id` and `agent_id`, and the record's `event` made safe for a name: each character that is not `A-Z`, `a-z`, `0-9`, `.`, `_` or `-` is replaced by `_`, the result is cut to 32 characters, and an empty result is `_`. Each value is written between double quotes with the three characters RFC 5624 section 6.3.3 names escaped by a backslash: `\`, `"` and `]`. The structured data is there so that a collector can route and filter without parsing JSON; the record is always in `MSG`, whole, with the unabridged `event`, and a collector that needs the record reads `MSG`.

### 5.2 Size

A whole message is at most 8000 bytes, so that it fits one UDP datagram. When the message built from the full record is longer, the exporter sends the record with its `fields` replaced by `{"truncated":true}`, keeping every other member. A collector MUST accept such a record and MUST NOT treat it as another record than the one it stands for: the `id` is the same.

## 6. Syslog transports

### 6.1 UDP

Each message is one datagram to the collector's host and port (514 by default), with no framing. The exporter opens a socket for each batch and closes it after the last datagram. Nothing is read back.

### 6.2 TCP

The frames are those of RFC 6587 section 3.4.1, **octet counting**: the decimal number of bytes of the message in ASCII with no leading zeros, one space, then the message, and no delimiter after it:

```
132 <34>1 2026-10-21T12:00:00.000Z stack stack-engine - security [stack@32473 …] {"stream":"security",…}
```

The count is of bytes, not characters. The exporter opens one connection for a batch (514 by default), writes every frame of the batch, then closes its side of the connection and does not read. A frame can be split across any number of segments at any byte: a collector reads a frame by its count, and reads until the end of the stream.

### 6.3 TLS

TLS carries the same frames over TCP (6514 by default). The exporter requires TLS 1.2 or later and checks the collector's certificate: the chain against the operating system's trust store and, when the install is configured with one (section 8), the customer's own certificate authority as well, and the name against the host the collector was configured by (a host name against the certificate's DNS names, an address against its IP addresses; an address is not sent as a server name). It presents no client certificate. A connection to a collector whose certificate does not pass is closed before anything is sent, and the batch is not taken. There is no setting that turns the check off.

## 7. HTTPS

The exporter sends one batch as one request:

```
POST <the configured URL>
Content-Type: application/x-ndjson
Content-Length: <bytes>
Authorization: Bearer <token>

<one record per line>
```

- The `Authorization` header is present when the install is configured with a token (section 8) and absent when it is not. The exporter sends no other credential and no cookie.
- The body is the JSON text of each record of the batch, one record to a line, each line ended by `\n`, the last one too. A batch is 1 to 200 records, in the order of section 4.5. The body is not compressed.
- The exporter checks the collector's certificate as in 6.3. A URL is `https`; `http` is accepted by the exporter only for a loopback host, for development.
- A `2xx` answer takes the batch. Any other status, a `3xx` included, does not: **redirects are not followed**, so the token is never sent to a place the configured address did not name. The answer's body is ignored. A request that is not answered within 10 seconds fails.

## 8. Configuration

The install is configured by environment variables (a secret may be given as a file instead, as the install documentation says). A setting that is not valid refuses to start the engine with an error that begins `[BOOT]`; nothing is exported until the settings are valid.

| Variable | Meaning |
|---|---|
| `STACK_SIEM_SYSLOG_URL` | `udp://host:port`, `tcp://host:port` or `tls://host:port`. The port defaults as in the table in 4.1. |
| `STACK_SIEM_HTTP_URL` | The HTTPS collector's address. It MUST be `https` and carry no user name or password (`http` is allowed only for a loopback host). |
| `STACK_SIEM_HTTP_TOKEN` | The bearer token of the HTTPS collector. Optional. |
| `STACK_SIEM_STREAMS` | `security` (the default), `audit`, or both, comma separated. Any other word is refused. |
| `STACK_SIEM_TLS_CA_FILE` | A certificate authority (PEM) the exporter trusts for the collectors in addition to the system's. |

With neither a syslog address nor an HTTPS address set, the export is off.

## 9. What a collector must do

A collector:

1. MUST read a TCP or TLS stream by octet counting (6.2), including a frame split across segments and a message that holds any UTF-8 text, and MUST read to the end of the stream. A collector that splits on newlines does not conform.
2. MUST read each UDP datagram as one message.
3. MUST take the record from `MSG`, as JSON, and MUST ignore members it does not know, in the record, in `fields` and in the structured data. It MAY use the structured data to route before it parses.
4. MUST drop a repeat by the pair of `stream` and `id` (4.4), and MUST keep two records that have the same `id` in different streams.
5. On HTTPS, MUST check the bearer token when it requires one and answer `401` or `403` without storing anything when it is missing or wrong, MUST answer a `2xx` only after it has durably accepted the whole batch and never before, MUST accept a body of 200 records and of at least 8 MiB, and MUST NOT answer with a redirect.
6. On HTTPS, SHOULD answer `400` or another `4xx` for a body that is not newline-delimited JSON of records (the exporter treats it as a failure and sends the batch again, so a collector that wants the batch gone has to take it), and MAY answer `5xx`, `408` or `429` to ask for another try. It SHOULD accept a body whose last line has no `\n`.
7. MUST accept a record whose `fields` is `{"truncated":true}` (5.2).
8. SHOULD order by `time` rather than by arrival (4.5).
9. MUST treat the content of a record as data (section 11).

## 10. Failures and retries

The exporter pauses a stream when a collector does not take a batch: a connection that is refused, reset or times out, a TLS failure, a certificate that does not pass, a `3xx`, `4xx` or `5xx` answer. It tries again on the next pass, five seconds later, from the same position, with the same records and any that have arrived since, forever. There is no back-off, no dead-letter state and no gap marker, because nothing is skipped: the position does not move until the batch is taken.

The exporter writes one line to the install's log when a stream is paused, with the reason, and writes it again only when the reason changes or after a batch has been taken in between; it writes nothing more while the reason stays the same. A collector that has been down therefore receives the backlog, in order, as soon as it returns; the backlog is limited by what the install has kept (the audit log and the security events stay in the install's own database).

A collector that answers `4xx` to every batch keeps the stream paused at the same position for as long as it does so: the exporter does not give up on a record, and the log line says what the collector answered.

## 11. Security considerations

- **The stream is sensitive.** Records name operators, agents, Passports and Missions, and the security events say what was attacked and how. A collector's storage and access control are the customer's to set at the level of the install's own database.
- **Prefer HTTPS or TLS.** UDP and TCP syslog carry the records in the clear and, for UDP, from an unauthenticated source: a collector that accepts datagrams from anyone accepts forgeries, and an observer on the path reads every record. Use them only on a network the customer trusts, and prefer TLS or HTTPS, which authenticate the collector to the exporter.
- **The token is a credential.** The bearer token authorises sending records to the collector. Keep it in a file or a secret store, never in a URL, and never in a log. The exporter sends it only to the configured address, over TLS (or to a loopback address in development), and never follows a redirect with it.
- **No way around certificate checks.** The exporter has no setting that skips the check of a collector's certificate. A collector with a private certificate authority is trusted by naming the authority (section 8).
- **Content is data.** `message` and `metadata` can carry text an agent or a third party wrote (3.2). A collector that shows records to a person or hands them to a language model MUST present them as data. The JSON in `MSG` escapes every control character, so a record cannot add a line to a log file; a collector that writes records out as text still escapes for its own format.
- **Exactly the listed fields.** Because each record is built from a fixed list (3.4), a column added to the audit log or the security events tomorrow is not exported until this specification says so.
- **Loss is possible on UDP, and on TCP in one case.** The collector's duty to drop repeats is the whole of its duty to exactly-once; the exporter's duty is at least once, as far as the transport lets it see (4.3).

## 12. Machine-readable schemas

The JSON Schemas in [`schemas/`](schemas/) (draft-07) are generated from the reference implementation: `SiemRecord` (the record, a union of the two streams), `SiemSecurityFields` and `SiemAuditFields`. Where a schema and this text disagree, report it as a defect; the schema is what the reference implementation builds.

## 13. Conformance

The `siem-exporter` suite of the [conformance kit](../conformance/README.md) plays the collector, at every address the exporter is configured with (a UDP socket, a TCP server, a TLS server with a certificate of its own and an HTTPS server), and judges an exporter that a harness drives: it gives the harness the records of the two streams, has it run a pass, and checks what arrived. It checks that nothing from before the first pass is sent; that each record is one syslog message with the PRI, version, timestamp, host name, application name and message id of section 5, a structured data element that parses with the escaping of 5.1 for an identifier that holds a quote, a closing bracket and a backslash, and a body that is the record, and one that is too large for a datagram is sent with `{"truncated":true}`; that TCP frames are counted in bytes (with text that is not ASCII), that a batch is one connection that the exporter closes, and that a datagram is one message; that TLS is used with a collector whose certificate chains to the authority the exporter was given, and not with one whose certificate is unknown or names another host; that an HTTPS batch has the content type and the bearer token, is one record to a line, holds at most 200 records, and carries nothing in the `Authorization` header when no token is set; that records arrive in order, once each when nothing fails, with only the streams that were asked for, and without a value the harness hid in a field that is not public; and that when the collector fails (a `503`, a `401`, a redirect, a refused connection) nothing is lost and the same records arrive, in order, when it recovers, with the redirect not followed.

The `siem-collector` suite plays the exporter and judges a collector that a harness starts: it sends the frames of sections 5 to 7 over each transport the collector offers, and checks that every record is stored whole, from a frame split at any byte, from a message with text that is not ASCII and from a batch of 200; that a repeat is dropped, over one transport and across two, while the same `id` in another stream is kept; that a missing or wrong bearer token is refused and nothing is stored; that a malformed body is refused with a `4xx` and a good one is acknowledged only after it is stored; that a record is taken from the body of a message and never from its structured data or its priority, that no answer is a redirect, and that members it does not know and a truncated record are accepted.

The reference exporter and collector in `conformance/reference/siem-reference.mjs` pass both suites, and the suites fail each of their defective variants. The engine's own exporter passes the `siem-exporter` suite against a real database in the continuous integration of STACK's code.
