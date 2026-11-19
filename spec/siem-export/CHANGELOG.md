# Changelog: STACK Security Monitoring Export

This specification follows semantic versioning. A new optional member of a record, a new stream or a new transport is a minor version: a collector ignores what it does not know. A change that makes a conforming collector or exporter stop conforming is a major version. The shapes in `schemas/` are generated from the reference implementation.

## 1.0.0 - 2026-10-25

Initial public release.

- The record: two streams (`security` and `audit`), the members every record has, the fields of each stream, and what is never sent.
- Delivery: passes, batches of 200, the settling delay, the position that moves only when every collector took the batch, no replay of history, at-least-once with the meaning of "took" for each transport, repeats and the pair of stream and id that identifies a record, order.
- Syslog: RFC 5424 messages with the PRI, structured data and body defined, the escaping, the 8000 byte limit and the truncated record; UDP datagrams, RFC 6587 octet counting over TCP, TLS 1.2 or later with the collector's certificate checked.
- HTTPS: newline-delimited JSON with a bearer token, the answers that take a batch, no redirects.
- What a collector must do, how failures are retried, the settings of the install, and the security considerations.
- JSON Schemas for the record and the fields of both streams.
