# STACK Control Socket Protocol

**Specification:** STACK Control Socket Protocol
**Version:** 1.2.0
**Status:** Stable
**Licence:** Apache-2.0

The control socket lets a customer decide, on their own server, whether each action an AI agent is about to take may go ahead, and receive a signed stream of everything that happened. This document defines the two HTTP exchanges involved: the **decision exchange** (STACK asks the customer's server before an action runs) and the **events stream** (STACK delivers the customer's record to their server afterwards), and what each side must do.

Contents: 1 Conventions, 2 Overview, 3 Message signing, 4 Decision exchange, 5 Action kinds and targets, 6 Failure handling, 7 Events stream, 8 Addresses, 9 Security considerations, 10 Machine-readable schemas, 11 Conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. Two roles are used: the **gateway** is the STACK deployment that sends requests and delivers events; the **receiver** is the customer's server that answers decisions or accepts events. A receiver implementation conforms to this specification if it satisfies every MUST in sections 3, 4 and 7 that is addressed to a receiver. The conformance kit in [`../conformance/`](../conformance/README.md) tests exactly that.

## 2. Overview

A customer registers up to two addresses:

- a **decision address**, to which the gateway POSTs a signed request before each *checked* action and expects a signed allow or deny within a deadline; and
- an **events address**, to which the gateway POSTs signed batches of the customer's audit events, in order, at least once.

The two addresses have separate signing secrets, so a receiver of the record can never sign an allow.

The customer chooses which action kinds are checked. An action of an unchecked kind goes through without a decision. When the decision address is the active decider, the gateway MUST NOT let a checked action run without a valid signed `allow`: silence, errors, slowness and bad signatures all refuse the action (section 6).

## 3. Message signing

Both directions use Standard Webhooks (<https://www.standardwebhooks.com>) with the `v1` HMAC-SHA256 scheme, the one scheme every STACK webhook uses, defined in full in the [STACK Webhooks](../webhooks/SPEC.md) specification. Any published Standard Webhooks library verifies the gateway's messages.

Each message carries three headers:

| Header | Value |
|---|---|
| `webhook-id` | A unique id: the `decision_id` for a decision request and its answer, the `batch_id` for an events batch. |
| `webhook-timestamp` | Unix time in seconds, as a decimal string. |
| `webhook-signature` | One or more space-separated signatures, each `v1,` followed by the base64 of `HMAC-SHA256(key, id + "." + timestamp + "." + body)`. |

The `key` is the base64-decoded bytes of the secret that follows the prefix `whsec_` (`whsec_<base64>`). A secret MUST hold at least 16 bytes; the gateway generates 32.

A receiver (and the gateway, for answers) MUST:

1. Verify the signature over the **raw body bytes exactly as received**. A body that is parsed and re-serialised does not verify.
2. Compare signatures in constant time and accept the message if any listed signature matches any secret it holds.
3. Reject a message whose `webhook-timestamp` differs from the current time by more than the tolerance (section 3 constants), in either direction, and a message that lacks any of the three headers or whose timestamp is not a decimal integer.
4. Treat a malformed signature as a mismatch, not as an error.

During a **secret rotation** the gateway signs with both the new and the previous secret (two signatures in one header) for 24 hours, and the gateway accepts answers signed with either. A receiver SHOULD keep both secrets for that period.

Constants:

<!-- spec:generated:control-constants -->

| Constant | Value |
|---|---|
| Decision timeout, default | 1500 ms |
| Decision timeout, configurable range | 300 to 2000 ms |
| Largest decision answer | 16384 bytes |
| Largest decision request or events batch | 32768 bytes |
| Signature timestamp tolerance | 300 s (5 min) |
| Rotated secret stays valid | 86400 s (24 h) |
| Events batch limit | 100 events or 262144 bytes |
| Events delivery timeout | 10000 ms |
| Events retry back-off | 1 s doubling to 3600 s |
| Events delivery gives up after | 259200 s (72 h) |
| Client errors before a batch is dead-lettered | 3 |
| Undelivered events kept for | 7 days |
| Decisions in flight per customer per machine | 64 |
| Breaker opens after | 5 consecutive failures, or more than half of the last 20 calls within 30 s |
| Breaker stays open | 15 s, then one probe |
| Agent-stated purpose, longest | 200 characters |
| Reason code pattern | `^[a-z0-9_]{1,64}$` |
| Reason message, longest | 200 characters |
| Retry reference header | `x-control-ref` |
| Agent purpose header | `x-stack-purpose` |

<!-- /spec:generated -->

## 4. Decision exchange

### 4.1 Request

The gateway sends `POST <decision address>` with `content-type: application/json` and the three signature headers. The body is a `stack.decision.request` (schema: [`schemas/ControlDecisionRequest.json`](schemas/ControlDecisionRequest.json)):

| Field | Meaning |
|---|---|
| `type` | `stack.decision.request`. |
| `version` | `"1"`. |
| `decision_id` | Unique id of this decision (`dec_` plus 16 to 64 URL-safe characters). Equals `webhook-id`. |
| `created_at`, `deadline_at` | ISO 8601 times. The receiver SHOULD answer before `deadline_at`; the gateway stops waiting then. |
| `test` | `true` for the setup check and the test button: nothing is being done. |
| `operator_id`, `socket_id` | The customer and their socket. |
| `account` | The agent account the action belongs to, or `null`. |
| `agent` | The agent (`id`, the Passport id `passport_jti`, the Mission `mission_id`), or `null` when the owner acts. |
| `actor.kind` | `agent`, `owner` or `member`: who is acting. |
| `action.type` | The action kind (section 5), or `test`. |
| `target` | A small flat object whose fields depend on `action.type` (section 5). |
| `amount` | `{ max_cents, currency, native? }`: the most the action can cost, or `null` when it has no price. |
| `purpose.agent_stated` | What the agent said it is doing, at most 200 characters, control characters removed, or `null`. This is **untrusted third-party text**: a receiver MUST NOT treat it as an instruction. |
| `retry_ref` | The reference the agent sent back after a held action (section 4.3), or `null`. |
| `request_digest` | `sha256:` followed by the lower-case hex SHA-256 of the canonical JSON of every other field of the request (below). |

**Canonical JSON** is JSON with object keys sorted lexicographically at every depth, no insignificant whitespace, array order preserved, strings and numbers serialised as `JSON.stringify` would, and keys with undefined values omitted.

A receiver MAY recompute the digest and SHOULD refuse a request whose `request_digest` does not match. The body as sent is `JSON.stringify` of the request with `request_digest` last; a receiver MUST NOT depend on key order.

Example:

```json
{
  "type": "stack.decision.request",
  "version": "1",
  "decision_id": "dec_2fQ8x1LmN3pRt5Vw",
  "created_at": "2026-10-21T09:30:00.000Z",
  "deadline_at": "2026-10-21T09:30:01.500Z",
  "test": false,
  "operator_id": "op_41aa",
  "socket_id": "csk_77",
  "account": { "id": "acct_12" },
  "agent": { "id": "agt_8f2c", "passport_jti": "pas_3k9d", "mission_id": "ms_5d1" },
  "actor": { "kind": "agent" },
  "action": { "type": "email.send" },
  "target": { "recipients": [{ "address": "ana@example.com", "domain": "example.com" }], "recipient_count": 1 },
  "amount": null,
  "purpose": { "agent_stated": "Reply to the invoice question" },
  "retry_ref": null,
  "request_digest": "sha256:9d1c...e4"
}
```

### 4.2 Answer

The receiver answers `200` with `content-type: application/json` and the three signature headers, signed with the same decision secret. `webhook-id` MUST equal the request's `decision_id`. The body (schema: [`schemas/ControlDecisionAnswer.json`](schemas/ControlDecisionAnswer.json)) is at most 16 KiB:

| Field | Meaning |
|---|---|
| `decision_id` | MUST echo the request. |
| `request_digest` | MUST echo the request's digest. |
| `verdict` | `allow` or `deny`. There is no other verdict: an action cannot be modified in flight. |
| `reason.code` | Machine-readable, `[a-z0-9_]{1,64}`. Recommended for `deny`. When absent the gateway uses `denied`. |
| `reason.message` | Up to 200 characters, shown to the agent. SHOULD name no secret and no personal data. |
| `retry` | A held action: `{ ref, after_seconds? }` (section 4.3). |
| `policy_ref` | The receiver's own reference for the rule that decided, kept on the decision record (at most 200 characters). |

The gateway ignores unknown fields. An answer is **usable** only if all of these hold: HTTP status `200`; a body within the size limit; a valid signature within the tolerance; `webhook-id` equal to the request's `decision_id`; a body that parses against the answer schema; and `decision_id` and `request_digest` equal to the request's. Anything else is treated as no answer (section 6).

A receiver MUST answer a `test: true` request with `allow`. The setup check puts an address into use only when it receives a signed `allow` to a test request.

A receiver:

- MUST verify the request signature and timestamp before acting on the body, and MUST NOT answer a request that fails verification with a signed `allow` (answer `401` or `400`).
- SHOULD check that `webhook-id` equals the body's `decision_id`: the gateway signs a decision with its decision id as the message id, so a request signed under any other id was not built by it.
- SHOULD be idempotent per `decision_id`: the gateway may retry within the deadline, and a retried request MUST get the same verdict. A receiver that counts actions (a daily limit, say) SHOULD count by `decision_id`.
- SHOULD answer well inside the deadline: the default is 1.5 s and the maximum 2 s, and the gateway adds the round trip to every checked action.

### 4.3 Holding an action for a person

To hold an action until a person approves it, the receiver answers `deny` with a `reason.code` (for example `approval_required`) and `retry: { "ref": "<your reference>", "after_seconds": 60 }`. The gateway refuses the action and hands the reference to the agent. When the agent retries it sends the reference as the header `X-Control-Ref`, and the gateway puts it in the next request's `retry_ref`. The receiver then allows the retry once the person has approved that reference. The reference is opaque to the gateway.

### 4.4 Which actions are asked

The gateway asks after it has authenticated the caller and counted the action, and before the action touches anything: before a hold on funds, a credential read or a provider call. It asks once per action. Actions that only read or end something (reading a message, ending a session, any revocation) are not asked. A refused action is never charged to the customer.

## 5. Action kinds and targets

`action.type` is one of the kinds below, or `test`. New kinds are added in minor versions; a receiver MUST treat an action kind it does not know as one it has no rule for (and SHOULD answer according to its default posture, not crash). A customer chooses which kinds are checked; `null` means every kind, including kinds added later.

<!-- spec:generated:control-action-types -->

- `model.call`
- `proxy.call`
- `tool.run`
- `email.send`
- `sms.send`
- `telegram.send`
- `call.start`
- `call.answer`
- `meeting.join`
- `browser.session.start`
- `browser.navigate`
- `card.checkout`
- `wallet.payment`
- `workspace.exec`
- `account.open`
- `dropoff.create`
- `dropoff.deposit`
- `a2a.send`
- `skill.invoke`
- `passport.delegate`
- `wake.deliver`
- `drive.upload`
- `drive.share`
- `memory.write`
- `memory.delete`
- `brain.add`
- `site.publish`
- `payment.request`
- `letter.send`
- `post.scan`
- `post.forward`
- `post.shred`
- `making.quote`
- `making.order`

<!-- /spec:generated -->

The `target` of each kind names exactly these fields and nothing else:

| Kind | `target` fields |
|---|---|
| `model.call` | `provider`, `model` (at most 200 characters, or null), `stream` (boolean), `max_output_tokens` (number or null) |
| `proxy.call` | `service`, `connection_id` (or null), `method`, `host`, `path` (no query string) |
| `tool.run` | `provider`, `endpoint` |
| `email.send` | `recipients` (list of `{ address, domain }`, address lower-cased), `recipient_count` |
| `sms.send` | `recipients` (list of `{ number }` in E.164), `recipient_count` |
| `call.start` | `recipients` (list of `{ number }`), `recipient_count`, `max_seconds` |
| `call.answer` | `caller` (`{ number, attestation }`: the number calling in E.164, or null when it was withheld, and what the carrier vouches for it with, `A`, `B` or `C`, or null; a caller ID can be faked), `max_seconds` |
| `meeting.join` | `event_id` (the id STACK gave the calendar event whose room the agent joins: never its title, guests or link), `max_seconds` (the longest the agent's part may last, or null when the join names none). Also asked once when an event is made or changed so that the agent attends it at each start (with the event's id and `max_seconds`); the later join at the start is not asked again |
| `browser.session.start` | none (an empty object) |
| `browser.navigate` | `origin`, `path` (no query string) |
| `card.checkout` | `merchant_origin`, `amount_minor` (minor units), `currency` (upper case) |
| `wallet.payment` | `chain_id`, `token` (contract address), `payee`, `amount` (atomic units), `valid_before` (each text, at most 80 characters, or null) |
| `workspace.exec` | `new_workspace` (boolean: the command makes a workspace), `timeout_seconds` (null for a command started in the background, which has no limit; a rule that caps how long a command may run refuses it), `stack_access` (boolean), `command_bytes`: the command itself is never sent |
| `account.open` | `name` (at most 120 characters), `skipped_pieces` (list) |
| `dropoff.create` | `to_agent` (the first agent named), `to_agents` (every agent named, in the order named: one for a drop-off to one agent) |
| `dropoff.deposit` | `to_agent`, `to_agents` (as above), `payload_bytes` |
| `a2a.send` | `to_agent`, `message_bytes` |
| `skill.invoke` | `skill_id` |
| `passport.delegate` | `binding_id` |
| `telegram.send` | `recipients` (list of `{ chat_id }`, the Telegram id of the chat), `recipient_count` |
| `wake.deliver` | `source` (the kind of event that starts the agent), `rule_id`, `schedule_id` (each or null) |
| `drive.upload` | `content_type`, `bytes`, `visibility`, `expires_in_seconds` (or null) |
| `drive.share` | `file_id`, `ttl_seconds`, `max_downloads` (or null) |
| `memory.write` | `change` (`add_memory`, `add_triplet` or `summarize_saga`), `chars` |
| `memory.delete` | `change` (`delete_episode` or `delete_entity_edge`): which one, never the id or what it holds |
| `brain.add` | `files` (how many drive files are added), `pages` (the pages AWS is expected to bill for reading them, estimated from the files' size and type before they are read); the request's `amount` is what the wallet pays for them at most. Never a name or what a file holds |
| `site.publish` | `kind` (`files`, `hostname` or `prices`) and, by kind, `file_count`, `total_bytes`, `has_server_code`; `hostname`; `price_count` |
| `payment.request` | `kind` (`payment_link` or `checkout_session`), `amount_minor`, `currency` (lower case) |
| `letter.send` | `country`, `postal_code`, `kind`, `pages`, `color`, `mail_class`, `use_type`, `extra_service` (or null) |
| `post.scan` | `item_id` |
| `post.forward` | `item_id`, `destination_state` (or null), `destination_postal_code` |
| `post.shred` | `item_id` |
| `making.quote` | `supplier` (or null), `design_format`, `design_sha256`, `quantity`, `destination_country` |
| `making.order` | `supplier`, `payment`, `design_sha256`, `quantity`, `destination_country`, `total_cents` |

**What is never sent.** The request carries who, what and how much; it never carries message bodies or subjects, prompts, model output, code, page text, typed text, call instructions, card numbers, credentials, Passport tokens or query strings. Recipients are sent as plain addresses or numbers because the customer chose them. A receiver MUST NOT assume it can reconstruct content from a request.

`amount.max_cents` is a ceiling in US cents for actions that have a price; for `wallet.payment` it is the payment rounded up to a cent. `amount.native` carries the original currency and minor-unit value when it differs.

## 6. Failure handling

When the decision address is the active decider, the gateway MUST refuse the action, and hand it back so that the customer is not charged, in each of these cases. The refusal names the cause, one of:

<!-- spec:generated:control-unavailable-causes -->

- `timeout`
- `unreachable`
- `unsafe_address`
- `http_status`
- `bad_signature`
- `bad_body`
- `mismatch`
- `busy`
- `breaker_open`
- `unverified`
- `paused`
- `secret_unavailable`
- `hosted_failure`

<!-- /spec:generated -->

- No answer within the deadline (`timeout`), a connection failure (`unreachable`), or an address that fails the safety check (`unsafe_address`).
- A status other than `200` (`http_status`).
- A missing, wrong or stale signature (`bad_signature`).
- A body that is too large, not JSON, or not an answer (`bad_body`).
- An answer for another request: wrong `decision_id` or `request_digest` (`mismatch`).
- A full queue (`busy`) or an open circuit breaker (`breaker_open`).

A configured decision address that is broken MUST NOT fall back to no controls: that would turn an outage of the customer's server into a bypass. The refusal is `403 CONTROL_SOCKET_UNAVAILABLE`. A denial is `403 CONTROL_DENIED` with the reason code and, if the receiver gave one, the retry reference. Both are `403` and not `5xx` so that clients that retry on `5xx` do not retry into the circuit breaker.

The gateway limits the work one customer can cause: at most 64 decisions in flight per machine (more queue until their deadline), a breaker that opens after five consecutive failures or when more than half of the last 20 calls within 30 seconds failed and refuses for 15 seconds before letting one probe through, and a pause of the socket after 50 answers in a row with a bad signature (it stays paused until the address is verified again).

## 7. Events stream

### 7.1 Delivery

The gateway delivers every audit event of the customer to the events address, in order, at least once. Each delivery is `POST <events address>` with `content-type: application/json`, the three signature headers (`webhook-id` is the `batch_id`) and a body that is a `stack.events.batch` (schema: [`schemas/ControlEventsBatch.json`](schemas/ControlEventsBatch.json)):

```json
{
  "type": "stack.events.batch",
  "version": "1",
  "batch_id": "evb_4Nw8x1LmN3pRt5VwQ2Ya7Zk",
  "test": false,
  "operator_id": "op_41aa",
  "socket_id": "csk_77",
  "events": [ { "...": "see ControlEvent" } ]
}
```

A batch holds at most 100 events or 256 KiB, whichever is smaller. At most one batch per customer is in flight. The setup check and the test button send a batch with `test: true` and no events.

Each event ([`schemas/ControlEvent.json`](schemas/ControlEvent.json)) is an audit row reduced to its public fields:

| Field | Meaning |
|---|---|
| `id`, `type`, `occurred_at` | The event id, kind (for example `control.decision.deny`) and time. |
| `seq` | A positive integer, strictly increasing and gapless per customer, in audit-chain order. |
| `operator_id`, `agent_id`, `account_id` | Whose event it is. |
| `outcome`, `layer`, `error_code` | What happened and where. |
| `decision_id`, `amount_cents` | Present when the event relates to a decision or a charge. |
| `chain` | `{ entry_hash, prev_entry_hash }` of the audit row, or `null`. |
| `refusal` | Set when a hosted policy refused the action: which policy rule, never a value from the call. |
| `gap` | Set on a gap marker (section 7.3). |

Events never carry error messages, payloads or secrets.

### 7.2 What the receiver must do

A receiver of the events stream:

1. MUST verify the signature and timestamp as in section 3 before it reads or stores anything, and MUST answer a message that fails verification with a `4xx` status, never `2xx`.
2. MUST answer `2xx` once it has durably accepted the batch, and only then. The gateway deletes the batch on `2xx`.
3. MUST be idempotent: delivery is at least once, so it will see a `batch_id` and an event `seq` more than once. It SHOULD de-duplicate by `seq`.
4. SHOULD check the sequence: each event's `seq` is one more than the previous, unless a gap marker announces the difference. A missing number without an announcement is an anomaly worth alerting on.
5. SHOULD check the chain: where two events have consecutive `seq` and both have a `chain`, the later event's `prev_entry_hash` equals the earlier event's `entry_hash`. The `entry_hash` itself is computed by the gateway over the full audit row and cannot be recomputed from the reduced event; the chain link is what can be checked. For full verification use a record export ([Record Format](../record/SPEC.md)).
6. MAY answer `5xx`, `408` or `429` to ask for a retry.

The gateway treats the answer as follows. `2xx` is success. `5xx`, `408`, `429`, a timeout (10 s) and an unreachable address are retried with exponential back-off from 1 s to 1 h. Any other `4xx` is a refusal: after three refusals the batch becomes a dead letter and is announced by a gap marker. Redirects are not followed. A receiver's response body is ignored, read to at most 4 KiB.

### 7.3 Gaps

If events cannot be delivered the gateway announces the loss rather than hiding it, with a synthetic event of type `stack.events.gap` whose `gap` field is `{ from_seq, to_seq }` and whose `seq` is `to_seq`. Gaps arise when a batch is dead-lettered, when undelivered events are older than seven days, and when delivery was paused. Delivery pauses after 72 hours of continuous failure (the customer is told once); while it is paused the outbox stops storing events, the sequence numbers are still taken, and a successful setup check resumes delivery and the skipped numbers are announced as one gap. A receiver MUST treat a gap marker as "events `from_seq` to `to_seq` are not coming" and SHOULD record it.

## 8. Addresses

The gateway checks an address when it is set and again on every call: the scheme MUST be `https` (a development build may allow `http`), the URL MUST carry no credentials, query string or fragment, and the host MUST resolve only to public addresses. The connection is made to the checked addresses, redirects are not followed, no cookies are sent, and responses are size-capped. A receiver therefore cannot be on a private network; a customer who needs that runs the gateway themselves.

A new decision address waits as a candidate while the current one keeps deciding; it decides only after a setup check succeeds. An address that was never verified never decides.

## 9. Security considerations

- The decision secret is the authority to allow actions. Keep it out of logs and source control, and separate from the events secret, which cannot allow anything.
- Verify before parse. A receiver that parses first and verifies later can be steered by an unsigned body.
- Reason messages reach the agent. A receiver SHOULD NOT put anything in a `reason.message` it would not want a possibly compromised agent to read.
- The `purpose.agent_stated` field and any `target` field that echoes agent-controlled text (a model name, a path) are untrusted input.
- Bind decisions to `request_digest` and `decision_id`: they are what stops an answer for one action being replayed for another.
- Expose the decision endpoint on a path with no other function, rate-limit unauthenticated traffic to it, and keep it close (the same region) to the gateway: the deadline is short.

## 10. Machine-readable schemas

The JSON Schemas in [`schemas/`](schemas/) (draft-07) are generated from the reference implementation: `ControlDecisionRequest`, `ControlDecisionAnswer`, `ControlEvent` and `ControlEventsBatch`. A TypeScript receiver can use the helper functions `verifyControlSocketRequest` and `signControlSocketAnswer` in `@getstackrun/sdk`; a complete example server is in [`examples/control-socket/`](../../examples/control-socket/README.md).

## 11. Conformance

Two suites of the [conformance kit](../conformance/README.md) test a receiver against this specification; both play the gateway, sign with a test secret you give them, and use the synthetic operator `op_conformance`.

The `decision` suite is pointed at the URL of a decision server and a test decision secret (section 4). It checks that the server answers a signed test request with a signed allow (D01), within the 2 second maximum (D02) and, as a warning, within the 1.5 second default (D03); that it answers a request of each action kind of section 5 with a well-formed signed answer (D10 onward, one check for each kind); that it answers an action kind it does not know with a well-formed signed answer rather than an error (D30); that it accepts a request carrying two signatures when one matches, as in a rotation (D31); and that it never allows a request signed with the wrong secret (D40), a request without signature headers (D41), a correctly signed request ten minutes old or ten minutes ahead (D42, D43) or a body changed after it was signed (D44). As warnings it checks that a `webhook-id` that is not the `decision_id` (D45) and a `request_digest` that does not match the content (D47) are not allowed, that an unauthenticated request gets a `4xx` (D46) and that the same request twice gets the same verdict (D50).

The `events` suite is pointed at the URL of an events receiver and a test events secret (section 7). It checks that the receiver accepts a signed test batch (E01), a signed batch of events (E02), the same batch again, because delivery is at least once (E03), a batch that carries a gap marker (E04) and a request carrying two signatures (E05), each with a `2xx`, within the gateway's 10 second timeout (E06); and that it refuses, with anything but a `2xx`, a batch signed with the wrong secret (E10), a batch without signature headers (E11), a batch ten minutes old (E12) and a body changed after it was signed (E13). As a warning it checks that an unauthenticated batch gets a `4xx` and not a `5xx`, which would ask the gateway to retry (E14).

The example server in [`examples/control-socket/`](../../examples/control-socket/README.md) passes both suites with no warnings, and `negative-controls.test.mjs` in the kit runs the suites against decision servers and an events receiver that each break one rule on purpose (no signature check, a stale timestamp accepted, a wrong message id or digest in the answer, a verdict other than allow or deny, an error on an unknown action kind, no reading of a rotation overlap) and requires the suites to fail every one of them.
