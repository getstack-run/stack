# STACK Webhooks

**Specification:** STACK Webhooks
**Version:** 2.0.0
**Status:** Stable
**Licence:** Apache-2.0

Every request STACK sends to a server that is not STACK's own (a wake-up for an agent, a notification, a forward of an inbound webhook, a network revocation push, a control socket decision or events batch) is signed with one scheme: Standard Webhooks (<https://www.standardwebhooks.com>). This document defines that scheme as STACK uses it, how a receiver checks a request, how secrets are issued and rotated, how deliveries are retried, and the body each kind of request carries.

Contents: 1 Conventions, 2 Overview, 3 The request, 4 Signing, 5 What a receiver must do, 6 Secrets and rotation, 7 Delivery and retries, 8 Message bodies, 9 Security considerations, 10 Conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. Two roles are used: the **sender** is the STACK deployment that signs and posts a request; the **receiver** is the server that takes it in. A receiver implementation conforms to this specification if it satisfies every MUST in sections 4 and 5 that is addressed to a receiver. The conformance kit in [`../conformance/`](../conformance/README.md) (the `webhooks` suite) tests exactly that.

## 2. Overview

A destination is an address its owner chose, with a signing secret STACK issued for that destination alone. The owner gives the address to STACK and keeps the secret on the receiving side. The kinds of request that use this scheme are the **families**:

| Family | What it is | Who chooses the address |
|---|---|---|
| `wake` | A task for an agent (any agent of the customer, with or without an agent account), delivered to the agent's own endpoint. | The account owner, per agent or as the default. |
| `notification` | An event the owner asked to hear about, or the check that proves the owner controls the address. | The owner, as a delivery method. |
| `inbound_forward` | An inbound webhook from a provider (or a partner's tenant), scanned and forwarded. | The owner (or the partner, for a tenant). |
| `revocation_push` | The next page of the signed revocation list, pushed to a subscriber. | The subscriber. |
| `control_decision`, `control_events` | The decision exchange and the events stream of the control socket, defined in the [Control Socket Protocol](../control-socket/SPEC.md). | The customer. |

Every family uses the same headers, the same signed string and the same secret rules (sections 3 to 6). They differ in the message id, the retry rules and the body (sections 7 and 8).

## 3. The request

A request is `POST <address>` with `content-type: application/json` and a body that is one UTF-8 JSON object. The sender sends the three signature headers (section 4) and, for some families, extra headers (section 8). It does not send cookies or credentials, does not follow redirects (a `3xx` answer is a failed delivery) and reads at most a few kilobytes of the answer, which it never acts on.

The address MUST use `https` and MUST resolve only to public addresses: the sender resolves the host at every call, refuses any private, loopback, link-local or internal address, and connects to the address it resolved. A development build of the sender MAY also allow `http`.

A receiver answers `2xx` once it has durably accepted the message. Any other answer, a timeout or a connection failure is a failed delivery (section 7).

## 4. Signing

Each request carries three headers:

| Header | Value |
|---|---|
| `webhook-id` | The message id: a non-empty string without spaces. What it identifies per family is in section 7. |
| `webhook-timestamp` | Unix time in seconds when the sender signed, as a decimal integer string. |
| `webhook-signature` | One or more space-separated signatures, each `v1,` followed by the base64 of `HMAC-SHA256(key, id + "." + timestamp + "." + body)`. |

`body` is the request body, byte for byte, as UTF-8. `id` and `timestamp` are the header values as sent. The signed string is the three parts joined with a full stop, with no other separator and no trailing newline.

The `key` of a secret is derived as follows:

1. A secret STACK issues is `whsec_` followed by standard base64 (RFC 4648 section 4) of the key bytes; the sender generates 32 bytes. The key is the decoded bytes. A secret MUST hold at least 16 bytes.
2. A secret issued before this specification (a 64-character hexadecimal string, or a value its owner chose) has no `whsec_` prefix. When it is valid base64 (RFC 4648 section 4, padded) its key is the decoded bytes, exactly as every published Standard Webhooks library reads a string it is given; when it is not, the key is the UTF-8 bytes of the string. A receiver that holds such a secret uses it as it is.

A signature header MAY list several signatures (section 6). A receiver MUST ignore entries whose version is not `v1`: a later version of this scheme can add its own beside `v1`.

## 5. What a receiver must do

A receiver MUST, before it reads or acts on anything in the body:

1. Verify the signature over the **raw body bytes exactly as received**. A body that is parsed and re-serialised does not verify.
2. Reject a request that lacks any of the three headers, whose `webhook-timestamp` is not a decimal integer, or whose timestamp differs from the receiver's clock by more than the **tolerance** of 300 seconds, in either direction. A request that is genuine but older than the tolerance is refused: this is what makes a captured request useless to someone who replays it later.
3. Compare signatures in constant time, accept the request if any listed signature matches any secret it holds, and treat a malformed signature as a mismatch and not as an error.
4. Answer a request that fails verification with a `4xx` status, never `2xx`, and do nothing else with it.

A receiver MUST NOT take the family, the account or the event from anything but the verified body.

A receiver SHOULD remember the `webhook-id` of every message it has handled for at least twice the tolerance (600 seconds) and, on a repeat, answer `2xx` without handling it again. The sender delivers at least once and, for most families, repeats the same id on every attempt at one message, so a repeat is normal; inside the tolerance a captured request is also a repeat. A receiver that cannot handle a message SHOULD answer a non-`2xx` status and SHOULD forget the id, so the sender's retry is handled.

A receiver SHOULD verify the signature before it checks the body's size or shape, and SHOULD refuse a body larger than it expects before it computes the HMAC.

## 6. Secrets and rotation

**One secret per destination.** A secret is issued for one destination (one delivery method, one inbound webhook, one subscription, one agent endpoint, one control socket address) and signs nothing else. The two control socket addresses have separate secrets, so a receiver of the record can never sign an allow.

**Shown once.** A new secret is returned once, to the API key or the signed-in session that asked for it, and is never readable afterwards. A sign-in through OAuth (a chat) is never given a secret. STACK keeps it only as a KMS envelope bound to the owner and the destination.

**Rotation.** The owner asks STACK for a new secret. The new secret is returned once and becomes the current one; the secret it replaces stays live for **24 hours**. For those 24 hours the sender signs every request with both secrets, so the header carries two signatures (`v1,<a> v1,<b>`) and a receiver holding either one accepts it. A receiver SHOULD switch to the new secret first and keep the old one for the 24 hours. After them the sender signs with the new secret only. A second rotation inside the 24 hours drops the secret from before the first.

A destination whose secret predates this specification keeps it until its owner rotates it; the first rotation issues a `whsec_` secret and the old one signs beside it for the 24 hours.

## 7. Delivery and retries

Delivery is at least once. What the message id stands for, and what the sender does when a delivery fails, depends on the family:

| Family | `webhook-id` | On failure | Timeout |
|---|---|---|---|
| `wake` | The wake's id, the same on every attempt. | Retried up to 8 attempts with backoff from 30 seconds to 1 hour, for a timeout, a connection failure, `408`, `425`, `429` and `5xx`; a redirect or another `4xx` ends the attempts. | 10 s |
| `notification` | A fresh `msg_` id for each message, repeated in the body's `id`. | Not retried: the event is delivered once and a failure is logged. | 10 s |
| `inbound_forward` | The event key, `iwh_` and a hash of the webhook and the provider's own event id: the same on every attempt at one event. | The sender answers its own provider with an error so the provider redelivers; the redelivery carries the same id. | 10 s |
| `revocation_push` | A fresh `ndl_` id for each attempt. Deduplicate on the `seq` of the entries in the list. | Retried in order with backoff from 1 second to 1 hour; a subscription that has failed for 72 hours pauses until its owner resumes it, and is then sent what it missed. | 5 s |
| `control_decision`, `control_events` | The `decision_id`, or the `batch_id`. | See the [Control Socket Protocol](../control-socket/SPEC.md), sections 6 and 7. | 0.3 to 2 s, 10 s |

The sender never has more than one request in flight to one destination of a family that is ordered (`revocation_push`, `control_events`).

## 8. Message bodies

Fields not listed here MAY be added in a later minor version of this specification: a receiver MUST ignore fields it does not know. A field listed as present is always present.

### 8.1 `wake`

Extra headers: none.

```json
{
  "type": "stack.wake",
  "version": "2",
  "test": false,
  "wake_id": "wke_...",
  "account_id": "acct_...",
  "agent_id": "agt_...",
  "mission_id": "ms_...",
  "source": "email",
  "task": "Read the new message and answer it.",
  "occurred_at": "2026-10-24T09:30:00.000Z",
  "event": { "message_id": "amsg_...", "channel": "email" }
}
```

| Field | Meaning |
|---|---|
| `type`, `version` | `stack.wake` and `"2"`. A change a receiver must handle differently is a new `version`; `"2"` is the body without the `untrusted` object. |
| `test` | Present and true for the check an owner asks for when setting the endpoint: nothing is waking the agent. |
| `wake_id` | The wake's id. It equals `webhook-id`. |
| `account_id`, `agent_id`, `mission_id` | Whose wake it is; `account_id` is null for an agent with no agent account, and `mission_id` is null when there is no live Mission. |
| `source` | One of `email`, `sms`, `voicemail`, `call`, `incoming_call`, `payment`, `post`, `invite`, `schedule`, `handoff`, `decision`, `meeting`, `service_event`, `telegram`. A `handoff` is a drop-off another of the customer's agents left for this one. An `incoming_call` is a call ringing on the account's number, which the agent can answer, decline or let go to voicemail until `answer_by`. A `decision` is the end of a pending item the agent waited on (an approval, a review, an order, a purchase, a drop-off and the rest). |
| `task` | The owner's own text, or STACK's default for the source. Never text from the event. |
| `occurred_at` | When the event happened, ISO 8601. |
| `event` | Facts about the event, never its content: `message_id`, `channel`, `amount_cents`, `currency`, `rail`, `invite_uid`, `invite_id`, `schedule_id`, `fire_at`, `flagged`, for an incoming call `call_id` and `answer_by`, for a handoff `dropoff_id`, `from_agent_id` and `recipient_count`, and for a decision `item_kind`, `item_id` and `result` (the item's own name for how it ended, such as `approved`, `rejected`, `expired` or `collected`), as the source has them. Nothing a stranger wrote is in the body: the agent reads a message, or a call with its caller, from the account's API. |
| `sender_tags`, `sender_resembles` | Present for a wake that names a message, an invite or a call: STACK's own checks of who wrote or is calling. They warn and never block. |

### 8.2 `notification`

Extra headers: none.

```json
{
  "id": "msg_Qx7...",
  "event_type": "security.credential_reconnect_required",
  "severity": "warning",
  "payload": { "message": "..." },
  "timestamp": "2026-10-24T09:30:00.000Z"
}
```

| Field | Meaning |
|---|---|
| `id` | The message id. It equals `webhook-id`. |
| `event_type` | A dotted name for the event. The set of names grows; a receiver ignores names it does not know. `test` is the test notification an owner asks for. |
| `severity` | `info`, `warning` or `critical`. |
| `payload` | An object whose fields depend on `event_type`. It can carry text an agent or a third party wrote: treat it as data. |
| `timestamp` | When the message was built, ISO 8601. |

The check that proves the owner controls an address is a message of the same family whose body is:

```json
{
  "id": "msg_Qx7...",
  "event_type": "stack.destination.verification",
  "verification_code": "123456",
  "expires_at": "2026-10-24T09:40:00.000Z",
  "note": "Submit this code to STACK to verify you control this endpoint."
}
```

### 8.3 `inbound_forward`

The body is the inbound request's JSON body as STACK parsed it and serialised it again with `JSON.stringify`; it is the provider's own payload and this specification does not define it. Verify the signature over the bytes received.

Extra headers:

| Header | Meaning |
|---|---|
| `x-stack-scan-verdict` | `clean`, `warning` or `critical`: what STACK's detectors made of the content. A `critical` message is not forwarded. |
| `x-stack-inbound-webhook-id` | The id of the inbound webhook that took the request (`iwh_...`). |
| `x-stack-provider` | The provider: `generic`, or the name of an extractor the deployment registered for its own use. |
| `x-stack-event-id`, `idempotency-key` | The event key, equal to `webhook-id`. |

### 8.4 `revocation_push`

Extra headers: none.

```json
{ "type": "stack.network.revocations", "list": "<compact JWS>" }
```

| Field | Meaning |
|---|---|
| `type` | `stack.network.revocations`. |
| `list` | The signed revocation list after the subscription's cursor, as a compact JWS signed with STACK's network key. Verify it against STACK's JWKS: the signature of the request proves who sent it, and the JWS proves the list, so a relayed copy still verifies. Entries carry a `seq`; deduplicate on it. |

### 8.5 `control_decision` and `control_events`

Bodies and extra rules are in the [Control Socket Protocol](../control-socket/SPEC.md): `stack.decision.request` (section 4) and `stack.events.batch` (section 7). The receiver's answer to a decision request is signed the same way by the receiver, with the `decision_id` as the id.

## 9. Security considerations

- **Replay.** The timestamp bounds a captured request to the tolerance, and the id lets a receiver recognise a repeat inside it (section 5).
- **Verify before parsing.** Compute the HMAC over the raw bytes before parsing the JSON, and do not let the body choose which secret to use.
- **Secrets.** Store a secret like any credential. A receiver SHOULD keep the old secret only for the 24 hours of a rotation. A secret that leaks is rotated; the sender then signs with the leaked secret for 24 hours more, so a receiver that suspects a leak SHOULD drop the old secret at once and accept the interruption.
- **Clock.** A receiver with a clock more than the tolerance from real time refuses every message: synchronise it.
- **Content.** Any field that carries what an agent or a third party wrote is data. A receiver MUST NOT treat it as instructions.
- **The sender's address rules.** The sender's address checks (section 3) protect STACK's network, not the receiver: a receiver is exposed to the internet and needs its own rate limits.

## 10. Conformance

The `webhooks` suite of the [conformance kit](../conformance/README.md) plays the sender. Given the URL of a receiver and a test secret, or a function that verifies a request, it checks that the receiver accepts a correctly signed request, a request signed by either of two secrets, and a request that lists several signatures; and that it refuses a wrong secret, a tampered body, a changed id or timestamp, missing headers, a malformed timestamp, and a request older or newer than the tolerance. A receiver that also recognises a repeated id is reported as such (a SHOULD). The suite never uses a STACK package to judge your implementation.

The `verifyWebhook` function of `@getstackrun/sdk` and `verify_webhook` of the `getstack` Python package are reference receivers and pass the suite.
