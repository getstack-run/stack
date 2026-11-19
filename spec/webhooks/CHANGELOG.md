# Changelog: STACK Webhooks

This specification follows semantic versioning. A body that carries its own version (`"version": "1"`) changes it only in a major version of this specification. New families, new optional fields and new extra headers are minor versions: receivers ignore what they do not know.

## 2.0.0 - 2026-11-03

A breaking change: a receiver that reads the `untrusted` object of a wake no longer finds it.

- A wake's body is `"version": "2"`. The SDKs' verifiers accept only `"2"`.

- A wake can be for any agent of the customer, with or without an agent account: `account_id` is null for an agent with none.
- A wake has a new `source`, `decision` (the end of a pending item the agent waited on), whose `event` carries `item_kind`, `item_id` and `result`. A receiver ignores a source it does not know.
- The optional `untrusted` object is no longer sent: nothing a stranger wrote is in a wake. `sender_tags` and `sender_resembles`, STACK's own checks of who wrote or is calling, are now listed.
- The example's ids use their real prefixes (`wke_`, `amsg_`).

## 1.2.0 - 2026-10-31

- A wake has a new `source`, `incoming_call` (a call ringing on the agent's number), whose `event` carries `call_id` and `answer_by`. Its `untrusted` object carries `from`, the number calling, and the payload carries STACK's own checks of that number as `sender_tags`. A receiver ignores a source it does not know.

## 1.1.0 - 2026-10-29

- A wake has a new `source`, `handoff` (a drop-off another of the customer's agents left for the agent), whose `event` carries `dropoff_id`, `from_agent_id` and `recipient_count`. The `post` source, which was already sent, is now listed. A receiver ignores a source it does not know.

## 1.0.1 - 2026-10-25

- Wording: the `x-stack-provider` header of an `inbound_forward` is `generic` or the name of an extractor the deployment registered for itself. No behaviour changed.

## 1.0.0 - 2026-10-24

Initial public release. One signing scheme for every request STACK signs to someone else's server.

- Standard Webhooks (`webhook-id`, `webhook-timestamp`, `webhook-signature`, `v1` HMAC-SHA256 over `id.timestamp.body`) for wake-ups, notification delivery methods, inbound-webhook forwards (partner tenants included), network revocation pushes and both directions of the control socket.
- The secret format and key derivation, including secrets issued before this scheme.
- Receiver rules: raw-body verification, five minutes of tolerance in either direction, constant-time comparison, repeated ids.
- One secret per destination, shown once, and rotation with a 24 hour overlap in which both secrets sign.
- Delivery and retry rules per family, and the body of each family.
- Standard Webhooks is the only signature STACK sends: no other signature header is sent beside it, for any family.
