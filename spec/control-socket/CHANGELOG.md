# Changelog: STACK Control Socket Protocol

This specification follows semantic versioning. The wire messages carry their own version (`"version": "1"`); a change that a conforming receiver would have to handle differently is a new wire version and a major version of this specification. New action kinds, optional request fields and optional answer fields are minor versions: receivers ignore what they do not know.

## 1.2.0 - 2026-11-05

- New action kind `memory.delete`: the agent deleting something from its account's memory. Its `target` carries `change` (`delete_episode` or `delete_entity_edge`) and never the id or what the item holds. It is asked of the customer's decider after the agent is admitted and before anything is deleted. The kind came after 1.1.0 and was not listed then.
- New action kind `call.answer`: the agent answering a call that is ringing on its number. Its `target` carries `caller` (`number`, the caller in E.164 or null when it was withheld, and `attestation`, `A`, `B` or `C` or null) and `max_seconds`. It is asked once the call is known to still be ringing, after the agent is admitted and the action counted and before the call is answered or anything is held.
- New action kind `brain.add`: the agent adding files from its drive to its account's brain. Its `target` carries `files` (how many) and `pages` (the pages AWS is expected to bill for reading them), and the request's `amount` is what the wallet pays for them at most. It is asked before any file is read or anything is held, and never carries a file's name or what it holds.
- New action kind `meeting.join`: the agent joining the meeting room of one of its own calendar events. Its `target` carries `event_id` and `max_seconds` (or null). It is asked like `call.answer`: of the customer's decider when the customer has one, after the agent is admitted and the action counted and before anything is held or joined. It is also asked once when the agent's calendar event is made or changed so that the agent attends it at each start (the same `target`: the event's id and `max_seconds`); a refusal leaves the event without that, and the join at each start is not asked again. A receiver that does not know the kind treats it as one it has no rule for, as for every new kind.
- Wording: the `pages` of `brain.add` are an estimate of the pages AWS is expected to bill (worked out from the files' size and type before any file is read), and the request's `amount` is what the wallet pays for them at most. The fields did not change.

## 1.1.0 - 2026-10-29

- The `target` of `dropoff.create` and `dropoff.deposit` carries `to_agents`, every agent a drop-off names, beside `to_agent` (the first), because a drop-off can now be for several of the customer's agents. The new field is optional for a receiver to read; one that ignores it still sees the first agent.

## 1.0.2 - 2026-10-25

- Added section 11, Conformance, which names the `decision` and `events` suites of the conformance kit and what each checks. No behaviour changed.

## 1.0.1 - 2026-10-24

- Wording: the signing in section 3 is the scheme of the new STACK Webhooks specification, which now defines it for every request STACK signs. No behaviour changed.

## 1.0.0 - 2026-10-21

Initial public release.

- Decision exchange: signed `stack.decision.request` and signed answer, with the request digest, the 1.5 s default and 2 s maximum deadline, holding an action for approval with a retry reference, and the setup check.
- Standard Webhooks signing in both directions, five minutes of tolerance, separate decision and events secrets, and a 24 hour rotation overlap.
- The 30 action kinds and the fields each target carries; what is never sent.
- Failure handling: every unusable answer refuses the action and hands it back; no fallback when a configured address is broken; the in-flight limit and circuit breaker.
- Events stream: signed, ordered, at-least-once batches with gapless sequence numbers and chain links, the retry and dead-letter rules, gap markers, the 72 hour pause.
- Address rules: https only, public hosts only, no redirects.
- JSON Schemas generated from the reference implementation.
