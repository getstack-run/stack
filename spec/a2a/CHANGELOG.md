# Changelog: STACK A2A Profile

This specification follows semantic versioning. A new optional card field, a new method or a new optional parameter is a minor version: a caller ignores what it does not know. A change that makes a conforming server or caller stop conforming is a major version. The A2A protocol is young: a change of the protocol version STACK speaks is recorded here.

## 1.1.0 - 2026-10-25

- The signed card of an agent is served by STACK on its own domain (`/v1/agent-identity/agents/{agent_id}/agent-card.json`) and no longer by the agent's site, which serves only what the agent publishes. Its `jku` names the agent's key directory on STACK's domain, its one skill is the identity lookup, and it names no inbox, contact form or site; its name and description are the owner's only when the owner shows the name. The platform card, the endpoint and its methods are unchanged.

## 1.0.0 - 2026-10-24

- Initial public release. The platform agent card at `/.well-known/agent.json` (A2A 0.2.1), the signed card an agent's site serves (A2A 0.3, a JWS over the canonical card against the site's key directory), and the JSON-RPC 2.0 endpoint at `/v1/a2a/jsonrpc`.
- The envelope rules (a malformed envelope is `400` and `-32600`; an id that is not a string, a number or null is read as null), `tasks/send`, `tasks/get` and `tasks/cancel`, the STACK metadata (`stack_from_agent`, `stack_to_agent`, `stack_passport_id`, `stack_mission_id`, `stack_dropoff_id`, `stack_expires_at`), the mapping of drop-off states to task states, and the error codes with their fixed messages.
- What is not implemented: streaming, push notifications, state history, a reply on the same task, federation across accounts.
- The agent card of an agent's site now lists its keys in the directory it names with the same members as every other STACK directory (`kid`, `use`, `nbf`, and `exp` for a retired key); it listed `kty`, `crv` and `x` only. A cancelled task reads as `failed` afterwards, as it always has.
