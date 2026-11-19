# STACK A2A Profile

**Specification:** STACK A2A Profile
**Version:** 1.1.0
**Status:** Stable
**Licence:** Apache-2.0

The A2A protocol (Agent2Agent, <https://a2a-protocol.org>) is how agent frameworks talk to each other: an agent card says where an agent is and what it offers, and a JSON-RPC 2.0 endpoint takes tasks. STACK speaks a profile of it. Its endpoint turns an A2A task into a **drop-off** (the schema-checked, encrypted hand-over between two agents of one account that STACK already has), so a framework that speaks A2A can send a task to an agent of a STACK account without learning STACK's own API, and everything STACK does around a drop-off (the Mission, the customer's controls, the meter, the signed record) applies to the task. This document defines the agent cards STACK serves and the JSON-RPC envelope, methods, task states and errors of the endpoint, as the code serves them.

Contents: 1 Conventions, 2 Overview, 3 The agent cards, 4 The endpoint, 5 tasks/send, 6 tasks/get, 7 tasks/cancel, 8 Task states, 9 Errors, 10 What is not implemented, 11 Security considerations, 12 Conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. The **server** is an implementation of this profile; the **caller** is the A2A client. JSON-RPC is version 2.0 (<https://www.jsonrpc.org/specification>). This profile is written against A2A 0.2.1 for the platform card and the endpoint and A2A 0.3 for the card STACK serves for an agent; the protocol is young and moves, so the profile says which fields STACK writes, not what A2A may later add. A server conforms if it satisfies every MUST in sections 3 to 9. The conformance kit in [`../conformance/`](../conformance/README.md) (the `a2a` suite) tests exactly that.

## 2. Overview

- **A task is a drop-off.** `tasks/send` creates a drop-off from one agent of the caller's account to another and deposits the A2A message in it. The recipient collects it through the drop-off API. There is no A2A method to receive a task and no reply on the same task: the exchange is one way and asynchronous.
- **Same account only.** Both agents must belong to the account the caller authenticates as. Federation across accounts is not part of this profile.
- **Two kinds of card.** STACK serves a platform card at its API origin, which advertises the endpoint, and, from the same origin, a signed card for each agent (section 3.2). An agent's site serves neither: it serves only what the agent publishes.
- **Not a control.** The endpoint is how a task is handed over. Whether an agent may send one is decided as for any action of an agent: its Mission, its Passport, the customer's controls and the meter (section 5).

## 3. The agent cards

### 3.1 The platform card

`GET /.well-known/agent.json` at the API origin. Public: it needs no credential and is not metered. The answer is `200` with a JSON object:

```json
{
  "name": "STACK",
  "description": "...",
  "url": "https://api.getstack.run/v1/a2a/jsonrpc",
  "provider": { "organization": "getstack.run", "url": "https://getstack.run" },
  "version": "0.2.1",
  "defaultInputModes": ["text", "data"],
  "defaultOutputModes": ["text", "data"],
  "capabilities": { "streaming": false, "pushNotifications": false, "stateTransitionHistory": false },
  "authentication": { "schemes": ["bearer", "operator_api_key"] },
  "skills": [
    {
      "id": "stack.dropoff.relay",
      "name": "Drop-off relay",
      "description": "...",
      "tags": ["messaging", "dropoff"]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `name`, `description` | Free text. A caller treats `description` as data. |
| `url` | The absolute address of the JSON-RPC endpoint (section 4): the origin of the deployment and `/v1/a2a/jsonrpc`. https, except for a local development server. |
| `provider` | `organization` is the deployment's issuer name (its Passport `iss`, `getstack.run` for STACK's hosted service) and `url` its site. |
| `version` | The A2A protocol version the endpoint speaks: `0.2.1`. |
| `defaultInputModes`, `defaultOutputModes` | Lists of strings. |
| `capabilities` | Three booleans, all `false`: no streaming, no push notifications, no state history (section 10). A card MUST NOT advertise a capability the endpoint does not implement. |
| `authentication.schemes` | The ways to authenticate (section 4): `bearer` and `operator_api_key`. |
| `skills` | One skill, `stack.dropoff.relay`, with `id`, `name`, `description` and `tags`. |

### 3.2 The card of an agent

Every agent of an account has a signed card, served by STACK on its own domain at `GET /v1/agent-identity/agents/{agent_id}/agent-card.json` ([Agent Identity](../agent-identity/SPEC.md) section 8). The card is of A2A 0.3. It is served with `Cache-Control: public, max-age=60` and `Access-Control-Allow-Origin: *`, and only when the agent is active or suspended, the account has a key STACK can sign it with and the owner has not switched the public answer off; otherwise the answer is the one an unknown agent gets, and a card is never served unsigned.

```json
{
  "name": "agt_Q2x5b3Vkc0FyZUp1c3RlA",
  "description": "An AI agent operated through STACK.",
  "url": "https://api.getstack.run/v1/a2a/jsonrpc",
  "version": "1.0.0",
  "protocolVersion": "0.3.0",
  "supportedInterfaces": [{ "url": "https://api.getstack.run/v1/a2a/jsonrpc", "protocolBinding": "JSONRPC", "protocolVersion": "0.3" }],
  "provider": { "organization": "STACK", "url": "https://getstack.run" },
  "documentationUrl": "https://api.getstack.run/v1/agent-identity?agent_id=agt_Q2x5b3Vkc0FyZUp1c3RlA",
  "capabilities": { "streaming": false, "pushNotifications": false },
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["text/plain"],
  "skills": [{ "id": "identity", "name": "Identity", "description": "Who this agent is and who stands behind it, signed by STACK: https://api.getstack.run/v1/agent-identity?agent_id=agt_Q2x5b3Vkc0FyZUp1c3RlA", "tags": ["identity"] }],
  "signatures": [{ "protected": "<base64url>", "signature": "<base64url>" }]
}
```

The name is the agent's own only when its owner shows it (`show_name`, off by default): otherwise `name` is the agent id and `description` is the fixed sentence above, and with it shown the description is the one the owner gave the account. The one skill is the way to ask who the agent is, which is the lookup of the Agent Identity specification; the card names no inbox, phone number, wallet or site of the agent and carries no contact form, and no `authentication` and no `stateTransitionHistory`.

**The signature.** `signatures` holds one JWS in the detached form of A2A section 8.4. The `protected` header is the base64url of a JSON object with `alg` `EdDSA`, `kid` (the JWK thumbprint of the signing key), `typ` `JOSE` and `jku`, the address of the agent's Web Bot Auth key directory on STACK's own domain, `/v1/agent-identity/agents/{agent_id}/http-message-signatures-directory` ([Web Bot Auth profile](../web-bot-auth/SPEC.md), section 5.6). The signing input is the `protected` string, a full stop, and the base64url of the **canonical JSON** (RFC 8785: keys sorted at every depth, no whitespace) of the card **without** `signatures`. The signature is Ed25519 over those bytes, base64url. A caller that verifies a card fetches the directory at `jku`, finds the key whose thumbprint is `kid`, and checks the signature; a card whose signature does not verify is not the agent's. A card that cannot be signed is not served.

## 4. The endpoint

`POST /v1/a2a/jsonrpc` at the address in the card, with `Content-Type: application/json` and a JSON-RPC 2.0 request as the body. The methods are `tasks/send`, `tasks/get` and `tasks/cancel`.

**Authentication.** The endpoint is not public. It takes the credentials the STACK API takes (an operator API key or an OAuth token that carries the drop-off scope, an agent's credential, or a Passport used as inbound authentication) in `Authorization: Bearer`. A call with none, or one that is not valid, is refused before the envelope is read, with `401` and the STACK error body (`{ "error": { "code", "message" } }`), not a JSON-RPC answer. A member of the account with less than the standard role is refused `tasks/send` and `tasks/cancel` as an invalid request (section 9).

**The envelope.** A request is a JSON object with `jsonrpc` equal to `"2.0"`, a `method` that is a string, an `id` and an optional `params`.

- `id` MAY be a string, a number or null; anything else (an object, an array, a boolean) is read as null, and a request with no `id` is answered with a null `id`. The server echoes the `id` it read in every answer.
- `params` is read when it is an object; anything else is read as absent.
- A body that is not such an object (null, an array, a string, a wrong or missing `jsonrpc`, a missing or non-string `method`) is answered with HTTP `400` and `{ "jsonrpc": "2.0", "id": <the id when it is a string, a number or null, else null>, "error": { "code": -32600, "message": "Invalid JSON-RPC envelope" } }`.
- A method that is not one of the three is answered with HTTP `200` and error `-32601`, message `Unknown method "<method>"`, echoing the `id`. A method the card's `capabilities` say is off, such as `tasks/sendSubscribe`, is such a method.
- Every other answer is HTTP `200`: a result `{ "jsonrpc": "2.0", "id", "result" }` or an error `{ "jsonrpc": "2.0", "id", "error": { "code", "message" } }`, never both. The two exceptions are in section 5.

## 5. tasks/send

`params`:

| Field | Meaning |
|---|---|
| `message` | Required. An object: the A2A message (`role`, `parts`). Its content is not interpreted. It is stored as the drop-off payload, with `sessionId`, the caller's `id` and the metadata, and is subject to the drop-off limits. |
| `sessionId` | A string, optional. Echoed. |
| `id` | A string, optional. Kept in the payload as `a2a_task_id`. It is **not** the task's id: the server assigns that. |
| `metadata.stack_from_agent` | Required: the id of the sending agent. It MUST be an agent of the caller's account; when the caller is an agent it MUST be that agent. |
| `metadata.stack_to_agent` | Required: the id of the receiving agent, of the caller's account. |
| `metadata.stack_passport_id` | Optional: the Passport of the sender (its `jti`), for the record. When the caller authenticated with a Passport this MUST equal it. |
| `metadata.stack_mission_id` | Optional: the Mission the task belongs to. |

The answer is the task, in state `submitted`:

```json
{
  "jsonrpc": "2.0",
  "id": "send-1",
  "result": {
    "id": "dof_...",
    "sessionId": null,
    "status": { "state": "submitted", "timestamp": "2026-10-24T09:30:00.000Z" },
    "metadata": { "stack_from_agent": "agt_...", "stack_to_agent": "agt_...", "stack_dropoff_id": "dof_..." }
  }
}
```

`result.id` is the drop-off's id and `metadata.stack_dropoff_id` repeats it; `metadata` echoes the request's metadata. `sessionId` is the request's, or null.

A server that conforms:

1. MUST refuse a request with no `message` (`-32602`, message `params.message is required`) or with no `stack_from_agent` or no `stack_to_agent` (`-32602`, message `params.metadata.stack_from_agent and stack_to_agent are required (STACK extension)`).
2. MUST refuse a sender or receiver that is not an agent of the caller's account, and MUST NOT create a task or name the agent in its answer. The unknown agent is the error `-32001` (section 9).
3. MUST check, before anything is written, as for any action of an agent: the sender's Mission and Passport (an agent without a Passport, or a Passport without exactly one live Mission, is refused), the customer's controls and the meter. A refusal is an error `-32602` with the message `Invalid task request`; nothing in it says which check refused.
4. MUST NOT charge for a refused task.
5. When the sender's accountability is `enforced` and a Passport is named, MUST require an approved intent for the task: with none that matches (the same target and arguments) the server answers **HTTP `403`** with a JSON-RPC error `-32602` whose message says what was missing, and records the refusal. This is one of two answers that are JSON-RPC errors with an HTTP status other than 200 and `400`.
6. MUST record the task: the drop-off's creation and deposit, and the dispatch, are rows of the audit chain, and when a Passport is named, a signed intent and outcome claim ([Record Format](../record/SPEC.md)).

Every refusal that is a STACK error is a JSON-RPC error with HTTP `200` (section 9), a temporary one (a dependency that is down, a customer's server that did not answer) included: the endpoint does not tell the two apart, so a caller that is refused with `Invalid task request` may retry. An unexpected failure of the server, which is not a refusal, is not a JSON-RPC answer: the server answers `5xx` with the STACK error body.

## 6. tasks/get

`params.id` is the task's id. The answer is the task's current state:

```json
{
  "jsonrpc": "2.0",
  "id": "get-1",
  "result": {
    "id": "dof_...",
    "status": { "state": "working", "timestamp": "2026-10-24T09:30:00.000Z" },
    "metadata": {
      "stack_dropoff_id": "dof_...",
      "stack_from_agent": "agt_...",
      "stack_to_agent": "agt_...",
      "stack_expires_at": "2026-10-24T10:00:00.000Z"
    }
  }
}
```

`status.timestamp` is when the message was collected, else when it was deposited, else when the task was created. `stack_expires_at` is when the task lapses if it is not collected: 30 minutes after it was sent.

A server that conforms MUST answer a task that does not exist, or that the caller may not see, with `-32001`, message `Task not found`, no `data`, and no text that repeats the id. The caller may see a task when it authenticated as the account (an operator key or a member), or as one of the task's two agents. Without `params.id` the answer is `-32602` with the message `params.id is required`. `tasks/get` needs no more than the caller's read of the account and is not metered.

## 7. tasks/cancel

`params.id` is the task's id. A task that has not been collected and has not lapsed is cancelled, and the answer is:

```json
{ "jsonrpc": "2.0", "id": "cancel-1", "result": { "id": "dof_...", "status": { "state": "canceled", "timestamp": "2026-10-24T09:31:00.000Z" } } }
```

with no `metadata`. A task already collected, or already cancelled or lapsed, is `-32002`, message `Task cannot be changed`. An unknown task, or one the caller may not cancel, is `-32001`. When the caller is an agent, only the sending agent may cancel. A cancelled task reads as `failed` afterwards (section 8). The call writes a row of the audit chain and is not metered.

## 8. Task states

`status.state` is one of the A2A task states. A drop-off maps to a state as follows:

| Drop-off | `state` | When |
|---|---|---|
| `created` | `submitted` | The task exists and has no message yet. A task made by `tasks/send` is deposited in the same call: it is `submitted` in the answer to `tasks/send` and never read as `created`. |
| `deposited` | `working` | The message is waiting to be collected. |
| `collected` | `completed` | The recipient collected the message. |
| `expired` | `failed` | The task lapsed unread, or it was cancelled. |
| any other | `failed` | |

`canceled` is the state in the answer to `tasks/cancel` only. A drop-off records no more than that it expired, so a cancelled task and a task that lapsed read the same afterwards, as `failed`. A caller that needs to know that it cancelled keeps that itself.

## 9. Errors

| Code | Message | HTTP | When |
|---|---|---|---|
| `-32600` | `Invalid JSON-RPC envelope` | 400 | The body is not a JSON-RPC 2.0 request. |
| `-32601` | `Unknown method "<method>"` | 200 | The method is not one of the three. |
| `-32602` | `params.message is required`, `params.id is required`, the `stack_from_agent` message, or `Invalid task request` | 200, or 403 for the approval check of section 5 | A parameter is missing, or the task was refused: a check of section 5, a role too low, an agent that may not act as the sender. |
| `-32001` | `Task not found` | 200 | The task, or an agent named in `tasks/send`, does not exist for the caller. |
| `-32002` | `Task cannot be changed` | 200 | The task is already collected, cancelled or lapsed, or is not active. |

The messages of `-32001`, `-32002` and `Invalid task request` are fixed. They never carry an id, an internal code, the name of a check, or validation detail. `-32700` (parse error) and `-32603` (internal error) are not used: a body that is not JSON is refused by the HTTP layer with `400` and the STACK error body, and an unexpected failure of the server is the STACK error body with a `5xx` status.

## 10. What is not implemented

A card at the well-known address of an agent's own host (an agent's site serves only what the agent publishes: its card is on STACK's domain, section 3.2); `tasks/sendSubscribe` (streaming); `tasks/pushNotification/set` and push notifications; the state history of a task; a reply on the same task; file and data parts richer than what the message carries inline; federation with agents of other accounts. The card says so (`capabilities`), and a call to a method that is not there is `-32601`. A later minor version of this specification MAY add them.

## 11. Security considerations

- **Content.** The message is data. The server stores it and hands it to the receiving agent; it does not run it. A receiving agent treats it as untrusted content, as it does anything another party wrote.
- **Same account.** A task cannot reach an agent of another account, so an A2A caller learns nothing about agents it does not own: an unknown agent and a foreign one are the same answer.
- **The sender is bound.** An agent that authenticates cannot send as another agent, or under another agent's Passport.
- **Replay and duplicates.** `tasks/send` has no idempotency key: a retried call is a second task. A caller that cannot tolerate that checks with `tasks/get` before it sends again.
- **Discovery.** The card is public by design and says nothing about any account. An agent's card is signed so that a caller can tell it from a copy; the signature proves the card came from the holder of the key in the agent's directory on STACK's domain, not that the agent is trustworthy.
- **Errors.** Errors carry no identifier and no internal text, so a caller cannot use them to learn what exists.

## 12. Conformance

The `a2a` suite of the [conformance kit](../conformance/README.md) is given the origin of a server and the credentials of a test caller, and, to run the task flow, two agents of that caller (and a second caller for the isolation check). It reads the card without credentials and checks its fields and capabilities; it checks that a call without credentials is refused and that a malformed envelope, an unknown method, parameters that are not an object, a missing task id, an unknown task and an unknown agent are answered as sections 4 to 9 say; and it sends a task, reads it (`working`), cancels it and reads it again (`failed`), checks that a second cancel is `-32002`, and that another caller sees `-32001`. Given the signed card of an agent, it checks the JWS against the key directory the header names.

The reference server in `conformance/reference/a2a-reference.mjs` passes the suite, and STACK's own endpoint and card builders pass it in the continuous integration of STACK's code.
