# STACK Agent Identity

**Specification:** STACK Agent Identity
**Version:** 1.0.0
**Status:** Stable
**Licence:** Apache-2.0

An agent has a website, an inbox, a phone number, a wallet, and it makes requests to other people's sites. Whoever meets it can ask STACK one question: who is this? STACK answers on its own domain, on request, in a statement it signs. The statement says which agent it is, whether its account is in use, and two yes-or-no facts about the owner who stands behind it: whether STACK has verified who the owner is and whether the owner's account is one STACK serves. It never carries the agent's Passport, and nothing else about the owner: no name, email, address, card or location, and nothing from the identity check or from a payment provider beyond those two answers. This document defines the lookup, the answer, the signed statement, how an asker verifies it, what the answer must never reveal, the machine files STACK serves for an agent from the same address (its signed A2A card, its MCP server card and its Web Bot Auth key directory), and the two switches the owner has.

The statement says who stands behind an agent. It is not a control (what an agent may do is decided by its Mission, its Passport and its owner's controls) and it is not an authentication (a statement about a key does not prove that whoever is talking holds the key: a site checks the request's signature for that, as [`../web-bot-auth/SPEC.md`](../web-bot-auth/SPEC.md) section 7 says).

Contents: 1 Conventions, 2 Overview, 3 The lookup, 4 The answer, 5 The signed statement, 6 What the answer never carries, 7 An agent that is not found, 8 The machine files of an agent, 9 The owner's switches, 10 Errors, 11 Rate limits, 12 What an asker must do, 13 Security considerations, 14 Privacy considerations, 15 Conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. The **server** is an implementation of this specification (STACK's hosted service is one), the **asker** is whoever sends a lookup, and the **verifier** is the code that checks a statement. A server conforms if it satisfies every MUST in sections 3 to 11; a verifier if it satisfies every MUST in section 12. The conformance kit in [`../conformance/`](../conformance/README.md) (the `agent-identity` suite) tests exactly that.

Times are Unix time in seconds. JSON is as in RFC 8259; members not defined here are not part of this version. A **key id** is the JWK thumbprint of an Ed25519 key as [`../web-bot-auth/SPEC.md`](../web-bot-auth/SPEC.md) section 4 defines it. An **agent id** is the public id of an agent, `agt_` and 21 characters of base64url. The endpoint is served only by STACK's hosted service: the engine in STACK's repository does not serve it, and this document describes the wire contract a verifier relies on and a server implements.

## 2. Overview

- **On request.** Nothing about who an agent is is published on the agent's site. A site belongs to its agent and carries only what the agent publishes. The question is answered by the server, on its own origin, when someone asks.
- **One origin.** The server is at the origin a signed request names in `Signature-Agent` (`https://api.getstack.run` for STACK's hosted service). A site that has checked a signature against the key directory there asks the same origin who the key belongs to.
- **Three ways to ask.** By the key id of a request the agent signed, by the host name of its site, or by its id (section 3). Something that is easy to guess, such as an inbox address, a phone number or a name, is not a way to ask.
- **Signed, short-lived.** The answer carries a compact JWS made with the deployment's signing key, the one that signs Passports, under a type and an audience of its own, valid for minutes (section 5). The same facts are in plain JSON for people.
- **Nothing to learn from a refusal.** An agent that does not exist, one that is closed, one that is still opening and one whose owner has switched the answer off are refused in exactly the same words (section 7).
- **Minimum by default.** The agent's name is shown only when its owner chose to show it (section 9).

## 3. The lookup

```
GET /v1/agent-identity?key_id=<key id>
GET /v1/agent-identity?site=<host name>
GET /v1/agent-identity?agent_id=<agent id>
```

Public: no credential, no request body. A lookup names exactly one of the three. A request with none, with two, with a parameter of another name, or with a value that does not have the form below is refused with `400` and the error `AGENT_IDENTITY_LOOKUP_INVALID` (section 10); the refusal says nothing about the value.

| Parameter | Form | Where an asker has it |
|---|---|---|
| `key_id` | 43 characters of base64url: `^[A-Za-z0-9_-]{43}$` | The `keyid` of the `Signature-Input` of a request the agent signed. |
| `site` | A host name of at most 253 characters, at least two labels, letters, digits and hyphens: no scheme, port, path or trailing dot. Case is not significant; the server answers in lower case. | The address of the agent's website, STACK's own address for it or the owner's own domain. |
| `agent_id` | `^agt_[A-Za-z0-9_-]{21}$` | An earlier answer, or an agent card. |

The three differ in what they find:

| Parameter | Finds an agent while | A closed agent is |
|---|---|---|
| `key_id` | its key is published in the server's key directory: the key in use, or a retired one within its publication window | not found: the keys of a closed account stop being published at once |
| `site` | its site is live or suspended and the address is active | not found |
| `agent_id` | its account exists and is not still opening | answered, with status `closed` |

The second and third rows follow section 7: a host name can be guessed, so it never confirms that a closed agent existed. A key id is a hash of a public key and an agent id is 126 random bits, so neither can be searched for, and a closed agent is named only to someone who already holds its id.

## 4. The answer

A found agent is answered `200` with `Content-Type: application/json; charset=utf-8` and `Cache-Control: no-store`. The body is a JSON object:

```json
{
  "statement": "eyJhbGciOiJFZERTQSIsImtpZCI6InN0YWNrLXBhc3Nwb3J0LXYxIiwidHlwIjoic3RhY2stYWdlbnQtaWRlbnRpdHkrand0In0.eyJpc3MiOi...",
  "agent": { "id": "agt_Q2x5b3Vkc0FyZUp1c3RlA", "status": "active" },
  "owner": { "identity_verified": true, "good_standing": true },
  "lookup": { "key_id": "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U" },
  "issued_at": 1790000000,
  "expires_at": 1790000300
}
```

| Member | Meaning |
|---|---|
| `statement` | The compact JWS of section 5: the answer itself. Everything below is the same facts for a reader who does not check a signature, and MUST equal the claims the statement carries. |
| `agent.id` | The agent's public id. |
| `agent.name` | The name the owner gave the agent. Present only when the owner chose to show it (section 9); otherwise the member is absent, not null and not empty. At most 120 characters. |
| `agent.status` | `active`, `suspended` or `closed` (the table below). |
| `owner.identity_verified` | STACK has verified who the owner is. A yes or no: not who, not when, not by whom. |
| `owner.good_standing` | The owner's account is one STACK serves: it is not suspended or removed, and its subscription or contract is in force. A yes or no: not why, not since when, and nothing about the owner's behaviour. |
| `lookup` | What the asker named, as one member: `key_id`, `site` (in lower case) or `agent_id`. Present only in the answer for an agent that exists. |
| `issued_at`, `expires_at` | When the statement was made and when it stops being good: the `iat` and `exp` of the statement. |

| `agent.status` | The agent's account is |
|---|---|
| `active` | open: the agent can act |
| `suspended` | suspended or frozen, or its owner's account is suspended, whatever the reason (the answer never says which): its actions are refused for now |
| `closed` | closing or closed: it is over |

An account that is still being opened has no status and is not found: the server does not vouch for an agent that cannot act yet.

The members of the body are exactly those of the example. A server MUST NOT add a member to the body, to `agent`, to `owner` or to `lookup`, and an asker MUST NOT read one it finds as a fact.

The constants of this version:

<!-- spec:generated:agent-identity-constants -->

| Constant | Value |
|---|---|
| Protected header `typ` of a statement | `stack-agent-identity+jwt` |
| Audience (`aud`) | `stack:agent-identity` |
| Issuer (`iss`) | `getstack.run` |
| Signature algorithm | `EdDSA` (Ed25519) |
| Version of the claim (`identity.v`) | 1 |
| A statement is good for | 300 s (5 min) |
| A statement may be good for, at most | 900 s (15 min) |
| Ways to ask | `key_id`, `site`, `agent_id` |
| Statuses | `active`, `suspended`, `closed` |
| Agent name, longest | 120 characters |
| The owner's switches and their defaults | `enabled` true, `show_name` false |
| Description in a card when the name is not shown | `An AI agent operated through STACK.` |
| Files of an agent | `agent-card.json`, `mcp-server-card.json`, `http-message-signatures-directory` |

<!-- /spec:generated -->

## 5. The signed statement

`statement` is a compact JWS (RFC 7515) with EdDSA (Ed25519, RFC 8037).

**Protected header.** Exactly `{"alg":"EdDSA","kid":"<kid>","typ":"stack-agent-identity+jwt"}`: `kid` names the signing key in the server's JWKS. The `typ` is the one this type of object has and no other type of object of STACK has; a Passport has no `typ` at all.

**Payload.** A JSON object with these members and no other:

| Claim | Value |
|---|---|
| `iss` | The deployment's issuer: the same as the `iss` of its Passports (`getstack.run` for STACK's hosted service). |
| `aud` | `stack:agent-identity`. A Passport's is `stack:passport`; no statement can be taken for a Passport, and no Passport for a statement. |
| `sub` | The agent id. |
| `iat` | The time the statement was made. |
| `exp` | When it stops being good. A server MUST NOT set it more than 900 seconds after `iat`; STACK sets it 300 seconds after. |
| `identity` | The facts, below. |

`identity` is an object with exactly these members: `v`, the integer `1`; `agent` and `owner`, as in section 4 (`agent.name` only when shown); and `lookup`, as in section 4. `sub` MUST equal `identity.agent.id`. There is no `jti`, no `nbf` and no other claim: the statement is made again for every lookup.

Decoded, the payload of the example in section 4:

```json
{
  "iss": "getstack.run",
  "aud": "stack:agent-identity",
  "sub": "agt_Q2x5b3Vkc0FyZUp1c3RlA",
  "iat": 1790000000,
  "exp": 1790000300,
  "identity": {
    "v": 1,
    "agent": { "id": "agt_Q2x5b3Vkc0FyZUp1c3RlA", "status": "active" },
    "owner": { "identity_verified": true, "good_standing": true },
    "lookup": { "key_id": "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U" }
  }
}
```

**Keys.** The statement is signed with the deployment's signing key, the one that signs its Passports. The public keys are the issuer's JWKS at `GET /v1/.well-known/jwks.json` ([`../passport/SPEC.md`](../passport/SPEC.md), the section on the issuer's keys): the key in use and every retired key that statements or Passports may still be signed with. The same rotation rules apply: a retired key stays published until every statement signed by it has expired.

The vectors of the conformance kit ([`../conformance/fixtures/agent-identity/vectors.json`](../conformance/fixtures/agent-identity/vectors.json)) hold a statement that verifies and the statements that must not, with the key set and the time to check them at (each statement is written as its parts, to be joined with a full stop). They are written by [`../conformance/scripts/build-agent-identity-vectors.mjs`](../conformance/scripts/build-agent-identity-vectors.mjs); Ed25519 is deterministic, so the same inputs give the same bytes.

## 6. What the answer never carries

Neither the body nor the statement, whatever the owner has switched:

- The agent's Passport, any token or credential of the agent or its owner, and any claim that is in a Passport.
- The owner's name, email address, postal address, phone number, location, identifier or the name of their organisation; the owner's customer record at a payment provider, and anything from a payment, a card or a wallet.
- Anything from the identity check beyond the one yes or no: who the provider was, what the document was, what was found, and when.
- The agent's inbox address, phone number, wallet address or the address of its site.
- The id of the owner's account at the server, or of the agent's account.
- Why an agent is suspended or an owner is not in good standing (a staff decision, a lapsed plan, a debt, a refund or a check the owner's account is held for), whether there is a reason at all, and for how long.

A server MUST NOT put any of these in the answer or in an error, and a verifier MUST NOT expect them.

## 7. An agent that is not found

A lookup that finds no agent is answered `404` with this body, and with nothing else different:

```json
{ "error": { "code": "AGENT_IDENTITY_NOT_FOUND", "message": "No agent answers to this lookup." } }
```

The same answer, byte for byte, is given when the agent never existed, when it is closed and was asked for by a `key_id` or a `site` (section 3), when its account is still opening, and when its owner switched the answer off (section 9). It carries no `details`, and it MUST NOT repeat any part of what was asked: not the key id, not the host name, not the agent id. For a request of one kind (a lookup, or a request for one file) the status, the body, the headers that vary with the answer (`Content-Type`, `Cache-Control`) and the error code MUST NOT differ between those cases, so that nobody can find out which agents exist by asking. The answer for a file is the same `404` and body as for a lookup; only a header that belongs to the kind of request may differ. A server SHOULD also take about as long to refuse as to answer; STACK's does not guarantee it (section 13).

A host name is a way to ask that can be guessed. A server MUST NOT answer a lookup by host name in a way that confirms that a closed or removed agent had a site there. The id forms (key id, agent id) cannot be guessed, so a server MAY name a closed agent to someone who holds its id (section 3).

A lookup that is refused because it is not well formed (section 3) is a different answer on purpose: the form of a value is not a secret.

## 8. The machine files of an agent

A server serves three files for an agent from the same origin, under its agent id:

| File | Address | Media type |
|---|---|---|
| The signed A2A agent card | `GET /v1/agent-identity/agents/{agent_id}/agent-card.json` | `application/json; charset=utf-8` |
| The MCP server card | `GET /v1/agent-identity/agents/{agent_id}/mcp-server-card.json` | `application/json; charset=utf-8` |
| The Web Bot Auth key directory | `GET /v1/agent-identity/agents/{agent_id}/http-message-signatures-directory` | `application/http-message-signatures-directory+json` |

Public, no credential. The cards carry `Access-Control-Allow-Origin: *` and `Cache-Control: public, max-age=60`; the key directory carries the headers of [`../web-bot-auth/SPEC.md`](../web-bot-auth/SPEC.md) section 5.2.

A server MUST serve a file only for an agent whose status is `active` or `suspended` and whose owner has not switched the answer off. For any other agent, for an agent id of no possible form, and for an agent whose account has no key the server can sign with, the answer is the `404` of section 7: a card is never served unsigned.

**The cards** are built on request and signed with the account's own Ed25519 key, the one its signed requests carry ([`../web-bot-auth/SPEC.md`](../web-bot-auth/SPEC.md) section 4). The A2A card is of A2A 0.3 and is described in [`../a2a/SPEC.md`](../a2a/SPEC.md) section 3.2: its `jku` is the address of the key directory of this agent in the table above, and its one skill points at the lookup. The MCP server card follows the draft of SEP-2127 and names the server's own MCP endpoint in `remotes`; its signature, the same detached JWS object as a card's (`{ "protected", "signature" }`, over the canonical card without `_meta`, with the same header), is `_meta["run.getstack/signature"]`. Neither names the agent's inbox, wallet or site, and neither carries a contact form. The agent's name appears in a card only when the owner shows it: otherwise the card's name is the agent id and its description is the fixed sentence `An AI agent operated through STACK.`

**The key directory** is the account's own directory: the keys its signatures can carry, the key in use first and a retired key still published after it, signed by the key in use over the host the request came to, exactly as [`../web-bot-auth/SPEC.md`](../web-bot-auth/SPEC.md) sections 5.3 and 5.4 write. It is the same document the server's public directory lists these keys in, for one account.

The files are not on the agent's site. An agent's site serves only what the agent publishes.

## 9. The owner's switches

The owner of an agent's account has two switches over what the public answer shows. They belong to the account, they are the owner's alone (an agent that could change what is said about it could hide itself), and they start at the minimum:

| Switch | Default | When off |
|---|---|---|
| `enabled` | `true` | The server answers every lookup of this agent, and requests its files, with the `404` of section 7, as for an agent that does not exist. |
| `show_name` | `false` | `agent.name` is absent from the answer and the statement, and the cards show the agent id and the fixed description of section 8. |

They are read and changed at `GET /v1/accounts/{id}/identity` and `PUT /v1/accounts/{id}/identity` of the REST API ([`../rest-api/SPEC.md`](../rest-api/SPEC.md)), with an authenticated owner or administrator; a Passport or any agent credential is refused for the change. The body of the change is an object with `enabled` and `show_name`, each optional, at least one given, and no other member. The answer is the setting: `account_id`, `agent_id`, `enabled`, `show_name` and `urls`, the addresses of the lookup and of the three files on the server's own origin. A change is a row of the account's signed record ([`../record/SPEC.md`](../record/SPEC.md)), written in the same transaction as the change. A change takes effect on the next lookup: a statement already made stays good until it expires.

## 10. Errors

Errors have the envelope of the REST API (`{ "error": { "code", "message" } }`).

| Status | Code | When |
|---|---|---|
| 400 | `AGENT_IDENTITY_LOOKUP_INVALID` | The lookup names none, or two, or a parameter that is not defined, or a value of no possible form. The message is fixed and repeats nothing. |
| 404 | `AGENT_IDENTITY_NOT_FOUND` | Section 7. |
| 429 | `RATE_LIMITED` | The source asked too often (section 11). |
| 5xx | the server's own | The server cannot tell what is true (it cannot read the owner's standing, or its signing key is unavailable). It MUST NOT then sign or send a statement, and MUST NOT guess a fact; a refused read is never answered with `good_standing` set from a default. A server MAY answer such a failure of a lookup as section 7's not-found instead, so that how a lookup ends never tells a failure from an agent that has no answer; STACK does. |

## 11. Rate limits

The endpoint and the files are public, so a server MUST limit them per source address. STACK limits lookups and file reads per source and, past its limit, answers `429` with a `Retry-After` header. The limit is the server's choice and is not part of the contract an asker relies on, but an asker SHOULD cache what it can (a verified statement until it expires, a card for its `max-age`) and MUST NOT send lookups in a loop.

The server MUST NOT write anything for a read: no audit row and no log line that names what was asked.

## 12. What an asker must do

A verifier that has a statement:

1. MUST require a compact JWS whose protected header has `alg` equal to `EdDSA` and `typ` equal to `stack-agent-identity+jwt`, and MUST refuse any other `alg` (including `none` and a MAC) and any other or missing `typ`.
2. MUST find the key whose `kid` is the header's in the issuer's JWKS and refuse an unknown `kid`. A verifier SHOULD cache the JWKS and, when it meets an unknown `kid`, fetch it once more before refusing.
3. MUST verify the signature.
4. MUST require `iss` to be the issuer it trusts, and `aud` to be `stack:agent-identity`. A token with the audience of a Passport is not a statement.
5. MUST refuse a statement at or after its `exp` (with at most 5 seconds of clock skew), and a statement whose `iat` is more than 5 seconds in the future, and SHOULD refuse one whose `exp` is more than 900 seconds after its `iat`.
6. MUST require `sub` to equal `identity.agent.id`, and `identity.v` to be `1`: a verifier of this version refuses another.
7. MUST compare `identity.lookup` with what it asked and refuse a statement that is about something else: a statement about one key id is no answer for another.
8. MUST take the facts from the statement, never from the plain JSON beside it, and MUST NOT keep a statement past its `exp` or use one to answer a later question: it asks again.
9. MUST treat a statement that fails any check as no statement, and a `404` or an error as not knowing, never as good standing.

What a verified statement says is that STACK, when it signed, vouched that the agent exists and that these facts about its owner were true. It does not say that the agent behind a request is honest, that the request is the agent's (check the request's signature), or what the owner will do.

## 13. Security considerations

- **A vouching, not an authentication.** A statement named by `key_id` says the key belongs to an active agent. It does not prove that a request was made by the holder of the key. A site checks the signature of the request first ([`../web-bot-auth/SPEC.md`](../web-bot-auth/SPEC.md) section 7), then asks who the key belongs to.
- **Never a Passport.** The statement is signed with the key that signs Passports and carries no authority: its `typ` and `aud` are its own and both are required on verification, so no Passport verifies as a statement and no statement is accepted where a Passport is expected. A verifier that skips the `typ` and `aud` checks takes that protection away.
- **Freshness.** A statement lives five minutes and is not cached by anything between the server and the asker (`no-store`). Suspension and closure are seen at the next lookup, not at once in a statement already held.
- **Enumeration.** Section 7. The one thing a server cannot hide is a refusal's timing: STACK looks an agent up in the database before it answers, and an unknown key or host answers a little faster than a known one. With a key id or an agent id the asker has nothing to search with; a host name can be guessed, but the sites on STACK's agent domain are public, and a closed agent is not found by it.
- **Search by host name.** An asker that tries many host names learns which sites are live and their agents' id, status and standing: what a visitor to those sites could see, and no more. The per-source limit makes this slow; it is not a defence against someone with many sources, and what the answer carries is chosen with that in mind (section 6).
- **Fail closed.** A server that cannot read the owner's standing or cannot sign answers with an error. It never answers with a default.
- **Replay.** A statement can be copied and shown again within its five minutes. A site that needs a statement bound to a request asks for itself.

## 14. Privacy considerations

The statement is public by design, so what it can say is limited to what an agent's counterparties need and the owner would expect to be known: that the agent is real, whether it is in use, and two facts about its owner that say nothing about who the owner is. The owner's identity, contact details and money are never in it (section 6). The agent's name is the owner's to show, and is hidden until it does (section 9). The owner can switch the whole answer off. A lookup is not written to the account's record and the server keeps nothing about who asked: no audit row, no log line with the key id, host name or agent id.

## 15. Conformance

The `agent-identity` suite of the [conformance kit](../conformance/README.md) judges the two roles. Given the origin of a server and the handles of a test agent (its key id, its host name and its id, and optionally a closed agent and one whose owner switched the answer off), it makes the lookups of section 3 and checks the forms and the refusals, the exact members of the answer, the signed statement against the server's JWKS (type, audience, issuer, expiry, the claims equal to the plain JSON, and that no statement is taken for a Passport), that an unknown, a closed-by-host, an opening and a switched-off agent are answered in the same words and that none repeats what was asked, the machine files of section 8 (the card signature against the key directory its header names, and the directory against the Web Bot Auth suite), and that the server limits a source. Given a verifier, it checks the vectors: the statement that verifies and the statements that must be refused, one defect at a time (expired, from the future, wrong or missing `typ`, a Passport's audience, another issuer, an unknown key, an altered payload, `alg` `none` and a MAC under the public key, a subject that is not the agent, another version, and a statement about another lookup).

The reference server, the reference verifier and a set of deliberately defective servers and verifiers in `conformance/reference/agent-identity-reference.mjs` are written from this document with `node:crypto` alone; the reference passes the suite and each defect fails the check it should. STACK's own implementation, behind the routes of its API, passes it in the continuous integration of STACK's hosted service, and the verifiers of its SDKs pass the verifier checks.
