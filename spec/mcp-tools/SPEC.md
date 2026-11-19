# STACK MCP Tool Definitions

**Specification:** STACK MCP Tool Definitions
**Version:** 2.3.1
**Status:** Stable
**Licence:** Apache-2.0

STACK exposes its capabilities to AI clients as tools of a Model Context Protocol (MCP) server. This document defines how the tools are named, described, annotated and grouped into profiles, the conventions every tool follows, and the machine-readable catalog that lists them. The catalog is **generated from the reference implementation** by a script, so it cannot drift from the code.

Contents: 1 Conventions, 2 Catalog, 3 Tool definitions, 4 Profiles, 5 Annotations, 6 Results and errors, 7 Governance approval, 8 Secrets, 9 Versioning, 10 Keeping the catalog current, 11 Which tools a session lists, 12 Conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. The transport, message formats and lifecycle are those of the Model Context Protocol; this document adds only what is specific to STACK's tools.

## 2. Catalog

<!-- spec:generated:mcp-counts -->

The standard profile has 404 tools; the directory profile serves 145 of them. 185 are answered by the engine and 219 by STACK's network (`served_by`). The full reference is [TOOLS.md](TOOLS.md) and the machine-readable catalog is [tools.json](tools.json).

<!-- /spec:generated -->

The catalog is the output of a live `tools/list` against the reference server, per profile, with no staff privileges:

- [`tools.json`](tools.json): every tool with `name`, `title`, `description`, `inputSchema` (JSON Schema), `annotations`, the profiles that serve it, `served_by`, and what section 11 defines: `group`, `audience`, `pieces` and `on_demand`. This file is normative for tool names, input schemas, annotations and the listing fields.
- [`TOOLS.md`](TOOLS.md): the same, rendered for reading, one section per tool.

`served_by` says what answers the tool's calls: `engine` for a tool every install of the engine serves, `network` for a tool whose calls STACK's hosted service answers, which an install reaches only through its network client or not at all. The definition of a `network` tool is public like any other.

Tools that exist only for a platform operator's own staff are registered only for a staff session and are not part of this catalog.

## 3. Tool definitions

- A tool's `name` is `stack_` followed by a lower-case verb phrase in snake case (`stack_issue_passport`, `stack_list_agents`). Names are unique and stable.
- `title` is a short human-readable label.
- `description` says what the tool does, what it returns and any precondition, in plain language written for a model to read. It states the behaviour the tool really has, including approval requirements and what it never returns. A description MUST NOT instruct the model to call a tool that the tool's profile does not serve.
- `inputSchema` is a JSON Schema object generated from the tool's validation schema. Every parameter has a description. Identifiers have documented patterns where the server enforces one (for example Mission ids match `^ms_[\w-]+$`).
- A tool that accepts a value the server cannot allow to pass through a model (a secret) is declared strict: an argument it does not declare is refused by name and never echoed.
- Tools are idempotent where their descriptions say so; a retry with the same identifiers either repeats the effect harmlessly or fails with a documented error.

## 4. Profiles

Two profiles are defined:

| Profile | Purpose |
|---|---|
| `standard` | The full catalog, for a customer's own agents and clients. |
| `directory` | A subset for public connector directories. It omits tools that move money, run arbitrary calls with a customer's connections, handle credentials, or act as a platform administrator, and it omits optional parameters that carry a Passport token. |

A tool's `profiles` array in `tools.json` lists where it is served. A profile never adds a tool that the standard profile lacks.

Both profiles also serve one MCP resource, `stack://catalogue` (`application/json`): the catalogue of everything an agent can use through its account, as the [Catalogue specification](../catalogue/SPEC.md) defines it. Reading it needs the same access as `stack_catalogue`, and it is read-only and never counted as an action.

## 5. Annotations

Every tool carries all three behaviour hints, set explicitly, with these meanings:

| Hint | Meaning |
|---|---|
| `readOnlyHint` | `true` only when the tool changes no state. Writing an audit row for access is not a state change; metering an action is. A tool that persists, meters or records anything is not read-only. |
| `destructiveHint` | `true` when the tool revokes, deletes, disconnects, expires, collects (deleting the payload), suspends, blocks, ends a lifecycle, or overwrites or resets configuration so that prior values are lost. Always `false` for a read-only tool. |
| `openWorldHint` | `true` when the tool's effect reaches a party outside the caller's own STACK account: a provider API, an email, SMS or webhook recipient, an identity provider, or a marketplace shared with other customers. |

A client SHOULD use the hints to decide when to ask a person before calling. A client MUST NOT treat them as security controls: they are advisory, and the server enforces its own authorisation on every call.

## 6. Results and errors

A successful tool call returns one `text` content item whose text is JSON (the tool's result object, pretty-printed). A failed call returns an MCP tool result with `isError: true` whose text states the cause. The causes are those of the STACK API, whose errors have the shape `{ "error": { "code", "message", "details" } }` with a stable `code`.

A tool that is temporarily unable to serve because a dependency is down says so with a retriable error and a retry delay; it never reports a server fault as a bad credential.

## 7. Governance approval

Some changes (loosening a control, deleting an account, changing where decisions are made) need a person to approve them. A tool that can require this follows one flow: if the client supports MCP elicitation, the person is asked in the client to confirm the exact change and the change applies only after they approve; otherwise the tool returns `GOVERNANCE_APPROVAL_REQUIRED` with an `approval_id` and an `approval_url` for that one approval, and the same call repeated with `governance_approval_id` applies the change once the person has approved. An approval is single-use, bound to the exact payload, and expires after 24 hours. Some actions are never approvable from a chat and require the person to use a browser. A model MUST NOT be given the means to approve its own request.

## 8. Secrets

No tool returns a secret it can avoid returning. A signing secret or API key that is created for the caller is returned once, only to a caller that is allowed to hold it; a caller authenticated through an OAuth token (which is what a chat assistant has) receives a one-time link to a page where a person reads it, never the value. Tools that connect a service accept a one-time link flow so that a credential never passes through a chat.

## 9. Versioning

This specification uses semantic versioning applied to the catalog:

- **Major**: a tool is removed or renamed, a required parameter is added, a parameter's type is narrowed, or an annotation changes from non-destructive to destructive or from closed-world to open-world in a way that changes what a client must confirm.
- **Minor**: a tool is added, an optional parameter is added, or a tool is added to the directory profile.
- **Patch**: a description or title is corrected.

The catalog states the version of the specification in this file. The tool count and the tools themselves are generated; a change to either is visible in the diff of `tools.json`.

## 10. Keeping the catalog current

`tools.json` and `TOOLS.md` are written by the script `scripts/generate-spec.mjs` from the built server. `node scripts/generate-spec.mjs --check` fails when either differs from what the code produces, and a continuous-integration job runs it, so a tool cannot be added, changed or removed without the catalog in the same change. A change that alters the catalog is accompanied by an entry in [CHANGELOG.md](CHANGELOG.md) and, if it is a major or minor change, a version bump in this file.

## 11. Which tools a session lists

The catalog is every tool the server has. A session does not have to be shown all of them: a full list costs a client tens of thousands of tokens of definitions before an agent does anything, and most of it does not apply to who is connected. A server MAY therefore list a subset in the standard profile, by these rules. Listing is visibility only: a tool that is not listed is not callable in that session (the server answers a call to it as an error), and every tool that is listed still checks its scope, the Passport, the Mission and the customer's controls when it is called.

Each tool says who it is for (`audience`), which account pieces it belongs to (`pieces`), the group it is registered with (`group`) and whether it is rarely used (`on_demand`):

| Audience | Meaning |
|---|---|
| `agent` | Only a session of an agent (a Passport-bearing principal). The tool is for an agent acting and means nothing to a person managing the account. |
| `owner` | Only a session of an owner or a member (an API key or an OAuth sign-in): administration and settings, where a person decides what an agent may do. Listed whether or not a piece it belongs to is on, because it is how the piece is switched on. |
| `both` | A tool an agent uses and a person may also need. |

A tool whose `pieces` is empty is part of the core (passports and Missions, connections and the proxy, the record, the account's status, the catalogue) and is always listed to its audience. A tool of one or more pieces is listed to an agent while a piece it names is switched on for the agent's account, and to an owner while one of the customer's accounts has it on. A piece is switched on from state the account already has: a piece that is ready or paused, a connected Telegram bot, an active street address, an active Stripe connection, wake-ups switched on, skill access beyond none, a fleet membership.

<!-- spec:generated:mcp-exposure -->

| Group | Tools | Agent | Owner | Both | On demand |
|---|---|---|---|---|---|
| `accountability` | 5 | 2 | 2 | 1 | 2 |
| `accounts` | 71 | 1 | 23 | 47 | 40 |
| `agents` | 9 | 0 | 9 | 0 | 9 |
| `approvals` | 2 | 0 | 2 | 0 | 0 |
| `audit` | 4 | 0 | 4 | 0 | 4 |
| `authority` | 2 | 0 | 0 | 2 | 2 |
| `billing` | 3 | 0 | 1 | 2 | 3 |
| `brain` | 4 | 0 | 0 | 4 | 1 |
| `calendar` | 11 | 0 | 0 | 11 | 7 |
| `catalogue` | 2 | 0 | 0 | 2 | 0 |
| `chat-channels` | 3 | 0 | 3 | 0 | 3 |
| `control-policies` | 9 | 0 | 9 | 0 | 9 |
| `control-socket` | 12 | 0 | 12 | 0 | 12 |
| `credentials` | 2 | 0 | 2 | 0 | 2 |
| `drive` | 11 | 0 | 0 | 11 | 8 |
| `dropoffs` | 6 | 0 | 0 | 6 | 6 |
| `fleets` | 12 | 3 | 8 | 1 | 10 |
| `identity` | 18 | 0 | 18 | 0 | 18 |
| `llm` | 2 | 0 | 2 | 0 | 2 |
| `making` | 11 | 0 | 2 | 9 | 9 |
| `meetings` | 8 | 0 | 0 | 8 | 8 |
| `memory` | 18 | 0 | 2 | 16 | 15 |
| `message-access` | 2 | 0 | 2 | 0 | 2 |
| `missions` | 11 | 0 | 5 | 6 | 6 |
| `network` | 12 | 0 | 10 | 2 | 12 |
| `notifications` | 10 | 0 | 10 | 0 | 10 |
| `openrouter` | 1 | 1 | 0 | 0 | 0 |
| `partners` | 11 | 0 | 11 | 0 | 11 |
| `passports` | 10 | 0 | 4 | 6 | 5 |
| `payments` | 8 | 0 | 0 | 8 | 6 |
| `post` | 19 | 0 | 8 | 11 | 16 |
| `proxy` | 9 | 0 | 2 | 7 | 6 |
| `rentahuman` | 5 | 2 | 0 | 3 | 5 |
| `security` | 12 | 0 | 10 | 2 | 11 |
| `services` | 14 | 0 | 11 | 3 | 7 |
| `signed-records` | 4 | 0 | 1 | 3 | 2 |
| `skills` | 16 | 0 | 6 | 10 | 16 |
| `team` | 5 | 0 | 5 | 0 | 5 |
| `trust` | 2 | 0 | 2 | 0 | 2 |
| `wake` | 13 | 0 | 10 | 3 | 11 |
| `webhooks` | 4 | 0 | 4 | 0 | 4 |
| `website` | 11 | 0 | 2 | 9 | 9 |

<!-- /spec:generated -->

A server that lists a subset MUST send `notifications/tools/list_changed` to a session when a change to its pieces changes what the session lists, MUST answer `tools/list` with the current set, and MUST NOT depend on the client acting on the notice (a client that ignores it sees the change on its next connection). A server SHOULD read the pieces again before it answers a `tools/list` whose last reading is a few seconds old.

`on_demand` is the load-on-demand hint: a rarely used tool stays registered and callable, and a client with tool search keeps its definition out of the model's context until it is searched for. The Model Context Protocol has no field for it. A server sends it as `_meta` of the tool in `tools/list`: `"anthropic/alwaysLoad": false`, the key Claude Code reads. A client that does not know the key ignores it. The server marks no tool `true`: a client with tool search already defers every tool of a server unless the person's own configuration says otherwise.

The directory profile is never narrowed and carries no hint: the list that was reviewed is the list that is served. A tool of the standard profile that is not listed to a session is still an entry of the catalogue (`mcp_tool:<name>` in the [Catalogue specification](../catalogue/SPEC.md)), so an agent can find it by searching.

## 12. Conformance

The `mcp-listing` suite of the [conformance kit](../conformance/README.md) judges section 11 on a server that lists a subset. It is given a way to open a session on the server (an audience, the pieces that are on, a profile) and the catalog the server is to be judged against (`tools.json`, or the part of it the server serves). The kit applies the listing rule of section 11 itself and compares, tool by tool, with what the server lists:

- an agent session and an owner session, with no piece on and with every piece on, and with each piece on alone, list exactly the tools the rule gives, and a tool that is not listed is refused when it is called;
- every tool with `on_demand` carries `_meta` `"anthropic/alwaysLoad": false` in the standard profile, none is marked `true`, and the directory profile carries no hint;
- the directory profile lists the same tools to every session, those of the catalog's `directory` profile;
- when a piece comes on or goes off, `tools/list` answers the new set and `notifications/tools/list_changed` is sent, once for one change, and not for a change that changes nothing.

The reference in `conformance/reference/mcp-listing-reference.mjs` (over the MCP TypeScript SDK alone) passes the suite, and so does the MCP server of the engine and, in the continuous integration of STACK's hosted service, the whole catalog.
