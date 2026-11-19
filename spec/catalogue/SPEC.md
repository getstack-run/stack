# STACK Catalogue

**Specification:** STACK Catalogue
**Version:** 1.4.0
**Status:** Stable
**Licence:** Apache-2.0

An agent on STACK has an account, and the account is how it gets everything it uses: models, tools, the services its owner connected, published skills, and the account's own inbox, phone number, drive and the rest. The **catalogue** is one document that says all of it upfront: what each thing is, what it costs, what it takes as input, whether what it returns can be trusted, and which route runs it. An agent reads the catalogue instead of searching marketplaces, and a client, a framework or another provider can read, serve or check the same document.

This document defines the catalogue document, how it is versioned and cached, how an entry is run, and what a publisher MUST do with text and schemas it takes from a provider. The TypeScript definition is `packages/shared/src/schemas/catalogue.ts`; the JSON Schemas are generated from it and listed in section 12. This text and those schemas describe the same format.

Contents: 1 Conventions, 2 Model, 3 The document, 4 Entries, 5 Prices, 6 Trust, 7 Sections, 8 Version and caching, 9 Running an entry, 10 One account's part, 11 Security considerations, 12 Machine-readable schemas, 13 MCP, 14 Conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. A **publisher** is a service that builds and serves a catalogue document (in the reference implementation, STACK's worker builds it and STACK's API serves it). A **reader** is anything that fetches and uses one: an agent, a client library, a framework. Money is in US dollars and written as integer **micro-dollars** (millionths of a dollar) wherever a field name ends in `_usd_micros`.

## 2. Model

The catalogue has two parts that are never mixed.

- **The shared document** says what exists. It is the same for every reader, it contains nothing that belongs to a customer (no key, no connection, no account), and it is built ahead of time from its sources and stored, never computed for a request. Section 3 to 9 define it.
- **One account's part** says what is true of one account: the services its owner has connected and the state of its own pieces. It is served only to that account and is never cached across accounts (section 10).

Searching and inspecting the catalogue is free and never counted as an action. Only running an entry spends anything (section 9).

## 3. The document

```json
{
  "spec": "stack.catalogue",
  "spec_version": "1",
  "version": "<64 hexadecimal characters>",
  "generated_at": "2026-10-22T09:00:00.000Z",
  "notice": "...",
  "pricing": { "currency": "USD", "rule": "...", "included_actions_per_month": 100, "bands": [] },
  "sections": [{ "source": "models", "status": "ok", "refreshed_at": "2026-10-22T09:00:00.000Z", "count": 312 }],
  "entries": []
}
```

- `spec` is `stack.catalogue` and `spec_version` is `1`. A reader MUST refuse a document whose `spec` it does not know, and SHOULD refuse one whose `spec_version` it does not know.
- `version` is the hash of what the document says (section 8). `generated_at` is when this copy was built.
- `notice` is a sentence that tells a reader that provider text is data (section 11). A publisher MUST include one.
- `pricing` says what an action costs (section 5). `sections` says how each source stands (section 7). `entries` is the list.
- A document is at most the size in the constants table below, and has at most as many entries. A publisher MUST NOT serve a larger one.

<!-- spec:generated:catalogue-constants -->

| Constant | Value |
|---|---|
| Kinds | `model`, `tool`, `service`, `skill`, `account`, `mcp_tool` |
| Sections (`source`) | `stack`, `models`, `tools`, `services`, `skills` |
| Section statuses | `ok`, `not_configured`, `unavailable`, `stale` |
| Price units | `token`, `call`, `result`, `image`, `lines`, `free`, `varies` |
| Result trust | `standard`, `untrusted` |
| Origins | `stack`, `models`, `tools`, `publisher` |
| Tool audiences (`tool.audience`) | `agent`, `owner`, `both` |
| Entry id, longest | 330 characters |
| Name, longest | 120 characters |
| Input schema, largest | 16 KiB |
| Input schema, deepest | 8 levels |
| Properties in one input schema object, most | 64 |
| Entries in a document, most | 10000 |
| Document, largest | 64 MiB |
| Entries in a search answer, most | 100 |
| Path of the file on the API | `/v1/catalogue` |
| MCP resource | `stack://catalogue` |
| Cost cap header of a model call | `X-Max-Cost-Cents` |
| A shared cache may keep the file for | 300 s (5 min) |
| The reference publisher refreshes the provider parts every | 1800 s (30 min) |

<!-- /spec:generated -->

A publisher MUST NOT add fields to any object of this version. A reader MUST ignore a field it does not know, and MUST ignore an entry whose `kind` it does not know, so that a later minor version can add either.

## 4. Entries

An entry is one thing an agent can use. Its `id` is the kind, a colon, and a name that identifies it within the kind. Ids are unique in a document.

<!-- spec:generated:catalogue-kinds -->

| Kind | Id | Section | Comes from |
|---|---|---|---|
| `model` | `model:<model id>` | `models` | the model list of a model provider, every model with the modalities it lists |
| `tool` | `tool:<provider><endpoint>` | `tools` | every endpoint of the paid-tools provider |
| `service` | `service:<provider>` | `services` | the services a customer can connect |
| `skill` | `skill:<skill id>` | `skills` | published skills |
| `account` | `account:<piece>` | `stack` | the pieces of the account itself |
| `mcp_tool` | `mcp_tool:<tool name>` | `stack` | the tools of STACK's own MCP server |

<!-- /spec:generated -->

| Field | Meaning |
|---|---|
| `id` | `kind:name`, at most the length in the constants table; the characters `A-Z a-z 0-9 . _ ~ : @ / + -`, and the name starts with a letter, a digit or `~` (a model provider's alias such as `~vendor/model-latest` does). The kind in the id MUST be the entry's `kind`. |
| `kind` | One of the kinds above. |
| `name` | A short name, plain text. |
| `description` | One or two sentences, plain text. May be empty. |
| `origin` | Who wrote the name and description: see section 6. |
| `provider` | Optional. The provider behind the entry: a model provider, a paid-tools provider's slug, a service's provider. |
| `modalities` | Optional, models. What the model takes in and gives out, as its provider lists it (`text`, `image`, `audio`, `video`, `file`, `speech`, `transcription`, `embeddings`, `rerank`, ...): `{ "input": ["text"], "output": ["text"] }`. Each list has at most 8 names. |
| `context_length` | Optional, models. The most tokens the model reads. |
| `max_completion_tokens` | Optional, models. The most tokens the model writes in one answer. With the context length and the price lines it bounds what a call can cost. |
| `input_schema` | Optional. A JSON Schema of the input of a run, reduced to the keywords in section 11. An `account` entry carries the input of its run route and an `mcp_tool` entry that of its tool; a schema that is larger than the bound is left out. |
| `price` | What a run costs (section 5). |
| `result_trust` | What a run returns, in the terms of section 6. |
| `run` | Optional. How to run the entry (section 9). |
| `tool` | Only on an `mcp_tool` entry. What the entry says about the tool beyond its definition (below). |

A **model** entry is any model the model provider lists, whatever it makes (text, pictures, sound, video, embeddings, speech, transcription, ranking): it carries what it takes in and gives out and the provider's own prices (section 5), and its run is a call to the publisher's model gateway at the endpoint its output needs (section 9). A **tool** entry is an endpoint of the paid-tools provider, with the provider's own name, description, input schema and price; the publisher lists every endpoint the provider lists, and the entry has a `run` only when the publisher can compute a worst case for it (section 9). A **service** entry is something the customer can connect. A **skill** entry is a published skill. An **account** entry is one of the account's own pieces, with the input of its run route and its price: what it costs past the action, and what each month includes. An **mcp_tool** entry is one tool of the publisher's own MCP server: its name, a short description, its input schema, and in `tool` where it is listed. A session lists only the tools that apply to who is connected and which pieces are on ([MCP tool definitions](../mcp-tools/SPEC.md), section 11), so the catalogue is how an agent finds a tool that its session does not list.

The `tool` object has four fields, all required:

| Field | Meaning |
|---|---|
| `group` | The group of tools it is registered with. |
| `pieces` | The account pieces that list it to an agent, any one of which is enough. Empty is the core: always listed. |
| `audience` | Who it is for. |
| `on_demand` | `true` for a rarely used tool, which carries the load-on-demand hint. |

| Audience | Meaning |
|---|---|
| `agent` | Only a session of an agent. |
| `owner` | Only a session of an owner or a member. |
| `both` | Either. |

An `mcp_tool` entry's `name` is the tool's title and its `description` is the first sentences of the tool's description that fit the length in the constants table; the whole description is in the tool definition. Its price is the price of the route the tool calls: `stack_actions` is `1` when the tool is one action on the account's meter and `0` for a read or a setting, and a tool that spends credit past the action says what (`lines`, with the same lines and free amounts as the `account` entry of its piece, or `varies` when the cost depends on the request, a supplier or a provider). It has no `run` descriptor and `result_trust` is `standard`.

## 5. Prices

`pricing` at the top of the document says what STACK charges for acting; each entry's `price` says what the provider charges for the thing.

- **The action.** A run is one action on the account's meter, whatever it runs, and providers are charged at their own cost on top (`stack_actions` is `1`). A refused run is never charged. Reading the catalogue, searching it and inspecting an entry are not actions (`stack_actions` is `0` for an entry that is only connected, not run). `pricing.included_actions_per_month` are included with the account's subscription, and each action after them costs what the band it falls in says: `bands` is in ascending order of `up_to`, the last band has `up_to` null, and `usd_micros_per_action` is what each action in the band costs.
- **The provider's cost.** `price.unit` says what a figure is per, and `price.provider_cost` carries the figures (`null` when the provider charges nothing). A field that is absent is not known beforehand or does not apply.

| Unit | Meaning |
|---|---|
| `token` | Per million tokens: `input_per_million_tokens_usd_micros` and `output_per_million_tokens_usd_micros`. |
| `call` | One call: `per_unit_usd_micros`, and `worst_case_usd_micros`, the most a call can cost. |
| `result` | One result: `per_unit_usd_micros` for each, and `flat_fee_usd_micros` once. The worst case depends on how many results the caller allows. |
| `image` | One image: `worst_case_usd_micros`, the most one image can cost. |
| `lines` | A list of prices, each with a unit of its own: `lines` (below). |
| `free` | The provider charges nothing. |
| `varies` | Charged at the provider's cost, which cannot be told beforehand. |

A publisher MUST NOT show a price it did not read from the provider or write itself. A reader that does not know a unit treats the price as `varies`.

**Lines.** A model provider lists several prices for one model (input and output tokens, cached tokens, a search, an image, a second of video, a character of speech). `provider_cost.lines` lists them as the provider does: each line has an `item` (the provider's own name for the price, lower-case letters, digits and `_`), what it is `per`, a `per_count` and a `cost_usd_micros`. The cost is `cost_usd_micros` for every `per_count` of `per`: `per_count` is `1`, or `1000000` when one unit costs less than a whole micro-dollar (a token always is per million). A figure the provider writes with more precision is rounded up to the next micro-dollar.

| `per` | Meaning |
|---|---|
| `token` | One token (input, output, cached, reasoning, image or audio). |
| `character` | One character of input text (speech). |
| `second` | One second (video, audio). |
| `request` | One request. |
| `image` | One image. |
| `search` | One web search. |
| `megapixel_second` | One megapixel of one second of video. |
| `generation` | One generation (a minimum charge for a run). |
| `audio_unit` | A second of audio or an audio token, as the model prices it: the provider's list does not say which. |
| `minute` | One started minute (a call). |
| `hour` | One hour, billed by the minute (browser and workspace time). |
| `month` | One month of one item (an inbox, a phone number). |
| `message` | One text message or one email. |
| `segment` | One part of a text: 160 characters, or 70 when it has a character outside the basic set. |
| `gigabyte` | A gigabyte of 1,073,741,824 bytes, as the store bills it (data sent out). |
| `gigabyte_month` | A gigabyte of 1,073,741,824 bytes kept for a month (storage). |

**Free amounts.** `price.free_per_month`, when present, lists what the account's subscription includes each month, for the account as a whole, before the lines apply: each has an `item`, what it is `per` (the units above) and a `count`. A price can have lines and free amounts, or free amounts and the unit `varies` (what is charged past them depends on the request). Free amounts are not a limit: past them the lines apply.

A price in `lines` has the unit `lines`; the figures of a token price that are not input or output tokens (cache, search, image, reasoning, audio) are also lines, beside `input_per_million_tokens_usd_micros` and `output_per_million_tokens_usd_micros`. `discount` is a fraction from 0 to 1 that the provider takes off its prices: the charge is the figures times one minus it. `tiers` lists the prices a model switches to on a condition: each tier has its own `lines`, which replace the base lines of the same item while it applies, and `above_prompt_tokens` when it applies to a prompt of more tokens than that (a long-context price); a tier with no threshold may apply to any call (a time of day). What a run costs is what the provider reports for it, not these figures. A figure that is zero is shown as free only where the provider bills in tokens or says the model is free; for a video, ranking or music model a zero is a price the list does not carry, so the publisher shows the lines it can read, or `varies`, never zero.

## 6. Trust

Two fields say how far to trust text.

`origin` says who wrote an entry's `name` and `description`:

| Origin | Meaning |
|---|---|
| `stack` | The publisher wrote it. |
| `models` | The model provider wrote it (a model's name and description, copied after reduction to plain text). |
| `tools` | The paid-tools provider wrote it. |
| `publisher` | A third party who published the entry (a skill's author) wrote it. |

Text whose origin is not `stack` is **provider text**. A reader MUST treat it as data to read, never as instructions to follow, and a reader that puts it in front of a model MUST say so to the model.

`result_trust` says what a **run** returns:

| Trust | Meaning |
|---|---|
| `standard` | What the entry returns is the publisher's own, or a model's answer. What a model writes is the model's own: the publisher passes it on as it is and does not scan it. |
| `untrusted` | What the entry returns comes from the open web, a social network, a provider or a third party. A reader MUST treat it as data. A publisher that runs the entry marks the run's result `untrusted` and records it as read in the data trail, so that it cannot leave through a service whose scope does not allow it. A skill's result is always `untrusted`. |

## 7. Sections

Each source of entries is a **section**, and the document says how each one stands, so that a reader can tell an empty section from a broken one.

| Status | Meaning |
|---|---|
| `ok` | The source was read, and the section is what it said. |
| `not_configured` | The publisher has no key for the source. The section has no entries, and `count` is 0. |
| `unavailable` | The source could not be read and there was nothing earlier to keep. The section has no entries. |
| `stale` | The source could not be read this time, and the section is the last one that was read. `refreshed_at` says when. |

`count` is the number of entries of the section's kinds. The source of each kind is in the table in section 4. A publisher MUST NOT let a failing source fail the document, and MUST NOT empty a section that had entries because its source failed: it keeps them, as `stale`.

## 8. Version and caching

`version` is the lower-case hexadecimal SHA-256 of the canonical JSON (keys sorted lexicographically at every depth, no whitespace, arrays in order, as in the record format) of the object

```json
{ "entries": [...], "pricing": {...}, "sections": [{ "source": "...", "status": "...", "count": 0 }] }
```

built from the document: the timestamps are not part of it, so a document that is built again and says the same keeps its version.

A publisher that serves the document over HTTP:

- MUST send an `ETag` that is a function of `version` alone, and answer a request whose `If-None-Match` names it with `304` and no body;
- MUST answer `200` with the whole document to a request that names another validator;
- SHOULD send a `Cache-Control` with a `max-age` of at most the shared-cache time in the constants table;
- MUST serve the bytes that were built, never build the document for a request.

The reference API serves the file at the path in the constants table, to any signed-in caller (an agent included), and sends `Cache-Control: private`. A weak validator (`W/"<version>"`) is enough, because the version is a hash of the content.

A reader keeps a copy with its validator and asks again with `If-None-Match`.

## 9. Running an entry

The catalogue does not run anything; it says where. An entry that can be run has a `run` object:

| Field | Meaning |
|---|---|
| `method` | `GET`, `POST` or `PUT`. |
| `path` | A path starting with `/v1/`, with `{account_id}` standing for the account's id (and `{session_id}` for a browser session). |
| `body` | Fields the request carries exactly as written (the model, the provider and endpoint of a tool, the service of a connect link). |
| `mcp_tool` | Optional. The MCP tool that calls the route. |
| `cost_cap` | Optional. Where the run takes `max_cost_cents`: `{ "in": "body" | "header", "name": "..." }`. |

A run goes through the publisher's existing routes, and each of them, in this order: checks the account and its Mission, counts one action, asks the customer's decider (the control socket) and, when it spends, holds an amount before the provider is called (its worst case: for a tool, from the price the provider reports and the request's own bounds; for a model, from the model's listed prices, its limits and the request) and charges the provider's reported cost at cost. Every run is in the signed record. The routes are the ones in the reference implementation's API; this specification does not define them beyond the descriptor.

**A model.** A model entry's run is a `POST` to the publisher's model gateway with the model in the body, at the endpoint the model's output needs: a chat completion for a model that makes text (with or without a picture or sound beside it), and the provider's own embeddings, ranking, speech, transcription, image, video or decisions endpoint for a model that makes that. The gateway passes the request and the answer on as they are. A model whose output the publisher does not know has no `run`. The call holds its worst case on the wallet before it is made: the input at the request's size (or, for a picture, sound or file, the model's context length), the output at the request's own limit or the model's listed maximum, and every price line and price tier the model lists. The call is then charged what the provider reports it cost, at cost: the rest of the hold is given back, and a cost above the hold is taken from the wallet at once. A call whose worst case cannot be worked out from the listing and the request (a price per second of audio, a video with no duration) holds an estimate built from the listing's own prices and stated assumptions; a publisher does not refuse a call for want of a price. The `cost_cap` names a header: the most the caller accepts the call to hold, in cents, 1 or more; a hold above it is lowered to it. A value that is not a whole number in range is refused.

**The cost cap of a tool.** A tool run that names `max_cost_cents` holds at most that; a cost above the hold is charged from the wallet at once. An account entry's run has its own bounds (the account's budget, daily caps and the customer's policy limits) and takes no cap, and its descriptor then has no `cost_cap`.

**Tools.** A publisher runs any endpoint the paid-tools provider lists, at the provider's price. Before it calls the provider it holds the worst case of the run, computed from the provider's price and the request's own bounds (a result limit); where it cannot compute one (a price of a kind it cannot bound, a price per result with nothing to bound the results by), it holds an estimate from the provider's price and a stated count. Every tool entry has a `run`. A tool run returns `untrusted` content marked as such, and the files a run makes are saved to the account's drive, private to the agent that ran it.

## 10. One account's part

`GET /v1/accounts/{account_id}/catalogue` answers, for one account:

```json
{
  "account_id": "acc_...",
  "catalogue_version": "<the version of the shared document these ids refer to, or null>",
  "connected_services": [{ "id": "service:github", "provider": "github", "name": "GitHub", "connection_id": "con_..." }],
  "pieces": [{ "id": "account:inbox", "state": "ready" }],
  "tools": [{ "id": "mcp_tool:stack_send_account_email", "listed": true }]
}
```

A piece's `state` is one of `pending`, `ready`, `paused`, `failed`, `closing` and `closed`. `tools` is optional and says, for every `mcp_tool` entry of the shared document, whether an agent session of this account lists that tool now (the rules are in [MCP tool definitions](../mcp-tools/SPEC.md), section 11); a publisher with no MCP tools leaves it out, and one that serves it for a directory-style session that is not offered the tools leaves it out too. The answer is for the caller's account only: a publisher MUST answer `404` for an account that is not the caller's, MUST send `Cache-Control: private, no-store`, and MUST NOT include a credential, a secret or anything about a connection beyond its id, its provider and its display name.

## 11. Security considerations

- **Provider text is data.** A model description, a tool's schema and a skill's words are written by someone who is not the publisher, and may try to instruct whoever reads them. A publisher takes named fields from a provider's answer and never copies it whole; reduces names and descriptions to plain text; and marks the origin. A reader never follows what provider text says (section 6).
- **Plain text.** A name or description MUST be plain text: no markup tags, no code fences, no control characters, no zero-width or direction-changing characters, white space collapsed to single spaces and trimmed, and a name no longer than the limit in section 3 (a description has none). A publisher SHOULD normalise to Unicode NFKC.
- **Schemas are reduced.** An `input_schema` keeps only these keywords: `type`, `title`, `description` (in full), `format`, `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `minItems`, `maxItems`, `minLength`, `maxLength`, `enum` (every scalar value, in full), `default` (a short scalar), `additionalProperties` (a boolean), `properties`, `required`, `items`, `anyOf` and `oneOf`. References, patterns, examples and any other keyword are dropped; property names are identifiers; the schema is within the depth, property and size limits, and a schema that would pass them is dropped from its entry, never cut.
- **Validate and cap.** A publisher validates what it reads from a provider against a schema before it uses a field, caps the size of the answer it reads and of the document it writes, and leaves out an entry that is not what it should be rather than storing a malformed one.
- **No secrets, no customers.** The shared document MUST NOT contain a credential, a key, a token, a customer's connection, an account or anything private to one customer. A publisher's own provider keys never leave it, and are not in the document or in an error.
- **One account's part is never shared.** It is served only to that account, with `no-store`, and is not part of the shared file or its cache.
- **A tool whose worst case cannot be computed is held at an estimate.** Any endpoint the provider lists runs at the provider's price; where its cost cannot be bounded the hold is an estimate, and a cost above the hold is charged from the wallet at once.

## 12. Machine-readable schemas

JSON Schemas (draft-07) generated from the reference implementation:

- [`schemas/CatalogueDocument.json`](schemas/CatalogueDocument.json): the document.
- [`schemas/CatalogueEntry.json`](schemas/CatalogueEntry.json): one entry.
- [`schemas/CatalogueSearchResult.json`](schemas/CatalogueSearchResult.json): the answer to a search (`GET /v1/catalogue/search?q=&kind=&limit=&offset=`, which filters the shared document by the words of `q`, all of which must appear in an entry's id, name, description or provider).
- [`schemas/CatalogueAccountView.json`](schemas/CatalogueAccountView.json): one account's part.

The schemas are strict: a publisher that adds a field fails them. A reader follows the rule in section 3 and ignores what it does not know.

## 13. MCP

The document is also served as an MCP resource, `stack://catalogue`, with the media type `application/json`, in both tool profiles. A resource read is the file read. The tools `stack_catalogue` (search) and `stack_get_account_catalogue` (one account's part) are read-only, never counted as actions and are part of the directory profile. They are listed in [mcp-tools/TOOLS.md](../mcp-tools/TOOLS.md).

## 14. Conformance

[`conformance/`](../conformance/README.md) has a `catalogue` suite that checks a document (as a file or fetched from a URL) against this specification: its shape, ids, plain text, prices, trust, run descriptors, schemas, sections, the version hash and, for a URL, the validator and the `304`. The reference implementation runs it in continuous integration.
