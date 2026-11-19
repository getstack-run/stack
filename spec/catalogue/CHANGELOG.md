# Changelog: STACK Catalogue

This specification follows semantic versioning. A change that makes a previously conforming publisher or reader non-conforming is a major version; a new optional field, a new kind of entry or a new section is a minor version; a wording fix is a patch.

## 1.4.0 - 2026-11-06

- Every description is kept in full: an entry's description (the 400-character limit is gone), a property description in an input schema (the 200-character limit is gone) and every enum value (the limit of 50 values of at most 100 characters is gone), for every entry, STACK's own included. Only a name keeps a length limit. A loosening: a reader that follows section 3 keeps working. A validator built from the 1.3.0 JSON Schemas rejects a longer description; use the 1.4.0 schemas.
- The conformance kit's `catalogue` suite no longer checks the removed limits.

## 1.3.0 - 2026-11-01

- A price may list any number of lines, in `provider_cost.lines` and in each tier (the format capped a list at 64). More than 16 price `tiers` are still shown as `varies`. Text a provider wrote for a tool entry (its description and the text of its input schema) is shown in full, and no enum or default value is dropped for what it says. Both are loosenings: a reader that follows section 3 keeps working.

## 1.2.0 - 2026-10-30

- A model entry can be any model a model provider lists, and shows what the provider charges for it: a new optional `lines` list in `provider_cost` (each line has an `item`, what it is `per`, a `per_count` and a `cost_usd_micros`), a new price unit `lines`, and an optional `discount`. A price the provider does not state in a unit the list carries is `varies`, never zero.
- An id may start with `~` after the colon (a provider's alias of a model).
- A price can carry `tiers` in `provider_cost`: prices the model switches to on a condition, each with its own `lines` and, for a long-prompt price, `above_prompt_tokens` (the tier applies when the prompt has more tokens than that). A tier with no threshold may apply to any call (a time window).
- A model entry has an optional `max_completion_tokens`, the most tokens the model writes in one answer, which with `context_length` and the price lines bounds what a call can cost.
- A model's `run` names the endpoint its output needs, and its `cost_cap` header is the most the caller accepts the call to hold: a hold above it is lowered to it. A call whose worst case cannot be worked out holds an estimate from the listing's own prices. The call is charged what the provider reports.
- A tool's `cost_cap` (`max_cost_cents`) is the most the run holds: a hold above it is lowered to it, and a cost above the hold is charged from the wallet at once. It no longer refuses a run.
- The `image` unit and `worst_case_usd_micros` stay in the format; a model is no longer priced that way.
- A tool entry can be any endpoint the paid-tools provider lists, in the provider's own words: its `origin` is `tools`, its `name` is the endpoint path, and a price of a kind the publisher does not read is `varies` with no figure. Every tool entry has a `run`; one whose cost the publisher cannot bound holds an estimate. A publisher no longer limits the tools it runs to a vetted list (every endpoint runs, at a worst case or an estimate).
- The bounds grow so every endpoint a run request can name fits: an entry id is at most 330 characters (was 200), a document has at most 10,000 entries (was 5,000) and is at most 64 MiB (was 12 MiB).
- An `account` entry carries the price of its piece (the lines of what it costs past the action, from the same figures the meters charge) and the `input_schema` of its run route, where before it was `varies` with no input. A price that depends on the request or on a supplier (a letter, a quote, a model, a skill) stays `varies`.
- An `mcp_tool` entry carries the price of the route its tool calls: `stack_actions` `1` for a tool that is one action on the account's meter, and for one that spends credit, the lines and free amounts of its piece, or `varies`. Before, every tool said free with no action.
- New units for a price line (`per`): `minute`, `hour`, `month`, `message`, `segment`, `gigabyte` and `gigabyte_month`.
- A price has an optional `free_per_month`: a list of `item`, `per` and `count` for what the account's subscription includes each month before the lines apply.
- The new fields are optional and additive, so `spec_version` stays `1` and a reader that follows section 3 (ignores what it does not know, and reads an unknown unit as `varies`) is not stopped by them. A validator built from the 1.1.0 JSON Schemas is strict and rejects them; use the 1.2.0 schemas.

## 1.1.0 - 2026-10-23

- A new kind of entry, `mcp_tool`: one entry for every tool of the publisher's own MCP server, with its short description, its input schema and a `tool` object (group, pieces, audience, and whether it is rarely used). A reader that does not know the kind ignores the entry, as section 3 has always said.
- A new optional `tools` list in one account's part: whether an agent session of the account lists each tool now.
- Nothing that conformed to 1.0.0 stops conforming.

## 1.0.0 - 2026-10-22

Initial public release.

- The catalogue document: its header, pricing, sections and entries, and the five kinds of entry (models, tools, services, skills and the account's own pieces).
- Prices at the provider's cost, and one action per run on the account's meter.
- Provider text as data: origins, result trust, plain-text names and descriptions, and the reduced input schema.
- The version hash, the validator and the conditional read of the file.
- How an entry is run (the descriptor), the per-run cost cap and the rule that only listed tools run.
- One account's part, served to that account only.
- The MCP resource `stack://catalogue` and the JSON Schemas of the document, an entry, a search answer and an account's part.
