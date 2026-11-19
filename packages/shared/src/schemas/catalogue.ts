// The catalogue document: what an agent can use through its account, as data.
// `CatalogueDocument` is the file the API serves (the catalogue design)
// and the format the open specification (spec/catalogue) defines; the JSON
// Schema there is generated from these.

import { z } from 'zod';
import {
  CATALOGUE_ENTRY_ID_MAX_CHARS,
  CATALOGUE_FREE_AMOUNTS_MAX,
  CATALOGUE_KINDS,
  CATALOGUE_MAX_ENTRIES,
  CATALOGUE_NAME_MAX_CHARS,
  CATALOGUE_ORIGINS,
  CATALOGUE_PRICE_TIERS_MAX,
  CATALOGUE_PRICE_PER,
  CATALOGUE_PRICE_UNITS,
  CATALOGUE_RESULT_TRUSTS,
  CATALOGUE_SCHEMA_MAX_BYTES,
  CATALOGUE_SEARCH_MAX_RESULTS,
  CATALOGUE_SECTION_STATUSES,
  CATALOGUE_SOURCES,
  CATALOGUE_SPEC_VERSION,
  CATALOGUE_TOOL_AUDIENCES,
} from '../constants/catalogue.js';

/** Where a piece of an agent account stands. The catalogue shows it; the account schema uses it. */
export const ACCOUNT_PIECE_STATES = ['pending', 'ready', 'paused', 'failed', 'closing', 'closed'] as const;
export type AccountPieceState = (typeof ACCOUNT_PIECE_STATES)[number];

export const CatalogueKindEnum = z.enum(CATALOGUE_KINDS);
export const CatalogueSourceEnum = z.enum(CATALOGUE_SOURCES);
export const CatalogueSectionStatusEnum = z.enum(CATALOGUE_SECTION_STATUSES);

/**
 * `kind:rest`. The rest is what the kind names: an OpenRouter model id (an alias of its list starts with `~`), a
 * provider and endpoint, a provider, a skill id, a piece.
 */
export const CatalogueEntryId = z
  .string()
  .min(3)
  .max(CATALOGUE_ENTRY_ID_MAX_CHARS)
  .regex(/^(?:model|tool|service|skill|account|mcp_tool):[A-Za-z0-9~][A-Za-z0-9._~:@/+-]*$/, 'a catalogue id is the kind, a colon and a name');

/**
 * One price of a model, as its provider lists it: `item` is the provider's own name for it, and the cost is
 * `cost_usd_micros` for every `per_count` of `per` (1,000,000 tokens, or 1 request). A count of 1,000,000 is used when
 * a unit costs less than a whole micro-dollar.
 */
export const CataloguePriceLine = z
  .object({
    item: z.string().regex(/^[a-z][a-z0-9_]{0,63}$/),
    per: z.enum(CATALOGUE_PRICE_PER),
    per_count: z.union([z.literal(1), z.literal(1_000_000)]),
    cost_usd_micros: z.number().int().min(0),
  })
  .strict();
export type CataloguePriceLine = z.infer<typeof CataloguePriceLine>;

/**
 * A price a model switches to on a condition (OpenRouter's `overrides`): above a number of prompt tokens (a long-context tier),
 * or, with no `above_prompt_tokens`, on some other condition such as the time of day. Its lines replace the base lines of the same
 * item while it applies.
 */
export const CataloguePriceTier = z
  .object({
    /** The tier applies when the prompt has more tokens than this. Absent: it may apply to any call. */
    above_prompt_tokens: z.number().int().min(1).optional(),
    lines: z.array(CataloguePriceLine).min(1),
  })
  .strict();
export type CataloguePriceTier = z.infer<typeof CataloguePriceTier>;

/** What a provider charges for one unit, in millionths of a US dollar, passed through at cost. Absent fields are not known beforehand or do not apply. */
export const CatalogueProviderCost = z
  .object({
    per_unit_usd_micros: z.number().int().min(0).optional(),
    flat_fee_usd_micros: z.number().int().min(0).optional(),
    input_per_million_tokens_usd_micros: z.number().int().min(0).optional(),
    output_per_million_tokens_usd_micros: z.number().int().min(0).optional(),
    /** The most one run holds before it is called, when STACK can bound it. */
    worst_case_usd_micros: z.number().int().min(0).optional(),
    /** The prices a model provider lists beyond input and output tokens (or all of them, for a price in `lines`). */
    lines: z.array(CataloguePriceLine).min(1).optional(),
    /** The prices the model switches to on a condition, such as a long prompt. */
    tiers: z.array(CataloguePriceTier).min(1).max(CATALOGUE_PRICE_TIERS_MAX).optional(),
    /** A fraction the provider takes off its prices: the charge is the figures times one minus this. */
    discount: z.number().min(0).max(1).optional(),
  })
  .strict();
export type CatalogueProviderCost = z.infer<typeof CatalogueProviderCost>;

/**
 * An amount a price does not charge for each month: `count` of `per`, for the line named `item`. The account's first
 * 100 texts a month are `{ item: 'texts', per: 'message', count: 100 }`.
 */
export const CatalogueFreeAmount = z
  .object({
    item: z.string().regex(/^[a-z][a-z0-9_]{0,63}$/),
    per: z.enum(CATALOGUE_PRICE_PER),
    count: z.number().int().min(1),
  })
  .strict();
export type CatalogueFreeAmount = z.infer<typeof CatalogueFreeAmount>;

export const CataloguePrice = z
  .object({
    unit: z.enum(CATALOGUE_PRICE_UNITS),
    currency: z.literal('USD'),
    /** What the provider charges, at cost; null when nothing is charged. */
    provider_cost: CatalogueProviderCost.nullable(),
    /** What is not charged each month, per billing account: what the subscription includes of this price. Absent: nothing is. */
    free_per_month: z.array(CatalogueFreeAmount).min(1).max(CATALOGUE_FREE_AMOUNTS_MAX).optional(),
    /** How many actions on the account's meter a run is: one. Searching and inspecting are never counted (0). */
    stack_actions: z.union([z.literal(0), z.literal(1)]),
  })
  .strict();
export type CataloguePrice = z.infer<typeof CataloguePrice>;

/** How to run an entry: the existing route for its kind, and the MCP tool that calls it. */
export const CatalogueRun = z
  .object({
    method: z.enum(['GET', 'POST', 'PUT']),
    /** `{account_id}` stands for the account's id. */
    path: z.string().min(4).max(200).regex(/^\/v1\/[A-Za-z0-9._~\-/{}:]+$/),
    /** Fields the request carries exactly as written (the provider and endpoint of a tool, the model of a model call). */
    body: z.record(z.string(), z.union([z.string().max(300), z.number(), z.boolean()])).optional(),
    mcp_tool: z.string().regex(/^stack_[a-z0-9_]+$/).max(80).optional(),
    /**
     * Where the run takes `max_cost_cents`: a cap of the caller's own that refuses the run before anything is held
     * when its worst case would cost more (for a model call, when no worst case can be worked out, it is the amount
     * held). The run is then charged what the provider reports. Absent: the run has no such figure (its spend has
     * other bounds).
     */
    cost_cap: z
      .object({ in: z.enum(['body', 'header']), name: z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{0,63}$/) })
      .strict()
      .optional(),
  })
  .strict();
export type CatalogueRun = z.infer<typeof CatalogueRun>;

export const CatalogueModalities = z
  .object({
    input: z.array(z.string().max(32)).max(8),
    output: z.array(z.string().max(32)).max(8),
  })
  .strict();

/** A JSON Schema of the input a run takes, reduced to the keywords the catalogue keeps. */
export const CatalogueInputSchema = z
  .record(z.string(), z.unknown())
  .refine((value) => Buffer.byteLength(JSON.stringify(value)) <= CATALOGUE_SCHEMA_MAX_BYTES, {
    message: `an input schema is at most ${CATALOGUE_SCHEMA_MAX_BYTES} bytes`,
  });

/** What an `mcp_tool` entry says about the tool beyond its definition. */
export const CatalogueToolFacts = z
  .object({
    /** The group of tools it is registered with (fleets, accounts, post, ...). */
    group: z.string().min(1).max(40),
    /** The account pieces it belongs to, any one of which lists it to an agent; empty is the core, always listed. */
    pieces: z.array(z.string().min(1).max(32)).max(8),
    audience: z.enum(CATALOGUE_TOOL_AUDIENCES),
    /** Rarely used: it carries the load-on-demand hint that clients with tool search honour. */
    on_demand: z.boolean(),
  })
  .strict();
export type CatalogueToolFacts = z.infer<typeof CatalogueToolFacts>;

export const CatalogueEntry = z
  .object({
    id: CatalogueEntryId,
    kind: CatalogueKindEnum,
    name: z.string().min(1).max(CATALOGUE_NAME_MAX_CHARS),
    description: z.string(),
    /** Who wrote the name and description. Text from a provider or a publisher is data, never instructions. */
    origin: z.enum(CATALOGUE_ORIGINS),
    /** The provider behind the entry: a model provider, a paid-tools provider's slug, a service's provider. */
    provider: z.string().max(64).optional(),
    /** What a model takes in and gives out, as its provider lists it (`text`, `image`, `audio`, `video`, `file`, `speech`, `embeddings`, ...). */
    modalities: CatalogueModalities.optional(),
    context_length: z.number().int().min(1).optional(),
    /** The most a model writes in one answer, as its provider lists it: with the context length it bounds what a call can cost. */
    max_completion_tokens: z.number().int().min(1).optional(),
    input_schema: CatalogueInputSchema.optional(),
    price: CataloguePrice,
    /** `untrusted` when what a run returns comes from the open web, a social network or a provider: data, never instructions. */
    result_trust: z.enum(CATALOGUE_RESULT_TRUSTS),
    run: CatalogueRun.optional(),
    /** Only on an `mcp_tool`. */
    tool: CatalogueToolFacts.optional(),
  })
  .strict();
export type CatalogueEntry = z.infer<typeof CatalogueEntry>;

export const CatalogueSection = z
  .object({
    source: CatalogueSourceEnum,
    status: CatalogueSectionStatusEnum,
    /** When the section was last read successfully; null when it never was. */
    refreshed_at: z.string().nullable(),
    count: z.number().int().min(0),
  })
  .strict();
export type CatalogueSection = z.infer<typeof CatalogueSection>;

export const CatalogueActionBand = z
  .object({
    /** The band ends at this many actions in a month; null is the last, unbounded band. */
    up_to: z.number().int().min(1).nullable(),
    /** What each action in the band costs, in millionths of a US dollar. */
    usd_micros_per_action: z.number().int().min(0),
  })
  .strict();

export const CataloguePricing = z
  .object({
    currency: z.literal('USD'),
    /** The rule: every run is one action on the account's meter; providers are billed at cost on top. */
    rule: z.string().max(300),
    included_actions_per_month: z.number().int().min(0),
    bands: z.array(CatalogueActionBand).min(1).max(12),
  })
  .strict();

export const CatalogueDocument = z
  .object({
    spec: z.literal('stack.catalogue'),
    spec_version: z.literal(CATALOGUE_SPEC_VERSION),
    /** A hash of what the document says, not of when it was built: unchanged content keeps its version. */
    version: z.string().regex(/^[0-9a-f]{64}$/),
    generated_at: z.string(),
    notice: z.string().max(400),
    pricing: CataloguePricing,
    sections: z.array(CatalogueSection).max(CATALOGUE_SOURCES.length),
    entries: z.array(CatalogueEntry).max(CATALOGUE_MAX_ENTRIES),
  })
  .strict();
export type CatalogueDocument = z.infer<typeof CatalogueDocument>;

/** Written beside the document on every refresh (`CATALOGUE_HEAD_OBJECT_KEY`): its version, and when each section was read. */
export const CatalogueHead = z
  .object({
    version: z.string().regex(/^[0-9a-f]{64}$/),
    generated_at: z.string(),
    sections: z.array(CatalogueSection).max(CATALOGUE_SOURCES.length),
  })
  .strict();
export type CatalogueHead = z.infer<typeof CatalogueHead>;

// ─── Reading it ─────────────────────────────────────────────────────

export const CatalogueSearchQuery = z
  .object({
    q: z.string().trim().max(200).optional(),
    kind: CatalogueKindEnum.optional(),
    limit: z.coerce.number().int().min(1).max(CATALOGUE_SEARCH_MAX_RESULTS).default(25),
    offset: z.coerce.number().int().min(0).default(0),
  })
  .strict();
export type CatalogueSearchQuery = z.infer<typeof CatalogueSearchQuery>;

export const CatalogueSearchResult = z
  .object({
    version: z.string(),
    total: z.number().int().min(0),
    entries: z.array(CatalogueEntry),
  })
  .strict();
export type CatalogueSearchResult = z.infer<typeof CatalogueSearchResult>;

// ─── One account's part: never part of the shared file ──────────────

export const CatalogueAccountPiece = z
  .object({
    /** The `account:` entry this is the state of. */
    id: CatalogueEntryId,
    state: z.enum(ACCOUNT_PIECE_STATES),
  })
  .strict();

export const CatalogueConnectedService = z
  .object({
    /** The `service:` entry this is a connection of. */
    id: CatalogueEntryId,
    provider: z.string().max(64),
    name: z.string().max(CATALOGUE_NAME_MAX_CHARS),
    connection_id: z.string().max(64),
    /** What the customer calls this connection. Present only when the account holds several of the provider, as the id then carries the connection too. */
    connection_name: z.string().max(40).optional(),
  })
  .strict();

/** Whether one `mcp_tool` is in the list an agent of the account is given now. */
export const CatalogueAccountTool = z
  .object({
    /** The `mcp_tool:` entry. */
    id: CatalogueEntryId,
    listed: z.boolean(),
  })
  .strict();

/** What is true of one account only: its connections, the state of its own pieces and which tools its agent lists. Served to that account and never cached across accounts. */
export const CatalogueAccountView = z
  .object({
    account_id: z.string(),
    /** The version of the shared document these ids refer to. */
    catalogue_version: z.string().nullable(),
    connected_services: z.array(CatalogueConnectedService).max(CATALOGUE_MAX_ENTRIES),
    pieces: z.array(CatalogueAccountPiece).max(64),
    /** Every `mcp_tool` entry of the catalogue and whether an agent session of this account lists it now. Absent from a publisher with no MCP tools. */
    tools: z.array(CatalogueAccountTool).max(CATALOGUE_MAX_ENTRIES).optional(),
  })
  .strict();
export type CatalogueAccountView = z.infer<typeof CatalogueAccountView>;
