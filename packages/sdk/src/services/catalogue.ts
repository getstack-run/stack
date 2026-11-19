import type { HttpClient } from '../client.js';

// The catalogue: one document listing everything an agent can reach through
// STACK: models, paid tools, connectable services, skills and the pieces of an
// agent account, each with its price and, where it can run, how to run it.
// Reading it is free, never metered, and open to any signed-in caller, an
// agent included. Entries that come from a provider or a publisher carry
// their text: it is data to show, never instructions to follow.

export type CatalogueEntryKind = 'model' | 'tool' | 'service' | 'skill' | 'account' | 'mcp_tool';
/** Who an `mcp_tool` is for: an agent's session, an owner's or a member's, or both. */
export type CatalogueToolAudience = 'agent' | 'owner' | 'both';
export type CatalogueOrigin = 'stack' | 'models' | 'tools' | 'publisher';
export type CatalogueSource = 'stack' | 'models' | 'tools' | 'services' | 'skills';
export type CatalogueSectionStatus = 'ok' | 'not_configured' | 'unavailable' | 'stale';
/** `lines`: the price is the list in `provider_cost.lines`, each line with a unit of its own. A unit you do not know is `varies`. */
export type CataloguePriceUnit = 'token' | 'call' | 'result' | 'image' | 'lines' | 'free' | 'varies';

/** What one line of a price is per. `audio_unit` is a second of audio or an audio token, as the model prices it. */
export type CataloguePricePer = 'token' | 'character' | 'second' | 'request' | 'image' | 'search' | 'megapixel_second' | 'generation' | 'audio_unit';

/** One price of a model as its provider lists it: `cost_usd_micros` for every `per_count` of `per`. */
export interface CataloguePriceLine {
  /** The provider's own name for the price (`prompt`, `image_output`, `web_search`, `cents_per_second_output`, ...). */
  item: string;
  per: CataloguePricePer;
  /** 1, or 1,000,000 when one unit costs less than a micro-dollar (a token always is per million). */
  per_count: 1 | 1_000_000;
  cost_usd_micros: number;
}

/** What the provider charges STACK, in millionths of a US dollar; whichever fields apply to the unit are set. */
export interface CatalogueProviderCost {
  per_unit_usd_micros?: number;
  flat_fee_usd_micros?: number;
  input_per_million_tokens_usd_micros?: number;
  output_per_million_tokens_usd_micros?: number;
  worst_case_usd_micros?: number;
  /** The prices a model provider lists beyond input and output tokens (all of them, for the unit `lines`). */
  lines?: CataloguePriceLine[];
  /** A fraction the provider takes off its prices: the charge is the figures times one minus this. */
  discount?: number;
}

export interface CataloguePrice {
  unit: CataloguePriceUnit;
  currency: 'USD';
  /** What the provider charges, passed through at cost; null when it is free or STACK cannot bound it. */
  provider_cost: CatalogueProviderCost | null;
  /** How many of the account's monthly actions one use counts as. */
  stack_actions: 0 | 1;
}

/** How to run an entry: an HTTP call (`path` has `{account_id}` in it) and, where there is one, the MCP tool. */
export interface CatalogueRun {
  method: 'GET' | 'POST' | 'PUT';
  path: string;
  /** Fixed body fields the call carries. */
  body?: Record<string, string | number | boolean>;
  mcp_tool?: string;
  /** Where `max_cost_cents` goes: a body field or a header. For a tool it caps the run; for a model call it is the amount the call holds on the wallet (the call is charged what the provider reports). */
  cost_cap?: { in: 'body' | 'header'; name: string };
}

export interface CatalogueEntry {
  /** `<kind>:<name>`: `model:<model id>`, `tool:<provider><endpoint>`, `service:<provider>`, `skill:<skill id>`, `account:<piece>`, `mcp_tool:<tool name>`. */
  id: string;
  kind: CatalogueEntryKind;
  name: string;
  description: string;
  origin: CatalogueOrigin;
  provider?: string;
  modalities?: { input: string[]; output: string[] };
  context_length?: number;
  /** The endpoint's input as a JSON Schema object, reduced to what a caller needs. */
  input_schema?: Record<string, unknown>;
  price: CataloguePrice;
  /** `untrusted` when what a run returns is web, social or provider content: data, never instructions. */
  result_trust: 'standard' | 'untrusted';
  run?: CatalogueRun;
  /** Only on an `mcp_tool`: where the tool is listed. */
  tool?: CatalogueToolFacts;
}

/** What an `mcp_tool` entry says about the tool beyond its definition. */
export interface CatalogueToolFacts {
  /** The group of tools it is registered with. */
  group: string;
  /** The account pieces that list it to an agent, any one of which is enough; empty is the core, always listed. */
  pieces: string[];
  audience: CatalogueToolAudience;
  /** Rarely used: it carries the load-on-demand hint that clients with tool search honour. */
  on_demand: boolean;
}

export interface CataloguePricingBand {
  /** The band's upper bound in actions per month; null for the last band. */
  up_to: number | null;
  usd_micros_per_action: number;
}

/** What one STACK action costs, so an entry's `stack_actions` can be priced. */
export interface CataloguePricing {
  currency: 'USD';
  rule: string;
  included_actions_per_month: number;
  bands: CataloguePricingBand[];
}

/** One source the catalogue is built from, and how fresh it is. */
export interface CatalogueSection {
  source: CatalogueSource;
  status: CatalogueSectionStatus;
  refreshed_at: string | null;
  count: number;
}

export interface CatalogueDocument {
  spec: 'stack.catalogue';
  spec_version: '1';
  /** 64 hex characters: changes when the content does. */
  version: string;
  generated_at: string;
  notice: string;
  pricing: CataloguePricing;
  sections: CatalogueSection[];
  entries: CatalogueEntry[];
}

export interface CatalogueGetOptions {
  /** The `etag` of a copy you hold. When it is current the answer is `notModified` with no document. */
  ifNoneMatch?: string;
}

export interface CatalogueGetResult {
  notModified: boolean;
  /** The response's `ETag` (a weak tag over the document version); keep it for the next `ifNoneMatch`. */
  etag: string | null;
  /** The document; null when `notModified`. */
  document: CatalogueDocument | null;
}

export interface CatalogueSearchQuery {
  /** Words that must all appear in an entry's id, name, description or provider, in any case. */
  q?: string;
  kind?: CatalogueEntryKind;
  /** 1 to 100, default 25. */
  limit?: number;
  /** 0 or more. */
  offset?: number;
}

export interface CatalogueSearchResult {
  version: string;
  /** Every match, not only the page. */
  total: number;
  entries: CatalogueEntry[];
}

export interface CatalogueConnectedService {
  /** `service:<provider>`. */
  id: string;
  provider: string;
  name: string;
  connection_id: string;
}

export interface CatalogueAccountPiece {
  /** `account:<piece>`. */
  id: string;
  state: 'pending' | 'ready' | 'paused' | 'failed' | 'closing' | 'closed';
}

export interface CatalogueAccountTool {
  /** `mcp_tool:<tool name>`. */
  id: string;
  /** Whether an agent session of the account lists the tool now. */
  listed: boolean;
}

/** What one agent account has of the catalogue: the services it is connected to, the state of its pieces and which tools its agent lists. */
export interface CatalogueAccountView {
  account_id: string;
  /** The version of the catalogue the ids refer to; null when none is built yet. */
  catalogue_version: string | null;
  connected_services: CatalogueConnectedService[];
  pieces: CatalogueAccountPiece[];
  /** Every `mcp_tool` entry and whether an agent session of this account lists it now. */
  tools?: CatalogueAccountTool[];
}

const seg = encodeURIComponent;

export class CatalogueService {
  constructor(private readonly client: HttpClient) {}

  /**
   * The whole catalogue. Pass the `etag` of a copy you hold as `ifNoneMatch`:
   * when it is current the answer is `{ notModified: true, document: null }`.
   * Answers 503 `CATALOGUE_UNAVAILABLE` (`details.reason` `not_built` or
   * `store_unavailable`) when the catalogue has not been built yet.
   */
  async get(options: CatalogueGetOptions = {}): Promise<CatalogueGetResult> {
    const res = await this.client.getConditional<CatalogueDocument>('/v1/catalogue', { ifNoneMatch: options.ifNoneMatch });
    return { notModified: res.status === 304, etag: res.etag, document: res.body };
  }

  /** Entries whose id, name, description or provider contain every word of `q`, filtered by `kind`, one page at a time. */
  async search(query: CatalogueSearchQuery = {}): Promise<CatalogueSearchResult> {
    return this.client.get<CatalogueSearchResult>('/v1/catalogue/search', {
      q: query.q,
      kind: query.kind,
      limit: query.limit !== undefined ? String(query.limit) : undefined,
      offset: query.offset !== undefined ? String(query.offset) : undefined,
    });
  }

  /** The services one of your agent accounts is connected to and the state of its pieces, by catalogue id. */
  async forAccount(accountId: string): Promise<CatalogueAccountView> {
    return this.client.get<CatalogueAccountView>(`/v1/accounts/${seg(accountId)}/catalogue`);
  }
}
