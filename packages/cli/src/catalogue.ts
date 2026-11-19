import { writeFileSync } from 'node:fs';
import { stdout } from 'node:process';
import { api } from './api.js';
import { flag, positional, takeSwitch, wholeNumber } from './account-args.js';
import { fmt, printJson, printTable } from './format.js';

// The catalogue: one file of what an agent can use (models, tools, services,
// skills and the pieces of an account), read-only and free. A signed-in
// caller of any kind may read it, so these commands send no Passport.
//
// Entries from a provider or publisher carry text that provider wrote. It is
// data: it is printed, never followed, and anything that could drive the
// terminal (escape sequences and other control characters) is stripped first.

export const CATALOGUE_KINDS = ['model', 'tool', 'service', 'skill', 'account', 'mcp_tool'] as const;

interface CatalogueEntry {
  id: string;
  kind: string;
  name: string;
  origin?: string;
  result_trust?: string;
  price?: { unit?: string; provider_cost?: { worst_case_usd_micros?: number } | null };
}

interface CatalogueSearchResult {
  version?: string;
  total?: number;
  entries?: CatalogueEntry[];
}

interface CatalogueDocument {
  version?: string;
  entries?: unknown[];
}

interface CatalogueAccountView {
  account_id?: string;
  catalogue_version?: string | null;
  connected_services?: Array<{ id: string; provider: string; name: string; connection_id: string }>;
  pieces?: Array<{ id: string; state: string }>;
  tools?: Array<{ id: string; listed: boolean }>;
}

/** Provider text as one safe line: control characters become spaces, long text is cut. */
export function plainText(value: unknown, max = 60): string {
  // Control characters (escape sequences included) and line separators become one space.
  const line = String(value ?? '').replace(/[\p{Cc}\p{Zl}\p{Zp}]+/gu, ' ').trim();
  return line.length > max ? `${line.slice(0, max - 1)}…` : line;
}

function priceCell(entry: CatalogueEntry): string {
  const unit = plainText(entry.price?.unit ?? 'varies', 12);
  const worst = entry.price?.provider_cost?.worst_case_usd_micros;
  return typeof worst === 'number' ? `${unit} (worst $${(worst / 1_000_000).toFixed(4)})` : unit;
}

/** A leftover option is a typo, not a search word. */
function refuseUnknownOptions(args: string[], command: string): void {
  const stray = args.find((arg) => arg.startsWith('--'));
  if (stray !== undefined) throw new Error(`Invalid input: ${stray} is not an option of ${command}`);
}

async function cmdSearch(args: string[], json: boolean): Promise<void> {
  const kind = flag(args, '--kind');
  if (kind !== undefined && !(CATALOGUE_KINDS as readonly string[]).includes(kind)) {
    throw new Error(`--kind must be one of ${CATALOGUE_KINDS.join(', ')}`);
  }
  const limit = wholeNumber(args, '--limit');
  if (limit !== undefined && (limit < 1 || limit > 100)) throw new Error('--limit must be between 1 and 100');
  const offset = wholeNumber(args, '--offset');
  refuseUnknownOptions(args, 'catalogue');
  const q = args.join(' ').trim();

  const query: Record<string, string | number> = {};
  if (q !== '') query['q'] = q;
  if (kind !== undefined) query['kind'] = kind;
  if (limit !== undefined) query['limit'] = limit;
  if (offset !== undefined) query['offset'] = offset;
  const result = await api<CatalogueSearchResult>('GET', '/v1/catalogue/search', { query });
  if (json) return printJson(result);

  const entries = result.entries ?? [];
  printTable(
    ['ID', 'KIND', 'NAME', 'PRICE', 'TRUST'],
    entries.map((entry) => [
      plainText(entry.id, 80),
      plainText(entry.kind, 10),
      plainText(entry.name),
      priceCell(entry),
      entry.result_trust === 'untrusted' ? fmt.warn('untrusted') : plainText(entry.result_trust ?? 'standard', 10),
    ]),
  );
  const total = result.total ?? entries.length;
  const next = (offset ?? 0) + entries.length;
  stdout.write(`${entries.length} of ${total}${next < total ? ` (more: --offset ${next})` : ''}\n`);
}

async function cmdGet(args: string[], json: boolean): Promise<void> {
  const out = flag(args, '--out');
  refuseUnknownOptions(args, 'catalogue get');
  if (args.length > 0) throw new Error('Invalid input: catalogue get takes only --out <path>');
  const document = await api<CatalogueDocument>('GET', '/v1/catalogue');
  if (out === undefined) return printJson(document);
  writeFileSync(out, `${JSON.stringify(document, null, 2)}\n`);
  const written = { written: out, version: document.version ?? null, entries: document.entries?.length ?? 0 };
  if (json) return printJson(written);
  stdout.write(`Wrote catalogue ${written.version ?? ''} (${written.entries} entries) to ${out}\n`);
}

async function cmdAccountView(args: string[], json: boolean): Promise<void> {
  const accountId = positional(args, 'account id');
  refuseUnknownOptions(args, 'catalogue account');
  const view = await api<CatalogueAccountView>('GET', `/v1/accounts/${encodeURIComponent(accountId)}/catalogue`);
  if (json) return printJson(view);

  stdout.write(`account ${plainText(view.account_id ?? accountId, 80)}, catalogue ${plainText(view.catalogue_version ?? 'not built', 80)}\n`);
  stdout.write('connected services\n');
  printTable(
    ['ID', 'NAME', 'CONNECTION'],
    (view.connected_services ?? []).map((service) => [plainText(service.id, 80), plainText(service.name), plainText(service.connection_id, 80)]),
  );
  stdout.write('pieces\n');
  printTable(['ID', 'STATE'], (view.pieces ?? []).map((piece) => [plainText(piece.id, 80), plainText(piece.state, 12)]));
  if (view.tools !== undefined) {
    const listed = view.tools.filter((tool) => tool.listed).length;
    stdout.write(`tools the agent lists now: ${listed} of ${view.tools.length}; the others are found with catalogue search --kind mcp_tool\n`);
  }
}

export async function cmdCatalogue(argv: string[]): Promise<void> {
  const args = [...argv];
  const json = takeSwitch(args, '--json');
  // `get` and `account` are commands; to look for those words, say `catalogue search get`.
  const sub = args[0];
  if (sub === 'get') {
    args.shift();
    return cmdGet(args, json);
  }
  if (sub === 'account') {
    args.shift();
    return cmdAccountView(args, json);
  }
  if (sub === 'search') args.shift();
  return cmdSearch(args, json);
}
