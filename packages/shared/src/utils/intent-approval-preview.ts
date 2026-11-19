// What a person is shown before they approve an intent an agent submitted, and whether that intent can move money.
//
// Approving releases the action the agent was held on, so the confirmation shows what the agent asked to do: the
// kind of intent, the named intent, the target, the action, every parameter (an amount, a URL, a recipient), the
// estimated cost and the agent's own stated reason. Every one of those is text the agent wrote. Each value is capped
// in length BEFORE the line is composed (so a long action cannot push the target or the reason out of view), put on
// one line, and shown in quotes, so nothing the agent wrote can pose as a line of its own.
//
// An intent that can move money is approved only in the browser (`intentMovesMoney`); every other intent is decided
// directly by the owner's key, SDK, CLI or chat. An intent that does not parse as an intent claim is shown as its raw JSON
// and judged by the same three fields read from that JSON (`rawMovesMoney`); only a payload that is not a JSON object, or
// one whose `intent_type`, `wallet_cents` or `gas_gwei` is there but not readable, counts as one that can move money.

import { IntentClaim } from '../schemas/passport-claims/intent-claim.js';
import { oneLine } from './approval-scope-lines.js';

/** The most characters of any one agent-written value that a line shows. */
export const INTENT_PREVIEW_FIELD_MAX = 200;
const KEY_MAX = 60;
const REQUIRES_MAX = 10;

/** A text on one line, cut to `max` characters with an ellipsis when it was longer. */
function capped(text: string, max = INTENT_PREVIEW_FIELD_MAX): string {
  const line = oneLine(text);
  return line.length > max ? `${line.slice(0, max)}…` : line;
}

const quoted = (text: string, max = INTENT_PREVIEW_FIELD_MAX): string => JSON.stringify(capped(text, max));

/** The host of a text that is an http(s) URL, or null. */
function urlHost(text: string): string | null {
  if (!/^https?:\/\//i.test(text.trim())) return null;
  try {
    return new URL(text.trim()).hostname.toLowerCase() || null;
  } catch {
    return null;
  }
}

function withHost(text: string, shown: string): string {
  const host = urlHost(text);
  return host === null ? shown : `${shown} (host ${quoted(host, 120)})`;
}

function valueText(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value) ?? '';
  } catch {
    return '[unreadable]';
  }
}

// ── Can it move money? ────────────────────────────────────────────────────

/** Can this intent move money? An onchain transaction, or a wallet or gas cost. */
export function intentMovesMoney(intent: IntentClaim): boolean {
  if (intent.intent_type === 'onchain_tx') return true;
  const cost = intent.estimated_cost;
  return (cost.wallet_cents ?? 0) > 0 || (cost.gas_gwei ?? 0) > 0;
}

// ── The lines ─────────────────────────────────────────────────────────────

/**
 * What the person reads: the lines of an intent that can be read, or the raw JSON of one that cannot (then `lines` is
 * empty and `raw` holds the JSON).
 */
export interface IntentApprovalPreview {
  lines: string[];
  raw: string | null;
  movesMoney: boolean;
}

/**
 * The money test on a payload that does not parse as an intent claim: the same three fields, read from the JSON as it is.
 * A field that is absent moves no money; one that is there but of another kind cannot be judged, so it counts as money, and
 * so does a payload that is not a JSON object at all.
 */
export function rawMovesMoney(claim: unknown): boolean {
  if (typeof claim !== 'object' || claim === null || Array.isArray(claim)) return true;
  const record = claim as Record<string, unknown>;
  const type = record['intent_type'];
  if (type !== undefined && typeof type !== 'string') return true;
  if (type === 'onchain_tx') return true;
  const cost = record['estimated_cost'];
  if (cost === undefined || cost === null) return false;
  if (typeof cost !== 'object' || Array.isArray(cost)) return true;
  for (const field of ['wallet_cents', 'gas_gwei']) {
    const value = (cost as Record<string, unknown>)[field];
    if (value === undefined || value === null) continue;
    if (typeof value !== 'number' || !Number.isFinite(value)) return true;
    if (value > 0) return true;
  }
  return false;
}

/** The stored claim as JSON text, whatever it holds. */
function rawJson(claim: unknown): string {
  try {
    return JSON.stringify(claim, null, 2) ?? 'null';
  } catch {
    return String(claim);
  }
}

/**
 * The lines a person reads before approving this intent, and whether it can move money. Takes the stored claim as it
 * is (unknown): a claim that does not parse is shown as its raw JSON and judged by `rawMovesMoney`.
 */
export function intentApprovalPreview(claim: unknown): IntentApprovalPreview {
  const parsed = IntentClaim.safeParse(claim);
  if (!parsed.success) return { lines: [], raw: rawJson(claim), movesMoney: rawMovesMoney(claim) };
  const intent = parsed.data;
  const parameters = Object.entries(intent.parameters);
  const lines = [
    `agent ${capped(intent.agent_id, 80)} asked to run the named intent ${quoted(intent.named_intent)} (type ${quoted(intent.intent_type)})`,
    `target ${withHost(intent.target, quoted(intent.target))}`,
    `action ${quoted(intent.action)}`,
  ];
  for (const [key, value] of parameters) {
    const text = valueText(value);
    lines.push(`parameter ${quoted(key, KEY_MAX)}: ${withHost(text, quoted(text))}`);
  }
  const cost = intent.estimated_cost;
  const costParts = [
    cost.wallet_cents !== null ? `wallet ${cost.wallet_cents} cents` : null,
    cost.tokens !== null ? `tokens ${cost.tokens}` : null,
    cost.gas_gwei !== null ? `gas ${cost.gas_gwei} gwei` : null,
  ].filter((part): part is string => part !== null);
  lines.push(`estimated cost: ${costParts.length > 0 ? costParts.join('; ') : 'none declared'}`);
  lines.push(intent.reason ? `reason ${quoted(intent.reason)}` : 'no reason given');
  if (intent.requires.length > 0) {
    const shown = intent.requires.slice(0, REQUIRES_MAX).map((id) => capped(id, 80));
    const more = intent.requires.length > REQUIRES_MAX ? ` and ${intent.requires.length - REQUIRES_MAX} more` : '';
    lines.push(`needs the earlier results ${shown.join(', ')}${more}`);
  }
  return { lines, raw: null, movesMoney: intentMovesMoney(intent) };
}
