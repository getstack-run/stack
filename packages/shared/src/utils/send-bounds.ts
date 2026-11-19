import type { Constraint, PlainConstraint } from '../schemas/passport.js';
import { expandIntents, INTENT_REGISTRY, listIntents, type Intent } from '../intents/index.js';
import { sampleParams } from '../intents/support/sample-params.js';
import { UnboundedSendRuleError } from '../errors/index.js';
import { alternativesOf } from './constraints.js';

// ── Send bounds ──────────────────────────────────────────────────────────
//
// A policy rule that ALLOWS a send must name who receives it. "Post to any
// channel" or "email anyone" is how one injected instruction becomes a leak,
// so a rule may grant an unbounded send only as `review` (a human approves
// each one) or `deny`.
//
// Pure and self-contained: the functions take a structural rule shape (any
// policy rule with an effect and an access of connection, intents and raw
// constraints satisfies it) and the intent catalog. Nothing here is called
// from a route; a hosted policy applies it when it is written.
//
// A recipient is pinned when a constraint in the rule fixes the field the
// intent names in `recipient_paths`: exact email addresses, domains, phone
// numbers or channel ids with `eq` or `in`, or `not_exists` for "none".

export interface SendBoundIntentRef {
  name: string;
  params?: Record<string, unknown>;
}

export interface SendBoundAccess {
  connection_id: string;
  intents: readonly SendBoundIntentRef[];
  constraints: readonly Constraint[];
}

export interface SendBoundRule {
  id: string;
  effect: 'allow' | 'review' | 'deny';
  access: SendBoundAccess;
  /**
   * `per_mission`: the rule leaves the recipients of its sends to each Mission. It passes the bound
   * when every send it names has recipient fields a Mission can pin; the Mission is checked when
   * the call is made (see mission-recipients.ts).
   */
  recipients?: 'per_mission' | undefined;
}

export interface UnboundSendRule {
  rule_id: string;
  connection_id: string;
  /** Provider of the connection when known. */
  provider: string | null;
  /**
   * `unbound_recipient`: a send intent whose recipient fields are not pinned.
   * `implicit_recipient`: a send whose recipient cannot be named (a reply, a public post).
   * `unpinned_operation`: no intent names the action, so any call, sends included, is allowed.
   * `unknown_intent`: the rule names an intent STACK does not know.
   */
  reason: 'unbound_recipient' | 'implicit_recipient' | 'unpinned_operation' | 'unknown_intent';
  /** The send intents involved (empty for unpinned_operation). */
  intents: string[];
  /** Recipient fields that need an eq or in constraint. */
  unbound_paths: string[];
}

let egressProviders: Set<string> | null = null;
/** Providers with at least one catalog send intent: the ones a call can deliver content through. */
export function isEgressProvider(provider: string): boolean {
  egressProviders ??= new Set(listIntents().filter(i => i.effect === 'send').map(i => i.name.slice(0, i.name.indexOf('.'))));
  return egressProviders.has(provider);
}

/**
 * Is a `matches` pattern a fully anchored, finite set of literal strings,
 * like `^/api/v10/channels/(123|456)/messages$`? Only then does it name its
 * recipients as precisely as `in`. Any wildcard, class, quantifier or escape
 * class (\d, \w) makes it open. Deliberately conservative: when in doubt,
 * the answer is no.
 */
export function isFiniteLiteralPattern(pattern: string): boolean {
  if (pattern.length < 2 || pattern.length > 1024 || pattern[0] !== '^' || !pattern.endsWith('$') || pattern.endsWith('\\$')) return false;
  let depth = 0;
  for (let i = 1; i < pattern.length - 1; i++) {
    const c = pattern[i]!;
    if (c === '\\') {
      const next = pattern[i + 1];
      if (next === undefined || i + 1 >= pattern.length - 1 || /[A-Za-z0-9]/.test(next)) return false; // \d, \w, \b, \1 ...
      i++;
      continue;
    }
    if (c === '(') {
      if (pattern[i + 1] === '?') {
        if (pattern[i + 2] !== ':') return false;
        i += 2;
      }
      depth++;
      continue;
    }
    if (c === ')') { if (--depth < 0) return false; continue; }
    if (c === '|') continue;
    if ('.*+?{}[]^$'.includes(c)) return false;
  }
  return depth === 0;
}

/**
 * A recipient path is bound by an eq/in on that exact path, or by not_exists
 * on it or on any container above it (`body.cc` absent means no
 * `body.cc[].email` either; `body.messageVersions` absent means no
 * `body.messageVersions[].to[].email`). `derived.email.*` is never bound by
 * not_exists: the engine reads it as absent whenever the message cannot be
 * read, so absent there means "unknown", not "no recipients".
 */
function pathIsBound(path: string, constraints: readonly Constraint[]): boolean {
  return constraints.some(c => {
    if (c.op === 'not_exists') {
      if (path.startsWith('derived.') || c.path.startsWith('derived.')) return false;
      return c.path === path || path.startsWith(`${c.path}.`) || path.startsWith(`${c.path}[]`);
    }
    if (c.path !== path) return false;
    if (c.op === 'eq') return typeof c.value === 'string' || typeof c.value === 'number' || typeof c.value === 'boolean';
    if (c.op === 'in') return Array.isArray(c.value) && c.value.length > 0;
    return path === 'url.pathname' && c.op === 'matches' && typeof c.value === 'string' && isFiniteLiteralPattern(c.value);
  });
}

function restrictsToReads(constraints: readonly Constraint[]): boolean {
  return constraints.some(c => c.path === 'method' && (
    (c.op === 'eq' && (c.value === 'GET' || c.value === 'HEAD')) ||
    (c.op === 'in' && Array.isArray(c.value) && c.value.length > 0 && c.value.every(v => v === 'GET' || v === 'HEAD'))));
}

/**
 * Every `allow` rule in a policy that grants a send without binding its
 * recipients. Pure: safe to call on stored or proposed policies.
 *
 * Within a rule, intents and constraints combine with AND, so a recipient is
 * bound when any constraint in the rule pins that field with `eq`, `in` or
 * `not_exists` (no recipient there at all), or, for a recipient carried in
 * the URL, a finite anchored `matches`.
 *
 * `providerOf` maps a connection to its provider. Without it, a rule that
 * names no intent cannot be judged and is skipped; with it, such a rule on a
 * provider that can send is reported as `unpinned_operation` unless its
 * constraints restrict it to GET/HEAD.
 */
export function findUnboundSendRules(
  policy: { rules: readonly SendBoundRule[] },
  providerOf?: (connectionId: string) => string | undefined,
): UnboundSendRule[] {
  const out: UnboundSendRule[] = [];
  for (const rule of policy.rules) {
    if (rule.effect !== 'allow') continue;
    const finding = unboundSendOf(rule, providerOf);
    if (!finding) continue;
    // A rule that leaves its recipients to each Mission is bounded when its own send intents name fields a Mission can pin.
    if (rule.recipients === 'per_mission' && finding.reason === 'unbound_recipient' && perMissionRecipientPaths(rule) !== null) continue;
    out.push(finding);
  }
  return out;
}

/**
 * The recipient fields of the sends a per-job rule names. `enforced` is every recipient field of its
 * send intents; `required` is the ones the rule's own constraints leave open, which each Mission
 * must pin. Null when the rule cannot be per job: it names no send intent, or one of them has no
 * recipient field to pin (a reply, a stored draft, a public post), or its intents cannot be read.
 */
export function perMissionRecipientPaths(rule: Pick<SendBoundRule, 'access'>): { enforced: string[]; required: string[] } | null {
  const { access } = rule;
  if (access.intents.some(ref => !INTENT_REGISTRY.has(ref.name))) return null;
  let constraints: Constraint[];
  try {
    constraints = ruleConstraints(access);
  } catch {
    return null;
  }
  const sends = access.intents.map(ref => INTENT_REGISTRY.get(ref.name)!).filter(i => i.effect === 'send');
  if (!sends.length || sends.some(i => !i.recipient_paths?.length)) return null;
  const enforced = [...new Set(sends.flatMap(i => [...i.recipient_paths!]))];
  return { enforced, required: enforced.filter(p => !pathIsBound(p, constraints)) };
}

/** The constraints of an intent that say which endpoint it binds; the others pick a value of the call (a sender, a recipient). */
const ENDPOINT_PATHS: ReadonlySet<string> = new Set(['method', 'url.host', 'url.pathname']);

/**
 * Which endpoints the intents of a rule bind: one list of constraints (method, host and path) per intent, never the ones
 * that pick a value of the call, so a call that fails a rule's sender or subject constraint still counts as at its endpoint.
 * A path that carries the recipient (a channel in the URL) is left out, which makes the endpoint every call of that method.
 * `sends` reads only the send intents; with none named `all` is one empty list, every call. Null when an intent cannot be read.
 */
export function intentEndpoints(access: Pick<SendBoundAccess, 'intents'>, which: 'sends' | 'all'): PlainConstraint[][] | null {
  if (access.intents.some(ref => !INTENT_REGISTRY.has(ref.name))) return null;
  const refs = access.intents.filter(ref => which === 'all' || INTENT_REGISTRY.get(ref.name)!.effect === 'send');
  if (refs.length === 0) return which === 'all' ? [[]] : [];
  try {
    const sets: PlainConstraint[][] = [];
    for (const ref of refs) {
      const intent = INTENT_REGISTRY.get(ref.name)!;
      const inUrl = intent.recipient_paths?.includes('url.pathname') === true;
      // An intent that holds a choice of rules is one endpoint per alternative.
      const alternatives = alternativesOf(expandIntents([{ name: ref.name, params: ref.params ?? {} }]));
      if (!alternatives) return null;
      for (const alternative of alternatives) sets.push(alternative.filter(c => ENDPOINT_PATHS.has(c.path) && !(inUrl && c.path === 'url.pathname')));
    }
    return sets;
  } catch {
    return null;
  }
}

/** Could one call satisfy both lists of endpoint constraints? False only when they pin the same field to different exact values. */
export function endpointsOverlap(a: readonly PlainConstraint[][], b: readonly PlainConstraint[][]): boolean {
  const conflict = (x: readonly PlainConstraint[], y: readonly PlainConstraint[]) =>
    x.some(cx => cx.op === 'eq' && y.some(cy => cy.op === 'eq' && cy.path === cx.path && cy.value !== cx.value));
  return a.some(x => b.some(y => !conflict(x, y)));
}

function ruleConstraints(access: SendBoundAccess): Constraint[] {
  return [...expandIntents(access.intents.map(ref => ({ name: ref.name, params: ref.params ?? {} }))), ...access.constraints];
}

/**
 * The one way a single allow rule can send without naming its recipients, or null.
 *
 * A rule that holds a choice of rules (an `any_of`, as a grant with several rules stores it) is judged one alternative at
 * a time, each as its own rule: a rule that only reads and a rule that posts to named channels are both fine, and the
 * choice is unbound only when some alternative is.
 */
function unboundSendOf(rule: Pick<SendBoundRule, 'id' | 'access'>, providerOf?: (connectionId: string) => string | undefined): UnboundSendRule | null {
  const { access } = rule;
  const known = providerOf?.(access.connection_id);
  const base = { rule_id: rule.id, connection_id: access.connection_id, provider: known ?? null };
  const unknown = access.intents.filter(ref => !INTENT_REGISTRY.has(ref.name)).map(ref => ref.name);
  if (unknown.length) return { ...base, reason: 'unknown_intent', intents: unknown, unbound_paths: [] };
  let alternatives: Constraint[][] | null;
  try {
    alternatives = alternativesOf(ruleConstraints(access));
  } catch {
    // Params that no longer validate cannot be expanded, so the rule cannot be judged: fail closed.
    return { ...base, reason: 'unknown_intent', intents: access.intents.map(i => i.name), unbound_paths: [] };
  }
  // A rule too branched to read cannot be judged either (the schema keeps real ones far below this): fail closed.
  if (!alternatives) return { ...base, reason: 'unknown_intent', intents: access.intents.map(i => i.name), unbound_paths: [] };
  for (const constraints of alternatives) {
    const finding = unboundSendIn(base, access, constraints, known);
    if (finding) return finding;
  }
  return null;
}

/** One alternative of a rule (its intents and the constraints of that alternative, all of which apply together). */
function unboundSendIn(
  base: Pick<UnboundSendRule, 'rule_id' | 'connection_id' | 'provider'>,
  access: SendBoundAccess,
  constraints: Constraint[],
  known: string | undefined,
): UnboundSendRule | null {
  const intents = access.intents.map(ref => INTENT_REGISTRY.get(ref.name)!);
  const sends = intents.filter(i => i.effect === 'send');
  if (sends.length) {
    const implicit = sends.filter(i => !i.recipient_paths?.length);
    if (implicit.length) return { ...base, reason: 'implicit_recipient', intents: [...new Set(implicit.map(i => i.name))], unbound_paths: [] };
    const unbound = [...new Set(sends.flatMap(i => [...i.recipient_paths!]).filter(p => !pathIsBound(p, constraints)))];
    return unbound.length ? { ...base, reason: 'unbound_recipient', intents: [...new Set(sends.map(i => i.name))], unbound_paths: unbound } : null;
  }
  // A provider intent that is not a send pins the rule to that non-send
  // operation (AND semantics). Only custom.* modifiers leave it open.
  if (intents.some(i => !i.name.startsWith('custom.'))) return null;
  if (restrictsToReads(constraints) || known === undefined || !isEgressProvider(known)) return null;
  // Raw constraints: find every send operation of this provider the rule
  // could still admit, and require that send's recipients to be bound.
  const literals = pinnedPaths(constraints);
  const methods = allowedMethods(constraints);
  const overlapping = sendSignatures(known).filter(s =>
    (methods === null || s.methods === null || [...methods].some(m => s.methods!.has(m))) &&
    (literals === null || literals.some(path => s.matchesPath(path))));
  if (!overlapping.length) return null;
  if (literals === null) return { ...base, reason: 'unpinned_operation', intents: overlapping.map(s => s.intent.name), unbound_paths: [] };
  const implicit = overlapping.filter(s => !s.intent.recipient_paths?.length);
  if (implicit.length) return { ...base, reason: 'implicit_recipient', intents: implicit.map(s => s.intent.name), unbound_paths: [] };
  const unbound = [...new Set(overlapping.flatMap(s => [...s.intent.recipient_paths!]).filter(p => !pathIsBound(p, constraints)))];
  return unbound.length ? { ...base, reason: 'unbound_recipient', intents: overlapping.map(s => s.intent.name), unbound_paths: unbound } : null;
}

/** Literal paths a rule pins with eq/in, or null when the path is open. */
function pinnedPaths(constraints: readonly Constraint[]): string[] | null {
  for (const c of constraints) {
    if (c.path !== 'url.pathname') continue;
    if (c.op === 'eq' && typeof c.value === 'string') return [c.value];
    if (c.op === 'in' && Array.isArray(c.value)) return c.value;
  }
  return null;
}

/** Methods a rule admits, or null when any method is admitted. */
function allowedMethods(constraints: readonly Constraint[]): Set<string> | null {
  const sets = constraints.filter(c => c.path === 'method').flatMap((c): string[][] =>
    c.op === 'eq' && typeof c.value === 'string' ? [[c.value.toUpperCase()]]
      : c.op === 'in' && Array.isArray(c.value) ? [c.value.map(v => v.toUpperCase())] : []);
  if (!sets.length) return null;
  return new Set(sets.reduce((acc, next) => acc.filter(m => next.includes(m))));
}

interface SendSignature { intent: Intent; methods: Set<string> | null; matchesPath: (path: string) => boolean }
const signatureCache = new Map<string, SendSignature[]>();

/**
 * The method and path each send intent of a provider binds, learned by
 * expanding it with sample params. Path segments that came from a param
 * (an id, a phone-number id, an inbox) are generalised to "any segment", so a
 * rule naming a different id still overlaps. When a pattern cannot be read,
 * it matches every path: unsure means "may send".
 */
function sendSignatures(provider: string): SendSignature[] {
  const cached = signatureCache.get(provider);
  if (cached) return cached;
  const out: SendSignature[] = [];
  for (const intent of listIntents()) {
    if (intent.effect !== 'send' || !intent.name.startsWith(`${provider}.`)) continue;
    const params = sampleParams(intent);
    const constraints = expandSample(intent, params);
    const samples = sampleStrings(params);
    const method = constraints.find(c => c.path === 'method');
    const methods = method?.op === 'eq' && typeof method.value === 'string' ? new Set([method.value])
      : method?.op === 'in' && Array.isArray(method.value) ? new Set(method.value) : null;
    out.push({ intent, methods, matchesPath: pathMatcher(constraints.find(c => c.path === 'url.pathname'), samples) });
  }
  signatureCache.set(provider, out);
  return out;
}

/** The intent expanded with sample params, or no constraints when it cannot be (it then matches any path). */
function expandSample(intent: Intent, params: ReturnType<typeof sampleParams>): Constraint[] {
  try { return params ? intent.expand(intent.params.parse(params)) : []; } catch { return []; }
}

function sampleStrings(value: unknown, out = new Set<string>()): Set<string> {
  if (typeof value === 'string') out.add(value);
  else if (Array.isArray(value)) value.forEach(v => sampleStrings(v, out));
  else if (value && typeof value === 'object') Object.values(value).forEach(v => sampleStrings(v, out));
  return out;
}

function pathMatcher(c: Constraint | undefined, samples: Set<string>): (path: string) => boolean {
  if (!c || typeof c.value !== 'string') return () => true;
  const variants = new Set<string>();
  for (const s of samples) { variants.add(s); variants.add(s.replace(/[.*+?^${}()|[\]\\/-]/g, m => `\\${m}`)); variants.add(s.replace(/[.*+?^${}()|[\]\\]/g, m => `\\${m}`)); }
  const isAlternation = (segment: string) => segment.length > 2 && segment.startsWith('(') && segment.endsWith(')') &&
    segment.slice(1, -1).split('|').every(v => variants.has(v));
  const generalise = (segment: string) => (variants.has(segment) || isAlternation(segment) ? '[^/]+' : segment);
  try {
    if (c.op === 'eq') {
      const pattern = `^${c.value.split('/').map(seg => { const g = generalise(seg); return g === seg ? seg.replace(/[.*+?^${}()|[\]\\]/g, m => `\\${m}`) : g; }).join('/')}$`;
      const re = new RegExp(pattern);
      return path => re.test(path);
    }
    if (c.op === 'matches') {
      const re = new RegExp(c.value.split('/').map(generalise).join('/'));
      return path => re.test(path);
    }
    if (c.op === 'starts_with') return path => path.startsWith(c.value as string);
  } catch { /* unreadable pattern: assume it may match */ }
  return () => true;
}

/** Customer-facing sentence for one finding. */
export function describeUnboundSendRule(f: UnboundSendRule): string {
  const where = f.provider ?? f.connection_id;
  switch (f.reason) {
    case 'unbound_recipient':
      return `Rule "${f.rule_id}" allows sending on ${where} without naming who receives it. Bind ${f.unbound_paths.join(', ')} with eq or in (or not_exists), set the rule's recipients to "per_mission" so each Mission names them, or set the rule's effect to "review" or "deny".`;
    case 'implicit_recipient':
      return `Rule "${f.rule_id}" allows ${f.intents.join(', ')}, whose recipients cannot be named in advance. Set the rule's effect to "review" or "deny".`;
    case 'unpinned_operation':
      return `Rule "${f.rule_id}" allows any call on ${where}, including sends. Name the actions with intents and bind their recipients, or set the rule's effect to "review" or "deny".`;
    case 'unknown_intent':
      return `Rule "${f.rule_id}" names an intent STACK does not know: ${f.intents.join(', ')}.`;
  }
}

/**
 * Refuse a NEW or REVISED policy that allows an unbounded send. Do not call
 * this on stored policies; use findUnboundSendRules there.
 */
export function assertSendRulesBounded(
  policy: { rules: readonly SendBoundRule[] },
  providerOf?: (connectionId: string) => string | undefined,
): void {
  const findings = findUnboundSendRules(policy, providerOf);
  if (!findings.length) return;
  throw new UnboundedSendRuleError(findings.map(describeUnboundSendRule).join(' '), { rules: findings });
}
