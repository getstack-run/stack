// Parameter-level scope constraint evaluator.
//
// Layer 2 (Proxy) enforcement: every outbound call routes through the
// proxy, which calls `findFailingConstraint` against the request's
// NormalizedRequest view. AND semantics across the constraint array —
// any failure denies, except that an `any_of` constraint passes when any one
// of its groups holds in full (the way a grant carries a read rule and a post
// rule on one connection). Unresolved paths (missing field) always fail,
// i.e. deny-by-default.
//
// Regex (`matches`) uses RE2 for linear-time evaluation — vanilla RegExp
// is ReDoS-vulnerable and operator-authored patterns are untrusted input.
// See shared/schemas/passport.ts for the Constraint zod schema.

import RE2 from 're2';
import type { AnyOfConstraint, Constraint, PlainConstraint } from '../schemas/passport.js';
import type { ProxyRequestInput } from '../schemas/proxy.js';
import { deriveRequestEmail } from './derived-email.js';
import { flowServiceKey, parseFlowSource } from './data-flow.js';

// Shape the evaluator reads from. Built once per proxy call via
// normalizeRequest() — all later resolvePath calls read from this.
export interface NormalizedRequest {
  method: string;                      // upper-cased
  url: {
    pathname: string;                  // trailing slash stripped
    host: string;                      // lowercased
    origin: string;
  };
  body: unknown;                       // whatever the agent sent (JSON-like)
  /**
   * The query the upstream actually receives: parameters already in the URL,
   * overridden key by key by `input.query` (the proxy sets those with
   * searchParams.set). A key the URL repeats is a list, so a constraint has
   * to hold for every value.
   */
  query: Record<string, string | string[]>;
  headers: Record<string, string>;     // keys lowercased
}

export function normalizeRequest(input: ProxyRequestInput): NormalizedRequest {
  const parsed = new URL(input.url);
  const rawPath = parsed.pathname;
  const pathname =
    rawPath.length > 1 && rawPath.endsWith('/') ? rawPath.slice(0, -1) : rawPath;
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(input.headers ?? {})) {
    headers[k.toLowerCase()] = v;
  }
  return {
    method: input.method.toUpperCase(),
    url: {
      pathname,
      host: parsed.host.toLowerCase(),
      origin: parsed.origin,
    },
    body: input.body,
    query: mergedQuery(parsed, input.query),
    headers,
  };
}

/**
 * URL parameters were invisible to constraints, so a value smuggled in the
 * URL (`?sendTo=...` with no `query.sendTo`) passed `not_exists`, `not_eq`
 * and `not_in` while still reaching the upstream.
 */
function mergedQuery(url: URL, explicit: Record<string, string> | undefined): Record<string, string | string[]> {
  // Null prototype: a parameter named __proto__ or constructor is data, not
  // a path into Object.prototype.
  const out = Object.create(null) as Record<string, string | string[]>;
  for (const key of new Set(url.searchParams.keys())) {
    const values = url.searchParams.getAll(key);
    out[key] = values.length === 1 ? values[0]! : values;
  }
  for (const [key, value] of Object.entries(explicit ?? {})) out[key] = value;
  return out;
}

// Resolve a dotted path against the normalized request. Returns undefined
// when any segment is missing — caller (evaluateConstraint) treats
// undefined as a constraint failure (deny-by-default).
//
// A segment ending in `[]` fans out over an array: `body.to[].email` is the
// list of every element's `email`, which evaluateConstraint then checks
// element by element. Pinning `body.to.0.email` checks only the first
// recipient, so a second one walked straight past it. A fan-out never
// silently drops what it cannot read: an element that is not an object where
// the path goes deeper, a field that should be an array and is not, and a
// list past FAN_OUT_LIMIT all resolve to a value that no operator accepts and
// that `not_exists` does not treat as absent.
//
// `derived.email.*` reads the recipients and text of an outbound email whose
// headers are encoded in the body (Gmail `raw`, Graph MIME), through the one
// reader in derived-email.ts. It is computed only when a constraint asks for
// it and is `undefined` whenever the message cannot be read, so a recipient
// pin refuses what it cannot see. An absent value there means "unreadable",
// never "no recipients": `not_exists` is not a recipient bound on it.
export function resolvePath(req: NormalizedRequest, path: string): unknown {
  if (path === 'method') return req.method;
  if (path === 'body') return req.body;
  if (path === 'url.pathname') return req.url.pathname;
  if (path === 'url.host') return req.url.host;
  if (path === 'url.origin') return req.url.origin;
  if (path.startsWith('headers.')) {
    return req.headers[path.slice(8).toLowerCase()];
  }
  if (path.startsWith('query.')) {
    return req.query[path.slice(6)];
  }
  if (path.startsWith('body.')) {
    return resolveDotted(req.body, path.slice(5).split('.'));
  }
  if (path.startsWith('body[].')) {
    return resolveDotted({ '': req.body }, ['[]', ...path.slice(7).split('.')]);
  }
  if (path.startsWith('derived.email.')) {
    const email = deriveRequestEmail(req);
    if (!email) return undefined;
    switch (path.slice(14)) {
      case 'recipients': return email.recipients;
      case 'from': return email.from;
      case 'subject': return email.subject;
      case 'text': return email.text;
      default: return undefined;
    }
  }
  return undefined;
}

/** Most elements one fan-out path may visit; a request past it is unreadable, not allowed. */
export const FAN_OUT_LIMIT = 10_000;

/** What a fan-out yields for a shape it cannot read: present, and equal to nothing. */
const UNREADABLE: unknown = Object.freeze({ unreadable: true });

function isScalar(value: unknown): boolean {
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';
}

function resolveDotted(root: unknown, parts: string[]): unknown {
  if (root == null) return undefined;
  return walk(root, parts, { left: FAN_OUT_LIMIT });
}

function walk(root: unknown, parts: string[], budget: { left: number }): unknown {
  let cur: unknown = root;
  for (let i = 0; i < parts.length; i++) {
    const raw = parts[i]!;
    const fan = raw.endsWith('[]');
    const key = fan ? raw.slice(0, -2) : raw;
    if (key !== '') {
      if (cur == null || typeof cur !== 'object') return undefined;
      // Own properties only: a request cannot be read through Object.prototype.
      cur = Object.hasOwn(cur, key) ? (cur as Record<string, unknown>)[key] : undefined;
    } else if (!fan) {
      return undefined; // empty segment ("a..b")
    } else if (i === 0) {
      cur = (cur as Record<string, unknown>)[''];
    }
    if (!fan) continue;
    if (cur === undefined) return undefined;
    if (!Array.isArray(cur)) return UNREADABLE;
    // Every element's value, flattened one level. An element object without
    // the field adds nothing: it carries no value to check. A field absent
    // from every element is absent.
    const rest = parts.slice(i + 1);
    const values: unknown[] = [];
    for (const element of cur) {
      if (--budget.left < 0) return UNREADABLE;
      let value: unknown;
      if (rest.length === 0) value = element;
      else if (element === null || typeof element !== 'object') value = UNREADABLE;
      else value = walk(element, rest, budget);
      if (value === undefined) continue;
      // What a fan-out hands the operators is flat scalars. A null or an
      // object where a value belongs is a shape it cannot judge.
      for (const v of Array.isArray(value) ? value : [value]) values.push(isScalar(v) ? v : UNREADABLE);
    }
    return values.length === 0 && cur.length > 0 ? undefined : values;
  }
  return cur;
}

/**
 * Is `path` one the evaluator can resolve? The grammar of resolvePath, for
 * code that declares paths in advance (an intent's recipient paths) and must
 * not declare one the engine would read as always absent. `[]` ends any
 * `body` segment; `body[].x` fans out over a root array body.
 */
export function isResolvablePath(path: string): boolean {
  if (path === 'method' || path === 'body' || path === 'url.pathname' || path === 'url.host' || path === 'url.origin') return true;
  if (/^(headers|query)\.[^.\s]+$/.test(path)) return true;
  if (/^derived\.email\.(recipients|from|subject|text)$/.test(path)) return true;
  const rest = path.startsWith('body.') ? path.slice(5) : path.startsWith('body[].') ? path.slice(7) : null;
  if (rest === null) return false;
  return rest.split('.').every((segment) => /^[A-Za-z0-9_]+(\[\])?$/.test(segment));
}

// Compiled RE2 cache. Passports tend to reuse the same patterns across
// many requests; compiling once per pattern amortizes cost.
const MAX_REGEX_CACHE = 1024;
const regexCache = new Map<string, RE2>();
function compileRegex(pattern: string): RE2 {
  const cached = regexCache.get(pattern);
  if (cached) return cached;
  if (regexCache.size >= MAX_REGEX_CACHE) {
    const first = regexCache.keys().next().value;
    if (first !== undefined) regexCache.delete(first);
  }
  const compiled = new RE2(pattern);
  regexCache.set(pattern, compiled);
  return compiled;
}

/**
 * Evaluate a single constraint against a normalized request.
 *
 * Returns `true` if the constraint holds (request is allowed under this
 * constraint), `false` if it fails.
 *
 * Unresolved paths fail (deny-by-default) — there is no implicit "optional
 * field passes". Authors wanting optionality should express it explicitly.
 */
export function evaluateConstraint(c: Constraint, req: NormalizedRequest): boolean {
  if (c.op === 'any_of') return c.value.some((group) => group.every((leaf) => evaluateConstraint(leaf, req)));
  const target = resolvePath(req, c.path);

  // Presence is decided before the missing-field rule, because
  // `not_exists` is precisely the constraint that must PASS when the field
  // is absent.
  if (c.op === 'exists') return target !== undefined;
  if (c.op === 'not_exists') return target === undefined;

  if (target === undefined) return false;
  // A shape a fan-out could not read is not a value any operator may judge,
  // not even `not_eq` or `not_in`, which would otherwise pass it.
  if (target === UNREADABLE || (Array.isArray(target) && target.includes(UNREADABLE))) return false;

  // A field carrying a list is the exfiltration shape that mattered:
  // `resend.send_email_to` pins `body.to`, and Resend accepts `to` as either
  // a string or an array. Under the old primitive-only comparison an array
  // ALWAYS failed, so the tightest email intent we ship broke on a perfectly
  // ordinary request and operators were pushed to drop the constraint.
  //
  // Arrays are now quantified UNIVERSALLY: the constraint must hold for
  // every element. `body.to eq alice` accepts ["alice"] and rejects
  // ["alice","attacker"] — adding a recipient cannot slip past a pin.
  //
  // An empty array fails a positive op and passes a negative one. Claiming a
  // pinned value while supplying none is not a match, but "none of these are
  // forbidden" is trivially true of nothing.
  if (Array.isArray(target)) {
    const negative = c.op === 'not_eq' || c.op === 'not_in';
    if (target.length === 0) return negative;
    return target.every((element) => evaluateAgainstValue(c, element));
  }

  return evaluateAgainstValue(c, target);
}

/** Apply a constraint's operator to one resolved scalar. */
function evaluateAgainstValue(c: PlainConstraint, target: unknown): boolean {
  switch (c.op) {
    case 'eq':
      return primitiveEq(target, c.value);
    case 'not_eq':
      return !primitiveEq(target, c.value);
    case 'in':
      return Array.isArray(c.value) && c.value.some((v) => primitiveEq(target, v));
    case 'not_in':
      return Array.isArray(c.value) && !c.value.some((v) => primitiveEq(target, v));
    case 'matches':
      if (typeof c.value !== 'string' || typeof target !== 'string') return false;
      return compileRegex(c.value).test(target);
    case 'starts_with':
      if (typeof c.value !== 'string' || typeof target !== 'string') return false;
      return target.startsWith(c.value);
    case 'lt':
    case 'lte':
    case 'gt':
    case 'gte': {
      if (typeof c.value !== 'number') return false;
      const n = toFiniteNumber(target);
      if (n === null) return false;
      if (c.op === 'lt') return n < c.value;
      if (c.op === 'lte') return n <= c.value;
      if (c.op === 'gt') return n > c.value;
      return n >= c.value;
    }
    // Handled by the caller before the missing-field rule.
    case 'exists':
      return target !== undefined;
    case 'not_exists':
      return target === undefined;
  }
}

/**
 * Numeric view of a target, or null when there isn't one.
 *
 * Numeric strings are accepted because form-encoded bodies and query
 * parameters are strings on the wire — a Stripe amount arrives as `"5000"`
 * through `query.amount` and as `5000` through a JSON body, and a cap has to
 * hold in both. Booleans are deliberately NOT numbers here: `true` coercing
 * to 1 would let a boolean satisfy a spend cap.
 */
function toFiniteNumber(value: unknown): number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (trimmed === '') return null;
    const n = Number(trimmed);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

function primitiveEq(a: unknown, b: unknown): boolean {
  if (typeof a !== typeof b) return false;
  if (typeof a === 'string' || typeof a === 'number' || typeof a === 'boolean') {
    return a === b;
  }
  return false;
}

/**
 * AND-evaluate an array of constraints. Returns the first failing
 * constraint, or null if all pass.
 */
export function findFailingConstraint(
  constraints: Constraint[],
  req: NormalizedRequest,
): Constraint | null {
  for (const c of constraints) {
    if (!evaluateConstraint(c, req)) return c;
  }
  return null;
}

/**
 * Structural subset check used at delegation + passport-issue time.
 *
 * Returns true if every constraint in `parent` appears verbatim (same
 * path, op, value) in `child`. `child` MAY have additional constraints
 * (that's tightening). Missing any parent constraint = loosening = fail.
 *
 * v1 uses structural equality. A future pass can upgrade to semantic
 * implication (e.g. `in [A,B]` ⊆ `in [A,B,C]`) without touching call
 * sites — this helper is the only surface.
 */
export function constraintsAreSubset(
  child: readonly Constraint[],
  parent: readonly Constraint[],
): boolean {
  return compareConstraintSets(child, parent) === 'within';
}

/** The most pairs of alternatives a comparison of two constraint lists will judge; past it the answer is `too_many_to_compare`. */
export const MAX_SUBSET_COMPARISONS = 4_096;

export type ConstraintSetVerdict = 'within' | 'wider' | 'too_many_to_compare';

/**
 * Whether `child` holds everything `parent` does. Both sides are read as their alternatives (plain constraint sets,
 * any one of which admits a call): the child is within the parent when every alternative of the child holds every
 * constraint of some alternative of the parent. With no `any_of` on either side each is one set, and this is the
 * plain check above.
 *
 * It is cheap whatever it is given. A child that holds every parent constraint as it stands (what delegation always
 * hands over) is answered at once from canonical keys, without spreading any choice. Otherwise the pairs to compare
 * are counted first, and past MAX_SUBSET_COMPARISONS the answer is `too_many_to_compare` (a refusal), so one request
 * can never make the check run long.
 */
export function compareConstraintSets(
  child: readonly Constraint[],
  parent: readonly Constraint[],
): ConstraintSetVerdict {
  const childKeys = new Set(child.map(constraintKey));
  if (parent.every((p) => childKeys.has(constraintKey(p)))) return 'within';
  if (setCount(child) * setCount(parent) > MAX_SUBSET_COMPARISONS) return 'too_many_to_compare';
  const parentSets = keyedAlternatives(parent);
  const childSets = keyedAlternatives(child);
  const within = childSets.every((childSet) =>
    parentSets.some((parentSet) => [...parentSet].every((key) => childSet.has(key))),
  );
  return within ? 'within' : 'wider';
}

/** How many alternatives a list spreads into: the product of the rules of each choice in it. */
function setCount(constraints: readonly Constraint[]): number {
  let count = 1;
  for (const c of constraints) {
    if (c.op === 'any_of') count *= c.value.length;
    if (count > MAX_SUBSET_COMPARISONS) return count;
  }
  return count;
}

/** The alternatives of a list as sets of canonical keys. Only called when the count is within the budget. */
function keyedAlternatives(constraints: readonly Constraint[]): Array<Set<string>> {
  const plain: string[] = [];
  const anyOfs: AnyOfConstraint[] = [];
  for (const c of constraints) {
    if (c.op === 'any_of') anyOfs.push(c);
    else plain.push(constraintKey(c));
  }
  let sets: string[][] = [plain];
  for (const anyOf of anyOfs) {
    const groups = anyOf.value.map((group) => group.map(constraintKey));
    sets = sets.flatMap((set) => groups.map((group) => [...set, ...group]));
  }
  return sets.map((set) => new Set(set));
}

/** Two constraints are the same when their keys are: path, op and value, a list in any order, a choice in any order of rules. */
function constraintKey(c: Constraint): string {
  if (c.op === 'any_of') {
    const groups = c.value.map((group) => group.map(constraintKey).sort().join(','));
    return `any_of[${groups.sort().join('|')}]`;
  }
  const value = Array.isArray(c.value) ? JSON.stringify([...c.value].sort()) : `${typeof c.value}:${String(c.value)}`;
  return `${c.path}\u0000${c.op}\u0000${value}`;
}

/** The most alternatives a constraint list is spread into when it is read in full. */
const MAX_COMPARED_ALTERNATIVES = 1024;

/**
 * A constraint list as its alternatives: the plain constraints, plus one
 * group of each `any_of` (several `any_of` multiply). Null when that would
 * pass MAX_COMPARED_ALTERNATIVES.
 */
export function alternativesOf(constraints: readonly Constraint[]): PlainConstraint[][] | null {
  const plain: PlainConstraint[] = [];
  const anyOfs: AnyOfConstraint[] = [];
  for (const c of constraints) {
    if (c.op === 'any_of') anyOfs.push(c);
    else plain.push(c);
  }
  let sets: PlainConstraint[][] = [plain];
  for (const anyOf of anyOfs) {
    if (sets.length * anyOf.value.length > MAX_COMPARED_ALTERNATIVES) return null;
    sets = sets.flatMap((set) => anyOf.value.map((group) => [...set, ...group]));
  }
  return sets;
}

/**
 * `allow_data_from` subset check, used at passport-issue + delegation time.
 *
 * `allow_data_from` GRANTS a cross-service data flow, so it narrows the
 * OPPOSITE way to constraints: where a constraint set may only grow tighter
 * as authority narrows, an `allow_data_from` set may only shrink. A child (on
 * delegation) or an issued passport (against a grant baseline) may declare
 * only flows the parent/grant already permitted.
 *
 * Returns true iff every service in `child` also appears in `parent`
 * (child ⊆ parent). A `from` present in `child` but absent from `parent` is a
 * widening — a scope escalation — and returns false. An empty `child` is a
 * trivial subset of anything (declaring no flows never widens).
 */
export function allowDataFromIsSubset(child: string[], parent: string[]): boolean {
  const parentSet = new Set(parent);
  // The services a parent names whole, by their key: a long custom service is written by its name or by its key.
  const parentServices = new Set(
    parent.filter((from) => parseFlowSource(from).connectionId === null).map((from) => flowServiceKey(from)),
  );
  // A flow from one connection (`service@scon_...`) is narrower than a flow from its service, so a parent naming the
  // service covers it. The reverse is a widening and is not covered.
  return child.every((from) => {
    const source = parseFlowSource(from);
    return parentSet.has(from) || parentSet.has(source.service) || parentServices.has(flowServiceKey(source.service));
  });
}

/** Whether replacing one standing data-flow grant with another adds authority. */
export function allowDataFromGrantWidens(next: string[], current: string[]): boolean {
  if (current.includes('*')) return false;
  if (next.includes('*')) return true;
  return !allowDataFromIsSubset(next, current);
}

/**
 * Resolve standing data-flow authority into the exact values signed into a
 * Passport. A grant wildcard means the agent's currently active service
 * providers, excluding the destination itself (its own service's content is
 * never a cross-service flow, and a wildcard does not open one between two
 * connections of it). Exact names remain exact, the destination's own service
 * or one of its connections (`service@scon_...`) included: naming them is how
 * content may move between two connections of one service. A provider longer
 * than a source label can carry is written by its `flowServiceKey`, which
 * also keeps the entry within the 128 characters a Passport allows.
 */
export function resolveAllowDataFromGrant(
  granted: string[],
  activeProviders: readonly string[],
  destinationProvider: string,
): string[] {
  const values = granted.includes('*')
    ? activeProviders.filter((provider) => provider !== destinationProvider).map(flowServiceKey)
    : granted;
  return [...new Set(values)]
    .filter((provider) => provider !== '*')
    .sort();
}

/**
 * #7 — grant/connect scope subset check with wildcard support.
 * Returns the requested scopes that are NOT permitted by `parentScopes`.
 * A parent containing '*' permits ANY child scope (empty result). Otherwise
 * it's literal set membership. Previously both grant + connect did a bare
 * `filter(s => !parent.includes(s))`, which treated '*' as a literal string —
 * so a default `['*']` connection could only grant `['*']`, never `['read']`
 * (the FamilyBot grant failure). Centralised so grant + connect agree.
 */
export function invalidChildScopes(requested: string[], parentScopes: string[]): string[] {
  if (parentScopes.includes('*')) return [];
  return requested.filter((s) => !parentScopes.includes(s));
}

/**
 * The scopes a key or token connection stores when its connect names none. A service whose catalogue row lists scopes
 * (an OAuth service) stores those. A service that lists none is connected with a key that is all-or-nothing, so its
 * connection's ceiling is `['*']`, the value a custom service's connection already has: an agent's grant needs at least
 * one scope that is within the connection's, and with an empty list none exists, so nothing could be granted.
 * Whom the key is granted to, and with which constraints, is still the owner's decision on the grant.
 */
export function defaultConnectionScopes(scopesAvailable: string[]): string[] {
  return scopesAvailable.length > 0 ? scopesAvailable : ['*'];
}

/**
 * service-lane authorization. The GRANT is the sole authority
 * a passport's self-declared `intent_services` may only NARROW, never
 * widen. Returns true iff the provider is in the operator-granted service
 * list AND (no intent was declared OR the intent includes the provider).
 *
 * This replaces the old `intentServices.includes(x) || granted.includes(x)`
 * idiom that was copy-pasted across the LLM gateway, the credential proxy,
 * the raw-credential route, and the intent simulator. That `||` let an
 * agent authorize itself by self-declaring an intent for a service it was
 * never granted — so `revoke_agent_access` did not actually cut off the
 * credential lane (the agent re-minted a passport declaring the intent).
 * Grant-as-sole-authority makes revoke a real kill switch: once the grant
 * is gone, a freshly-issued passport carries an empty `services[]` and the
 * provider is out of scope regardless of what intent it declares.
 *
 * Centralised here so every credential lane agrees and the semantics can
 * never drift apart again. `intentServices` is treated as a tighten-only
 * declaration: an empty list means "no narrowing," a non-empty list means
 * "only these" (and the provider must ALSO be granted).
 */
export function isServiceInScope(
  provider: string,
  grantedProviders: readonly string[],
  intentServices: readonly string[],
): boolean {
  if (!grantedProviders.includes(provider)) return false; // grant is required
  if (intentServices.length === 0) return true; // no narrowing declared
  return intentServices.includes(provider); // intent narrows within the grant
}
