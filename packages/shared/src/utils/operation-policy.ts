// Closed operations and closed bodies.
//
// WHY. Constraints are a denial list wearing a whitelist's clothes. You pin
// the fields you thought of, and everything you did not think of is allowed.
// `resend.send_email_to` pins `body.to` and nothing else, so an injected
// agent keeps the approved recipient and adds a second one in `bcc` — a
// field the intent never mentions. Measured across the catalogue: 8% of
// intents pin any body field at all.
//
// The fix is to invert the default. A scope declares the operations it may
// perform, and each operation declares the fields it may carry. A request
// that matches no operation is refused. A field present in the request but
// absent from the matched operation's declaration is refused. Not because
// anyone forbade it — because nobody permitted it.
//
// This is what makes "the only front door it was allowed to walk through"
// literal rather than aspirational.

import type { Constraint } from '../schemas/passport.js';
import type { NormalizedRequest } from './constraints.js';
import { findFailingConstraint } from './constraints.js';

/** How a request path is matched against an operation. */
export type PathMatch =
  | { kind: 'exact'; value: string }
  | { kind: 'prefix'; value: string }
  | { kind: 'regex'; value: string };

export interface DeclaredOperation {
  /** Human label, surfaced in denials so an operator can see what was expected. */
  id: string;
  /** Upper-case HTTP methods this operation permits. */
  methods: string[];
  /** How `url.pathname` is matched. */
  path: PathMatch;
  /**
   * Field paths this operation may carry, in `resolvePath` notation
   * (`body.to`, `query.limit`). A declared path also permits everything
   * beneath it, so `body.metadata` admits `body.metadata.anything` — needed
   * for the free-form blobs real APIs accept.
   *
   * Array elements are matched positionally-agnostic: declaring
   * `body.attachments[].url` admits `body.attachments.0.url` and
   * `body.attachments.7.url` alike, so a policy never enumerates indices.
   */
  allow_fields: string[];
  /** Value rules for this operation, evaluated with the usual AND semantics. */
  constraints?: Constraint[];
}

export interface ScopePolicy {
  /**
   * `closed` enforces the declarations below. `open` preserves the legacy
   * behaviour where anything not explicitly constrained is permitted, and
   * exists so existing passports keep working while operators migrate.
   */
  mode: 'closed' | 'open';
  operations: DeclaredOperation[];
}

export type PolicyDenial =
  | { reason: 'no_matching_operation'; detail: string }
  | { reason: 'undeclared_field'; detail: string; field: string; operation: string }
  | { reason: 'constraint_violation'; detail: string; operation: string; constraint: Constraint };

/**
 * Enumerate the field paths a request actually carries.
 *
 * Only `body` and `query` are walked. Headers are deliberately excluded:
 * the proxy already strips caller-supplied auth headers and injects its own,
 * the destination host is pinned by the credential binding, and requiring a
 * policy to enumerate every benign header (content-type, accept, and the
 * rest) would make policies unusable in practice. That is a stated limit,
 * not an oversight — a header is still a channel to the ALLOWED host.
 *
 * Array indices are collapsed to `[]` so a policy never enumerates them.
 */
export function enumerateRequestFields(req: NormalizedRequest): string[] {
  const out: string[] = [];

  const walk = (value: unknown, path: string, depth: number) => {
    if (depth > 8) return;
    if (value === null || value === undefined) {
      out.push(path);
      return;
    }
    if (Array.isArray(value)) {
      if (value.length === 0) out.push(`${path}[]`);
      for (const element of value) walk(element, `${path}[]`, depth + 1);
      return;
    }
    if (typeof value === 'object') {
      const entries = Object.entries(value as Record<string, unknown>);
      // An empty object at depth > 0 IS a field: the caller sent that key, and
      // `body.metadata: {}` is something a policy should be able to declare.
      // At the ROOT it is not - `body: {}` is an empty envelope carrying no
      // data at all, and emitting `body` made every no-argument call
      // undeclarable: an operation would have had to declare a field literally
      // named "body". Measured on AgentDojo, that alone refused 38% of the
      // legitimate calls a closed policy turned away - get_channels(),
      // list_files(), get_current_day(), none of which carry anything.
      if (entries.length === 0 && depth > 0) out.push(path);
      for (const [k, v] of entries) walk(v, `${path}.${k}`, depth + 1);
      return;
    }
    out.push(path);
  };

  if (req.body !== undefined) walk(req.body, 'body', 0);
  for (const key of Object.keys(req.query ?? {})) out.push(`query.${key}`);

  return [...new Set(out)];
}

/**
 * Is `field` permitted by `allowed`?
 *
 * A declaration permits itself and everything beneath it. `[]` in either
 * side matches any index, so declaring `body.attachments[].url` admits
 * `body.attachments[].url` from an enumeration of any length.
 */
export function isFieldDeclared(field: string, allowed: readonly string[]): boolean {
  const normalized = normalizeFieldPath(field);
  for (const raw of allowed) {
    const decl = normalizeFieldPath(raw);
    if (normalized === decl) return true;
    // Subtree: `body.metadata` permits `body.metadata.anything`.
    if (normalized.startsWith(`${decl}.`)) return true;
    if (normalized.startsWith(`${decl}[]`)) return true;
  }
  return false;
}

/** Collapse concrete array indices to `[]` and lowercase nothing else. */
function normalizeFieldPath(path: string): string {
  return path.replace(/\.(\d+)(?=\.|\[|$)/g, '[]').replace(/\[\]\[\]/g, '[]');
}

function pathMatches(match: PathMatch, pathname: string): boolean {
  if (match.kind === 'exact') return pathname === match.value;
  if (match.kind === 'prefix') return pathname.startsWith(match.value);
  try {
    // RE2 is used by the constraint evaluator; a policy regex is operator
    // authored and small, and anchoring is the author's job.
    return new RegExp(match.value).test(pathname);
  } catch {
    return false;
  }
}

/**
 * Evaluate a request against a scope policy.
 *
 * Returns null when the request is permitted, or the reason it is not.
 *
 * `open` mode always permits — the caller still applies the scope's ordinary
 * constraints, exactly as before this existed.
 */
export function evaluateScopePolicy(
  policy: ScopePolicy | undefined,
  req: NormalizedRequest,
): PolicyDenial | null {
  if (!policy || policy.mode !== 'closed') return null;

  const candidates = policy.operations.filter(
    (op) => op.methods.includes(req.method) && pathMatches(op.path, req.url.pathname),
  );

  if (candidates.length === 0) {
    return {
      reason: 'no_matching_operation',
      detail:
        `${req.method} ${req.url.pathname} matches no declared operation. ` +
        `Declared: ${policy.operations.map((o) => o.id).join(', ') || 'none'}.`,
    };
  }

  const present = enumerateRequestFields(req);

  // Several operations can match the same method+path (a broad one and a
  // narrow one). The request is permitted if ANY of them fully admits it,
  // so the operator can declare overlapping shapes without the order
  // mattering. The reported denial comes from the first candidate, which is
  // the most specific thing we can say without inventing a ranking.
  let firstDenial: PolicyDenial | null = null;

  for (const op of candidates) {
    const undeclared = present.find((field) => !isFieldDeclared(field, op.allow_fields));
    if (undeclared) {
      firstDenial ??= {
        reason: 'undeclared_field',
        detail:
          `"${undeclared}" is not declared by operation "${op.id}". ` +
          `An operation carries only the fields it declares; anything else is refused ` +
          `whether or not anyone thought to forbid it.`,
        field: undeclared,
        operation: op.id,
      };
      continue;
    }

    const failed = op.constraints?.length
      ? findFailingConstraint(op.constraints, req)
      : null;
    if (failed) {
      firstDenial ??= {
        reason: 'constraint_violation',
        detail: `Operation "${op.id}" requires ${failed.path} ${failed.op}.`,
        operation: op.id,
        constraint: failed,
      };
      continue;
    }

    return null; // this operation fully admits the request
  }

  return firstDenial;
}
