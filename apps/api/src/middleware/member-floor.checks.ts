/**
 * The checks behind `member-floor.test.ts` (the engine's scan) and the hosted deployment's own coverage test: the one gate that refuses a read-only member's POST, PUT, PATCH and DELETE (`member-floor.ts`) must be wired on
 * every way a member reaches a route, and its allowlist must name only real, mutating routes with a reason.
 *
 * A route needs no mark of its own: the default is to refuse, so a new mutating route is covered when it is written. What a test
 * can still catch is the gate going unwired on a path (an authentication path or a flow that reads the browser session itself)
 * and an allowlist that has gone stale or grown without a reason.
 */

export const MUTATING = ['POST', 'PUT', 'PATCH', 'DELETE'] as const;

/** A route as `route-table.ts` lists it. */
export interface TableRoute { method: string; url: string }

/** Problems with an allowlist, as one line each, against the routes the deployment registers. */
export function allowlistProblems(
  allowlist: Readonly<Record<string, string>>,
  registered: readonly TableRoute[],
): string[] {
  const mutating = new Set(registered.filter((route) => (MUTATING as readonly string[]).includes(route.method)).map((route) => `${route.method} ${route.url}`));
  const all = new Set(registered.map((route) => `${route.method} ${route.url}`));
  const problems: string[] = [];
  for (const [key, reason] of Object.entries(allowlist)) {
    if (!/^(POST|PUT|PATCH|DELETE) \/\S*$/.test(key)) problems.push(`${key}: not a mutating METHOD /route entry`);
    else if (!mutating.has(key)) problems.push(`${key}: ${all.has(key) ? 'is not mutating' : 'names no route that is registered'}`);
    if (reason.trim().length < 20) problems.push(`${key}: no reason (a route is allowed only for a reason a reviewer can check)`);
  }
  return problems;
}

/** What marks a file as one that reads a person's browser session itself, and so is not seen by the authentication middleware. */
const SESSION_READER = /\bverifyAccessOrSession\(|\bbrowserSessions\.identity\(|\btryReadCookieSession\(/;
const FLOOR_CALL = /\benforceMemberFloor(?:ForSession|ForRequest)?\(/;

/**
 * Files of the engine that mention a session reader and are not a flow, each with why: the gate's own wiring and the shared cookie
 * reader (its callers are scanned). The hosted deployment's own exemptions are listed by its coverage test and passed in.
 */
export const SESSION_READER_EXEMPT: Readonly<Record<string, string>> = Object.freeze({
  'middleware/auth.ts': 'the authentication middleware: checked on its own (authenticationPathsWithoutFloor)',
  'routes/oauth-flows/cookie-session.ts': 'the shared cookie reader; the flows that call it (consent, device approval) are scanned',
});

/** Files (by path under `apps/api/src`) that read a member's browser session and never call the floor. */
export function sessionFlowsWithoutFloor(
  files: ReadonlyArray<{ path: string; text: string }>,
  exempt: Readonly<Record<string, string>> = SESSION_READER_EXEMPT,
): string[] {
  return files
    .filter((file) => !(file.path in exempt))
    .filter((file) => SESSION_READER.test(file.text) && !FLOOR_CALL.test(file.text))
    .map((file) => file.path);
}

/**
 * What `middleware/auth.ts` must do: the floor runs in the shared authentication preHandler, after the credential is resolved and
 * before the billing account is read, and in the enrollment ticket path, which resolves a member of its own.
 */
export function authenticationPathsWithoutFloor(authSource: string): string[] {
  const text = authSource.replace(/\r\n/g, '\n');
  const problems: string[] = [];
  const shared = /return async function authenticate\(request[\s\S]*?\n {2}\};/.exec(text)?.[0] ?? '';
  const caller = shared.indexOf('await authenticateCaller(');
  const floor = shared.indexOf('enforceMemberFloorForRequest(');
  const billing = shared.indexOf('await applyBillingAccount(');
  if (caller < 0 || floor < caller || billing < floor) {
    problems.push('createAuthMiddleware: the floor must run after authenticateCaller and before applyBillingAccount');
  }
  const ticket = /return async function enrollmentOrStandardAuth\([\s\S]*?\n {2}\};/.exec(text)?.[0] ?? '';
  const ticketMember = ticket.indexOf('applyMemberContext(');
  const ticketFloor = ticket.indexOf('enforceMemberFloorForRequest(');
  const ticketBilling = ticket.indexOf('await applyBillingAccount(');
  if (ticketMember < 0 || ticketFloor < ticketMember || ticketBilling < ticketFloor) {
    problems.push('createEnrollmentAuthMiddleware: the ticket path resolves a member and must run the floor before the billing account');
  }
  return problems;
}
