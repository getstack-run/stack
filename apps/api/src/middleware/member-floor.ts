import type { FastifyRequest } from 'fastify';
import { requireRole } from './require-role.js';

/**
 * The floor under every route: a read-only team member reads, and does not act.
 *
 * A request whose principal is a team member and whose method changes something (POST, PUT, PATCH, DELETE) is refused
 * with the role convention's own error (`requireRole(request, 'standard')`: 403 "This action requires standard access or
 * higher") unless its route is on the allowlist below or on the one the deployment adds (`registries.memberActionAllowlist`).
 * The default is to refuse, so a route added tomorrow is covered without anyone remembering to gate it.
 *
 * Where it runs: right after the credential is resolved and before the billing account is read, in the one authentication
 * preHandler every route shares (`createAuthMiddleware`, and the enrollment ticket path of `createEnrollmentAuthMiddleware`),
 * and in each flow that reads the browser session itself (OAuth consent and device approval, the governance and authority
 * decisions, proxy recovery). Metering and every handler come later, so a refused request does no work and is not counted
 * as an action.
 *
 * It is a floor, not a replacement: the owner-or-admin checks of a route stay where they are and are stricter. An owner's key,
 * an owner's session, an agent, a Passport, a fleet session, a workload and platform staff carry no member and pass.
 */

const MUTATING_METHODS: ReadonlySet<string> = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Routes of the engine a read-only member may still call, `METHOD /route pattern` to the reason it is on the list. A route
 * is here only because it changes nothing (it reads through a POST) or acts on the member's own sign-in and nothing of the
 * account's. Anything else is refused, and a public receiver or token endpoint never carries a member and needs no entry.
 */
export const ENGINE_MEMBER_ACTION_ALLOWLIST: Readonly<Record<string, string>> = Object.freeze({
  'POST /oauth/authorize': 'the member\'s own consent for a client they connect: the token they get carries the member and stays read-only',
  'POST /oauth/device/approve': 'the member\'s own approval of a device they sign in: the token it gets carries the member and stays read-only',
  'POST /oauth/device/deny': 'the member\'s own refusal of a device sign-in: it ends their own request and changes nothing of the account',
  'DELETE /v1/operators/me/mcp-sessions/:familyId': 'ends one of the member\'s OWN chat sessions: the revocation is partitioned by member and refuses another\'s family',
  'POST /v1/control-policies/simulate': 'reads: tries a call against a policy and answers the verdict; nothing is written, not even an audit row',
  'POST /v1/dashboard/proxy/operations/get': 'reads: the status of one proxied operation, through a POST so the id stays out of the URL',
  'POST /v1/proxy/operations/get': 'reads: the status of one proxied operation for the holder of its Passport, through a POST so the id stays out of the URL',
});

/** The registry a deployment adds its own entries to (a map from `METHOD /route` to the reason). */
export interface MemberActionRegistry {
  has(key: string): boolean;
}

export interface MemberFloorInput {
  /** An absent method counts as one that changes something. */
  method: string | undefined;
  /** The matched route pattern (`/v1/missions/:id`), never the concrete URL. An empty one is refused. */
  route: string;
  memberId: string | undefined;
  memberRole: string | undefined;
}

/** Throws the role convention's 403 for a read-only member (or one with a role nobody knows) acting on a route that is not on the allowlist. */
export function enforceMemberFloor(
  services: { registries?: { memberActionAllowlist: MemberActionRegistry } | undefined },
  input: MemberFloorInput,
): void {
  if (!input.memberId) return;
  // A request that names no method is treated as one that changes something: unknown is not allowed.
  const method = (input.method ?? '').toUpperCase();
  if (method !== '' && !MUTATING_METHODS.has(method)) return;
  const key = `${method} ${input.route}`;
  if (input.route !== '' && services.registries?.memberActionAllowlist.has(key)) return;
  requireRole({ memberId: input.memberId, memberRole: input.memberRole }, 'standard');
}

/** The same floor on a request the authentication middleware has just resolved. */
export function enforceMemberFloorForRequest(
  services: { registries?: { memberActionAllowlist: MemberActionRegistry } | undefined },
  request: Pick<FastifyRequest, 'method' | 'memberId' | 'memberRole'> & { routeOptions?: { url?: string | undefined } },
): void {
  enforceMemberFloor(services, {
    method: request.method,
    route: request.routeOptions?.url ?? '',
    memberId: request.memberId,
    memberRole: request.memberRole,
  });
}

/**
 * The same floor for a flow that reads the member from the browser session itself instead of going through the
 * authentication middleware (OAuth consent and device approval, the governance and authority decisions, proxy recovery).
 * `member` is what the session proved (`browserSessions.identity`), null for the owner.
 */
export function enforceMemberFloorForSession(
  services: { registries?: { memberActionAllowlist: MemberActionRegistry } | undefined },
  request: Pick<FastifyRequest, 'method'> & { routeOptions?: { url?: string | undefined } },
  member: { id: string; role: string } | null | undefined,
): void {
  enforceMemberFloor(services, {
    method: request.method,
    route: request.routeOptions?.url ?? '',
    memberId: member?.id,
    memberRole: member?.role,
  });
}
