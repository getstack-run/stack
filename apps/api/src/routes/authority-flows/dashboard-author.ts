import type { FastifyRequest } from 'fastify';
import {
  ForbiddenError,
  StackError,
  deployment,
  UnauthorizedError,
  type HumanOperatorAuthor,
} from '@stack/shared';
import { assertOperatorActive, type BrowserDecisionSession } from '@stack/vault';
import type { Services } from '../../config/services.js';
import { enforceAccessForRequest } from '../../middleware/auth.js';
import { enforceMemberFloorForSession } from '../../middleware/member-floor.js';

/**
 * The human behind a cookie-only authority route. Bearer credentials are
 * refused outright; the author is derived from the dashboard session and never
 * read from the request body.
 */

export function assertDashboardMutationOrigin(originHeader: string | undefined): void {
  let expectedOrigin: string;
  try {
    expectedOrigin = new URL(deployment().dashboardUrl).origin;
  } catch {
    throw new StackError('Dashboard origin configuration is invalid', 'SERVICE_UNAVAILABLE', 503);
  }
  if (!originHeader) {
    throw new ForbiddenError('Dashboard request origin is required');
  }
  try {
    const supplied = new URL(originHeader);
    if (supplied.origin !== originHeader || supplied.origin !== expectedOrigin) {
      throw new ForbiddenError('Dashboard request origin is invalid');
    }
  } catch (error) {
    if (error instanceof ForbiddenError) throw error;
    throw new ForbiddenError('Dashboard request origin is invalid');
  }
}

export async function resolveDashboardAuthorityAuthor(
  services: Services,
  request: FastifyRequest,
): Promise<{ operatorId: string; author: HumanOperatorAuthor; browserSession: BrowserDecisionSession }> {
  if (request.headers.authorization) {
    throw new UnauthorizedError('A signed-in dashboard session is required');
  }
  assertDashboardMutationOrigin(request.headers.origin);
  const sessionToken = services.browserSessions.extractCookie(request.headers.cookie);
  const session = await services.signer.verifyAccessOrSession(sessionToken ?? '').catch(() => null);
  if (!session || session.aud !== 'stack:dashboard') {
    throw new UnauthorizedError('A signed-in dashboard session is required');
  }
  const operator = await services.operator.getById(session.sub);
  assertOperatorActive(operator);
  // An account with no platform subscription does nothing here: the same 402 as every other route.
  await enforceAccessForRequest(services, request, session.sub);
  const identity = await services.browserSessions.identity(session, operator);
  // A read-only member decides nothing: the floor under every route (the check below is the same refusal for this flow's own words).
  enforceMemberFloorForSession(services, request, identity.member);
  let author: HumanOperatorAuthor = { kind: 'operator_owner', operator_id: session.sub };
  const memberId = session.payload['member_id'] as string | undefined;
  if (memberId) {
    const member = identity.member;
    if (!member || member.status !== 'active' || member.operator_id !== session.sub) {
      throw new UnauthorizedError('A signed-in dashboard session is required');
    }
    if (member.role !== 'standard' && member.role !== 'admin') {
      throw new ForbiddenError('A readonly member cannot decide an authority approval');
    }
    author = { kind: 'team_member', member_id: member.id, role_at_signing: member.role };
  }
  return { operatorId: session.sub, author, browserSession: services.browserSessions.decisionSession(session) };
}

export function requireAuthorityAdmin(author: HumanOperatorAuthor): void {
  if (author.kind === 'team_member' && author.role_at_signing !== 'admin') {
    throw new ForbiddenError('An owner or admin is required to approve Authority');
  }
}
