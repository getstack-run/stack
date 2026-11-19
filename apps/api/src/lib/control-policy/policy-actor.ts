import type { FastifyRequest } from 'fastify';

/** Who a policy revision is recorded as made by: the signed-in person, the member, the OAuth client or the key. */
export function policyActor(
  request: Pick<FastifyRequest, 'isDashboardSession' | 'memberId' | 'oauthClientId'>,
): string {
  if (request.isDashboardSession) return `dashboard:${request.memberId ?? 'owner'}`;
  if (request.memberId) return `member:${request.memberId}`;
  if (request.oauthClientId) return `oauth:${request.oauthClientId}`;
  return 'operator_key';
}
