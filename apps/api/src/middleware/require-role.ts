import type { FastifyRequest } from 'fastify';
import { ForbiddenError } from '@stack/shared';

const ROLE_LEVEL = { readonly: 0, standard: 1, admin: 2 } as const;
type Role = keyof typeof ROLE_LEVEL;

export function requireRole(request: Pick<FastifyRequest, 'memberId' | 'memberRole'>, minRole: Role) {
  if (!request.memberId) return; // operator — always allowed
  const level = ROLE_LEVEL[(request.memberRole as Role) ?? 'readonly'];
  if (typeof level !== 'number' || level < ROLE_LEVEL[minRole]) {
    throw new ForbiddenError(`This action requires ${minRole} access or higher`);
  }
}
