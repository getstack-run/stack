import { eq } from 'drizzle-orm';
import { operators } from '@stack/shared';
import type { Services } from '../../config/services.js';

/**
 * Read the dashboard session cookie (`stack_session`), verify it as a
 * stack:dashboard JWT, and return operator + member context. Returns null
 * on any failure (no cookie, bad signature, wrong audience, expired,
 * operator suspended/deleted). Does NOT throw — callers branch on null.
 *
 * Member detection: the member session token puts `member_id`, `role`, and
 * `is_member: true` on the session JWT alongside `sub` (= operator_id). We
 * read those raw fields so OAuth can plumb member context through consent → code → tokens.
 */
export async function tryReadCookieSession(
  services: Services,
  req: import('fastify').FastifyRequest,
): Promise<{ operatorId: string; email: string; ownerSessionRevision: string; memberId?: string; memberRole?: string } | null> {
  const token = services.browserSessions.extractCookie(req.headers.cookie);
  if (!token) return null;
  let verified: Awaited<ReturnType<typeof services.signer.verifyAccessOrSession>>;
  try {
    verified = await services.signer.verifyAccessOrSession(token);
  } catch {
    return null;
  }
  if (verified.aud !== 'stack:dashboard') return null;
  const op = await services.db.query.operators.findFirst({ where: eq(operators.id, verified.sub) });
  if (!op || op.status !== 'active') return null;
  try {
    const identity = await services.browserSessions.identity(verified, op);
    return { operatorId: op.id, email: identity.member?.email ?? op.email, ownerSessionRevision: op.owner_session_revision ?? '0', memberId: identity.member?.id, memberRole: identity.member?.role };
  } catch { return null; }
}
