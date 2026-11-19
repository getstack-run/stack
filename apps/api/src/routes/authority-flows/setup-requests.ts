import { ConflictError, NotFoundError, StackError, deployment, safeErrorSummary } from '@stack/shared';
import { z } from 'zod';
import type { Services } from '../../config/services.js';
import { announceDecision } from '../../lib/decision-reached.js';

/**
 * Enterprise OIDC Authority setup requests: the encrypted Redis records that
 * carry a request from creation through human approval, and the workflow
 * record that binds a started verification to one browser and one author.
 */

export interface AuthoritySetupWorkflow {
  request_id: string;
  operator_id: string;
  authenticated_author_hash: string;
  browser_binding_hash: string;
  method: 'company_sign_in' | 'stripe_identity';
  identity_claim_id?: string;
  result?: Record<string, unknown>;
}

type AuthoritySetupRequestStatus = 'pending' | 'rejected' | 'completed';

export interface AuthoritySetupRequestRecord {
  request_id: string;
  operator_id: string;
  request_hash: string;
  request: Record<string, unknown>;
  display: {
    agent_name: string;
    mission_summary: string | null;
    system_name: string;
  };
  status: AuthoritySetupRequestStatus;
  created_at: string;
  expires_at: string;
  completed_at?: string;
  rejected_at?: string;
  result?: Record<string, unknown>;
}

export const AuthoritySetupRequestParams = z.object({
  requestId: z.string().regex(/^aor_[a-f0-9]{32}$/),
}).strict();

export const AUTHORITY_SETUP_KEY = 'authority:oidc-setup:';
export const AUTHORITY_REQUEST_KEY = 'authority:oidc-request:';
export const AUTHORITY_REQUEST_TTL_SECONDS = 15 * 60;
export const AUTHORITY_COMPLETED_REQUEST_TTL_SECONDS = 24 * 60 * 60;
/**
 * The requests still pending, scored by when they expire (`<operator id>:<request id>`), so the one machine that takes a
 * due entry off tells the agent its request expired.
 */
export const AUTHORITY_REQUEST_EXPIRY_KEY = 'authority:oidc-request-expiry';

/** A pending request is kept until it expires and a day after, so a read says `expired` instead of not found. */
export function pendingAuthorityRequestTtlSeconds(record: Pick<AuthoritySetupRequestRecord, 'expires_at'>, now = Date.now()): number {
  const left = Math.ceil((new Date(record.expires_at).getTime() - now) / 1000);
  return Math.max(1, left) + AUTHORITY_COMPLETED_REQUEST_TTL_SECONDS;
}

export function authoritySetupKmsContext(operatorId: string, sessionRef: string) {
  return { operator_id: operatorId, session_ref: sessionRef, store: 'authority_oidc_setup' };
}

function authorityRequestKmsContext(operatorId: string, requestId: string) {
  return { operator_id: operatorId, request_id: requestId, store: 'authority_oidc_request' };
}

export function authorityApprovalUrl(requestId: string): string {
  return new URL(
    `/app/approve/authority/${encodeURIComponent(requestId)}`,
    deployment().dashboardUrl,
  ).toString();
}

export function authorityRequestProjection(record: AuthoritySetupRequestRecord) {
  const status = record.status === 'pending' && new Date(record.expires_at).getTime() <= Date.now()
    ? 'expired'
    : record.status;
  return {
    request_id: record.request_id,
    status,
    approval_url: authorityApprovalUrl(record.request_id),
    created_at: record.created_at,
    expires_at: record.expires_at,
    ...(record.completed_at ? { completed_at: record.completed_at } : {}),
    ...(record.rejected_at ? { rejected_at: record.rejected_at } : {}),
    ...(record.result ? { result: record.result } : {}),
  };
}

export async function saveAuthorityRequest(
  services: Services,
  record: AuthoritySetupRequestRecord,
  ttlSeconds: number,
): Promise<void> {
  const encrypted = await services.kms.encrypt(
    JSON.stringify(record),
    authorityRequestKmsContext(record.operator_id, record.request_id),
  );
  await services.redis.set(AUTHORITY_REQUEST_KEY + record.request_id, encrypted.ciphertext, 'EX', ttlSeconds);
}

export async function createAuthorityRequest(
  services: Services,
  record: AuthoritySetupRequestRecord,
): Promise<boolean> {
  const encrypted = await services.kms.encrypt(
    JSON.stringify(record),
    authorityRequestKmsContext(record.operator_id, record.request_id),
  );
  const result = await services.redis.set(
    AUTHORITY_REQUEST_KEY + record.request_id,
    encrypted.ciphertext,
    'EX',
    pendingAuthorityRequestTtlSeconds(record),
    'NX',
  );
  if (result !== 'OK') return false;
  await services.redis.zadd(AUTHORITY_REQUEST_EXPIRY_KEY, new Date(record.expires_at).getTime(), expiryMember(record));
  return true;
}

function expiryMember(record: Pick<AuthoritySetupRequestRecord, 'operator_id' | 'request_id'>): string {
  return `${record.operator_id}:${record.request_id}`;
}

/**
 * A request was approved or declined: tell the agent it was for, and drop it from the expiry list. A failure is logged
 * and never undoes the decision.
 */
export async function announceAuthorityDecision(
  services: Pick<Services, 'registries' | 'redis'>,
  record: AuthoritySetupRequestRecord,
  result: 'approved' | 'rejected' | 'expired',
): Promise<void> {
  await services.redis.zrem(AUTHORITY_REQUEST_EXPIRY_KEY, expiryMember(record)).catch(() => 0);
  const agentId = record.request['agent_id'];
  if (typeof agentId !== 'string' || agentId.length === 0) return;
  await announceDecision(services.registries, {
    operatorId: record.operator_id,
    agentId,
    kind: 'authority_request',
    itemId: record.request_id,
    result,
  });
}

/**
 * Requests that expired while nobody decided them: each is taken off the expiry list by exactly one machine (the one
 * whose removal counted), and its agent is told. Returns how many were announced.
 */
export async function announceExpiredAuthorityRequests(
  services: Pick<Services, 'redis' | 'kms' | 'registries'>,
  now = Date.now(),
  limit = 100,
): Promise<number> {
  const due = await services.redis.zrangebyscore(AUTHORITY_REQUEST_EXPIRY_KEY, '-inf', now, 'LIMIT', 0, limit);
  let announced = 0;
  for (const member of due) {
    if ((await services.redis.zrem(AUTHORITY_REQUEST_EXPIRY_KEY, member)) !== 1) continue;
    const split = member.indexOf(':');
    if (split <= 0) continue;
    try {
      const record = await loadAuthorityRequest(services, member.slice(0, split), member.slice(split + 1));
      if (record.status !== 'pending' || new Date(record.expires_at).getTime() > now) continue;
      await announceAuthorityDecision(services, record, 'expired');
      announced += 1;
    } catch (error) {
      // A record that is gone (decided long ago) has nothing to say; anything else is logged and not retried.
      if (!(error instanceof NotFoundError)) console.error('[authority] announcing an expired request failed:', safeErrorSummary(error));
    }
  }
  return announced;
}

export async function loadAuthorityRequest(
  services: Pick<Services, 'redis' | 'kms'>,
  operatorId: string,
  requestId: string,
): Promise<AuthoritySetupRequestRecord> {
  const encrypted = await services.redis.get(AUTHORITY_REQUEST_KEY + requestId);
  if (!encrypted) throw new NotFoundError('AuthorityRequest', requestId);
  const plaintext = await services.kms.decrypt(
    encrypted,
    authorityRequestKmsContext(operatorId, requestId),
  ).catch(() => { throw new NotFoundError('AuthorityRequest', requestId); });
  const record = JSON.parse(plaintext) as AuthoritySetupRequestRecord;
  if (record.operator_id !== operatorId || record.request_id !== requestId) {
    throw new NotFoundError('AuthorityRequest', requestId);
  }
  return record;
}

export function assertAuthorityRequestPending(record: AuthoritySetupRequestRecord): void {
  if (record.status === 'completed') return;
  if (record.status === 'rejected') {
    throw new ConflictError('This Authority request was declined');
  }
  if (new Date(record.expires_at).getTime() <= Date.now()) {
    throw new StackError('This Authority request has expired', 'AUTHORITY_REQUEST_EXPIRED', 410);
  }
}
