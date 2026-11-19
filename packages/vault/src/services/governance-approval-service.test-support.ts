// The in-memory repository and the requests the GovernanceApprovalService tests build on.

import { expect } from 'vitest';
import { GovernanceApprovalRequiredError } from '@stack/shared';
import { GovernanceApprovalService, type GovernanceApprovalDeps } from './governance-approval-service.js';
import type { GovernanceApprovalRow } from '../repositories/governance-approval-repo.js';

export const OP = 'op_test';

export function makeService(opts: {
  partnerOf?: (operatorId: string) => Promise<{ partner_operator_id: string; external_customer_id: string | null } | undefined>;
  /** The actions a deployment adds to the engine's own; none by default. */
  actions?: { get(action: string): unknown };
  /** How many channels the pending-approval event reaches (the engine's `dispatched`); one by default. */
  dispatched?: number;
  /** The owner mail's own failure, to prove it never fails or delays the request. */
  mailOwnerFails?: boolean;
} = {}) {
  const rows = new Map<string, GovernanceApprovalRow>();
  const notifications: Array<{ operatorId: string; eventType: string; payload: Record<string, unknown> }> = [];
  const ownerMails: Array<{ operatorId: string; eventType: string; summary?: string; payload: Record<string, unknown> }> = [];
  const repo = {
    async insert(input: Record<string, unknown>) {
      const row = {
        member_id: null,
        status: 'pending',
        decided_at: null,
        consumed_at: null,
        consumed_idempotency_key_hash: null,
        created_at: new Date(),
        ...input,
      } as unknown as GovernanceApprovalRow;
      rows.set(row.id, row);
      return row;
    },
    async insertIdenticalOnce(input: Record<string, unknown>) {
      const existing = [...rows.values()].find((r) =>
        r.operator_id === input['operator_id'] && r.action === input['action'] &&
        r.resource_id === input['resource_id'] && r.payload_hash === input['payload_hash'] &&
        r.member_id === (input['member_id'] ?? null) && ['pending', 'approved'].includes(r.status));
      if (existing) return { row: existing, created: false };
      return { row: await repo.insert(input), created: true };
    },
    async findById(id: string) {
      return rows.get(id);
    },
    async findByIdForOperator(id: string, operatorId: string) {
      const r = rows.get(id);
      return r && r.operator_id === operatorId ? r : undefined;
    },
    async listForOperator(operatorId: string) {
      return [...rows.values()].filter((r) => r.operator_id === operatorId);
    },
    async decide(id: string, decision: 'approved' | 'rejected') {
      const r = rows.get(id);
      if (!r || r.status !== 'pending') return undefined;
      Object.assign(r, { status: decision, decided_at: new Date() });
      return r;
    },
    async consume(id: string) {
      const r = rows.get(id);
      if (!r || r.status !== 'approved') return undefined;
      Object.assign(r, { status: 'consumed', consumed_at: new Date() });
      return r;
    },
    async consumeAuthorityIdempotently(input: {
      id: string;
      operatorId: string;
      action: string;
      resourceId: string;
      payloadHash: string;
      idempotencyKeyHash: string;
      now: Date;
    }) {
      const r = rows.get(input.id);
      if (!r || r.operator_id !== input.operatorId) return undefined;
      if (
        r.status === 'approved' &&
        r.action === input.action &&
        r.resource_id === input.resourceId &&
        r.payload_hash === input.payloadHash &&
        r.expires_at > input.now
      ) {
        Object.assign(r, {
          status: 'consumed',
          consumed_at: input.now,
          consumed_idempotency_key_hash: input.idempotencyKeyHash,
        });
        return { row: r, consumedNow: true };
      }
      return { row: r, consumedNow: false };
    },
    async expire(id: string) {
      const r = rows.get(id);
      if (!r || r.status !== 'pending') return undefined;
      Object.assign(r, { status: 'expired' });
      return r;
    },
    async sweepExpired() {
      return 0;
    },
    findActivePartnerOf: opts.partnerOf ?? (async () => undefined),
  };
  const notification = {
    async publishEvent(evt: { operatorId: string; eventType: string; payload: Record<string, unknown> }) {
      notifications.push(evt);
      return { dispatched: opts.dispatched ?? 1 };
    },
    async mailOwner(evt: { operatorId: string; eventType: string; summary?: string; payload: Record<string, unknown> }) {
      if (opts.mailOwnerFails) throw new Error('mail service down for owner@example.com');
      ownerMails.push(evt);
      return true;
    },
  };
  const svc = new GovernanceApprovalService({
    repo,
    notification,
    dashboardUrl: 'https://getstack.run',
    ...(opts.actions ? { actions: opts.actions } : {}),
  } as unknown as GovernanceApprovalDeps);
  return { svc, rows, notifications, ownerMails };
}

export const payload = { detector_key: 'prompt_injection', enabled: false };
export const baseReq = {
  operatorId: OP,
  memberId: null,
  action: 'detector_config_upsert' as const,
  resourceId: 'prompt_injection',
  payload,
  summary: 'Disable prompt_injection detector',
  requestedVia: 'operator_key' as const,
};

export async function createPending(svc: GovernanceApprovalService): Promise<string> {
  try {
    await svc.requireApproval(baseReq);
    throw new Error('should have thrown');
  } catch (e) {
    expect(e).toBeInstanceOf(GovernanceApprovalRequiredError);
    const m = (e as Error).message.match(/gvr_[A-Za-z0-9_-]+/);
    expect(m).toBeTruthy();
    return m![0];
  }
}
