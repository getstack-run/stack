// The in-memory collaborators and the signed requests the inbound webhook service tests build on.

import { vi } from 'vitest';
import { createHmac } from 'node:crypto';
import { Buffer } from 'node:buffer';
import type { InboundWebhookServiceDeps } from './inbound-webhook-service.js';
import type {
  InboundWebhookRepository,
  InboundWebhookRow,
} from '../repositories/inbound-webhook-repo.js';
import type { InboundWebhookReceiptsRepository } from '../repositories/inbound-webhook-receipts-repo.js';
import type { AgentRepository } from '../repositories/agent-repo.js';
import type { OperatorRepository } from '../repositories/operator-repo.js';
import type { DetectorService } from './detector-service.js';
import type { AuditService } from './audit-service.js';
import type { KmsService } from '../crypto/kms.js';
import { CONTRACT_PLAN_LIMITS } from '@stack/shared';

export const PARTNER_OP = 'op_partner';
export const AGENT_ID = 'agt_main';
export const SECRET = Array(4).fill('0123456789abcdef').join('');
export const DOWNSTREAM_SECRET = Array(4).fill('abcdef0123456789').join('');
export const SLUG = 's_test1234567890test1234567890ab';

export interface MockState {
  rows: InboundWebhookRow[];
  receipts: Set<string>;
  detectorCalls: Array<{ content: string }>;
  detectorVerdict: 'clean' | 'critical';
  forwardCalls: Array<{ url: string; headers: Record<string, string>; body: string }>;
  forwardStatus: number;
  forwardShouldThrow: boolean;
  kmsShouldFailDecrypt: boolean;
  auditCalls: Array<{ action: string; outcome: string }>;
  meterCalls: string[];
  meterShouldRefuse: boolean;
}

/** The service's collaborators in memory. `extractors` are the providers a deployment registers; the engine's own is the generic one. */
export function makeDeps(
  overrides: Partial<MockState> = {},
  extractors?: InboundWebhookServiceDeps['extractors'],
): { deps: InboundWebhookServiceDeps; state: MockState } {
  const state: MockState = {
    rows: [
      {
        id: 'iwh_test',
        operator_id: PARTNER_OP,
        provider: 'generic',
        slug: SLUG,
        forward_url: 'https://downstream.example.com/inbound',
        webhook_secret_encrypted: 'encrypted-blob',
        webhook_secret_previous_encrypted: null,
        webhook_secret_rotated_at: null,
        agent_id: AGENT_ID,
        created_via_grant_id: null,
        generic_config: { signature_header: 'X-Webhook-Signature', signature_algorithm: 'hmac-sha256', dedupe_key_path: 'message_id', content_paths: [] },
        provider_signing_secret_encrypted: 'provider-encrypted-blob',
        created_at: new Date(),
        revoked_at: null,
        last_used_at: null,
        last_block_at: null,
        total_calls: 0,
        total_blocked: 0,
      },
    ],
    receipts: new Set(),
    detectorCalls: [],
    detectorVerdict: 'clean',
    forwardCalls: [],
    forwardStatus: 200,
    forwardShouldThrow: false,
    kmsShouldFailDecrypt: false,
    auditCalls: [],
    meterCalls: [],
    meterShouldRefuse: false,
    ...overrides,
  };

  const repo = {
    async findActiveBySlug(_provider: string, slug: string) {
      const row = state.rows.find((r) => r.slug === slug && r.revoked_at === null);
      return row ?? null;
    },
    async findByIdScoped(id: string, operatorId: string) {
      return state.rows.find((r) => r.id === id && r.operator_id === operatorId) ?? null;
    },
    async listByOperator(operatorId: string) {
      return state.rows.filter((r) => r.operator_id === operatorId);
    },
    async revoke(id: string, operatorId: string) {
      const row = state.rows.find((r) => r.id === id && r.operator_id === operatorId && r.revoked_at === null);
      if (!row) return false;
      row.revoked_at = new Date();
      return true;
    },
    async rotateDownstreamSecret(id: string, operatorId: string, input: { encrypted: string; previousEncrypted: string; rotatedAt: Date }) {
      const row = state.rows.find((r) => r.id === id && r.operator_id === operatorId && !r.revoked_at);
      if (!row) return false;
      row.webhook_secret_encrypted = input.encrypted;
      row.webhook_secret_previous_encrypted = input.previousEncrypted;
      row.webhook_secret_rotated_at = input.rotatedAt;
      return true;
    },
    async setProviderSigningSecret(id: string, operatorId: string, encrypted: string, _provider = 'agentmail', downstreamEncrypted?: string) {
      const row = state.rows.find((r) => r.id === id && r.operator_id === operatorId && !r.revoked_at);
      if (!row) return false;
      row.provider_signing_secret_encrypted = encrypted;
      if (downstreamEncrypted !== undefined) row.webhook_secret_encrypted = downstreamEncrypted;
      return true;
    },
    async bumpCounters(id: string, blocked: boolean) {
      const row = state.rows.find((r) => r.id === id);
      if (!row) return;
      row.total_calls += 1;
      row.last_used_at = new Date();
      if (blocked) {
        row.total_blocked += 1;
        row.last_block_at = new Date();
      }
    },
    async insert(input: { id: string; operator_id: string; provider: string; slug: string; forward_url: string | null;
      webhook_secret_encrypted: string; provider_signing_secret_encrypted?: string | null; agent_id: string | null }) {
      const row: InboundWebhookRow = {
        ...input,
        provider_signing_secret_encrypted: input.provider_signing_secret_encrypted ?? null,
        webhook_secret_previous_encrypted: null,
        webhook_secret_rotated_at: null,
        generic_config: (input as { generic_config?: InboundWebhookRow['generic_config'] }).generic_config ?? null,
        created_via_grant_id: null,
        created_at: new Date(),
        revoked_at: null,
        last_used_at: null,
        last_block_at: null,
        total_calls: 0,
        total_blocked: 0,
      };
      state.rows.push(row);
      return row;
    },
  } as unknown as InboundWebhookRepository;

  const receipts = new Map<string, { state: string; bodyHash: string; attempt: string; metered: boolean; verdict: string | null; firstSeenAt: Date }>();
  const keyOf = (webhookId: string, messageId: string) => `${webhookId}::${messageId}`;
  let attempt = 0;
  const owned = (webhookId: string, messageId: string, attemptId: string) => {
    const row = receipts.get(keyOf(webhookId, messageId));
    return row?.state === 'processing' && row.attempt === attemptId ? row : undefined;
  };
  const receiptsRepo = {
    async claim(webhookId: string, messageId: string, bodyHash: string) {
      const key = keyOf(webhookId, messageId);
      let row = receipts.get(key);
      if (!row) { row = { state: 'pending', bodyHash, attempt: '', metered: false, verdict: null, firstSeenAt: new Date() }; receipts.set(key, row); }
      if (row.bodyHash !== bodyHash) return { state: 'conflict' };
      if (row.state === 'completed') return { state: 'completed' };
      if (row.state === 'processing') return { state: 'busy' };
      row.state = 'processing'; row.attempt = String(++attempt);
      return { state: 'acquired', attemptId: row.attempt, firstSeenAt: row.firstSeenAt, metered: row.metered, scanVerdict: row.verdict };
    },
    async renew(webhookId: string, messageId: string, attemptId: string) { return !!owned(webhookId, messageId, attemptId); },
    async markMetered(webhookId: string, messageId: string, attemptId: string) {
      const row = owned(webhookId, messageId, attemptId); if (!row) return false; row.metered = true; return true;
    },
    async markScanned(webhookId: string, messageId: string, attemptId: string, verdict: string) {
      const row = owned(webhookId, messageId, attemptId); if (!row) return false; row.verdict = verdict; return true;
    },
    async release(webhookId: string, messageId: string, attemptId: string) {
      const row = owned(webhookId, messageId, attemptId); if (!row) return false; row.state = 'pending'; return true;
    },
    async complete(webhookId: string, messageId: string, attemptId: string, blocked: boolean) {
      const row = owned(webhookId, messageId, attemptId); if (!row) return false;
      row.state = 'completed'; state.receipts.add(keyOf(webhookId, messageId));
      await repo.bumpCounters(webhookId, blocked); return true;
    },
  } as unknown as InboundWebhookReceiptsRepository;

  const detector = {
    async scanInput(args: { body: unknown }) {
      state.detectorCalls.push({ content: String(args.body) });
      if (state.detectorVerdict === 'critical') {
        return {
          verdict: 'critical' as const,
          match: { pattern_id: 'PI-001', field_path: 'body', matched_text: 'evil', severity: 'critical' as const },
          llm: null,
          denyReason: 'critical injection pattern matched',
        };
      }
      return {
        verdict: 'clean' as const,
        match: null,
        llm: null,
        denyReason: null,
      };
    },
  } as unknown as DetectorService;

  const audit = {
    async write(input: { action: string; outcome: string }) {
      state.auditCalls.push({ action: input.action, outcome: input.outcome });
    },
  } as unknown as AuditService;

  const kms = {
    async encryptDirect(_buf: Buffer, _opts: unknown) {
      return Buffer.from('encrypted-blob');
    },
    async decryptDirect(_buf: Buffer, _opts: unknown) {
      if (state.kmsShouldFailDecrypt) {
        throw new Error('KMS decrypt failed');
      }
      const purpose = (_opts as { expectedContext?: { purpose?: string } })?.expectedContext?.purpose;
      return Buffer.from(purpose === 'inbound_provider_signing_secret' ? SECRET : DOWNSTREAM_SECRET, 'utf8');
    },
  } as unknown as KmsService;

  const operatorRepo = {
    async findById(id: string) {
      if (id !== PARTNER_OP) return null;
      return { id, tier: 'free', is_partner: true } as never;
    },
  } as unknown as OperatorRepository;

  const agentRepo = {
    async findById(id: string) {
      if (id !== AGENT_ID) return null;
      return { id, operator_id: PARTNER_OP, status: 'active', passport_blocked: false } as never;
    },
  } as unknown as AgentRepository;

  const fetchFn = vi.fn(async (url: string, init: RequestInit) => {
    if (state.forwardShouldThrow) {
      throw new Error('downstream connection refused');
    }
    state.forwardCalls.push({
      url,
      headers: init.headers as Record<string, string>,
      body: init.body as string,
    });
    return new Response(null, { status: state.forwardStatus });
  }) as unknown as typeof globalThis.fetch;

  const deps: InboundWebhookServiceDeps = {
    repo,
    receiptsRepo,
    agentRepo,
    operatorRepo,
    detector,
    audit,
    kms,
    ...(extractors ? { extractors } : {}),
    entitlements: { resolve: async () => ({ limits: CONTRACT_PLAN_LIMITS, tier: 'free' }) as never },
    baseUrl: 'https://api.getstack.run',
    fetchFn,
    urlGuard: () => undefined, // skip SSRF check in tests
    // Stands in for the enforceOverage closure the API layer injects. Refusal
    // throws the same 402-shaped error the wallet path raises.
    meterAction: async (operatorId: string) => {
      state.meterCalls.push(operatorId);
      if (state.meterShouldRefuse) {
        throw Object.assign(new Error('allowance spent, wallet empty'), {
          code: 'INSUFFICIENT_BALANCE',
          statusCode: 402,
        });
      }
    },
  };

  return { deps, state };
}

export function hmacBody(body: string, secret: string): string {
  return createHmac('sha256', secret).update(body).digest('hex');
}

export function buildPayload(messageId = 'msg_test'): { raw: Buffer; parsed: unknown; sig: string } {
  const parsed = {
    message_id: messageId,
    subject: 'Quarterly invoice',
    text: 'Please find the Q2 invoice attached. Total $14,200. Net 30.',
  };
  const raw = Buffer.from(JSON.stringify(parsed), 'utf8');
  return { raw, parsed, sig: hmacBody(raw.toString('utf8'), SECRET) };
}

export function receiveInput(messageId = 'msg_retry') {
  const { raw, parsed, sig } = buildPayload(messageId);
  return { provider: 'generic', slug: SLUG, rawBody: raw, parsedBody: parsed,
    requestPath: '/v1/inbound/generic/' + SLUG, headers: { 'x-webhook-signature': `sha256=${sig}` } };
}
