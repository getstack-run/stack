// InboundWebhookService.
//
// Hosted inbound webhook surface. Operator creates an inbound_webhooks
// row, copies the (one-time-shown) URL + HMAC secret into a provider's
// webhook config, and STACK becomes the inbound path:
//
//   provider POST → /v1/inbound/:provider/:slug
//     → HMAC verify (per-provider extractor)
//     → idempotency dedupe (skip if (webhook_id, message_id) already seen)
//     → DetectorService.scanInput (mode='enforced')
//       → security_event claim emitted by DetectorService on non-clean
//     → forward to operator's forward_url with X-Stack-* headers and Standard Webhooks
//       signature headers
//     → audit row + counter bump
//
// Substrate is universal; per-provider plugins live under
// ./inbound-webhook-extractors/.
//
// Status code matrix (caller maps to HTTP):
//   200 clean | 200 blocked | 200 deduplicated | 400 bad_signature
//   404 missing_slug_or_revoked | 410 revoked_during_flight | 500 infra_failure

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { safeErrorSummary } from '@stack/shared';
import {
  generateWebhookSecret,
  signStandardWebhook,
  webhookRotationLive,
  WEBHOOK_SECRET_ROTATION_GRACE_MS,
  ids,
  ConflictError,
  NotFoundError,
  ForbiddenError,
  InvalidRequestError,
  UnsafeUrlError,
  INBOUND_WEBHOOK_FORWARD_TIMEOUT_MS,
  type CreateInboundWebhookInput,
  type CreateInboundWebhookResult,
  type InboundWebhookView,
} from '@stack/shared';
import type {
  GenericExtractorConfig,
  InboundDeliverySource,
  InboundExtractorSource,
  InboundManagedEndSource,
  InboundWebhookExtractor,
} from './inbound-webhook-extractors/index.js';
import type { EntitlementResolver } from './entitlements/entitlements.js';
import type { InboundWebhookRepository, InboundWebhookRow } from '../repositories/inbound-webhook-repo.js';
import type { InboundWebhookReceiptsRepository } from '../repositories/inbound-webhook-receipts-repo.js';
import type { AgentRepository } from '../repositories/agent-repo.js';
import type { OperatorRepository } from '../repositories/operator-repo.js';
import type { DetectorService } from './detector-service.js';
import type { AuditService } from './audit-service.js';
import type { KmsService } from '../crypto/kms.js';
import { getExtractor } from './inbound-webhook-extractors/index.js';
import { openDownstreamSecret } from './inbound-webhook-secret.js';
import { ManagedInboundWebhooks } from './inbound-webhook-managed-rows.js';
import { assertPublicUrl, publicFetch } from '@stack/shared';

export interface InboundWebhookServiceDeps {
  repo: InboundWebhookRepository;
  receiptsRepo: InboundWebhookReceiptsRepository;
  agentRepo: AgentRepository;
  operatorRepo: OperatorRepository;
  detector: DetectorService;
  audit: AuditService;
  kms: KmsService;
  /** The plan an operator's endpoint count is capped by. */
  entitlements: Pick<EntitlementResolver, 'resolve'>;
  /** The providers a deployment adds to the engine's (the receive route's `:provider`). */
  extractors?: InboundExtractorSource;
  /**
   * The providers a deployment takes the deliveries of itself (see `InboundDeliveryHandler`). Their rows are made by the deployment
   * (`createManaged`), belong to no agent, are not forwarded and are not shown to the owner as webhooks of its own.
   */
  deliveries?: InboundDeliverySource;
  /**
   * What ends a managed provider's side of a row when the owner revokes it (RentAHuman: the endpoint registered at RentAHuman). Called
   * before the row is ended, and the row stays when it throws, so an endpoint is never left at the provider by a row that says it is gone.
   */
  managedEnds?: InboundManagedEndSource;
  /**
   * Count one recorded action against the operator's allowance, throwing
   * (402) when the allowance is spent and the wallet cannot cover overage.
   *
   * Injected rather than imported: the receive route is public and
   * unauthenticated (slug + HMAC IS the auth), so there is no
   * `request.operatorId` at the route layer and this service is the only
   * place that knows who to charge. The API layer closes over
   * `enforceOverage` in `apps/api/src/config/services.ts`.
   *
   * Optional so tests and any non-metered embedding construct the service
   * unchanged.
   */
  meterAction?: (operatorId: string, eventKey: string, accountingDate: Date) => Promise<void>;
  /** Base URL returned in the webhook_url field at create time. Eg. https://api.getstack.run */
  baseUrl: string;
  /** Optional inert transport for tests. Production uses bounded publicFetch. */
  fetchFn?: typeof globalThis.fetch;
  /** Optional URL-guard override for tests (defaults to assertPublicUrl). */
  urlGuard?: (url: string) => Promise<void> | void;
}

export interface ReceiveInput {
  provider: string;
  slug: string;
  rawBody: Buffer;
  parsedBody: unknown;
  requestPath: string;
  headers: Record<string, string | string[] | undefined>;
  /** Inbound source IP — for audit attribution. */
  sourceIp?: string;
}

export interface ReceiveResult {
  /** Maps directly to the HTTP status code the caller should respond with. */
  status: 200 | 400 | 404 | 409 | 410 | 500 | 502 | 503;
  body: {
    decision?: 'clean' | 'blocked' | 'deduplicated' | 'revoked_during_flight';
    reason?: string;
    detector_signals?: string[];
    message_id?: string | null;
    forwarded?: boolean;
    downstream_status?: number;
    truncated_for_scan?: boolean;
    error?: string;
  };
}

interface DecryptedWebhook {
  row: InboundWebhookRow;
  downstreamSecret: string;
  /** The downstream secrets live now: the current one, then the previous for 24 hours after a rotation. */
  downstreamSecrets: string[];
  providerSecret: string | null;
  keySeparationReady: boolean;
}

export interface ConfigureInboundWebhookSigningResult {
  configured: true;
  /** Present only when STACK generated a replacement downstream key. */
  webhook_secret?: string;
}

function secretsEqual(left: string, right: string): boolean {
  const leftHash = createHash('sha256').update(left, 'utf8').digest();
  const rightHash = createHash('sha256').update(right, 'utf8').digest();
  return timingSafeEqual(leftHash, rightHash);
}

export class InboundWebhookService {
  constructor(private deps: InboundWebhookServiceDeps) {}

  private extractorFor(provider: string): InboundWebhookExtractor | null {
    return getExtractor(provider) ?? this.deps.extractors?.get(provider) ?? null;
  }

  async create(
    operatorId: string,
    input: CreateInboundWebhookInput,
  ): Promise<CreateInboundWebhookResult> {
    // Tier cap on count.
    const operator = await this.deps.operatorRepo.findById(operatorId);
    if (!operator) throw new NotFoundError('operator', operatorId);
    const tier = operator.tier ?? 'free';
    const cap = (await this.deps.entitlements.resolve(operatorId)).limits.inboundWebhooks;
    if (cap !== Infinity) {
      const existing = await this.deps.repo.listByOperator(operatorId);
      const active = existing.filter((w) => w.revoked_at === null).length;
      if (active >= cap) {
        throw new ForbiddenError(
          `inbound webhook count cap reached for ${tier} tier (${active}/${cap}). Revoke an existing webhook or upgrade your tier.`,
        );
      }
    }

    // Agent exists + belongs to operator.
    const agent = await this.deps.agentRepo.findById(input.agent_id);
    if (!agent || (agent as { operator_id?: string }).operator_id !== operatorId) {
      throw new NotFoundError('agent', input.agent_id);
    }

    // URL guard on forward_url at create time. assertPublicUrl rejects
    // localhost, RFC 1918, link-local, .internal, etc.
    const guard = this.deps.urlGuard ?? assertPublicUrl;
    if (input.forward_url) {
      try {
        await guard(input.forward_url);
      } catch (error) {
        // An address that is not public is the caller's mistake: a 400 that names the field, not an unhandled 500.
        if (error instanceof UnsafeUrlError) throw new InvalidRequestError('forward_url must be a public address');
        throw error;
      }
    }

    // Provider validity.
    const extractor = this.extractorFor(input.provider);
    if (!extractor) {
      throw new NotFoundError('inbound_webhook_provider', input.provider);
    }

    // Generic config only valid for provider='generic'.
    if (input.generic_config && input.provider !== 'generic') {
      throw new ConflictError(`generic_config is only valid when provider='generic' (got '${input.provider}')`);
    }

    // Incoming authentication and downstream STACK signing are separate trust
    // directions. Generic endpoints receive both values once at creation;
    // AgentMail supplies its incoming provider secret in the later setup call.
    const id = ids.inboundWebhook();
    const slug = ids.inboundWebhookSlug();
    const downstreamSecret = generateWebhookSecret();
    let incomingSecret: string | undefined;
    if (input.provider === 'generic') {
      do incomingSecret = randomBytes(32).toString('hex');
      while (secretsEqual(incomingSecret, downstreamSecret));
    }

    // KMS-wrap the secret with per-operator AAD. Matches the per-
    // operator signing key + service-connections wrap pattern.
    const wrappedBuf = await this.deps.kms.encryptDirect(Buffer.from(downstreamSecret, 'utf8'), {
      operatorId,
      context: {
        operator_id: operatorId,
        webhook_id: id,
        purpose: 'inbound_webhook_downstream_secret',
      },
    });
    const wrappedBase64 = wrappedBuf.toString('base64');
    const wrappedIncomingBase64 = incomingSecret
      ? (await this.deps.kms.encryptDirect(Buffer.from(incomingSecret, 'utf8'), {
          operatorId,
          context: {
            operator_id: operatorId,
            webhook_id: id,
            purpose: 'inbound_provider_signing_secret',
          },
        })).toString('base64')
      : null;

    const row = await this.deps.repo.insert({
      id,
      operator_id: operatorId,
      provider: input.provider,
      slug,
      forward_url: input.forward_url ?? null,
      webhook_secret_encrypted: wrappedBase64,
      provider_signing_secret_encrypted: wrappedIncomingBase64,
      agent_id: input.agent_id,
      generic_config: input.generic_config ?? null,
    });

    return {
      id: row.id,
      provider: row.provider as 'agentmail' | 'generic',
      slug: row.slug,
      webhook_url: `${this.deps.baseUrl}/v1/inbound/${row.provider}/${row.slug}`,
      webhook_secret: downstreamSecret,
      ...(incomingSecret ? { incoming_signing_secret: incomingSecret } : {}),
      agent_id: row.agent_id,
      forward_url: row.forward_url,
      created_at: row.created_at.toISOString(),
      signing_configured: row.provider !== 'agentmail',
    };
  }

  async setProviderSigningSecret(
    id: string,
    operatorId: string,
    secret: string,
    downstreamSecret?: string,
  ): Promise<ConfigureInboundWebhookSigningResult> {
    const row = await this.deps.repo.findByIdScoped(id, operatorId);
    if (!row || row.revoked_at) throw new NotFoundError('inbound_webhook', id);
    const secretProblem = this.extractorFor(row.provider)?.signingSecretProblem?.(secret);
    if (secretProblem) throw new ConflictError(secretProblem);
    if (row.provider === 'generic' && (Buffer.byteLength(secret, 'utf8') < 32 || Buffer.byteLength(secret, 'utf8') > 256 || !secret.trim())) {
      throw new ConflictError('A generic signing secret must contain 32 to 256 bytes');
    }
    if (row.provider !== 'agentmail' && row.provider !== 'generic') {
      throw new ConflictError('Unsupported inbound signing provider');
    }
    if (downstreamSecret !== undefined && (Buffer.byteLength(downstreamSecret, 'utf8') < 32 ||
      Buffer.byteLength(downstreamSecret, 'utf8') > 256 || !downstreamSecret.trim())) {
      throw new ConflictError('A downstream signing secret must contain 32 to 256 bytes');
    }
    let generatedDownstreamSecret: string | undefined;
    if (row.provider === 'generic' && downstreamSecret === undefined) {
      do generatedDownstreamSecret = generateWebhookSecret();
      while (secretsEqual(secret, generatedDownstreamSecret));
      downstreamSecret = generatedDownstreamSecret;
    }
    if (row.provider === 'agentmail' && downstreamSecret === undefined) {
      const existingDownstreamSecret = await this.decryptDownstreamSecret(row);
      if (secretsEqual(secret, existingDownstreamSecret)) {
        throw new ConflictError('Incoming and downstream signing secrets must be different');
      }
    }
    if (downstreamSecret !== undefined && secretsEqual(secret, downstreamSecret)) {
      throw new ConflictError('Incoming and downstream signing secrets must be different');
    }
    const encrypted = await this.deps.kms.encryptDirect(Buffer.from(secret), { operatorId, context: {
      operator_id: operatorId, webhook_id: id,
      purpose: 'inbound_provider_signing_secret',
    } });
    const encryptedDownstream = downstreamSecret === undefined ? undefined : await this.deps.kms.encryptDirect(Buffer.from(downstreamSecret), {
      operatorId, context: { operator_id: operatorId, webhook_id: id, purpose: 'inbound_webhook_downstream_secret' },
    });
    if (!await this.deps.repo.setProviderSigningSecret(id, operatorId, encrypted.toString('base64'), row.provider, encryptedDownstream?.toString('base64'))) {
      throw new NotFoundError('inbound_webhook', id);
    }
    return {
      configured: true,
      ...(generatedDownstreamSecret ? { webhook_secret: generatedDownstreamSecret } : {}),
    };
  }

  /**
   * A fresh downstream signing secret, returned once. The secret it replaces keeps signing the
   * forwards beside it for 24 hours, so a receiver can switch without dropping a delivery.
   */
  async rotateDownstreamSecret(
    id: string,
    operatorId: string,
  ): Promise<{ webhook_secret: string; previous_valid_until: string }> {
    const row = await this.deps.repo.findByIdScoped(id, operatorId);
    if (!row || row.revoked_at) throw new NotFoundError('inbound_webhook', id);
    // A generic row from before key separation has no usable downstream key to keep beside the new one.
    if (row.provider === 'generic' && !row.provider_signing_secret_encrypted) {
      throw new ConflictError('Configure the incoming signing secret before rotating the downstream one');
    }
    const secret = generateWebhookSecret();
    const context = { operator_id: operatorId, webhook_id: id, purpose: 'inbound_webhook_downstream_secret' };
    const encrypted = await this.deps.kms.encryptDirect(Buffer.from(secret, 'utf8'), { operatorId, context });
    // The current secret is read the way a delivery reads it (a row from before the purpose rename
    // included) and kept under the one purpose a delivery reads the previous secret with.
    const previous = await this.deps.kms.encryptDirect(Buffer.from(await this.decryptDownstreamSecret(row), 'utf8'), { operatorId, context });
    const rotatedAt = new Date();
    const rotated = await this.deps.repo.rotateDownstreamSecret(id, operatorId, {
      encrypted: encrypted.toString('base64'),
      previousEncrypted: previous.toString('base64'),
      rotatedAt,
    });
    if (!rotated) throw new NotFoundError('inbound_webhook', id);
    return {
      webhook_secret: secret,
      previous_valid_until: new Date(rotatedAt.getTime() + WEBHOOK_SECRET_ROTATION_GRACE_MS).toISOString(),
    };
  }

  /** Live, non-revoked endpoints. Ungated; counted for visibility only. */
  async countActive(operatorId: string): Promise<number> {
    const rows = await this.deps.repo.listByOperator(operatorId);
    return rows.filter((w) => w.revoked_at === null).length;
  }

  private isManaged(provider: string): boolean {
    return this.deps.deliveries?.get(provider) !== undefined;
  }

  async list(operatorId: string): Promise<InboundWebhookView[]> {
    const rows = await this.deps.repo.listByOperator(operatorId);
    return rows.map((r) => this.toView(r));
  }

  async get(id: string, operatorId: string): Promise<InboundWebhookView> {
    const row = await this.deps.repo.findByIdScoped(id, operatorId);
    if (!row) throw new NotFoundError('inbound_webhook', id);
    return this.toView(row);
  }

  async revoke(id: string, operatorId: string): Promise<{ transitioned: boolean }> {
    const row = await this.deps.repo.findByIdScoped(id, operatorId);
    if (!row) throw new NotFoundError('inbound_webhook', id);
    // A webhook STACK manages is ended at its provider first (RentAHuman's endpoint), then here; it stays when the provider cannot be reached.
    if (this.isManaged(row.provider) && !row.revoked_at) await this.deps.managedEnds?.get(row.provider)?.(operatorId, id);
    const transitioned = await this.deps.repo.revoke(id, operatorId);
    return { transitioned };
  }

  /**
   * A row for a provider the deployment takes the deliveries of itself. It has no agent and no forward address, and no signing secret
   * until `setManagedSecret`: the provider gives its secret when the endpoint is registered, and the row's URL is what it is
   * registered with. Returns the URL to register.
   */
  async createManaged(operatorId: string, provider: string): Promise<{ id: string; slug: string; webhook_url: string }> {
    if (!this.isManaged(provider) || !this.extractorFor(provider)) throw new NotFoundError('inbound_webhook_provider', provider);
    return this.managedRows().create(operatorId, provider);
  }

  /** The secret the provider signs this row's deliveries with, sealed under the row's own context. Until it is set, every delivery is refused 503. */
  async setManagedSecret(id: string, operatorId: string, secret: string): Promise<void> {
    const row = await this.deps.repo.findByIdScoped(id, operatorId);
    if (!row || row.revoked_at || !this.isManaged(row.provider)) throw new NotFoundError('inbound_webhook', id);
    await this.managedRows().setSecret(id, operatorId, secret);
  }

  /** End a managed row: deliveries to it are 404 from now on. Idempotent. */
  async revokeManaged(id: string, operatorId: string): Promise<void> {
    const row = await this.deps.repo.findByIdScoped(id, operatorId);
    if (!row || !this.isManaged(row.provider)) throw new NotFoundError('inbound_webhook', id);
    await this.managedRows().revoke(id, operatorId);
  }

  private managedRows(): ManagedInboundWebhooks {
    return new ManagedInboundWebhooks({ repo: this.deps.repo, kms: this.deps.kms, baseUrl: this.deps.baseUrl });
  }

  /**
   * Public receiver entrypoint. Called by the unauthenticated route
   * handler at POST /v1/inbound/:provider/:slug. Returns a typed
   * result the route maps to HTTP status + JSON body.
   *
   * Failure modes:
   *   - Missing extractor → 404 (provider not in registry)
   *   - Missing slug or already-revoked → 404 (no timing-leak mitigation v1)
   *   - HMAC verify fail → 400 (NOT 401; 401 would leak slug existence)
   *   - Dedupe hit → 200 with {deduplicated: true} (no detector cost)
   *   - Detector throw / KMS fail → 500 (provider will retry; document)
   *   - Revoked mid-flight → 410 Gone
   *   - Detector says critical → 200 with {decision: 'blocked'}
   *   - Clean → 200 with {decision: 'clean', forwarded: bool}
   */
  async receive(input: ReceiveInput): Promise<ReceiveResult> {
    const extractor = this.extractorFor(input.provider);
    if (!extractor) {
      return { status: 404, body: { error: 'unknown_provider' } };
    }

    const decrypted = await this.loadAndDecrypt(input.provider, input.slug);
    if (!decrypted) {
      return { status: 404, body: { error: 'not_found' } };
    }
    const { row, downstreamSecrets, providerSecret, keySeparationReady } = decrypted;
    // A provider the deployment takes the deliveries of: its handler decides what an event does, there is no agent or forward address.
    const handler = this.deps.deliveries?.get(input.provider);
    if ((row.provider === 'agentmail' || handler) && !providerSecret) {
      return { status: 503, body: { error: 'provider_signing_secret_unconfigured', forwarded: false } };
    }
    if (!keySeparationReady) {
      return { status: 503, body: { error: 'signing_key_separation_required', forwarded: false } };
    }

    const config: GenericExtractorConfig | undefined = row.provider === 'generic' ? row.generic_config ?? undefined : undefined;
    const sigResult = extractor.verifySignature({
      rawBody: input.rawBody, requestPath: input.requestPath, headers: input.headers, secret: providerSecret!,
    }, config);
    if (!sigResult.ok) return { status: 400, body: { error: sigResult.reason ?? 'bad_signature' } };

    const bodyHash = createHash('sha256').update(input.rawBody).digest('hex');
    const dedupeKey = extractor.extractDedupeKey({ parsedBody: input.parsedBody, headers: input.headers, config }) ?? `body:${bodyHash}`;
    if (dedupeKey.length > 1024 || dedupeKey.includes('\0')) {
      return { status: 400, body: { error: 'invalid_message_id' } };
    }
    const receipt = await this.deps.receiptsRepo.claim(row.id, dedupeKey, bodyHash);
    if (receipt.state === 'conflict') return { status: 409, body: { error: 'message_id_content_conflict', forwarded: false } };
    if (receipt.state === 'completed') return { status: 200, body: { decision: 'deduplicated', message_id: dedupeKey, forwarded: false } };
    if (receipt.state !== 'acquired') return { status: 503, body: { error: 'delivery_in_progress', forwarded: false } };

    const eventKey = `iwh_${createHash('sha256').update(`${row.id}\0${dedupeKey}`).digest('hex')}`;
    const attemptId = receipt.attemptId;
    let leaseLost = false;
    let renewing = false;
    const ensureLease = async () => {
      if (leaseLost || !await this.deps.receiptsRepo.renew(row.id, dedupeKey, attemptId)) {
        leaseLost = true;
        throw new Error('Inbound delivery lease lost');
      }
    };
    const heartbeat = setInterval(() => {
      if (renewing) return;
      renewing = true;
      void ensureLease().catch(() => { leaseLost = true; }).finally(() => { renewing = false; });
    }, 30_000);
    heartbeat.unref();
    const complete = async (blocked: boolean) => {
      await ensureLease();
      if (!await this.deps.receiptsRepo.complete(row.id, dedupeKey, attemptId, blocked)) {
        leaseLost = true;
        throw new Error('Inbound delivery completion lost its lease');
      }
    };

    try {
      if (!handler) {
        const currentAgent = row.agent_id ? await this.deps.agentRepo.findById(row.agent_id) : null;
        if (!currentAgent || currentAgent.operator_id !== row.operator_id || currentAgent.status !== 'active' || currentAgent.passport_blocked) {
          return { status: 410, body: { decision: 'revoked_during_flight', forwarded: false, message_id: dedupeKey } };
        }
      }
      if (!receipt.metered && this.deps.meterAction) {
        // The API's existing idempotent meter uses this stable event key and
        // first-seen month, including a crash after charging but before marking.
        await this.deps.meterAction(row.operator_id, eventKey, receipt.firstSeenAt);
        if (!await this.deps.receiptsRepo.markMetered(row.id, dedupeKey, attemptId)) {
          leaseLost = true;
          throw new Error('Inbound delivery metering lost its lease');
        }
      }

      let verdict = receipt.scanVerdict;
      // What a handler is given is the event's ids (a wake never carries the text), so a managed provider's payload is not scanned:
      // text a stranger wrote into it could only keep the owner's agent from being told.
      if (!verdict && handler) {
        verdict = 'clean';
        if (!await this.deps.receiptsRepo.markScanned(row.id, dedupeKey, attemptId, verdict)) {
          leaseLost = true;
          throw new Error('Inbound scan lost its lease');
        }
      }
      if (!verdict) {
        const scan = extractor.extractScanContent({ parsedBody: input.parsedBody, rawBody: input.rawBody, config });
        if (scan.truncated) {
          await this.writeAudit(row, 'blocked', input);
          await complete(true);
          return { status: 200, body: { decision: 'blocked', reason: 'scan_content_too_large', forwarded: false,
            truncated_for_scan: true, message_id: dedupeKey } };
        }
        const scanOperator = await this.deps.operatorRepo.findById(row.operator_id);
        if (!scanOperator) throw new Error('Inbound operator unavailable');
        let scanResult: Awaited<ReturnType<DetectorService['scanInput']>>;
        try {
          scanResult = await this.deps.detector.scanInput({
            ctx: { operatorId: row.operator_id, agentId: row.agent_id ?? 'agt_inbound_unknown', mode: 'enforced', tier: scanOperator.tier },
            body: scan.content, fieldPath: 'inbound_webhook.content',
            metadata: { inbound_webhook_id: row.id, provider: row.provider, provider_message_id: dedupeKey,
              truncated_for_scan: false, source_ip: input.sourceIp },
          });
        } catch {
          console.error('[InboundWebhookService.receive] detector failed');
          return { status: 500, body: { error: 'detector_failure', forwarded: false } };
        }
        if (scanResult.denyReason || scanResult.verdict === 'critical') {
          await this.writeAudit(row, 'blocked', input);
          await complete(true);
          return { status: 200, body: { decision: 'blocked', reason: scanResult.denyReason ?? 'critical_detector_verdict',
            detector_signals: this.summariseSignals(scanResult), forwarded: false, truncated_for_scan: false, message_id: dedupeKey } };
        }
        verdict = scanResult.verdict;
        if (!await this.deps.receiptsRepo.markScanned(row.id, dedupeKey, attemptId, verdict)) {
          leaseLost = true;
          throw new Error('Inbound scan lost its lease');
        }
      }

      // Recheck current authority even when reusing a completed scan on retry.
      const refreshed = await this.deps.repo.findByIdScoped(row.id, row.operator_id);
      const agent = row.agent_id ? await this.deps.agentRepo.findById(row.agent_id) : null;
      if (!refreshed || refreshed.revoked_at !== null || (!handler && (!agent || agent.operator_id !== row.operator_id ||
        agent.status !== 'active' || agent.passport_blocked))) {
        await this.writeAudit(row, 'revoked_during_flight', input);
        return { status: 410, body: { decision: 'revoked_during_flight', forwarded: false, message_id: dedupeKey } };
      }

      let downstreamStatus: number | undefined;
      if (handler) {
        try {
          await ensureLease();
          await handler({
            operatorId: row.operator_id, webhookId: row.id, provider: row.provider,
            parsedBody: input.parsedBody, headers: input.headers, deliveryId: dedupeKey,
          });
        } catch {
          await this.writeAudit(row, 'forward_failed', input);
          return { status: leaseLost ? 503 : 502, body: { error: leaseLost ? 'delivery_lease_lost' : 'delivery_failed', forwarded: false, message_id: dedupeKey } };
        }
      } else if (row.forward_url) {
        try {
          const guard = this.deps.urlGuard ?? assertPublicUrl;
          await guard(row.forward_url);
          await ensureLease();
          const result = await this.forwardToDownstream({ forwardUrl: row.forward_url, rawBody: input.rawBody,
            parsedBody: input.parsedBody, secrets: downstreamSecrets, webhookId: row.id, provider: row.provider, scanVerdict: verdict, eventKey });
          downstreamStatus = result.status;
          if (result.status < 200 || result.status >= 300) throw new Error('Downstream rejected delivery');
        } catch {
          await this.writeAudit(row, 'forward_failed', input);
          return { status: leaseLost ? 503 : 502, body: { error: leaseLost ? 'delivery_lease_lost' : 'forward_failed',
            forwarded: false, message_id: dedupeKey, ...(downstreamStatus !== undefined ? { downstream_status: downstreamStatus } : {}) } };
        }
      }
      await this.writeAudit(row, 'success', input);
      await complete(false);
      return { status: 200, body: { decision: 'clean', forwarded: !handler && !!row.forward_url, message_id: dedupeKey,
        truncated_for_scan: false, ...(downstreamStatus !== undefined ? { downstream_status: downstreamStatus } : {}) } };
    } catch (error) {
      if ((error as { statusCode?: number })?.statusCode === 402) throw error;
      console.error('[InboundWebhookService.receive] delivery processing failed');
      return { status: leaseLost ? 503 : 500, body: { error: leaseLost ? 'delivery_lease_lost' : 'processing_failure', forwarded: false } };
    } finally {
      clearInterval(heartbeat);
      // A completed receipt cannot be reopened by this compare-and-set. If the
      // database is unavailable, expiry permits a later fenced retry instead.
      await this.deps.receiptsRepo.release(row.id, dedupeKey, attemptId).catch(() => {
        console.error('[InboundWebhookService.receive] receipt release failed');
      });
    }
  }
  // ─── Internals ─────────────────────────────────────────────────────

  private async loadAndDecrypt(provider: string, slug: string): Promise<DecryptedWebhook | null> {
    const row = await this.deps.repo.findActiveBySlug(provider, slug);
    if (!row) return null;
    // Generic rows created before key separation stored one key in
    // webhook_secret_encrypted. Refuse them without probing or reusing it.
    if (row.provider === 'generic' && !row.provider_signing_secret_encrypted) {
      return { row, downstreamSecret: '', downstreamSecrets: [], providerSecret: null, keySeparationReady: false };
    }
    try {
      const downstreamSecret = await this.decryptDownstreamSecret(row);
      const downstreamSecrets = [downstreamSecret];
      if (row.webhook_secret_previous_encrypted && webhookRotationLive(row.webhook_secret_rotated_at)) {
        // The old secret is a courtesy to a receiver that has not switched yet: losing it must not stop the delivery.
        try {
          const previous = await this.deps.kms.decryptDirect(Buffer.from(row.webhook_secret_previous_encrypted, 'base64'), {
            operatorId: row.operator_id,
            expectedContext: { operator_id: row.operator_id, webhook_id: row.id, purpose: 'inbound_webhook_downstream_secret' },
          });
          downstreamSecrets.push(previous.toString('utf8'));
        } catch {
          console.error('[InboundWebhookService.loadAndDecrypt] previous secret unreadable');
        }
      }
      let providerSecret: string | null = null;
      if (row.provider_signing_secret_encrypted) {
        const decryptedProvider = await this.deps.kms.decryptDirect(Buffer.from(row.provider_signing_secret_encrypted, 'base64'), {
          operatorId: row.operator_id, expectedContext: {
            operator_id: row.operator_id, webhook_id: row.id, purpose: 'inbound_provider_signing_secret',
          },
        });
        providerSecret = decryptedProvider.toString('utf8');
      }
      return {
        row,
        downstreamSecret,
        downstreamSecrets,
        providerSecret,
        keySeparationReady: providerSecret !== null && !secretsEqual(providerSecret, downstreamSecret),
      };
    } catch {
      console.error('[InboundWebhookService.loadAndDecrypt] KMS decrypt failed');
      return null;
    }
  }

  private async decryptDownstreamSecret(row: InboundWebhookRow): Promise<string> {
    // AgentMail already had separate keys before the purpose was renamed, so its rows made earlier are sealed
    // under the earlier purpose. A generic row from then held one key for both directions and never receives
    // this compatibility path (loadAndDecrypt refuses it until distinct keys are configured).
    const { plain } = await openDownstreamSecret(this.deps.kms, {
      operatorId: row.operator_id,
      webhookId: row.id,
      sealed: row.webhook_secret_encrypted,
      allowLegacy: row.provider === 'agentmail',
    });
    return plain.toString('utf8');
  }

  private async forwardToDownstream(args: {
    forwardUrl: string;
    rawBody: Buffer;
    parsedBody: unknown;
    secrets: readonly string[];
    webhookId: string;
    provider: string;
    scanVerdict: 'clean' | 'warning' | 'critical';
    eventKey: string;
  }): Promise<{ status: number }> {
    const fetchFn = this.deps.fetchFn ?? publicFetch;
    // Outbound signature: Standard Webhooks over the JSON-stringified parsed body, keyed with
    // the downstream-only secret(s), so a sender that knows the inbound key cannot forge a
    // STACK-to-receiver delivery. The message id is the event key: the same on every attempt at
    // one event, so a receiver can ignore one it has handled.
    const outboundBody = JSON.stringify(args.parsedBody);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), INBOUND_WEBHOOK_FORWARD_TIMEOUT_MS);
    try {
      const res = await fetchFn(args.forwardUrl, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...signStandardWebhook({ id: args.eventKey, body: outboundBody, secrets: args.secrets }),
          'x-stack-scan-verdict': args.scanVerdict,
          'x-stack-inbound-webhook-id': args.webhookId,
          'x-stack-provider': args.provider,
          'idempotency-key': args.eventKey,
          'x-stack-event-id': args.eventKey,
        },
        body: outboundBody,
        signal: controller.signal,
        redirect: 'error',
      });
      return { status: res.status };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private async writeAudit(
    row: InboundWebhookRow,
    outcome: 'success' | 'blocked' | 'forward_failed' | 'revoked_during_flight',
    input: ReceiveInput,
  ): Promise<void> {
    try {
      await this.deps.audit.write({
        ctx: {
          trace_id: ids.session(),
          span_id: ids.session(),
          operator_id: row.operator_id,
          agent_id: row.agent_id ?? 'system',
          passport_jti: 'none',
        },
        layer: 'system',
        action: `inbound_webhook.receive.${row.provider}`,
        outcome: outcome === 'success' ? 'success' : 'failure',
        duration_ms: 0,
      });
      // Source-IP + inbound_webhook_id details land in the SecurityEvent
      // metadata on block; audit row carries the chain-binding context
      // only. The (timestamp, operator_id, action) tuple is sufficient
      // to join back to the per-receive forensic detail via the security
      // event when present.
      void input.sourceIp;
    } catch (err) {
      console.error('[InboundWebhookService.writeAudit] failed:', safeErrorSummary(err));
    }
  }

  private summariseSignals(scan: Awaited<ReturnType<DetectorService['scanInput']>>): string[] {
    const signals: string[] = [];
    if (scan.match) {
      signals.push(`prompt_injection_l1_l2:${scan.match.pattern_id}`);
    }
    if (scan.llm && !scan.llm.degraded && scan.llm.verdict !== 'clean') {
      signals.push(`prompt_injection_l3:${scan.llm.verdict}`);
    }
    return signals;
  }

  private toView(row: InboundWebhookRow): InboundWebhookView {
    return {
      id: row.id,
      provider: row.provider,
      managed: this.isManaged(row.provider),
      slug: row.slug,
      webhook_url: `${this.deps.baseUrl}/v1/inbound/${row.provider}/${row.slug}`,
      agent_id: row.agent_id,
      forward_url: row.forward_url,
      created_at: row.created_at.toISOString(),
      revoked_at: row.revoked_at?.toISOString() ?? null,
      last_used_at: row.last_used_at?.toISOString() ?? null,
      last_block_at: row.last_block_at?.toISOString() ?? null,
      total_calls: row.total_calls,
      total_blocked: row.total_blocked,
      signing_configured: row.provider !== 'agentmail' || !!row.provider_signing_secret_encrypted,
    };
  }
}
