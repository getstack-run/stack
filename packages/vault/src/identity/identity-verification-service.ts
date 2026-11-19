import {
  ids,
  NotFoundError,
  ForbiddenError,
  type Database,
  type PassportClaimRef,
  IdentityVerificationSessionStatus,
  type IdentityVerificationSessionView,
  identityVerificationSessions,
  operators,
} from '@stack/shared';
import { eq, and, gt, inArray, isNull, lte, sql } from 'drizzle-orm';
import { safeErrorSummary } from '@stack/shared';
import { createHash } from 'node:crypto';
import { IdentityProviderRegistry } from './provider-registry.js';
import { IdentityRepository } from './identity-repo.js';
import type { OperatorRepository } from '../repositories/operator-repo.js';
import type { KmsService } from '../crypto/kms.js';
import type { InitiateResult, VerificationContext, VerifiedClaim } from './types.js';
import type { ClaimRegistryService } from '../services/claim-registry-service.js';

/** Who started a verification session. Only an owner session verifies the operator. */
export type VerificationInitiator = 'owner' | 'member';

/** The one provider whose document-and-selfie check verifies an account owner. */
const OWNER_VERIFICATION_PROVIDER = 'stripe_identity';

const TTL_DAYS: Record<string, number> = {
  '30d': 30,
  '90d': 90,
  '180d': 180,
  '1y': 365,
};

export class IdentityVerificationService {
  private operatorRepo: OperatorRepository | null = null;
  /**
   * late-wired claim registry. When set
   * complete/completeWithToken/grantDelegation dual-write a signed
   * operator-scoped identity_claim envelope alongside the legacy
   * identity_claims row. PII NEVER enters the envelope. Mirror of
   * SecurityEventService.setClaimRegistryService.
   */
  private claimRegistry: ClaimRegistryService | null = null;
  private authorityInvalidationHandler:
    | ((operatorId: string, identityClaimId: string, reason: string) => Promise<void>)
    | null = null;

  /** What a verification by a provider costs once the first one is free. An install charges nothing. */
  private verificationPrice: (providerKey: string) => number = () => 0;

  constructor(
    private db: Database,
    private registry: IdentityProviderRegistry,
    private identityRepo: IdentityRepository,
    private kms: KmsService,
  ) {}

  /** The deployment's price list, in cents, for the price shown beside each provider. */
  setVerificationPricing(price: (providerKey: string) => number): void {
    this.verificationPrice = price;
  }

  setOperatorRepo(repo: OperatorRepository) {
    this.operatorRepo = repo;
  }

  setClaimRegistryService(claimRegistry: ClaimRegistryService): void {
    this.claimRegistry = claimRegistry;
  }

  setAuthorityInvalidationHandler(
    handler: (operatorId: string, identityClaimId: string, reason: string) => Promise<void>,
  ): void {
    this.authorityInvalidationHandler = handler;
  }

  /**
   * emit an operator-scoped identity_claim
   * envelope for an identity_claims row. Best-effort: claim emission
   * never fails the legacy write. PII NEVER enters the envelope —
   * only the assertion_hash (sha256 of the encrypted assertion bytes)
   * binds the envelope to the legacy row's encrypted content.
   */
  private async emitIdentityClaimEnvelope(args: {
    operatorId: string;
    rowId: string;
    providerKey: string;
    layer: 'humanity' | 'identity' | 'delegation';
    claimType: string;
    assuranceLevel: 'low' | 'substantial' | 'high';
    verifiedAt: Date;
    expiresAt: Date;
    assertionEncrypted: string;
    delegatedScopes?: string[];
  }): Promise<void> {
    if (!this.claimRegistry) return;
    try {
      const assertionHash = createHash('sha256').update(args.assertionEncrypted).digest('hex');
      const result = await this.claimRegistry.registerClaim({
        operatorId: args.operatorId,
        subjectOverride: 'operator',
        claimType: 'identity_claim',
        payload: {
          type: 'identity_claim',
          identity_claim_row_id: args.rowId,
          provider_key: args.providerKey,
          layer: args.layer,
          claim_type: args.claimType,
          assurance_level: args.assuranceLevel,
          verified_at: args.verifiedAt.getTime(),
          expires_at: args.expiresAt.getTime(),
          assertion_hash: assertionHash,
          ...(args.delegatedScopes ? { delegated_scopes: args.delegatedScopes } : {}),
        },
      });
      try {
        await this.identityRepo.linkClaim(args.rowId, result.claimId);
      } catch (linkErr) {
        console.error('identity_claim linkClaim failed:', safeErrorSummary(linkErr));
      }
    } catch (err) {
      console.error('identity_claim emission failed:', safeErrorSummary(err));
    }
  }

  /** Cap a claim's expires_at based on operator's identity_claim_ttl setting. */
  private async _capExpiry(operatorId: string, providerExpiry: Date): Promise<Date> {
    if (!this.operatorRepo) return providerExpiry;
    const operator = await this.operatorRepo.findById(operatorId);
    if (!operator) return providerExpiry;
    const days = TTL_DAYS[operator.identity_claim_ttl] ?? 365;
    const maxExpiry = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
    return providerExpiry > maxExpiry ? maxExpiry : providerExpiry;
  }

  // ── Verification Flow ─────────────────────────────────────────────

  /** Start a verification flow with a specific provider. */
  async initiate(
    operatorId: string,
    providerKey: string,
    requestedClaims: string[],
    returnUrl?: string,
    purpose?: VerificationContext['purpose'],
    /**
     * The principal that started the session, from the request's auth
     * context. An authority ceremony verifies another principal and is
     * recorded as such whatever is passed here. Omitted means unknown and
     * never verifies the operator.
     */
    initiatedBy?: VerificationInitiator,
  ): Promise<InitiateResult & { session_id: string }> {
    const provider = this.registry.get(providerKey);
    if (!provider) throw new NotFoundError('IdentityProvider', providerKey);

    // Validate requested claims are supported by this provider
    const unsupported = requestedClaims.filter(
      (ct) => !(provider.claimTypes as readonly string[]).includes(ct),
    );
    if (unsupported.length > 0) {
      throw new Error(`Provider "${providerKey}" does not support claims: ${unsupported.join(', ')}`);
    }

    const result = await provider.initiate(operatorId, {
      requested_claims: requestedClaims,
      return_url: returnUrl,
      ...(purpose ? { purpose } : {}),
    });

    const sessionId = ids.session();
    await this.db.insert(identityVerificationSessions).values({
      id: sessionId,
      operator_id: operatorId,
      provider_key: providerKey,
      session_ref: result.session_ref,
      status: 'pending',
      requested_claims: requestedClaims,
      expires_at: result.expires_at,
      initiated_by: purpose ? 'authority' : (initiatedBy ?? null),
    });

    return { ...result, session_id: sessionId };
  }

  /**
   * A provider session reference is not authorization. The current operator
   * must own a live pending session for the same provider before we call an
   * upstream provider or create any claim.
   */
  private async assertOwnedPendingSession(operatorId: string, providerKey: string, sessionRef: string) {
    const [session] = await this.db
      .select()
      .from(identityVerificationSessions)
      .where(eq(identityVerificationSessions.session_ref, sessionRef))
      .limit(1);

    if (
      !session
      || session.operator_id !== operatorId
      || session.provider_key !== providerKey
      || session.status !== 'pending'
      || session.expires_at <= new Date()
    ) {
      throw new NotFoundError('IdentityVerificationSession', sessionRef);
    }
    return session;
  }

  /**
   * Mark the operator verified once its owner passes Stripe Identity. A member,
   * an authority ceremony for another principal, or a session whose starter
   * was never recorded does not count. The first verification time is kept.
   */
  private async markOwnerVerified(
    operatorId: string,
    providerKey: string,
    session: { initiated_by: string | null },
  ): Promise<void> {
    if (providerKey !== OWNER_VERIFICATION_PROVIDER || session.initiated_by !== 'owner') return;
    await this.db
      .update(operators)
      .set({ identity_verified_at: sql`now()`, updated_at: sql`now()` })
      .where(and(eq(operators.id, operatorId), isNull(operators.identity_verified_at)));
  }

  /** Complete a verification flow. Stores encrypted assertions + PII as identity claims. */
  async complete(operatorId: string, providerKey: string, sessionRef: string) {
    const provider = this.registry.get(providerKey);
    if (!provider) throw new NotFoundError('IdentityProvider', providerKey);

    const providerRecord = await this.identityRepo.findProviderByKey(providerKey);
    if (!providerRecord) throw new NotFoundError('IdentityProvider', providerKey);

    const session = await this.assertOwnedPendingSession(operatorId, providerKey, sessionRef);

    const result = await provider.complete(operatorId, sessionRef);

    // Update session status
    await this.db
      .update(identityVerificationSessions)
      .set({
        status: result.success ? 'completed' : 'failed',
        completed_at: new Date(),
        provider_data: result.raw_response
          ? (await this.kms.encrypt(JSON.stringify(result.raw_response), { operator_id: operatorId, store: 'identity_session' })).ciphertext
          : null,
      })
      .where(
        and(
          eq(identityVerificationSessions.session_ref, sessionRef),
          eq(identityVerificationSessions.operator_id, operatorId),
        ),
      );

    if (!result.success) {
      return { success: false, claims: [] };
    }

    // Store each verified claim
    const storedClaims = await Promise.all(
      result.claims.map(async (claim: VerifiedClaim) => {
        const { ciphertext: assertionEncrypted } = await this.kms.encrypt(claim.assertion, { operator_id: operatorId, store: 'identity_claim_assertion' });

        // For Layer 2 (identity), encrypt PII payload separately
        let payloadEncrypted: string | null = null;
        if (claim.layer === 'identity' && claim.metadata?.['pii']) {
          const piiPayload = JSON.stringify(claim.metadata['pii']);
          const { ciphertext } = await this.kms.encrypt(piiPayload, { operator_id: operatorId, store: 'identity_claim_pii' });
          payloadEncrypted = ciphertext;
        }

        const cappedExpiry = await this._capExpiry(operatorId, claim.expires_at);

        const stored = await this.identityRepo.createClaim({
          id: ids.identityClaim(),
          operator_id: operatorId,
          provider_id: providerRecord.id,
          provider_key: providerKey,
          layer: claim.layer,
          claim_type: claim.claim_type,
          assurance_level: claim.assurance_level,
          verified_at: claim.verified_at,
          expires_at: cappedExpiry,
          assertion_encrypted: assertionEncrypted,
          payload_encrypted: payloadEncrypted,
        });
        // Skip emit for workload-layer claims — those ride the
        // svid_attestation / workload_attestation envelopes
        // not the identity_claim envelope.
        if (claim.layer === 'humanity' || claim.layer === 'identity' || claim.layer === 'delegation') {
          await this.emitIdentityClaimEnvelope({
            operatorId,
            rowId: stored.id,
            providerKey,
            layer: claim.layer,
            claimType: claim.claim_type,
            assuranceLevel: claim.assurance_level,
            verifiedAt: claim.verified_at,
            expiresAt: cappedExpiry,
            assertionEncrypted,
          });
        }
        return stored;
      }),
    );

    await this.markOwnerVerified(operatorId, providerKey, session);
    return { success: true, claims: storedClaims };
  }

  /**
   * Complete verification using an inline token (e.g. a widget's challenge response).
   * The token is passed to the provider's complete() for validation,
   * while the sessionRef is used to update our DB session record.
   */
  async completeWithToken(operatorId: string, providerKey: string, sessionRef: string, token: string) {
    const provider = this.registry.get(providerKey);
    if (!provider) throw new NotFoundError('IdentityProvider', providerKey);

    const providerRecord = await this.identityRepo.findProviderByKey(providerKey);
    if (!providerRecord) throw new NotFoundError('IdentityProvider', providerKey);

    const session = await this.assertOwnedPendingSession(operatorId, providerKey, sessionRef);

    // Pass the token (not sessionRef) to the provider — it validates with the external service
    const result = await provider.complete(operatorId, token);

    // Update session status using our internal sessionRef
    await this.db
      .update(identityVerificationSessions)
      .set({
        status: result.success ? 'completed' : 'failed',
        completed_at: new Date(),
        provider_data: result.raw_response
          ? (await this.kms.encrypt(JSON.stringify(result.raw_response), { operator_id: operatorId, store: 'identity_session' })).ciphertext
          : null,
      })
      .where(
        and(
          eq(identityVerificationSessions.session_ref, sessionRef),
          eq(identityVerificationSessions.operator_id, operatorId),
        ),
      );

    if (!result.success) {
      return { success: false, claims: [] };
    }

    // Store each verified claim
    const storedClaims = await Promise.all(
      result.claims.map(async (claim: VerifiedClaim) => {
        const { ciphertext: assertionEncrypted } = await this.kms.encrypt(claim.assertion, { operator_id: operatorId, store: 'identity_claim_assertion' });

        let payloadEncrypted: string | null = null;
        if (claim.layer === 'identity' && claim.metadata?.['pii']) {
          const piiPayload = JSON.stringify(claim.metadata['pii']);
          const { ciphertext } = await this.kms.encrypt(piiPayload, { operator_id: operatorId, store: 'identity_claim_pii' });
          payloadEncrypted = ciphertext;
        }

        const cappedExpiry = await this._capExpiry(operatorId, claim.expires_at);

        const stored = await this.identityRepo.createClaim({
          id: ids.identityClaim(),
          operator_id: operatorId,
          provider_id: providerRecord.id,
          provider_key: providerKey,
          layer: claim.layer,
          claim_type: claim.claim_type,
          assurance_level: claim.assurance_level,
          verified_at: claim.verified_at,
          expires_at: cappedExpiry,
          assertion_encrypted: assertionEncrypted,
          payload_encrypted: payloadEncrypted,
        });
        // Skip emit for workload-layer claims — those ride the
        // svid_attestation / workload_attestation envelopes
        // not the identity_claim envelope.
        if (claim.layer === 'humanity' || claim.layer === 'identity' || claim.layer === 'delegation') {
          await this.emitIdentityClaimEnvelope({
            operatorId,
            rowId: stored.id,
            providerKey,
            layer: claim.layer,
            claimType: claim.claim_type,
            assuranceLevel: claim.assurance_level,
            verifiedAt: claim.verified_at,
            expiresAt: cappedExpiry,
            assertionEncrypted,
          });
        }
        return stored;
      }),
    );

    await this.markOwnerVerified(operatorId, providerKey, session);
    return { success: true, claims: storedClaims };
  }

  // ── Provider sync — source of truth is the provider ──────────────

  /**
   * The providers a sync with no `provider_key` can mean: the registered ones that can list an operator's
   * verified sessions themselves. A deployment with none registered has nothing to sync.
   */
  syncableProviderKeys(): string[] {
    return this.registry.listAll().filter((provider) => 'listVerifiedSessions' in provider).map((provider) => provider.providerKey);
  }

  /**
   * Query the provider directly for verified sessions belonging to this operator,
   * then auto-complete any that don't already have claims.
   * Stripe IS the source of truth — our DB is secondary.
   */
  async syncProviderSessions(operatorId: string, providerKey: string) {
    const provider = this.registry.get(providerKey);
    if (!provider) return { synced: 0 };

    // Provider-specific: list verified sessions for this operator
    if (!('listVerifiedSessions' in provider)) return { synced: 0 };
    const verifiedRefs = await (provider as { listVerifiedSessions(id: string): Promise<string[]> })
      .listVerifiedSessions(operatorId);

    if (verifiedRefs.length === 0) return { synced: 0 };

    // Check which ones already have claims (completed sessions in our DB)
    const existingClaims = await this.identityRepo.findValidClaims(operatorId);
    const claimedProviderRefs = new Set<string>();
    for (const claim of existingClaims) {
      if (claim.provider_key === providerKey) {
        claimedProviderRefs.add(claim.provider_key);
      }
    }

    // If operator already has active claims for this provider, skip
    if (claimedProviderRefs.has(providerKey)) return { synced: 0 };

    // Complete the first verified session that hasn't been processed
    let synced = 0;
    for (const sessionRef of verifiedRefs) {
      try {
        const result = await this.complete(operatorId, providerKey, sessionRef);
        if (result.success) {
          synced++;
          break; // One successful completion is enough
        }
      } catch {
        // Session may have already been completed — continue to next
      }
    }

    return { synced };
  }

  // ── Webhook-driven completion ─────────────────────────────────────

  /**
   * Complete a verification by provider session reference, looking up the operator
   * from our DB. Used by webhooks where the operator_id comes from provider metadata
   * rather than an auth header.
   */
  async completeBySessionRef(providerKey: string, sessionRef: string, expectedOperatorId?: string) {
    // Look up the session in our DB to find the operator
    const [session] = await this.db
      .select()
      .from(identityVerificationSessions)
      .where(
        and(
          eq(identityVerificationSessions.session_ref, sessionRef),
          eq(identityVerificationSessions.provider_key, providerKey),
          eq(identityVerificationSessions.status, 'pending'),
        ),
      )
      .limit(1);

    if (!session) return { success: false, reason: 'no_pending_session' };

    // If an operator_id from metadata is provided, verify it matches
    if (expectedOperatorId && session.operator_id !== expectedOperatorId) {
      return { success: false, reason: 'operator_mismatch' };
    }

    return this.complete(session.operator_id, providerKey, sessionRef);
  }

  /** Get the provider registry for webhook signature verification. */
  getProvider(providerKey: string) {
    return this.registry.get(providerKey);
  }

  // ── Session Queries ──────────────────────────────────────────────

  /** Get pending (non-expired) verification sessions for an operator. */
  async getPendingSessions(operatorId: string) {
    return this.db
      .select()
      .from(identityVerificationSessions)
      .where(
        and(
          eq(identityVerificationSessions.operator_id, operatorId),
          eq(identityVerificationSessions.status, 'pending'),
          gt(identityVerificationSessions.expires_at, new Date()),
        ),
      );
  }

  /**
   * One verification session of this operator, with where it stands. A pending session past its `expires_at` reads
   * `expired` even before the sweep has marked it: it can no longer be completed. Another operator's reads as absent.
   */
  async getSession(operatorId: string, sessionId: string, now: Date = new Date()): Promise<IdentityVerificationSessionView> {
    const [row] = await this.db
      .select()
      .from(identityVerificationSessions)
      .where(and(eq(identityVerificationSessions.id, sessionId), eq(identityVerificationSessions.operator_id, operatorId)))
      .limit(1);
    if (!row) throw new NotFoundError('IdentityVerificationSession', sessionId);
    const status = row.status === 'pending' && row.expires_at <= now ? 'expired' : row.status;
    return {
      session_id: row.id,
      provider_key: row.provider_key,
      session_ref: row.session_ref,
      status: IdentityVerificationSessionStatus.parse(status),
      requested_claims: row.requested_claims,
      created_at: row.created_at.toISOString(),
      expires_at: row.expires_at.toISOString(),
      completed_at: row.completed_at ? row.completed_at.toISOString() : null,
    };
  }

  /**
   * Ends the pending sessions whose time has run out as `expired`, at most `limit` a pass (the oldest first). Each
   * row moves once, by a conditional update, so every machine can run it. Returns how many moved.
   */
  async expireDue(now: Date = new Date(), limit = 500): Promise<number> {
    const due = this.db
      .select({ id: identityVerificationSessions.id })
      .from(identityVerificationSessions)
      .where(and(eq(identityVerificationSessions.status, 'pending'), lte(identityVerificationSessions.expires_at, now)))
      .orderBy(identityVerificationSessions.expires_at)
      .limit(limit);
    const moved = await this.db
      .update(identityVerificationSessions)
      .set({ status: 'expired' })
      .where(
        and(
          inArray(identityVerificationSessions.id, due),
          eq(identityVerificationSessions.status, 'pending'),
          lte(identityVerificationSessions.expires_at, now),
        ),
      )
      .returning({ id: identityVerificationSessions.id });
    return moved.length;
  }

  // ── Layer 3: Delegation ───────────────────────────────────────────

  /**
   * Grant delegation scopes — separate consent step from identity verification.
   * Requires the operator to have a valid Layer 2 (identity) claim first.
   */
  async grantDelegation(operatorId: string, delegatedScopes: string[]) {
    // Verify operator has a valid identity claim (Layer 2)
    const validClaims = await this.identityRepo.findValidClaims(operatorId);
    const identityClaim = validClaims.find((c) => c.layer === 'identity');
    if (!identityClaim) {
      throw new Error('Layer 2 identity verification required before granting delegation');
    }

    // The "provider" for delegation is the same as the identity provider
    const providerRecord = await this.identityRepo.findProviderByKey(identityClaim.provider_key);
    if (!providerRecord) throw new NotFoundError('IdentityProvider', identityClaim.provider_key);

    const now = new Date();
    const expiresAt = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000); // 1 year

    const delegationAssertion = JSON.stringify({
      type: 'delegation',
      delegated_by: identityClaim.id, // reference to the identity claim
      delegated_scopes: delegatedScopes,
      granted_at: now.toISOString(),
    });

    const { ciphertext } = await this.kms.encrypt(delegationAssertion, { operator_id: operatorId, store: 'identity_claim_assertion' });

    const stored = await this.identityRepo.createClaim({
      id: ids.identityClaim(),
      operator_id: operatorId,
      provider_id: providerRecord.id,
      provider_key: identityClaim.provider_key,
      layer: 'delegation',
      claim_type: 'delegated_authority',
      assurance_level: identityClaim.assurance_level as 'low' | 'substantial' | 'high',
      verified_at: now,
      expires_at: expiresAt,
      assertion_encrypted: ciphertext,
      delegated_scopes: delegatedScopes,
    });
    await this.emitIdentityClaimEnvelope({
      operatorId,
      rowId: stored.id,
      providerKey: identityClaim.provider_key,
      layer: 'delegation',
      claimType: 'delegated_authority',
      assuranceLevel: identityClaim.assurance_level as 'low' | 'substantial' | 'high',
      verifiedAt: now,
      expiresAt,
      assertionEncrypted: ciphertext,
      delegatedScopes,
    });
    return stored;
  }

  // ── Claim Queries ─────────────────────────────────────────────────

  /** Get operator's valid (non-expired, non-revoked) claims. */
  async getValidClaims(operatorId: string) {
    return this.identityRepo.findValidClaims(operatorId);
  }

  /** Get all claims for an operator (including expired/revoked). */
  async getAllClaims(operatorId: string) {
    return this.identityRepo.findClaimsByOperator(operatorId);
  }

  /** Count lifetime L2 claims for an operator (for billing gate). */
  async countLifetimeL2Claims(operatorId: string): Promise<number> {
    return this.identityRepo.countLifetimeL2ClaimsForOperator(operatorId);
  }

  /**
   * Build PassportClaimRef[] for embedding in a passport JWT.
   * Layer 1: includes humanity_verified = true
   * Layer 2: includes claim_id ref only (PII resolved server-side)
   * Layer 3: includes delegated_scopes
   */
  async buildPassportClaimRefs(operatorId: string, claimIds?: string[]): Promise<PassportClaimRef[]> {
    // Empty means "carry no claims". Undefined means "apply the operator
    // default". Preserve that difference across issue and refresh.
    if (claimIds !== undefined && claimIds.length === 0) return [];

    // Enforce claim inheritance setting:
    // - "opt_in": only embed claims when explicitly requested via claimIds
    // - "auto" (default): embed all valid claims when no claimIds specified
    if (claimIds === undefined) {
      if (this.operatorRepo) {
        const operator = await this.operatorRepo.findById(operatorId);
        if (operator?.identity_claim_inheritance === 'opt_in') {
          return []; // opt_in mode: no claims unless explicitly requested
        }
      }
    }

    let validClaims = await this.identityRepo.findValidClaims(operatorId);

    // When specific claim IDs provided, filter to only those (still must be valid + belong to operator)
    if (claimIds && claimIds.length > 0) {
      const requestedSet = new Set(claimIds);
      validClaims = validClaims.filter((c) => requestedSet.has(c.id));
    }

    return validClaims.map((claim) => {
      const base: PassportClaimRef = {
        claim_id: claim.id,
        provider: claim.provider_key,
        layer: claim.layer as PassportClaimRef['layer'],
        claim_type: claim.claim_type,
        assurance_level: claim.assurance_level as PassportClaimRef['assurance_level'],
        verified_at: Math.floor(claim.verified_at.getTime() / 1000),
        expires_at: Math.floor(claim.expires_at.getTime() / 1000),
      };

      // Layer 1 — embed humanity_verified flag (no PII)
      if (claim.layer === 'humanity') {
        base.humanity_verified = true;
      }

      // Layer 3 — embed delegated_scopes (no PII)
      if (claim.layer === 'delegation' && claim.delegated_scopes) {
        base.delegated_scopes = claim.delegated_scopes;
      }

      // Layer 2 — NO PII embedded. claim_id is the ref for server-side resolution.
      return base;
    });
  }

  /**
   * Resolve Layer 2 PII for a specific claim.
   * Called server-side during passport verification when a service requires PII.
   * Returns the decrypted PII payload.
   */
  async resolvePii(claimId: string, operatorId: string): Promise<Record<string, unknown> | null> {
    const claim = await this.identityRepo.findClaimById(claimId);
    if (!claim) return null;
    if (claim.operator_id !== operatorId) return null;
    if (claim.layer !== 'identity') return null;
    if (claim.revoked_at || claim.expires_at <= new Date()) return null;
    if (!claim.payload_encrypted) return null;

    // Pass expectedContext to match what's written above. Old (pre-CMEK) rows
    // have no envelope context, and decrypt skips the check when envelope.ctx
    // is absent — so the same call works for both old and new envelopes.
    const decrypted = await this.kms.decrypt(claim.payload_encrypted, { operator_id: operatorId, store: 'identity_claim_pii' });
    return JSON.parse(decrypted) as Record<string, unknown>;
  }

  /** Revoke a specific claim. */
  async revokeClaim(claimId: string, operatorId: string) {
    const claim = await this.identityRepo.findClaimById(claimId);
    if (!claim) throw new NotFoundError('IdentityClaim', claimId);
    if (claim.operator_id !== operatorId) throw new ForbiddenError();

    await this.identityRepo.revokeClaim(claimId);
    if (this.authorityInvalidationHandler) {
      await this.authorityInvalidationHandler(operatorId, claimId, 'legacy_identity_claim_revoked');
    }
  }

  /**
   * List runtime-ready human verification providers for Connect.
   *
   * The database flag is only the catalog switch. The in-memory adapter is
   * the runtime truth. The provider must also opt into the Connect ceremony.
   * This keeps workload identity, enterprise federation, and test rows out of
   * a human verification list.
   */
  async listProviders(operatorId: string) {
    const [catalog, lifetimeL2Claims] = await Promise.all([
      this.identityRepo.listActiveProviders(),
      this.identityRepo.countLifetimeL2ClaimsForOperator(operatorId),
    ]);

    return catalog.flatMap((record) => {
      const provider = this.registry.get(record.provider_key);
      if (!provider?.connect) return [];

      const priceCents = lifetimeL2Claims > 0 && provider.connect.requestedClaim === 'verified_identity'
        ? this.verificationPrice(provider.providerKey)
        : 0;

      return [{
        provider_key: provider.providerKey,
        name: provider.displayName,
        supported_layers: [...provider.supportedLayers],
        claim_types: [...provider.claimTypes],
        assurance_level: provider.assuranceLevel,
        verification_flow: provider.connect.flow,
        requested_claim: provider.connect.requestedClaim,
        price_cents: priceCents,
      }];
    });
  }

  /**
   * Set an identity requirement for a service, scoped to the requiring
   * operator. The row gates only this operator's own passport
   * verification against the service — never any other tenant's.
   */
  async setServiceRequirement(
    operatorId: string,
    serviceId: string,
    input: {
      layer: string;
      requires_claim: string;
      minimum_assurance: string;
      accepted_providers: string[];
      required_scopes?: string[];
      requires_pii: boolean;
      lawful_basis?: string;
    },
  ) {
    return this.identityRepo.upsertRequirement({
      id: ids.serviceRequirement(),
      operator_id: operatorId,
      service_id: serviceId,
      layer: input.layer,
      requires_claim: input.requires_claim,
      minimum_assurance: input.minimum_assurance,
      accepted_providers: input.accepted_providers,
      required_scopes: input.required_scopes ?? null,
      requires_pii: input.requires_pii,
      lawful_basis: input.lawful_basis ?? null,
    });
  }

  /** Get this operator's identity requirements for a service. */
  async getServiceRequirements(operatorId: string, serviceId: string) {
    return this.identityRepo.findRequirementsByService(operatorId, serviceId);
  }

  async replaceServiceRequirement(
    operatorId: string,
    serviceId: string,
    input: {
      layer: string;
      requires_claim: string;
      minimum_assurance: string;
      accepted_providers: string[];
      required_scopes?: string[];
      requires_pii: boolean;
      lawful_basis?: string;
    } | null,
  ) {
    return this.identityRepo.replaceRequirements(
      operatorId,
      serviceId,
      input === null ? null : {
        id: ids.serviceRequirement(),
        operator_id: operatorId,
        service_id: serviceId,
        layer: input.layer,
        requires_claim: input.requires_claim,
        minimum_assurance: input.minimum_assurance,
        accepted_providers: input.accepted_providers,
        required_scopes: input.required_scopes ?? null,
        requires_pii: input.requires_pii,
        lawful_basis: input.lawful_basis ?? null,
      },
    );
  }

  /** Delete one of this operator's own service requirements. */
  async deleteServiceRequirement(operatorId: string, serviceId: string, requirementId: string) {
    await this.identityRepo.deleteRequirement(operatorId, serviceId, requirementId);
  }
}
