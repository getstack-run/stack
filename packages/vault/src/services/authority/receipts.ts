/** Receiver status checks and transaction receipts. */
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  canonicalize,
  generateId,
  type AuthorityStatusCheckInput,
  type ReceiverReceiptInput,
} from '@stack/shared';
import type {
  AuthorityReceiverAuthContext,
  AuthorityUseRecord,
  ReceiverTransactionReceiptRecord,
} from './records.js';
import type { AuthorityServiceDeps } from './contracts.js';
import { AuthorityCore } from './core.js';
import { AuthorityGuards } from './guards.js';
import { DomainSemantics } from './semantics.js';
import { EvaluationService } from './evaluation.js';
import {
  AUTHORITY_RECEIPT_MAX_SECONDS,
  assertBoundedJwtLifetime,
  assertReceiverKeyUsable,
} from './receiver-validation.js';
import { bindingDigest, sha256, transactionRequestHash } from './digest.js';
import { safeReceipt } from './redaction.js';

export class ReceiptService {
  private readonly deps: AuthorityServiceDeps;
  private readonly now: () => Date;

  constructor(
    private readonly core: AuthorityCore,
    private readonly guards: AuthorityGuards,
    private readonly semantics: DomainSemantics,
    private readonly evaluation: EvaluationService,
  ) {
    this.deps = core.deps;
    this.now = core.now;
  }

  async statusCheck(auth: AuthorityReceiverAuthContext, input: AuthorityStatusCheckInput) {
    const receiver = await this.deps.repo.findReceiverById(auth.receiverId);
    if (!receiver) throw new ForbiddenError('receiver is unavailable');
    const binding = await this.deps.repo.findBinding(
      receiver.managed_by_operator_id,
      input.binding_id,
    );
    if (
      !binding ||
      binding.receiver_id !== auth.receiverId ||
      binding.claim_id !== input.binding_claim_id
    ) {
      throw new ForbiddenError('authority binding is unavailable to this receiver');
    }
    await this.guards.assertBindingUsable(this.deps.repo, binding, this.now());
    if (
      binding.agent_id !== input.agent_id ||
      binding.agent_key_thumbprint !== input.agent_key_thumbprint
    ) {
      throw new ForbiddenError('authority agent key mismatch');
    }
    if (
      binding.mission_ids.length > 0 &&
      (!input.mission_id || !binding.mission_ids.includes(input.mission_id))
    ) {
      throw new ForbiddenError('authority Mission mismatch');
    }
    if (transactionRequestHash(input.receiver_request_id, input.normalized_request) !== input.request_hash) {
      throw new ForbiddenError('authority status request hash mismatch');
    }
    const semantics = await this.semantics.resolveNativeSemantics(
      binding,
      input.normalized_request,
    );
    if (semantics.actionUri !== input.action_uri || semantics.resourceRef !== input.resource_ref) {
      throw new ForbiddenError(
        'receiver-declared status semantics do not match the pinned domain profile',
      );
    }
    const scope = await this.guards.decryptBindingScope(binding);
    const action = scope.actions.find((candidate) => candidate.action_uri === semantics.actionUri);
    if (
      !action ||
      (action.resource_refs.length > 0 &&
        (!semantics.resourceRef || !action.resource_refs.includes(semantics.resourceRef))) ||
      !(await this.evaluation.constraintsPermit(
        this.deps.repo,
        binding,
        action.constraints,
        input.normalized_request,
      ))
    ) {
      throw new ForbiddenError('authority action or resource is outside scope');
    }
    return {
      active: true,
      binding_ref: await this.guards.authorityReference(binding),
      checked_at: this.now().toISOString(),
    };
  }

  async acceptReceipt(
    auth: AuthorityReceiverAuthContext,
    presentationId: string,
    input: ReceiverReceiptInput,
  ) {
    const presentation = await this.deps.repo.findPresentation(auth.receiverId, presentationId);
    if (!presentation || presentation.status !== 'delivered')
      throw new ForbiddenError('authority presentation is not awaiting a receipt');
    const receiver = await this.deps.repo.findReceiver(presentation.operator_id, auth.receiverId);
    const profile = await this.deps.repo.findReceiverProfile(
      presentation.operator_id,
      presentation.receiver_profile_version_id,
    );
    if (!receiver || !profile || receiver.status !== 'active' || profile.status !== 'active')
      throw new ForbiddenError('receiver is unavailable');
    const protocol = this.core.presentationProtocolForConfig(profile.config_json);
    protocol.validateProfile(profile.config_json);
    const route = protocol.peekReceiverRequest(input.signed_receipt);
    if (route.receiverId !== receiver.id)
      throw new ForbiddenError('receiver receipt issuer mismatch');
    const receiptConfig = profile.config_json.receipt as Record<string, unknown>;
    if (
      !((receiptConfig.signing_key_ids as string[]) ?? []).includes(route.keyId) ||
      !((receiptConfig.allowed_algs as string[]) ?? []).includes(route.algorithm)
    ) {
      throw new ForbiddenError('receiver receipt key is outside the active profile');
    }
    const key = await this.deps.repo.findReceiverKey(receiver.id, route.keyId, 'receipt_signing');
    const now = this.now();
    assertReceiverKeyUsable(key, now, route.algorithm);
    const receipt = (
      await protocol.verifyReceipt({
        compactReceipt: input.signed_receipt,
        receiver,
        profile,
        key,
        audience: `${this.deps.receiverRequestAudience.replace(/\/$/, '')}/v1/authority/presentations/${presentationId}/receipts`,
        now,
      })
    ).payload;
    const use = await this.deps.repo.findAuthorityUseById(
      receiver.id,
      presentation.authority_use_id,
    );
    const issuedAt = Number(receipt.iat);
    const expiresAt = Number(receipt.exp);
    assertBoundedJwtLifetime(issuedAt, expiresAt, now, AUTHORITY_RECEIPT_MAX_SECONDS, 'receiver receipt');
    if (
      !use ||
      receipt.receiver_id !== receiver.id ||
      receipt.presentation_id !== presentation.id ||
      receipt.authority_use_id !== use.id ||
      receipt.presentation_payload_hash !== presentation.payload_hash ||
      receipt.request_hash !== use.request_hash ||
      receipt.action_uri !== use.action_uri ||
      !receipt.jti ||
      !['accepted', 'rejected', 'failed'].includes(String(receipt.outcome))
    ) {
      throw new ForbiddenError('receiver receipt is not bound to the presented transaction');
    }
    const resultNonce = receipt.result_commitment_nonce;
    const resultHash = receipt.result_hash ? String(receipt.result_hash) : null;
    const computedResultHash =
      resultNonce && Object.prototype.hasOwnProperty.call(receipt, 'result')
        ? sha256(canonicalize({ value: receipt.result, commitment_nonce: resultNonce }))
        : null;
    if (
      (receiptConfig.required === true && !resultHash) ||
      typeof resultNonce !== 'string' ||
      !/^[A-Za-z0-9_-]{22,}$/.test(resultNonce) ||
      resultHash !== computedResultHash
    ) {
      throw new ForbiddenError('receiver receipt result hash is missing or invalid');
    }
    const receiptId = generateId('rtr');
    const encrypted = await this.deps.kms
      .encrypt(input.signed_receipt, {
        operator_id: presentation.operator_id,
        receipt_id: receiptId,
        presentation_id: presentation.id,
        store: 'receiver_transaction_receipt',
        purpose: 'native_signed_receipt',
      })
      .catch(() => {
        throw new ServiceUnavailableError('receiver receipt encryption is unavailable');
      });
    const receiptHash = sha256(input.signed_receipt);
    const unsignedReceipt: ReceiverTransactionReceiptRecord = {
      id: receiptId,
      operator_id: presentation.operator_id,
      authority_use_id: use.id,
      presentation_id: presentation.id,
      receiver_id: receiver.id,
      receiver_profile_version_id: profile.id,
      receiver_key_id: key!.id,
      receipt_jti_hash: sha256(String(receipt.jti)),
      native_format: input.native_format,
      native_receipt_encrypted: encrypted.ciphertext,
      receipt_hash: receiptHash,
      request_hash: use.request_hash,
      result_hash: resultHash,
      outcome: receipt.outcome as ReceiverTransactionReceiptRecord['outcome'],
      external_transaction_ref_hash: receipt.external_transaction_ref
        ? sha256(
            canonicalize({
              receipt_hash: receiptHash,
              value: String(receipt.external_transaction_ref),
            }),
          )
        : null,
      verified_at: now,
      received_at: now,
      claim_id: null,
      erased_at: null,
      tombstone_hash: null,
      tombstone_claim_id: null,
    };
    try {
      return await this.deps.repo.atomic(async (repo) => {
        const locked = await repo.lockReceiptAuthorityGraph(receiver.id, presentation.id, now);
        if (
          !locked ||
          locked.presentation.status !== 'delivered' ||
          locked.presentation.payload_hash !== presentation.payload_hash ||
          locked.use.id !== use.id ||
          locked.use.request_hash !== use.request_hash ||
          locked.use.action_uri !== use.action_uri ||
          locked.use.status !== 'dispatched'
        ) {
          throw new ConflictError('receiver receipt lost a concurrent transition');
        }
        await this.guards.assertBindingUsable(repo, locked.binding, now);
        if (
          !(await repo.isPassportAuthorizedForBinding({
            operatorId: locked.use.operator_id,
            passportJti: locked.use.passport_jti,
            agentId: locked.use.agent_id,
            bindingId: locked.binding.id,
            bindingVersion: locked.binding.version,
            now,
          }))
        )
          throw new ForbiddenError('receiver receipt authority Passport is unavailable');
        const lockedKey = await repo.findReceiverKey(receiver.id, route.keyId, 'receipt_signing');
        assertReceiverKeyUsable(lockedKey, now, route.algorithm);
        if (lockedKey!.id !== unsignedReceipt.receiver_key_id) {
          throw new ForbiddenError('receiver receipt key changed during finalisation');
        }
        const signedReceipt = await this.deps.claimIssuer
          .registerReceiverReceiptClaim(
            {
              operatorId: presentation.operator_id,
              receipt: unsignedReceipt,
              presentationPayloadHash: locked.presentation.payload_hash!,
              actionUri: locked.use.action_uri,
            },
            repo.currentTransaction(),
          )
          .catch(() => {
            throw new ServiceUnavailableError('receiver receipt signing is unavailable');
          });
        if (!signedReceipt.claimId || !signedReceipt.claimHash)
          throw new ServiceUnavailableError('receiver receipt claim is unavailable');
        const row = await repo.insertReceiverReceipt({
          ...unsignedReceipt,
          claim_id: signedReceipt.claimId,
        });
        const updated = await repo.updatePresentation({
          receiverId: receiver.id,
          presentationId: presentation.id,
          from: ['delivered'],
          patch: {
            status: row.outcome === 'accepted' ? 'accepted' : 'rejected',
            request_payload_encrypted: null,
          },
        });
        if (!updated) throw new ConflictError('receiver receipt lost a concurrent transition');
        const binding = locked.binding;
        const terminalStatus =
          row.outcome === 'accepted' ? ('succeeded' as const) : ('failed' as const);
        const terminalResultHash = row.result_hash;
        if (!terminalResultHash)
          throw new ForbiddenError('receiver receipt result hash is required');
        const terminalUse: AuthorityUseRecord = {
          ...locked.use,
          status: terminalStatus,
          result_hash: terminalResultHash,
          completed_at: now,
          outcome_claim_id: signedReceipt.claimId,
        };
        const terminalClaim = await this.deps.claimIssuer
          .registerAuthorityUseClaim(
            {
              operatorId: locked.use.operator_id,
              use: terminalUse,
              bindingDigest: bindingDigest(
                binding,
                await repo.listBindingProofs(locked.use.operator_id, binding.id, binding.version),
              ),
              domainProfileVersionId: binding.domain_profile_version_id,
            },
            repo.currentTransaction(),
          )
          .catch(() => {
            throw new ServiceUnavailableError('terminal authority use signing is unavailable');
          });
        if (!terminalClaim.claimId || !terminalClaim.claimHash)
          throw new ServiceUnavailableError('terminal authority use claim is unavailable');
        const completedUse = await repo.completeAuthorityUse({
          operatorId: locked.use.operator_id,
          useId: locked.use.id,
          outcome: terminalStatus,
          resultHash: terminalResultHash,
          outcomeClaimId: signedReceipt.claimId,
          now,
        });
        if (!completedUse)
          throw new ConflictError('receiver receipt use completion lost a concurrent transition');
        return safeReceipt(row);
      });
    } catch (error) {
      if (
        error instanceof ForbiddenError ||
        error instanceof ConflictError ||
        error instanceof NotFoundError ||
        error instanceof ServiceUnavailableError
      )
        throw error;
      throw new ServiceUnavailableError('receiver receipt authority revalidation is unavailable');
    }
  }
}
