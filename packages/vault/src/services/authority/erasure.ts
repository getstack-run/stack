/** Erasure of authority graphs with signed tombstones. */
import { ConflictError, NotFoundError, ServiceUnavailableError, canonicalize } from '@stack/shared';
import type { AuthorityErasureTombstone } from './records.js';
import type { AuthorityServiceDeps } from './contracts.js';
import { AuthorityCore } from './core.js';
import { sha256 } from './digest.js';

export class ErasureService {
  private readonly deps: AuthorityServiceDeps;
  private readonly now: () => Date;

  constructor(private readonly core: AuthorityCore) {
    this.deps = core.deps;
    this.now = core.now;
  }

  async eraseProof(operatorId: string, proofId: string, idempotencyKey: string) {
    return this.eraseAuthorityGraph(operatorId, 'proof', proofId, idempotencyKey);
  }

  async erasePrincipal(operatorId: string, principalId: string, idempotencyKey: string) {
    return this.eraseAuthorityGraph(operatorId, 'principal', principalId, idempotencyKey);
  }

  async eraseBinding(operatorId: string, bindingId: string, idempotencyKey: string) {
    return this.eraseAuthorityGraph(operatorId, 'binding', bindingId, idempotencyKey);
  }

  async erasePresentation(operatorId: string, presentationId: string, idempotencyKey: string) {
    return this.eraseAuthorityGraph(operatorId, 'presentation', presentationId, idempotencyKey);
  }

  private async eraseAuthorityGraph(
    operatorId: string,
    targetKind: 'principal' | 'binding' | 'proof' | 'presentation',
    targetId: string,
    idempotencyKey: string,
  ) {
    return this.core.idempotent(
      operatorId,
      `${targetKind}.erase:${targetId}`,
      idempotencyKey,
      {},
      async (repo) => {
        const erasedAt = this.now();
        const targets = await repo.lockErasureGraph({ operatorId, targetKind, targetId });
        if (!targets) {
          const entity =
            targetKind === 'principal'
              ? 'AuthorityPrincipal'
              : targetKind === 'binding'
                ? 'AuthorityBinding'
                : targetKind === 'proof'
                  ? 'AuthorityProof'
                  : 'AuthorityPresentation';
          throw new NotFoundError(entity, targetId);
        }
        if (targets.length === 0) throw new ConflictError('authority graph was already erased');
        const tombstones: AuthorityErasureTombstone[] = [];
        for (const target of targets) {
          const tombstoneDigest = sha256(
            canonicalize({
              target_kind: target.target_kind,
              target_id: target.target_id,
              target_version: target.target_version,
              prior_artifact_digest: target.prior_artifact_digest,
              prior_claim_digest: target.prior_claim_digest,
              erased_at: erasedAt.toISOString(),
            }),
          );
          const signed = await this.deps.claimIssuer
            .registerAuthorityErasureTombstone(
              {
                operatorId,
                tombstone: { ...target, tombstone_digest: tombstoneDigest },
                erasedAt,
              },
              repo.currentTransaction(),
            )
            .catch(() => {
              throw new ServiceUnavailableError(
                'authority erasure tombstone signing is unavailable',
              );
            });
          if (!signed.claimId || !signed.claimHash) {
            throw new ServiceUnavailableError('authority erasure tombstone claim is unavailable');
          }
          tombstones.push({
            ...target,
            tombstone_digest: tombstoneDigest,
            tombstone_claim_id: signed.claimId,
          });
        }
        const cascade = await repo.applyErasureGraph({
          operatorId,
          targetKind,
          targetId,
          erasedAt,
          tombstones,
        });
        await this.deps.passportRevocationPublisher
          .publishAuthorityRevocations(cascade.passportJtis, `authority_${targetKind}_erased`)
          .catch(() => {
            throw new ServiceUnavailableError('authority Passport revocation propagation failed');
          });
        const root = tombstones.find(
          (target) => target.target_kind === targetKind && target.target_id === targetId,
        );
        if (!root) throw new ConflictError('authority erasure root was not applied');
        return {
          target_kind: root.target_kind,
          target_id: root.target_id,
          target_version: root.target_version,
          erased_at: erasedAt.toISOString(),
          tombstone_hash: root.tombstone_digest,
          tombstone_claim_id: root.tombstone_claim_id,
        };
      },
    );
  }
}
