import { ForbiddenError, type Database } from '@stack/shared';
import {
  AuthorityService,
  AuthorityRepository,
  EnterpriseOidcAuthorityAdapter,
  StackIdentityAuthorityAdapter,
  PinnedAuthorityApprovalDecisionVerifier,
  StackDirectPostJwtV1Protocol,
  type AuthorityProofAdapter,
  type ClaimRegistryService,
  type IdentityVerificationService,
  type KmsService,
  type OidcIdpProvider,
  type PassportService,
  type PassportSigner,
  type ReceiverDirectory,
} from '@stack/vault';
import { env } from '../env.js';
import {
  createAuthorityPresentationTransport,
  createAuthorityReceiverOriginVerifier,
} from '../authority-network.js';
import { createAuthorityClaimIssuer } from './authority-claim-issuer.js';

type AuthorityPassportVerifier = ConstructorParameters<
  typeof AuthorityService
>[0]['passportVerifier'];

/**
 * Verifies the passport an agent presents to a receiver: it must belong to the
 * authority tenant and carry the exact authority reference and Mission the
 * request names.
 */
function createAuthorityPassportVerifier(passport: PassportService): AuthorityPassportVerifier {
  return {
    async verifyPresentationPassport(input) {
      const claims = await passport.verify(input.token, { check_freshness: true });
      if (claims.stk.operator_id !== input.operatorId || claims.stk.agent_id !== claims.sub) {
        throw new ForbiddenError('Passport does not belong to the authority tenant');
      }
      if (input.authorityRef.receiver_id !== input.receiverId) {
        throw new ForbiddenError('Passport authority receiver does not match the request');
      }
      const matchingReference = claims.stk.authority_refs?.some(
        (reference) =>
          reference.binding_id === input.authorityRef.binding_id &&
          reference.binding_version === input.authorityRef.binding_version &&
          reference.binding_claim_id === input.authorityRef.binding_claim_id &&
          reference.binding_digest === input.authorityRef.binding_digest &&
          reference.receiver_id === input.authorityRef.receiver_id &&
          reference.receiver_profile_version_id ===
            input.authorityRef.receiver_profile_version_id &&
          reference.expires_at === input.authorityRef.expires_at,
      );
      if (!matchingReference) {
        throw new ForbiddenError('Passport does not carry the requested authority reference');
      }
      if (input.missionId && !claims.stk.mission_ids?.includes(input.missionId)) {
        throw new ForbiddenError('Passport does not carry the requested Mission');
      }
      return { jti: claims.jti, agentId: claims.stk.agent_id };
    },
  };
}

/**
 * Principal, proof, mandate, receiver, presentation and runtime authority
 * rails.
 *
 * Proof/profile adapters are registered here only after their external
 * verification ceremonies are production-ready. An empty registry is
 * deliberately fail-closed: the rails boot, but no proof can be imported,
 * collected, disclosed, or accepted as an approval.
 */
export function createAuthority(deps: {
  db: Database;
  kms: KmsService;
  signer: PassportSigner;
  signerKid: string;
  claimRegistry: ClaimRegistryService;
  passport: PassportService;
  identity: IdentityVerificationService;
  oidcIdpProvider: OidcIdpProvider;
  /** The internal receiver kinds the deployment adds to the engine's (its skills). */
  receiverDirectories?: readonly ReceiverDirectory[];
}): AuthorityService {
  const { db, kms, signer, signerKid, claimRegistry, passport, identity, oidcIdpProvider, receiverDirectories } = deps;
  const authorityRepo = new AuthorityRepository(db, undefined, receiverDirectories);
  const authorityAdapters: AuthorityProofAdapter[] = [
    new EnterpriseOidcAuthorityAdapter(oidcIdpProvider, signer),
    new StackIdentityAuthorityAdapter(signer),
  ];
  const authorityApprovalDecisionVerifier = new PinnedAuthorityApprovalDecisionVerifier(
    authorityRepo,
    authorityAdapters,
  );
  const authorityPresentationProtocol = new StackDirectPostJwtV1Protocol(
    {
      keyId: signerKid,
      algorithm: 'EdDSA',
      sign: (payload) => signer.signAuthorityPresentation(payload),
    },
    createAuthorityPresentationTransport(),
  );
  const authorityReceiverAudience = new URL(env.STACK_API_BASE_URL).origin;
  const authority = new AuthorityService({
    repo: authorityRepo,
    kms,
    adapters: authorityAdapters,
    claimIssuer: createAuthorityClaimIssuer(claimRegistry),
    presentationProtocols: [authorityPresentationProtocol],
    receiverRequestAudience: authorityReceiverAudience,
    passportVerifier: createAuthorityPassportVerifier(passport),
    approvalDecisionVerifier: authorityApprovalDecisionVerifier,
    receiverOriginVerifier: createAuthorityReceiverOriginVerifier(),
    passportRevocationPublisher: {
      publishAuthorityRevocations: (jtis, reason) =>
        passport.syncAuthorityRevocations(jtis, reason),
    },
    legacyIdentityResolver: {
      async resolveFacts({ operatorId, identityClaimId }) {
        const facts = await identity.resolvePii(identityClaimId, operatorId);
        if (!facts) throw new ForbiddenError('legacy identity facts are unavailable');
        return facts;
      },
    },
  });
  identity.setAuthorityInvalidationHandler((operatorId, identityClaimId, reason) =>
    authority.invalidateLegacyIdentityClaim(operatorId, identityClaimId, reason),
  );
  return authority;
}
