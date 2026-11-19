import {
  PassportRevokedError,
  allowDataFromIsSubset,
  constraintsAreSubset,
  resolveAllowDataFromGrant,
  type Constraint,
} from '@stack/shared';
import type { PassportRepository } from '../../repositories/passport-repo.js';
import { verifyCarriedAuthorityRefs } from './authority-refs.js';
import {
  isRevoked,
  loadPassportLineage,
  requireActiveAgent,
  withActiveOperatorLock,
} from './context.js';
import { validateFleet } from './fleet.js';
import { assertServiceIdentityRequirements, identityClaimIsExpired } from './identity-requirements.js';
import { revokePassport } from './revoke.js';
import type { PassportContext } from './types.js';

export interface VerifyOptions {
  enforce_identity?: boolean;
  service_id?: string;
  check_freshness?: boolean;
}

export function passportServiceGrantIsFresh(
  signed: { scopes: string[]; constraints?: Constraint[]; allow_data_from?: string[] },
  current: { scopes: string[]; constraints: Constraint[] | null; allow_data_from: string[] | null },
  activeProviders: string[],
  targetProvider: string,
): boolean {
  const scopesFresh = signed.scopes.every(
    (scope) => current.scopes.includes('*') || current.scopes.includes(scope),
  );
  const constraintsFresh = constraintsAreSubset(
    signed.constraints ?? [],
    current.constraints ?? [],
  );
  const currentFlows = resolveAllowDataFromGrant(
    current.allow_data_from ?? [],
    activeProviders,
    targetProvider,
  );
  return (
    scopesFresh &&
    constraintsFresh &&
    allowDataFromIsSubset(signed.allow_data_from ?? [], currentFlows)
  );
}

/**
 * Verify a Passport token online and return its claims, plus the Passport's own
 * row as read during verification (null when verification made no lineage read).
 */
export async function verifyPassportCore(
  ctx: PassportContext,
  token: string,
  options?: VerifyOptions,
  allowInternalRoot = false,
) {
  // The Passport's own row, kept from whichever lineage read ran last so
  // verifyDetailed does not read it again. The read under the operator lock
  // runs after the unlocked one, so it wins when both run.
  // (Asserted, not annotated: it is assigned inside a callback, which
  // control-flow narrowing does not follow.)
  let record = null as NonNullable<Awaited<ReturnType<PassportRepository['findByJti']>>> | null;
  const claims = await ctx.signer.verify(token);
  await validateFleet(ctx, claims, allowInternalRoot);

  // The signed token is not sufficient for online verification. The owner
  // must still be live. Use the opaque revoked error for every dead state.
  const operator = await ctx.operatorRepo.findById(claims.stk.operator_id);
  if (!operator || operator.status !== 'active') {
    throw new PassportRevokedError();
  }

  // Check revocation: Redis first (fast), then DB.
  const revoked = await isRevoked(ctx, claims.jti);
  if (revoked) throw new PassportRevokedError();

  // Inbound authentication can omit connection freshness, but must never
  // authenticate a blocked agent or a delegated token with a dead ancestor.
  await requireActiveAgent(ctx, claims.stk.operator_id, claims.stk.agent_id);
  if (claims.stk.parent_passport_id)
    record = (await loadPassportLineage(ctx, claims))[0] ?? null;

  // Grant freshness is a security boundary, not an optional expensive
  // trust-chain check. It runs even when a caller disables the additional
  // identity/authority freshness checks. The shared operator lock orders
  // this read against atomic grant replacement and revocation.
  const staleGrantReason =
    claims.stk.services.length === 0
      ? null
      : await withActiveOperatorLock(ctx, claims.stk.operator_id, async (tx) => {
          const lineage = await loadPassportLineage(ctx, claims, tx);
          record = lineage[0] ?? null;
          const grantOwner = lineage[lineage.length - 1]!.agent_id;
          const grants = await ctx.serviceRepo.findGrantsWithConnectionByAgent(grantOwner, tx);
          const activeProviders = grants
            .filter(({ connection }) => connection?.status === 'active')
            .map(({ connection }) => connection!.provider);

          for (const signed of claims.stk.services) {
            // Legacy tokens without a canonical connection id drain at their
            // short expiry; no ambiguous provider-name lookup is attempted.
            if (!signed.connection_id) continue;
            const current = grants.find(({ connection }) => {
              if (!connection) return false;
              return (
                connection.id === signed.connection_id &&
                connection.status === 'active' &&
                connection.operator_id === claims.stk.operator_id &&
                connection.provider === signed.service_name &&
                connection.service_id === signed.service_id
              );
            });
            const connection = current?.connection;
            if (!current || !connection) {
              return `Service grant ${signed.connection_id} no longer active`;
            }
            if (
              !passportServiceGrantIsFresh(
                signed,
                current.grant,
                activeProviders,
                connection.provider,
              )
            ) {
              return `Service grant ${signed.connection_id} changed`;
            }
          }
          return null;
        });
  if (staleGrantReason) {
    await revokePassport(ctx, {
      jti: claims.jti,
      operatorId: claims.stk.operator_id,
      reason: staleGrantReason,
    }).catch(() => {});
    throw new PassportRevokedError();
  }

  // Freshness check: verify the underlying trust chain is still valid.
  // Catches cases where a cascade was missed or delayed (e.g. service
  // disconnected, identity claim revoked, agent suspended between issue and
  // verify). Adds DB hits, so a caller can opt out, but it is recommended for
  // high-value operations.
  if (options?.check_freshness !== false) {
    await verifyCarriedAuthorityRefs(ctx, claims);

    // Identity claims must still be valid (if passport carries them)
    if (claims.stk.identity_claims?.length) {
      for (const claimEntry of claims.stk.identity_claims) {
        const claim = await ctx.identityRepo.findClaimById(claimEntry.claim_id);
        if (!claim || claim.revoked_at || identityClaimIsExpired(claim, claimEntry)) {
          await revokePassport(ctx, {
            jti: claims.jti,
            operatorId: claims.stk.operator_id,
            reason: `Identity claim ${claimEntry.claim_id} no longer valid`,
          }).catch(() => {});
          throw new PassportRevokedError();
        }
      }
    }
  }

  // Auto-enforce identity requirements if services have them.
  if (options?.service_id) await assertServiceIdentityRequirements(ctx, claims, options.service_id);

  return { claims, record };
}
