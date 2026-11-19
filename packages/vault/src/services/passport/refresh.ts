import {
  ids,
  ForbiddenError,
  PassportExpiredError,
  PassportRevokedError,
  PASSPORT_DEFAULT_TTL_SECONDS,
  PASSPORT_MAX_TTL_SECONDS,
  PASSPORT_REFRESH_GRACE_SECONDS,
  CHECKPOINT_DEFAULT_INTERVAL_SECONDS,
  resolveAllowDataFromGrant,
  allowDataFromIsSubset,
} from '@stack/shared';
import { type PassportPayload } from '../../crypto/passport-signer.js';
import { linkAuthorityRefs, verifyCarriedAuthorityRefs } from './authority-refs.js';
import { loadPassportLineage, requireActiveAgent, withActiveOperatorLock } from './context.js';
import { fleetDeadline, validateFleet } from './fleet.js';
import { identityClaimIdsForRefresh } from './identity-requirements.js';
import { clampToMission, requireLiveMission } from './mission.js';
import type { PassportContext } from './types.js';

/**
 * Refresh a passport without expanding its signed authority.
 * For zero-downtime agents: refresh proactively before expiry (e.g. at 80% TTL).
 * Root tokens have a 24h recovery grace. Delegated tokens require a fresh
 * delegation when their original signed lifetime ends.
 */
export async function refreshPassport(
  ctx: PassportContext,
  operatorId: string,
  token: string,
  ttlSeconds?: number,
) {
  const claims = await ctx.signer.verify(token, { ignoreExpiration: true });
  // A command's Passport is that command's credential: it ends with the command and is never renewed.
  if (claims.stk.workspace_command) throw new ForbiddenError('A workspace command Passport is not refreshed');
  await validateFleet(ctx, claims);
  if (claims.stk.operator_id !== operatorId) {
    throw new ForbiddenError('Passport belongs to a different operator');
  }

  return withActiveOperatorLock(ctx, operatorId, async (tx, operator) => {
    const now = Date.now();
    if (now - claims.exp * 1000 > PASSPORT_REFRESH_GRACE_SECONDS * 1000) {
      throw new PassportExpiredError();
    }
    const lineage = await loadPassportLineage(ctx, claims, tx, true);
    const source = lineage[0]!;
    if (source.checked_out_at) throw new PassportRevokedError();
    const agent = await requireActiveAgent(ctx, operatorId, claims.stk.agent_id, tx);
    await validateFleet(ctx, claims);

    await verifyCarriedAuthorityRefs(ctx, claims);

    const rank = { standard: 1, logged: 2, enforced: 3 } as const;
    const currentMode =
      agent.accountability_mode === 'standard'
        ? 'standard'
        : agent.accountability_mode === 'logged'
          ? 'logged'
          : 'enforced';
    const signedMode = claims.stk.accountability ?? currentMode;
    const accountability = rank[currentMode] > rank[signedMode] ? currentMode : signedMode;
    const checkpointInterval = Math.min(
      claims.stk.checkpoint_interval ?? CHECKPOINT_DEFAULT_INTERVAL_SECONDS,
      source.checkpoint_interval_seconds ?? CHECKPOINT_DEFAULT_INTERVAL_SECONDS,
    );
    let ttl = Math.min(ttlSeconds ?? PASSPORT_DEFAULT_TTL_SECONDS, PASSPORT_MAX_TTL_SECONDS);
    if (accountability === 'enforced') ttl = Math.min(ttl, checkpointInterval);
    if (lineage.length > 1) {
      // A checkpoint can extend a parent's stored expiry without extending
      // its signed JWT. Without a fresh signed parent, renewal cannot add
      // duration to the delegated token. Re-delegate from a valid parent
      // when this signed lifetime ends.
      ttl = Math.min(
        ttl,
        Math.floor((claims.exp * 1000 - Date.now()) / 1000),
        ...lineage
          .slice(1)
          .map((parent) => Math.floor((parent.expires_at.getTime() - Date.now()) / 1000)),
      );
    }
    if (ttl <= 0) throw new PassportExpiredError();

    const originalClaimIds = identityClaimIdsForRefresh(claims.stk.identity_claims);
    const identityClaims = await ctx.identityVerification.buildPassportClaimRefs(
      operatorId,
      originalClaimIds,
    );

    // Delegation derives permission from the original granting agent. A
    // child need not have a separate standing grant, and its own broader
    // grants must never replace restrictions inherited from its parent.
    const grantOwner = lineage[lineage.length - 1]!.agent_id;
    const grants = await ctx.serviceRepo.findGrantsWithConnectionByAgent(grantOwner, tx);
    const activeProviders = grants
      .filter(({ connection }) => connection?.status === 'active')
      .map(({ connection }) => connection!.provider);
    const services: PassportPayload['services'] = [];
    for (const original of claims.stk.services) {
      const current = grants.find(
        ({ connection }) =>
          connection !== null &&
          connection.id === original.connection_id &&
          connection.status === 'active' &&
          connection.provider === original.service_name &&
          connection.service_id === original.service_id,
      );
      if (!current?.connection) continue;
      const { grant, connection } = current;
      const scopes = original.scopes.includes('*')
        ? grant.scopes
        : original.scopes.filter(
            (scope) => grant.scopes.includes('*') || grant.scopes.includes(scope),
          );
      if (scopes.length === 0) continue;
      const constraints = [
        ...new Map(
          [...(original.constraints ?? []), ...(grant.constraints ?? [])].map((constraint) => [
            JSON.stringify([constraint.path, constraint.op, constraint.value]),
            constraint,
          ]),
        ).values(),
      ];
      if (constraints.length > 32) {
        throw new ForbiddenError(
          `Too many constraints on refreshed scope for ${original.service_name} (max 32)`,
        );
      }
      const allowedFlows = resolveAllowDataFromGrant(
        grant.allow_data_from ?? [],
        activeProviders,
        connection.provider,
      );
      services.push({
        ...original,
        scopes,
        credential_ref: connection.credential_ref,
        constraints,
        allow_data_from: (original.allow_data_from ?? []).filter((flow) =>
          allowDataFromIsSubset([flow], allowedFlows),
        ),
      });
    }

    const platformIntent =
      operator.is_platform_staff &&
      (claims.stk.platform_intent !== 'monitor' || operatorId === ctx.systemOperatorId)
        ? claims.stk.platform_intent
        : undefined;
    // Refresh renews a credential for a live Mission only. A Passport with no
    // Mission (or one whose platform privilege lapsed) and a Passport whose
    // Mission ended are refused. Read under the operator lock, which a
    // Mission's end also takes.
    const mission = await requireLiveMission(ctx, operatorId, claims.stk.mission_ids, platformIntent);
    const payload: PassportPayload = {
      ...claims.stk,
      agent_name: agent.name,
      services,
      identity_claims: identityClaims,
      accountability,
      ...(accountability === 'enforced' ? { checkpoint_interval: checkpointInterval } : {}),
    };
    delete payload.platform_intent;
    if (platformIntent) payload.platform_intent = platformIntent;
    const jti = ids.passport();
    // The preceding lookups can take time. Apply absolute delegated
    // deadlines at signing as well as at admission.
    if (lineage.length > 1) {
      const signingNow = Date.now();
      ttl = Math.min(
        ttl,
        Math.floor((claims.exp * 1000 - signingNow) / 1000),
        ...lineage
          .slice(1)
          .map((parent) => Math.floor((parent.expires_at.getTime() - signingNow) / 1000)),
      );
    }
    if (claims.stk.fleet) {
      ttl = Math.min(
        ttl,
        Math.floor(
          ((await fleetDeadline(ctx, operatorId, agent.id, claims.stk.fleet)) - Date.now()) / 1000,
        ),
      );
    }
    ttl = clampToMission(ttl, mission);
    if (ttl <= 0) throw new PassportExpiredError();
    const result = await ctx.signer.sign(jti, payload, ttl);
    await ctx.passportRepo.create(
      {
        jti,
        operator_id: operatorId,
        agent_id: agent.id,
        session_id: claims.stk.session_id,
        delegation_depth: claims.stk.delegation_depth,
        parent_passport_id: claims.stk.parent_passport_id ?? null,
        expires_at: result.expires_at,
        identity_claim_ids: identityClaims?.length
          ? identityClaims.map((claim) => claim.claim_id)
          : null,
        intent_summary: claims.stk.intent_summary ?? source.intent_summary,
        intent_services: claims.stk.intent_services ?? source.intent_services,
        intent_refs: claims.stk.intent_refs ?? source.intent_refs,
        intent_delegates: source.intent_delegates,
        estimated_duration_seconds: source.estimated_duration_seconds,
        checkpoint_interval_seconds:
          accountability === 'enforced' ? checkpointInterval : source.checkpoint_interval_seconds,
        ...(claims.stk.mission_ids ? { mission_ids: claims.stk.mission_ids } : {}),
      },
      tx,
    );
    if (claims.stk.authority_refs) {
      await linkAuthorityRefs(
        ctx,
        { operatorId, passportJti: jti, refs: claims.stk.authority_refs },
        tx,
      );
    }
    return result;
  });
}
