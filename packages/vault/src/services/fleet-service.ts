import { createPublicKey, randomBytes, verify as verifySignature } from 'node:crypto';
import { calculateJwkThumbprint } from 'jose';
import { and, eq, gte, isNull, sql } from 'drizzle-orm';
import type { Redis } from 'ioredis';
import {
  FleetPolicyInput, FleetMissionStartInput, FleetEnrollmentInput, ForbiddenError, ConflictError,
  type FleetPassportBinding, type FleetAccess, type Constraint, type IssuePassportInput,
  agents, serviceConnections, agentServiceGrants, fleetPolicies,
  fleetPolicyRevisions, fleetMemberships, missions, spiffeTrustDomains, wimseIssuers,
  acquireOAuthOperatorLock, generateId, ids, fleetDigest, FLEET_ENROLLMENT_CHALLENGE_TTL_SECONDS, fleetAccessConstraints, fleetEnrollmentRotationMessage,
  resolveFleetAccess, resolveFleetOperations, assertFleetLimitsNarrow, fleetConstraintNarrows,
} from '@stack/shared';
import { FleetRepository, type FleetTransaction } from '../repositories/fleet-repo.js';
import type { MissionService } from './mission-service.js';
import type { EntitlementResolver } from './entitlements/entitlements.js';
import type { PassportService, PassportFleetLookup, PassportJWTPayload } from './passport-service.js';

/** Created only after issuer signature, exact trust policy and config validation. */
export interface VerifiedFleetWorkloadPrincipal {
  operatorId: string;
  kind: 'spiffe' | 'wimse';
  issuer: string;
  audience: string;
  subject: string;
  configId: string;
  notAfter: number;
  tokenDigest: string;
  confirmationThumbprint?: string;
}

type EnrollmentPrincipal = { kind: 'provisioner'; agentId: string } | { kind: 'workload'; identity: VerifiedFleetWorkloadPrincipal };

export class FleetService implements PassportFleetLookup {
  constructor(private deps: {
    repo: FleetRepository; mission: MissionService; passport: PassportService; redis: Redis;
    entitlements: Pick<EntitlementResolver, 'resolve'>;
  }) {}

  async assertExternalAgent(operatorId: string, agentId: string) {
    const root = await this.deps.repo.rootForAgent(agentId);
    if (root || !(await this.deps.repo.db.select({ id: agents.id }).from(agents).where(and(eq(agents.id, agentId), eq(agents.operator_id, operatorId)))).length) throw new ForbiddenError();
  }

  async assertUnboundIssue(operatorId: string, agentId: string, options?: { delegated?: boolean }) {
    await this.assertExternalAgent(operatorId, agentId);
    if (options?.delegated) return;
    if (await this.deps.repo.membership(operatorId, agentId)) throw new ForbiddenError();
  }

  async sessionState(operatorId: string, agentId: string, provisionerPolicyId?: string) {
    await this.assertExternalAgent(operatorId, agentId);
    const member = await this.deps.repo.membership(operatorId, agentId);
    if (!provisionerPolicyId && (!member || member.revoked_at || member.identity_expires_at.getTime() <= Date.now())) throw new ForbiddenError();
    const policy = await this.deps.repo.policy(operatorId, provisionerPolicyId ?? member!.policy_id);
    if (provisionerPolicyId && !policy.definition.provisioner_agent_ids.includes(agentId)) throw new ForbiddenError();
    const [agent] = await this.deps.repo.db.select().from(agents).where(and(eq(agents.id, agentId), eq(agents.operator_id, operatorId)));
    if (policy.status !== 'active' || policy.revoked_at || Date.parse(policy.definition.expires_at) <= Date.now() ||
      !agent?.pubkey || !agent.enrolled_at || agent.status !== 'active' || agent.passport_blocked ||
      (!provisionerPolicyId && (agent.credential_access !== 'proxy_only' || agent.accountability_mode !== 'enforced'))) throw new ForbiddenError();
    return {
      claims: { operator_id: operatorId, agent_id: agentId,
        principal_kind: provisionerPolicyId ? 'provisioner' as const : 'worker' as const,
        ...(!provisionerPolicyId ? { membership_id: member!.id } : {}),
        policy_id: policy.id, policy_revision: policy.revision, key_digest: fleetDigest(agent.pubkey) },
      expiresAt: Math.floor(Math.min(Date.now() + 300_000, provisionerPolicyId ? Infinity : member!.identity_expires_at.getTime(), Date.parse(policy.definition.expires_at)) / 1000),
    };
  }

  private async connections(operatorId: string, access: FleetAccess[], tx = this.deps.repo.db as FleetTransaction | typeof this.deps.repo.db) {
    const result = [];
    for (const item of access) {
      const [connection] = await tx.select().from(serviceConnections).where(and(eq(serviceConnections.id, item.connection_id), eq(serviceConnections.operator_id, operatorId)));
      if (!connection || connection.status !== 'active' || !connection.proxy_enabled || !connection.allowed_hosts?.length || !item.scopes.every(s => connection.scopes.includes(s))) throw new ForbiddenError();
      // Named intents are service-specific. A valid intent from another
      // provider must not manufacture action permissions on this account.
      if (item.intents.some(intent => !intent.name.startsWith(`${connection.provider}.`))) throw new ForbiddenError();
      fleetAccessConstraints(item);
      result.push(connection);
    }
    return result;
  }

  async activate(operatorId: string, raw: FleetPolicyInput, approvedBy: string, policyId?: string, creationKey?: string, expectedRevision?: number) {
    const definition = FleetPolicyInput.parse(raw);
    if (Date.parse(definition.expires_at) <= Date.now()) throw new ForbiddenError();
    const id = policyId ?? (creationKey ? `flp_${fleetDigest({ operatorId, creationKey }).slice(0, 32)}` : generateId('flp'));
    return this.deps.repo.db.transaction(async tx => {
      await acquireOAuthOperatorLock(tx, operatorId);
      if (!policyId && creationKey) {
        const [already] = await tx.select().from(fleetPolicies).where(and(eq(fleetPolicies.id, id), eq(fleetPolicies.operator_id, operatorId)));
        if (already) {
          const stored = await this.deps.repo.policy(operatorId, id, tx);
          if (stored.revoked_at || fleetDigest(stored.definition) !== fleetDigest(definition)) throw new ConflictError('Conflict');
          return { id, revision: stored.revision };
        }
      }
      const existing = policyId ? await this.deps.repo.policy(operatorId, policyId, tx) : null;
      if (existing?.revoked_at) throw new ForbiddenError();
      if (existing && expectedRevision !== undefined && existing.revision !== expectedRevision) {
        if (existing.revision === expectedRevision + 1 && fleetDigest(existing.definition) === fleetDigest(definition)) return { id, revision: existing.revision };
        throw new ConflictError('Conflict');
      }
      // Changing the window width would reset allowance at an arbitrary point.
      if (existing && existing.definition.window_seconds !== definition.window_seconds) throw new ForbiddenError();
      await this.connections(operatorId, definition.rules.map(rule => rule.access), tx);
      for (const provisionerId of definition.provisioner_agent_ids) {
        const [agent] = await tx.select().from(agents).where(and(eq(agents.id, provisionerId), eq(agents.operator_id, operatorId)));
        if (!agent || agent.status !== 'active' || agent.passport_blocked || agent.id === existing?.root_agent_id) throw new ForbiddenError();
      }
      const rootId = existing?.root_agent_id ?? ids.agent();
      if (!existing) {
        await tx.insert(agents).values({ id: rootId, operator_id: operatorId, name: id, accountability_mode: 'enforced', credential_access: 'proxy_only' });
        await tx.insert(fleetPolicies).values({ id, operator_id: operatorId, root_agent_id: rootId, revision: 1 });
      }
      const revision = (existing?.revision ?? 0) + 1;
      await tx.insert(fleetPolicyRevisions).values({ policy_id: id, revision, definition, approved_by: approvedBy });
      await tx.update(fleetPolicies).set({ revision }).where(eq(fleetPolicies.id, id));
      const allowedSkills = [...new Set(definition.operation_rules.filter(rule => rule.effect !== 'deny' && rule.access.producer === 'skill').map(rule => rule.access.target_id))];
      const members = await tx.select({ agent_id: fleetMemberships.agent_id }).from(fleetMemberships).where(eq(fleetMemberships.policy_id, id));
      for (const member of members) await tx.update(agents).set({ skill_access_mode: 'custom', allowed_skills: allowedSkills }).where(and(eq(agents.id, member.agent_id), eq(agents.operator_id, operatorId)));
      // The internal root's OAuth ceiling is installed atomically. Action
      // permissions are sealed in each Mission and checked on every use.
      await tx.update(agentServiceGrants).set({ revoked_at: new Date() }).where(eq(agentServiceGrants.agent_id, rootId));
      const grouped = new Map<string, FleetAccess[]>();
      for (const rule of definition.rules.filter(r => r.effect !== 'deny')) grouped.set(rule.access.connection_id, [...(grouped.get(rule.access.connection_id) ?? []), rule.access]);
      for (const [connectionId, entries] of grouped) {
        const grant = { scopes: [...new Set(entries.flatMap(a => a.scopes))], constraints: [] as Constraint[], allow_data_from: [...new Set(entries.flatMap(a => a.allow_data_from))], revoked_at: null };
        await tx.insert(agentServiceGrants).values({ id: generateId('grt'), agent_id: rootId, service_connection_id: connectionId, ...grant }).onConflictDoUpdate({ target: [agentServiceGrants.agent_id, agentServiceGrants.service_connection_id], set: grant });
      }
      return { id, revision };
    });
  }

  async revoke(operatorId: string, policyId: string) {
    return this.deps.repo.withPolicy(operatorId, policyId, async tx => {
      await tx.update(fleetPolicies).set({ status: 'revoked', revoked_at: new Date() }).where(eq(fleetPolicies.id, policyId));
    });
  }

  private async provisioner(operatorId: string, policyId: string, provisionerId: string) {
    const policy = await this.deps.repo.policy(operatorId, policyId);
    if (policy.status !== 'active' || policy.revoked_at || Date.parse(policy.definition.expires_at) <= Date.now() || !policy.definition.provisioner_agent_ids.includes(provisionerId)) throw new ForbiddenError();
    await this.assertExternalAgent(operatorId, provisionerId);
    return policy;
  }

  async enrollmentChallenge(operatorId: string, policyId: string, provisionerId: string) {
    return this.createEnrollmentChallenge(operatorId, policyId, { kind: 'provisioner', agentId: provisionerId });
  }

  async enroll(operatorId: string, policyId: string, provisionerId: string, raw: FleetEnrollmentInput) {
    return this.enrollPrincipal(operatorId, policyId, { kind: 'provisioner', agentId: provisionerId }, raw);
  }

  async workloadEnrollmentChallenge(policyId: string, identity: VerifiedFleetWorkloadPrincipal) {
    return this.createEnrollmentChallenge(identity.operatorId, policyId, { kind: 'workload', identity });
  }

  async enrollWorkload(policyId: string, identity: VerifiedFleetWorkloadPrincipal, raw: FleetEnrollmentInput) {
    return this.enrollPrincipal(identity.operatorId, policyId, { kind: 'workload', identity }, raw);
  }

  private enrollmentPrincipalId(principal: EnrollmentPrincipal): string {
    if (principal.kind === 'provisioner') return principal.agentId;
    const { kind, issuer, audience, subject, configId } = principal.identity;
    return `workload:${fleetDigest({ kind, issuer, audience, subject, configId })}`;
  }

  private async assertEnrollmentPrincipal(operatorId: string, policyId: string, principal: EnrollmentPrincipal, tx?: FleetTransaction) {
    const policy = await this.deps.repo.policy(operatorId, policyId, tx);
    if (policy.status !== 'active' || policy.revoked_at || Date.parse(policy.definition.expires_at) <= Date.now()) throw new ForbiddenError();
    if (principal.kind === 'provisioner') {
      if (tx) {
        const [agent] = await tx.select().from(agents).where(and(eq(agents.id, principal.agentId), eq(agents.operator_id, operatorId))).for('share');
        if (!agent || agent.status !== 'active' || agent.passport_blocked || policy.root_agent_id === agent.id || !policy.definition.provisioner_agent_ids.includes(agent.id)) throw new ForbiddenError();
      } else await this.provisioner(operatorId, policyId, principal.agentId);
    } else {
      const identity = principal.identity;
      const matches = policy.definition.workload_trust.filter(trust => trust.kind === identity.kind && trust.issuer === identity.issuer && trust.audience === identity.audience && trust.subjects.includes(identity.subject));
      if (identity.operatorId !== operatorId || identity.notAfter * 1000 <= Date.now() || matches.length !== 1) throw new ForbiddenError();
      const db = tx ?? this.deps.repo.db;
      if (identity.kind === 'wimse') {
        const configs = await db.select().from(wimseIssuers).where(and(eq(wimseIssuers.operator_id, operatorId), eq(wimseIssuers.issuer_uri, identity.issuer), eq(wimseIssuers.audience, identity.audience), eq(wimseIssuers.active, true))).for('share');
        if (configs.length !== 1 || configs[0]!.id !== identity.configId) throw new ForbiddenError();
      } else {
        const domain = /^spiffe:\/\/([^/]+)(?:\/|$)/.exec(identity.subject)?.[1];
        if (!domain) throw new ForbiddenError();
        const configs = await db.select().from(spiffeTrustDomains).where(and(eq(spiffeTrustDomains.operator_id, operatorId), eq(spiffeTrustDomains.trust_domain, domain), eq(spiffeTrustDomains.audience, identity.audience), eq(spiffeTrustDomains.active, true))).for('share');
        if (configs.length !== 1 || configs[0]!.id !== identity.configId) throw new ForbiddenError();
      }
    }
    return policy;
  }

  private async createEnrollmentChallenge(operatorId: string, policyId: string, principal: EnrollmentPrincipal) {
    const policy = await this.assertEnrollmentPrincipal(operatorId, policyId, principal);
    // Challenges also bound renewal attempts, not only newly inserted members.
    const rate = await this.deps.redis.eval("local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],3600) end; return n", 1, `fleet:enroll-rate:${policyId}`);
    if (Number(rate) > policy.definition.max_enrollments_per_hour) throw new ForbiddenError();
    const challengeId = generateId('fec');
    const challenge = randomBytes(32).toString('base64url');
    const principalId = this.enrollmentPrincipalId(principal);
    const tokenDigest = principal.kind === 'workload' ? principal.identity.tokenDigest : null;
    const stored = await this.deps.redis.set(`fleet:enroll:${challengeId}`, JSON.stringify({ operatorId, policyId, principalId, tokenDigest, revision: policy.revision, challenge }), 'EX', FLEET_ENROLLMENT_CHALLENGE_TTL_SECONDS, 'NX');
    if (stored !== 'OK') throw new ForbiddenError();
    return { challenge_id: challengeId, challenge, expires_in: FLEET_ENROLLMENT_CHALLENGE_TTL_SECONDS };
  }

  private async enrollPrincipal(operatorId: string, policyId: string, principal: EnrollmentPrincipal, raw: FleetEnrollmentInput) {
    const input = FleetEnrollmentInput.parse(raw);
    const policyBefore = await this.assertEnrollmentPrincipal(operatorId, policyId, principal);
    const principalId = this.enrollmentPrincipalId(principal);
    const key = `fleet:enroll:${input.challenge_id}`;
    const stored = await this.deps.redis.get(key);
    if (!stored) throw new ForbiddenError();
    const challenge = JSON.parse(stored) as { operatorId: string; policyId: string; principalId: string; tokenDigest: string | null; revision: number; challenge: string };
    if (challenge.operatorId !== operatorId || challenge.policyId !== policyId || challenge.principalId !== principalId || challenge.revision !== policyBefore.revision || challenge.tokenDigest !== (principal.kind === 'workload' ? principal.identity.tokenDigest : null)) throw new ForbiddenError();
    if (principal.kind === 'workload' && principal.identity.confirmationThumbprint && await calculateJwkThumbprint(input.public_key) !== principal.identity.confirmationThumbprint) throw new ForbiddenError();
    let valid = false;
    try { valid = verifySignature(null, Buffer.from(challenge.challenge), createPublicKey({ key: input.public_key, format: 'jwk' }), Buffer.from(input.proof, 'base64url')); } catch { /* invalid public key or proof */ }
    if (!valid) throw new ForbiddenError();
    const claimed = await this.deps.redis.eval("if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end", 1, key, stored);
    if (claimed !== 1) throw new ForbiddenError();
    return this.deps.repo.withPolicy(operatorId, policyId, async (tx, policy) => {
      await this.assertEnrollmentPrincipal(operatorId, policyId, principal, tx);
      if (policy.revision !== challenge.revision) throw new ForbiddenError();
      const hash = fleetDigest({ principal: principalId, key: input.idempotency_key });
      const payloadHash = fleetDigest({ name: input.name, public_key: input.public_key });
      const expiresAt = new Date(Math.min(Date.parse(policy.definition.expires_at), Date.now() + policy.definition.identity_lease_seconds * 1000,
        principal.kind === 'workload' ? principal.identity.notAfter * 1000 : Infinity));
      const [existing] = await tx.select().from(fleetMemberships).where(and(eq(fleetMemberships.policy_id, policyId), eq(fleetMemberships.enrollment_key_hash, hash)));
      if (existing) {
        if (existing.revoked_at || existing.enrolled_by !== principalId) throw new ConflictError('Conflict');
        const [agent] = await tx.select().from(agents).where(and(eq(agents.id, existing.agent_id), eq(agents.operator_id, operatorId))).for('update');
        if (!agent || agent.status !== 'active' || agent.passport_blocked || !agent.pubkey || agent.key_mode !== 'customer_managed') throw new ForbiddenError();
        const keyChanged = fleetDigest(agent.pubkey) !== fleetDigest(input.public_key);
        if (keyChanged) {
          // Possession of the new key cannot replace another worker's key.
          // Both proofs bind the same fresh challenge and immutable identity.
          if (!input.previous_key_proof || existing.enrollment_payload_hash !== fleetDigest({ name: input.name, public_key: agent.pubkey })) throw new ForbiddenError();
          const message = fleetEnrollmentRotationMessage({ challenge_id: input.challenge_id, challenge: challenge.challenge,
            policy_id: policyId, idempotency_key: input.idempotency_key, public_key_thumbprint: await calculateJwkThumbprint(input.public_key) });
          let previousValid = false;
          try { previousValid = verifySignature(null, Buffer.from(message), createPublicKey({ key: agent.pubkey, format: 'jwk' }), Buffer.from(input.previous_key_proof, 'base64url')); } catch { /* Invalid old-key proof. */ }
          if (!previousValid) throw new ForbiddenError();
          await tx.update(agents).set({ pubkey: input.public_key, enrolled_at: new Date() }).where(eq(agents.id, agent.id));
        } else if (existing.enrollment_payload_hash !== payloadHash) throw new ConflictError('Conflict');
        await tx.update(fleetMemberships).set({ identity_expires_at: expiresAt, enrollment_payload_hash: payloadHash }).where(eq(fleetMemberships.id, existing.id));
        return { agent_id: existing.agent_id, membership_id: existing.id, identity_expires_at: expiresAt.toISOString() };
      }
      if (input.previous_key_proof) throw new ForbiddenError();
      const [inventory] = await tx.select({ count: sql<number>`count(*)::int` }).from(fleetMemberships).where(and(eq(fleetMemberships.policy_id, policyId), isNull(fleetMemberships.revoked_at)));
      const [rate] = await tx.select({ count: sql<number>`count(*)::int` }).from(fleetMemberships).where(and(eq(fleetMemberships.policy_id, policyId), gte(fleetMemberships.created_at, new Date(Date.now() - 3600_000))));
      // The policy row serializes fleet quotas. The operator lock serializes
      // cross-fleet agent allowance, and is acquired before the policy lock
      // by callers that create across fleets (see enroll transaction below).
      // The agent allowance comes from the billing account, the same resolver
      // metering uses: a white-label tenant draws on its partner's plan (and
      // overrides), not its own `free` row. Fails closed on an inactive account.
      const { limits } = await this.deps.entitlements.resolve(operatorId);
      const [agentCount] = await tx.select({ count: sql<number>`count(*)::int` }).from(agents).where(and(eq(agents.operator_id, operatorId), eq(agents.status, 'active'),
        sql`NOT EXISTS (SELECT 1 FROM ${fleetPolicies} WHERE ${fleetPolicies.root_agent_id} = ${agents.id})`));
      if ((inventory?.count ?? 0) >= policy.definition.max_members || (rate?.count ?? 0) >= policy.definition.max_enrollments_per_hour || (agentCount?.count ?? 0) >= limits.agents) throw new ForbiddenError();
      const agentId = ids.agent();
      const membershipId = generateId('fmb');
      const allowedSkills = policy.definition.operation_rules.filter(rule => rule.effect !== 'deny' && rule.access.producer === 'skill').map(rule => rule.access.target_id);
      await tx.insert(agents).values({ id: agentId, operator_id: operatorId, name: input.name, key_mode: 'customer_managed', pubkey: input.public_key, enrolled_at: new Date(), accountability_mode: 'enforced', credential_access: 'proxy_only', skill_access_mode: 'custom', allowed_skills: [...new Set(allowedSkills)] });
      await tx.insert(fleetMemberships).values({ id: membershipId, operator_id: operatorId, policy_id: policyId, agent_id: agentId, enrolled_by: principalId, enrollment_key_hash: hash, enrollment_payload_hash: payloadHash, identity_expires_at: expiresAt });
      return { agent_id: agentId, membership_id: membershipId, identity_expires_at: expiresAt.toISOString() };
    }, true);
  }

  async start(operatorId: string, agentId: string, raw: FleetMissionStartInput) {
    const input = FleetMissionStartInput.parse(raw);
    const policy = await this.deps.repo.policy(operatorId, input.fleet_policy_id);
    const member = await this.deps.repo.membership(operatorId, agentId);
    if (!member || member.policy_id !== policy.id || member.revoked_at || member.identity_expires_at.getTime() <= Date.now() || policy.status !== 'active' || policy.revoked_at || Date.parse(policy.definition.expires_at) <= Date.now()) throw new ForbiddenError();
    assertFleetLimitsNarrow(input.limits, policy.definition.limits);
    const access = resolveFleetAccess(policy.definition, input.requested_access);
    const operations = resolveFleetOperations(policy.definition, input.requested_operations);
    const connections = await this.connections(operatorId, input.requested_access);
    const requestedId = ids.mission();
    const start = await this.deps.repo.claimStart({ id: generateId('fst'), operator_id: operatorId, policy_id: policy.id, agent_id: agentId, key_hash: fleetDigest(input.idempotency_key), payload_hash: fleetDigest(input), mission_id: requestedId });
    const missionId = start.row.mission_id;
    if (start.row.state === 'ready') return this.renew(operatorId, agentId, missionId);
    const sealed = { policy_id: policy.id, policy_revision: policy.revision, membership_id: member.id, agent_id: agentId, access, operations, limits: input.limits, authority_binding_ids: input.authority_binding_ids ?? [] };
    const digest = fleetDigest(sealed);
    const [existing] = await this.deps.repo.db.select().from(missions).where(and(eq(missions.mission_id, missionId), eq(missions.operator_id, operatorId)));
    if (existing && (existing.assigned_agent_id !== agentId || existing.authorization_digest !== digest)) throw new ConflictError('Conflict');
    if (!existing) {
      await this.deps.mission.open({ operatorId, missionId, assignedAgentId: agentId, authorizationDigest: digest,
        intent_summary: input.intent_summary, intent_services: connections.map(c => c.provider),
        max_actions: input.limits.max_actions, max_concurrent_intents: input.limits.max_concurrent_actions,
        max_duration_seconds: input.limits.max_duration_seconds,
        ...(input.limits.max_dropoff_bytes !== undefined ? { max_dropoff_bytes: input.limits.max_dropoff_bytes } : {}),
        ...(input.limits.max_spend_cents !== undefined ? { coverage_cap_cents: input.limits.max_spend_cents } : {}),
        expiresInSeconds: Math.min(input.limits.max_duration_seconds, Math.floor((Date.parse(policy.definition.expires_at) - Date.now()) / 1000)),
        ...(input.expected_output_shape ? { expected_output_shape: input.expected_output_shape } : {}),
      });
    }
    await this.deps.repo.completeStart(start.row.id, { mission_id: missionId, operator_id: operatorId, ...sealed, session_id: ids.session() });
    return this.renew(operatorId, agentId, missionId);
  }

  async renew(operatorId: string, agentId: string, missionId: string) {
    const live = await this.deps.repo.liveMission(operatorId, missionId, agentId);
    const connectionRows = await this.connections(operatorId, live.binding.access.map(a => a.access));
    const scopes = live.binding.access.map(entry => ({ service_connection_id: entry.access.connection_id, scopes: entry.access.scopes, constraints: entry.constraints, allow_data_from: entry.access.allow_data_from }));
    const binding: FleetPassportBinding = { policy_id: live.policy.id, policy_revision: live.policy.revision, membership_id: live.member.id, mission_id: missionId };
    const passport = await this.deps.passport.issueFleetMission(operatorId, {
      agent_id: live.policy.root_agent_id, mission_ids: [missionId], scopes,
      intent: { summary: live.mission.intent_summary, services: connectionRows.map(c => c.provider), will_delegate: true },
      authority_binding_ids: live.binding.authority_binding_ids,
    }, { child_agent_id: agentId, scopes }, binding, live.binding.session_id);
    return { mission_id: missionId, policy_id: live.policy.id, policy_revision: live.policy.revision, passport };
  }

  async issueFromMission(operatorId: string, input: IssuePassportInput) {
    const member = await this.deps.repo.membership(operatorId, input.agent_id);
    if (!member) return null;
    if (input.mission_ids?.length !== 1 || input.identity_claim_ids !== undefined || input.intent?.platform_intent) throw new ForbiddenError();
    const missionId = input.mission_ids[0]!;
    const live = await this.deps.repo.liveMission(operatorId, missionId, input.agent_id);
    const connections = await this.connections(operatorId, live.binding.access.map(entry => entry.access));
    if (input.intent?.services.some(service => !connections.some(connection => connection.provider === service))) throw new ForbiddenError();
    const authorityIds = input.authority_binding_ids ?? live.binding.authority_binding_ids;
    if (authorityIds.some(id => !live.binding.authority_binding_ids.includes(id))) throw new ForbiddenError();
    const ceiling = live.binding.access.map(entry => ({ service_connection_id: entry.access.connection_id,
      scopes: entry.access.scopes, constraints: entry.constraints, allow_data_from: entry.access.allow_data_from }));
    const requested = input.scopes ?? ceiling;
    if (new Set(requested.map(scope => scope.service_connection_id)).size !== requested.length) throw new ForbiddenError();
    for (const scope of requested) {
      const parent = ceiling.find(entry => entry.service_connection_id === scope.service_connection_id);
      if (!parent || !scope.scopes.length || scope.scopes.some(value => !parent.scopes.includes(value))) throw new ForbiddenError();
    }
    const fleetBinding: FleetPassportBinding = { policy_id: live.policy.id, policy_revision: live.policy.revision,
      membership_id: live.member.id, mission_id: missionId };
    return this.deps.passport.issueFleetMission(operatorId, {
      agent_id: live.policy.root_agent_id, mission_ids: [missionId], scopes: ceiling,
      intent: { summary: live.mission.intent_summary, services: connections.map(connection => connection.provider), will_delegate: true },
      authority_binding_ids: authorityIds, ...(input.ttl_seconds ? { ttl_seconds: input.ttl_seconds } : {}),
    }, { child_agent_id: input.agent_id, scopes: requested, ...(input.ttl_seconds ? { ttl_seconds: input.ttl_seconds } : {}) }, fleetBinding, live.binding.session_id);
  }

  async authorizeIssue(operatorId: string, binding: FleetPassportBinding, agentId: string) {
    const mission = await this.deps.repo.mission(operatorId, binding.mission_id);
    if (!mission) throw new ForbiddenError();
    const live = await this.deps.repo.liveMission(operatorId, binding.mission_id, binding.internal_root ? mission.agent_id : agentId, undefined, !binding.internal_root);
    if (binding.policy_id !== live.policy.id || binding.policy_revision !== live.policy.revision || binding.membership_id !== live.member.id || agentId !== (binding.internal_root ? live.policy.root_agent_id : live.member.agent_id)) throw new ForbiddenError();
    return { expiresAt: new Date(Math.min(live.mission.expires_at.getTime(), live.member.identity_expires_at.getTime(), Date.parse(live.policy.definition.expires_at))) };
  }

  async validate(claims: PassportJWTPayload) {
    const binding = claims.stk.fleet;
    if (!binding) return this.assertUnboundIssue(claims.stk.operator_id, claims.stk.agent_id, { delegated: claims.stk.delegation_depth > 0 });
    await this.authorizeIssue(claims.stk.operator_id, binding, claims.stk.agent_id);
    await this.deps.repo.assertPassportLineage(claims.stk.operator_id, binding.policy_id, claims.jti, undefined, true);
    if (claims.stk.mission_ids?.length !== 1 || claims.stk.mission_ids[0] !== binding.mission_id || claims.stk.accountability !== 'enforced') throw new ForbiddenError();
    const mission = await this.deps.repo.mission(claims.stk.operator_id, binding.mission_id);
    if (!mission || claims.stk.services.length > mission.access.length ||
        new Set(claims.stk.services.map(service => service.connection_id)).size !== claims.stk.services.length) throw new ForbiddenError();
    for (const service of claims.stk.services) {
      const access = mission.access.find(a => a.access.connection_id === service.connection_id);
      if (!access || !service.scopes.every(s => access.access.scopes.includes(s)) || !(service.allow_data_from ?? []).every(s => access.access.allow_data_from.includes(s)) || !access.constraints.every(p => (service.constraints ?? []).some(c => fleetConstraintNarrows(c, p)))) throw new ForbiddenError();
    }
  }

  async validateDelegation(parent: PassportJWTPayload, childAgentId: string): Promise<FleetPassportBinding> {
    await this.validate(parent);
    const binding = parent.stk.fleet;
    if (!binding) throw new ForbiddenError();
    const live = await this.deps.repo.liveMission(parent.stk.operator_id, binding.mission_id, (await this.deps.repo.mission(parent.stk.operator_id, binding.mission_id))!.agent_id);
    if (!binding.internal_root && !live.policy.definition.allow_delegation) throw new ForbiddenError();
    const child = await this.deps.repo.membership(parent.stk.operator_id, childAgentId);
    if (!child || child.policy_id !== live.policy.id || child.revoked_at || child.identity_expires_at.getTime() <= Date.now() || (binding.internal_root && child.agent_id !== live.binding.agent_id)) throw new ForbiddenError();
    return { policy_id: binding.policy_id, policy_revision: binding.policy_revision, membership_id: child.id, mission_id: binding.mission_id };
  }
}
