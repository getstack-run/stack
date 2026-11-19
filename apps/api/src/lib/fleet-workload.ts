import { calculateJwkThumbprint, decodeJwt, type JWK } from 'jose';
import { and, eq } from 'drizzle-orm';
import { FleetPolicyInput, ForbiddenError, fleetDigest, fleetPolicies, fleetPolicyRevisions } from '@stack/shared';
import type { Services } from '../config/services.js';

type WorkloadIdentity = {
  operatorId: string; kind: 'spiffe' | 'wimse'; issuer: string; audience: string; subject: string;
  configId: string; notAfter: number; tokenDigest: string; confirmationThumbprint?: string;
};
type Policy = { operatorId: string; active: boolean; definition: FleetPolicyInput };
type Config = { id: string; operator_id: string; audience: string | null; active: boolean };
type Acceptance = { subject: string; issuer: string; audience?: string; notAfter: number };

export interface FleetWorkloadVerifier {
  policy(id: string): Promise<Policy>;
  configs(kind: 'spiffe' | 'wimse', issuerOrDomain: string): Promise<Config[]>;
  accept(kind: 'spiffe' | 'wimse', token: string, configId: string): Promise<Acceptance>;
}

/** A decoded field only selects configured trust. Authority follows signature verification. */
export async function verifyFleetWorkload(verifier: FleetWorkloadVerifier, policyId: string, token: string): Promise<WorkloadIdentity> {
  if (!token || token.length > 4096) throw new ForbiddenError();
  let claims;
  try { claims = decodeJwt(token); } catch { throw new ForbiddenError(); }
  const { iss, sub, aud } = claims;
  if (typeof iss !== 'string' || typeof sub !== 'string' || typeof aud !== 'string') throw new ForbiddenError();
  const policy = await verifier.policy(policyId);
  if (!policy.active || Date.parse(policy.definition.expires_at) <= Date.now()) throw new ForbiddenError();
  const matching = policy.definition.workload_trust.filter(trust => trust.issuer === iss && trust.audience === aud && trust.subjects.includes(sub));
  if (matching.length !== 1) throw new ForbiddenError();
  const trust = matching[0]!;
  const domain = trust.kind === 'spiffe' ? /^spiffe:\/\/([^/]+)(?:\/|$)/.exec(sub)?.[1] : iss;
  if (!domain) throw new ForbiddenError();
  const configs = (await verifier.configs(trust.kind, domain)).filter(config => config.active && config.operator_id === policy.operatorId && config.audience === aud);
  if (configs.length !== 1) throw new ForbiddenError();
  const config = configs[0]!;
  let verified;
  try { verified = await verifier.accept(trust.kind, token, config.id); } catch { throw new ForbiddenError(); }
  if (verified.subject !== sub || verified.issuer !== iss || verified.audience !== aud || !Number.isSafeInteger(verified.notAfter) || verified.notAfter <= Math.floor(Date.now() / 1000) + 5) throw new ForbiddenError();

  // The existing WIMSE validator records cnf. Here a supplied cnf is enforced:
  // its key must be the key proving possession of the enrollment challenge.
  let confirmationThumbprint: string | undefined;
  if (claims['cnf'] !== undefined) {
    const cnf = claims['cnf'];
    if (!cnf || typeof cnf !== 'object' || Array.isArray(cnf)) throw new ForbiddenError();
    const confirmation = cnf as Record<string, unknown>;
    if (Object.keys(confirmation).some(key => key !== 'jwk' && key !== 'jkt')) throw new ForbiddenError();
    if (confirmation['jwk'] !== undefined) {
      const jwk = confirmation['jwk'] as JWK;
      if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string' || !/^[\w-]{43}$/.test(jwk.x) || jwk.d) throw new ForbiddenError();
      confirmationThumbprint = await calculateJwkThumbprint(jwk);
    }
    if (confirmation['jkt'] !== undefined) {
      const jkt = confirmation['jkt'];
      if (typeof jkt !== 'string' || !/^[\w-]{43}$/.test(jkt) || (confirmationThumbprint && confirmationThumbprint !== jkt)) throw new ForbiddenError();
      confirmationThumbprint = jkt;
    }
    if (!confirmationThumbprint) throw new ForbiddenError();
  }
  return { operatorId: policy.operatorId, kind: trust.kind, issuer: iss, audience: aud, subject: sub,
    configId: config.id, notAfter: verified.notAfter, tokenDigest: fleetDigest(token),
    ...(confirmationThumbprint ? { confirmationThumbprint } : {}),
  };
}

export function fleetWorkloadVerifier(services: Pick<Services, 'db' | 'spiffeTrustDomainRepo' | 'wimseIssuerRepo' | 'workloadProviderRegistry' | 'wimseWorkloadProvider'>): FleetWorkloadVerifier {
  return {
    async policy(id) {
      const [row] = await services.db.select({ operatorId: fleetPolicies.operator_id, status: fleetPolicies.status,
        revoked: fleetPolicies.revoked_at, definition: fleetPolicyRevisions.definition }).from(fleetPolicies)
        .innerJoin(fleetPolicyRevisions, and(eq(fleetPolicyRevisions.policy_id, fleetPolicies.id), eq(fleetPolicyRevisions.revision, fleetPolicies.revision)))
        .where(eq(fleetPolicies.id, id));
      if (!row) throw new ForbiddenError();
      return { operatorId: row.operatorId, active: row.status === 'active' && !row.revoked, definition: FleetPolicyInput.parse(row.definition) };
    },
    configs: (kind, identity) => kind === 'spiffe' ? services.spiffeTrustDomainRepo.findActiveByTrustDomain(identity) : services.wimseIssuerRepo.findActiveByIssuerUri(identity),
    async accept(kind, token, id) {
      if (kind === 'spiffe') {
        const cfg = await services.spiffeTrustDomainRepo.findById(id);
        const provider = services.workloadProviderRegistry.get('spiffe');
        if (!cfg || !provider || !cfg.active || !cfg.audience) throw new ForbiddenError();
        const accepted = await provider.acceptSvid(token, {
          kind: 'spiffe', id: cfg.id, trust_domain: cfg.trust_domain, jwks_uri: cfg.jwks_uri, audience: cfg.audience,
          jwks_cache_ttl_seconds: cfg.jwks_cache_ttl_seconds, jwks_cached_jwks_json: cfg.jwks_cached_jwks_json as { keys: JWK[] } | null,
        });
        return { subject: accepted.spiffe_id, issuer: accepted.issuer, audience: accepted.audience, notAfter: accepted.not_after };
      }
      const cfg = await services.wimseIssuerRepo.findById(id);
      if (!cfg || !cfg.active || !cfg.audience) throw new ForbiddenError();
      const accepted = await services.wimseWorkloadProvider.acceptWit(token, {
        id: cfg.id, issuer_uri: cfg.issuer_uri, jwks_uri: cfg.jwks_uri, audience: cfg.audience,
        jwks_cache_ttl_seconds: cfg.jwks_cache_ttl_seconds, jwks_cached_jwks_json: cfg.jwks_cached_jwks_json as { keys: JWK[] } | null,
      });
      return { subject: accepted.workload_id, issuer: accepted.issuer, audience: accepted.audience, notAfter: accepted.not_after };
    },
  };
}
