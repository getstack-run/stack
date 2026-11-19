import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { assertPublicUrl, IdentityConfigExistsError, StackError, NotFoundError, ids } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { auditCtx } from '../../middleware/audit.js';
import { requireRole } from '../../middleware/require-role.js';

type TrustDomainRow = NonNullable<
  Awaited<ReturnType<Services['spiffeTrustDomainRepo']['findById']>>
>;
type TrustDomainUpdates = Parameters<Services['spiffeTrustDomainRepo']['update']>[1];
type IdRequest = FastifyRequest<{ Params: { id: string } }>;

// ── SPIFFE Trust Domains ──────────────────────────────────────────
//
// Operator-scoped CRUD for spiffe_trust_domains rows. Each row
// configures a SPIRE/SPIFFE issuer the operator has decided to
// accept SVIDs from: trust_domain, jwks_uri, audience pin (optional),
// SPIFFE-ID-to-agent mapping policy (exact-match; a later revision adds
// regex/glob).
//
// The /v1/workload/passport route reads these rows when an
// SVID arrives. Mapping policy is the disambiguator when multiple
// operators share a trust_domain — only the operator whose policy
// contains the incoming SPIFFE ID owns the workload.

const SpiffeIdMappingEntry = z.object({
  agent_id: z.string().regex(/^agt_[A-Za-z0-9_-]+$/),
});

const TrustDomainCreateInput = z.object({
  trust_domain: z
    .string()
    .min(1)
    .max(253)
    // DNS-style: alphanumerics, hyphens, dots. No protocols, no slashes.
    .regex(/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/),
  display_name: z.string().max(120).optional(),
  jwks_uri: z.string().url().regex(/^https:\/\//, 'jwks_uri must use https://'),
  audience: z.string().max(512).optional().nullable(),
  jwks_cache_ttl_seconds: z.number().int().min(60).max(3600).optional(),
  spiffe_id_mapping_policy_json: z.record(z.string(), SpiffeIdMappingEntry).default({}),
  rate_limit_per_second: z.number().int().min(1).max(100_000).optional().nullable(),
  active: z.boolean().optional(),
});

const TrustDomainUpdateInput = TrustDomainCreateInput.partial();

/**
 * Validate that every key in `spiffe_id_mapping_policy_json` is a
 * SPIFFE URI under the configured `trust_domain`, and that every
 * mapped agent_id exists and belongs to the operator. Defense
 * against typos creating dead mappings + cross-operator agent leaks.
 */
async function validateMappingPolicy(
  services: Services,
  operatorId: string,
  trustDomain: string,
  policy: Record<string, { agent_id: string }>,
): Promise<void> {
  const SPIFFE_URI_RE = /^spiffe:\/\/([^/]+)(\/.*)?$/;
  for (const [spiffeId, entry] of Object.entries(policy)) {
    const m = SPIFFE_URI_RE.exec(spiffeId);
    if (!m) {
      throw new StackError(
        `Mapping key "${spiffeId}" is not a SPIFFE URI`,
        'INVALID_SPIFFE_ID',
        400,
      );
    }
    if (m[1] !== trustDomain) {
      throw new StackError(
        `Mapping key "${spiffeId}" trust_domain does not match config trust_domain "${trustDomain}"`,
        'TRUST_DOMAIN_MISMATCH',
        400,
      );
    }
    // services.agent.getById throws NotFoundError if the agent
    // doesn't belong to the operator — exactly the cross-operator
    // leak guard we want here.
    await services.agent.getById(entry.agent_id, operatorId);
  }
}

export async function listTrustDomains(
  request: FastifyRequest,
  services: Services,
): Promise<Array<Omit<TrustDomainRow, 'jwks_cached_jwks_json'> & { jwks_cached_jwks_json: string | null }>> {
  const rows = await services.spiffeTrustDomainRepo.listByOperator(request.operatorId);
  // Strip the cached JWKS body from list responses — it can be
  // multi-KB and isn't useful for the dashboard listing surface.
  return rows.map((r) => ({
    ...r,
    jwks_cached_jwks_json: r.jwks_cached_jwks_json ? '[cached]' : null,
  }));
}

export async function getTrustDomain(
  request: IdRequest,
  services: Services,
): Promise<TrustDomainRow> {
  const row = await services.spiffeTrustDomainRepo.findById(request.params.id);
  if (!row) throw new NotFoundError('SpiffeTrustDomain', request.params.id);
  if (row.operator_id !== request.operatorId) {
    throw new NotFoundError('SpiffeTrustDomain', request.params.id);
  }
  return row;
}

export async function createTrustDomain(
  request: FastifyRequest,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  requireRole(request, 'admin');
  const input = TrustDomainCreateInput.parse(request.body);
  const start = Date.now();

  await assertPublicUrl(input.jwks_uri, { allowedProtocols: ['https:'] });

  await validateMappingPolicy(
    services,
    request.operatorId,
    input.trust_domain,
    input.spiffe_id_mapping_policy_json,
  );

  // Conflict check: one config per (operator, trust_domain). The DB
  // unique index also enforces this; checking up front gives a
  // friendlier 409 instead of an opaque constraint-violation 500.
  const existing = await services.spiffeTrustDomainRepo.findByOperatorAndTrustDomain(
    request.operatorId,
    input.trust_domain,
  );
  if (existing) {
    throw new IdentityConfigExistsError(
      'spiffe',
      `Operator already has a config for trust_domain "${input.trust_domain}"`,
      existing.id,
    );
  }

  const row = await services.spiffeTrustDomainRepo.create({
    id: ids.spiffeTrustDomain(),
    operator_id: request.operatorId,
    trust_domain: input.trust_domain,
    display_name: input.display_name ?? null,
    jwks_uri: input.jwks_uri,
    audience: input.audience ?? null,
    jwks_cache_ttl_seconds: input.jwks_cache_ttl_seconds ?? 300,
    spiffe_id_mapping_policy_json: input.spiffe_id_mapping_policy_json,
    rate_limit_per_second: input.rate_limit_per_second ?? null,
    active: input.active ?? true,
  });

  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action: 'spiffe.trust_domain.create',
    outcome: 'success',
    duration_ms: Date.now() - start,
    payload_hash: row.id,
  });

  return reply.code(201).send(row);
}

export async function updateTrustDomain(
  request: IdRequest,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  requireRole(request, 'admin');
  const input = TrustDomainUpdateInput.parse(request.body);
  const start = Date.now();

  const existing = await services.spiffeTrustDomainRepo.findById(request.params.id);
  if (!existing) throw new NotFoundError('SpiffeTrustDomain', request.params.id);
  if (existing.operator_id !== request.operatorId) {
    throw new NotFoundError('SpiffeTrustDomain', request.params.id);
  }

  // If the policy is being changed (or trust_domain is changing),
  // re-validate against the resolved trust_domain. Catches both
  // direct policy edits and trust_domain renames that would
  // invalidate every existing mapping.
  const nextTrustDomain = input.trust_domain ?? existing.trust_domain;
  const nextPolicy =
    input.spiffe_id_mapping_policy_json ??
    (existing.spiffe_id_mapping_policy_json as Record<string, { agent_id: string }>);
  if (input.spiffe_id_mapping_policy_json || input.trust_domain) {
    await validateMappingPolicy(services, request.operatorId, nextTrustDomain, nextPolicy);
  }
  if (input.jwks_uri !== undefined) {
    await assertPublicUrl(input.jwks_uri, { allowedProtocols: ['https:'] });
  }

  const updates: TrustDomainUpdates = {};
  if (input.trust_domain !== undefined) updates.trust_domain = input.trust_domain;
  if (input.display_name !== undefined) updates.display_name = input.display_name ?? null;
  if (input.jwks_uri !== undefined) updates.jwks_uri = input.jwks_uri;
  if (input.audience !== undefined) updates.audience = input.audience ?? null;
  if (input.jwks_cache_ttl_seconds !== undefined) {
    updates.jwks_cache_ttl_seconds = input.jwks_cache_ttl_seconds;
  }
  if (input.spiffe_id_mapping_policy_json !== undefined) {
    updates.spiffe_id_mapping_policy_json = input.spiffe_id_mapping_policy_json;
  }
  if (input.rate_limit_per_second !== undefined) {
    updates.rate_limit_per_second = input.rate_limit_per_second ?? null;
  }
  if (input.active !== undefined) updates.active = input.active;

  const row = await services.spiffeTrustDomainRepo.update(request.params.id, updates);

  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action: 'spiffe.trust_domain.update',
    outcome: 'success',
    duration_ms: Date.now() - start,
    payload_hash: request.params.id,
  });

  return reply.send(row);
}

export async function deleteTrustDomain(
  request: IdRequest,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  requireRole(request, 'admin');
  const start = Date.now();

  const existing = await services.spiffeTrustDomainRepo.findById(request.params.id);
  if (!existing) throw new NotFoundError('SpiffeTrustDomain', request.params.id);
  if (existing.operator_id !== request.operatorId) {
    throw new NotFoundError('SpiffeTrustDomain', request.params.id);
  }

  await services.spiffeTrustDomainRepo.delete(request.params.id);

  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action: 'spiffe.trust_domain.delete',
    outcome: 'success',
    duration_ms: Date.now() - start,
    payload_hash: request.params.id,
  });

  return reply.code(204).send();
}
