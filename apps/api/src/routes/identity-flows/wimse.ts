import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { assertPublicUrl, IdentityConfigExistsError, StackError, NotFoundError, ids } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { auditCtx } from '../../middleware/audit.js';
import { requireRole } from '../../middleware/require-role.js';

type WimseIssuerRow = NonNullable<Awaited<ReturnType<Services['wimseIssuerRepo']['findById']>>>;
type WimseIssuerUpdates = Parameters<Services['wimseIssuerRepo']['update']>[1];
type IdRequest = FastifyRequest<{ Params: { id: string } }>;

/** An issuer row with the cached JWKS body replaced by a presence flag. */
type PublicWimseIssuer<T> = Omit<T, 'jwks_cached_jwks_json'> & { jwks_cached: boolean };

const WorkloadIdMappingEntry = z.object({
  agent_id: z.string().regex(/^agt_[A-Za-z0-9_-]+$/),
});
const WimseIssuerCreateInput = z.object({
  issuer_uri: z.string().url().regex(/^https:\/\//, 'issuer_uri must use https://'),
  display_name: z.string().max(120).optional(),
  jwks_uri: z.string().url().regex(/^https:\/\//, 'jwks_uri must use https://'),
  audience: z.string().max(512).optional().nullable(),
  jwks_cache_ttl_seconds: z.number().int().min(60).max(3600).optional(),
  workload_id_mapping_policy_json: z.record(z.string(), WorkloadIdMappingEntry).default({}),
  rate_limit_per_second: z.number().int().min(1).max(100_000).optional().nullable(),
  active: z.boolean().optional(),
});
const WimseIssuerUpdateInput = WimseIssuerCreateInput.partial();

async function validateWimseMappingPolicy(
  services: Services,
  operatorId: string,
  policy: Record<string, { agent_id: string }>,
): Promise<void> {
  for (const [workloadId, entry] of Object.entries(policy)) {
    let parsed: URL;
    try {
      parsed = new URL(workloadId);
    } catch {
      throw new StackError(`Mapping key "${workloadId}" is not a valid workload URI`, 'INVALID_WORKLOAD_ID', 400);
    }
    if (!parsed.protocol) {
      throw new StackError(`Mapping key "${workloadId}" is not a valid workload URI`, 'INVALID_WORKLOAD_ID', 400);
    }
    await services.agent.getById(entry.agent_id, operatorId);
  }
}

function publicWimseIssuer<T extends Record<string, unknown>>(row: T): PublicWimseIssuer<T> {
  const { jwks_cached_jwks_json: _jwks, ...rest } = row;
  return { ...rest, jwks_cached: Boolean(_jwks) };
}

export async function listWimseIssuers(
  request: FastifyRequest,
  services: Services,
): Promise<Array<PublicWimseIssuer<WimseIssuerRow>>> {
  const rows = await services.wimseIssuerRepo.listByOperator(request.operatorId);
  return rows.map(publicWimseIssuer);
}

export async function getWimseIssuer(
  request: IdRequest,
  services: Services,
): Promise<PublicWimseIssuer<WimseIssuerRow>> {
  const row = await services.wimseIssuerRepo.findById(request.params.id);
  if (!row || row.operator_id !== request.operatorId) throw new NotFoundError('WimseIssuer', request.params.id);
  return publicWimseIssuer(row);
}

export async function createWimseIssuer(
  request: FastifyRequest,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  requireRole(request, 'admin');
  const input = WimseIssuerCreateInput.parse(request.body);
  const start = Date.now();
  await assertPublicUrl(input.issuer_uri, { allowedProtocols: ['https:'] });
  await assertPublicUrl(input.jwks_uri, { allowedProtocols: ['https:'] });
  await validateWimseMappingPolicy(services, request.operatorId, input.workload_id_mapping_policy_json);
  const existing = await services.wimseIssuerRepo.findByOperatorAndIssuerUri(request.operatorId, input.issuer_uri);
  if (existing) throw new IdentityConfigExistsError('wimse', 'This issuer is already configured.', existing.id);
  const row = await services.wimseIssuerRepo.create({
    id: ids.session(), operator_id: request.operatorId, issuer_uri: input.issuer_uri,
    display_name: input.display_name ?? null, jwks_uri: input.jwks_uri, audience: input.audience ?? null,
    jwks_cache_ttl_seconds: input.jwks_cache_ttl_seconds ?? 300,
    workload_id_mapping_policy_json: input.workload_id_mapping_policy_json,
    rate_limit_per_second: input.rate_limit_per_second ?? null, active: input.active ?? true,
  });
  await services.audit.write({ ctx: auditCtx(request), layer: 'vault', action: 'wimse.issuer.create', outcome: 'success', duration_ms: Date.now() - start, payload_hash: row.id });
  return reply.code(201).send(publicWimseIssuer(row));
}

export async function updateWimseIssuer(
  request: IdRequest,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  requireRole(request, 'admin');
  const input = WimseIssuerUpdateInput.parse(request.body);
  const start = Date.now();
  const existing = await services.wimseIssuerRepo.findById(request.params.id);
  if (!existing || existing.operator_id !== request.operatorId) throw new NotFoundError('WimseIssuer', request.params.id);
  if (input.issuer_uri !== undefined) {
    await assertPublicUrl(input.issuer_uri, { allowedProtocols: ['https:'] });
    const duplicate = await services.wimseIssuerRepo.findByOperatorAndIssuerUri(request.operatorId, input.issuer_uri);
    if (duplicate && duplicate.id !== existing.id) throw new IdentityConfigExistsError('wimse', 'This issuer is already configured.', duplicate.id);
  }
  if (input.jwks_uri !== undefined) await assertPublicUrl(input.jwks_uri, { allowedProtocols: ['https:'] });
  if (input.workload_id_mapping_policy_json !== undefined) await validateWimseMappingPolicy(services, request.operatorId, input.workload_id_mapping_policy_json);
  const updates: WimseIssuerUpdates = {};
  if (input.issuer_uri !== undefined) updates.issuer_uri = input.issuer_uri;
  if (input.display_name !== undefined) updates.display_name = input.display_name ?? null;
  if (input.jwks_uri !== undefined) updates.jwks_uri = input.jwks_uri;
  if (input.audience !== undefined) updates.audience = input.audience ?? null;
  if (input.jwks_cache_ttl_seconds !== undefined) updates.jwks_cache_ttl_seconds = input.jwks_cache_ttl_seconds;
  if (input.workload_id_mapping_policy_json !== undefined) updates.workload_id_mapping_policy_json = input.workload_id_mapping_policy_json;
  if (input.rate_limit_per_second !== undefined) updates.rate_limit_per_second = input.rate_limit_per_second ?? null;
  if (input.active !== undefined) updates.active = input.active;
  const row = await services.wimseIssuerRepo.update(existing.id, updates);
  if (!row) throw new NotFoundError('WimseIssuer', request.params.id);
  await services.audit.write({ ctx: auditCtx(request), layer: 'vault', action: 'wimse.issuer.update', outcome: 'success', duration_ms: Date.now() - start, payload_hash: row.id });
  return reply.send(publicWimseIssuer(row));
}

export async function deleteWimseIssuer(
  request: IdRequest,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  requireRole(request, 'admin');
  const start = Date.now();
  const existing = await services.wimseIssuerRepo.findById(request.params.id);
  if (!existing || existing.operator_id !== request.operatorId) throw new NotFoundError('WimseIssuer', request.params.id);
  await services.wimseIssuerRepo.delete(existing.id);
  await services.audit.write({ ctx: auditCtx(request), layer: 'vault', action: 'wimse.issuer.delete', outcome: 'success', duration_ms: Date.now() - start, payload_hash: existing.id });
  return reply.code(204).send();
}
