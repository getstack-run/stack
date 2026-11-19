import { z } from 'zod';

/** Request and query schemas shared by more than one authority sub-resource. */

export const VersionQuery = z.object({
  version: z.coerce.number().int().positive().optional(),
});

export const BindingListQuery = z.object({
  agent_id: z.string().min(1).max(128).regex(/^agt_[A-Za-z0-9_-]+$/).optional(),
  page: z.coerce.number().int().min(1).max(100_000).default(1),
  limit: z.coerce.number().int().min(1).max(50).default(20),
  binding_id: z.string().min(1).max(128).optional(),
  binding_version: z.coerce.number().int().positive().optional(),
}).refine((query) => (query.binding_id === undefined) === (query.binding_version === undefined),
  'binding_id and binding_version must be supplied together')
  .refine((query) => !query.binding_id || Boolean(query.agent_id), 'binding filters require agent_id');

export const AuthorityUseListQuery = BindingListQuery;

const AccountAuthorityListQuery = z.object({
  page: z.coerce.number().int().min(1).max(100_000).default(1),
  limit: z.coerce.number().int().min(1).max(50).default(20),
  related: z.literal('bindings').optional(),
  record_id: z.string().min(1).max(128).optional(),
  version: z.coerce.number().int().positive().optional(),
}).refine((query) => Boolean(query.related) === Boolean(query.record_id), 'record_id requires related=bindings');

export function accountAuthorityPage(query: unknown, kind: 'principals' | 'proofs' | 'receivers') {
  const input = query as Record<string, unknown>;
  if (!['page', 'limit', 'related', 'record_id', 'version'].some((key) => input[key] !== undefined)) return null;
  return AccountAuthorityListQuery.refine((value) => kind === 'proofs' && value.related
    ? value.version !== undefined : value.version === undefined,
  'version is required only for a related proof').parse(query);
}

export const ReasonBody = z.object({
  reason_code: z.string().min(1).max(128)
    .regex(/^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/, 'reason_code must be a lowercase semantic code')
    .refine((value) => !/\d{6,}/.test(value), 'reason_code must not contain identifier-like digit runs'),
}).strict();

export const EmptyBody = z.object({}).strict();
