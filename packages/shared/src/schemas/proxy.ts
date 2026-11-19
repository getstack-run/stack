import { z } from 'zod';
import { ConnectionSelector } from './service.js';

export const CredentialAccess = z.enum(['direct', 'proxy_preferred', 'proxy_only']);
export type CredentialAccess = z.infer<typeof CredentialAccess>;

export const ProxyRequestInput = z.object({
  service: z.string().min(1).describe('Provider slug (e.g. "openai", "slack")'),
  url: z.string().url().describe('Full target URL'),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
  headers: z.record(z.string()).optional().describe('Extra headers (auth headers will be stripped)'),
  body: z.unknown().optional().describe('Request body'),
  query: z.record(z.string()).optional().describe('Query parameters to append to URL'),
  connection: ConnectionSelector.optional().describe(
    'Which connection of the service to use, by name or id. Needed only when the account holds more than one.',
  ),
});
export type ProxyRequestInput = z.infer<typeof ProxyRequestInput>;

export const ProxyOperationId = z.string().regex(/^[A-Za-z0-9_-]{22,256}$/);
export type ProxyOperationId = z.infer<typeof ProxyOperationId>;

export const ProxyOperationLookupInput = z.object({
  operation_id: ProxyOperationId,
  include_response: z.boolean().optional().default(false),
});
export type ProxyOperationLookupInput = z.infer<typeof ProxyOperationLookupInput>;

export const ProxyDeliveryState = z.enum([
  'admitted',
  'dispatching',
  'response_received',
  'outcome_unknown',
]);
export const ProxyReplayState = z.enum(['none', 'screening', 'available', 'expired', 'erased']);
export const ProxyAccountingState = z.enum(['reserved', 'committed', 'released']);

export const ProxyOperationStatus = z.object({
  operation_id: ProxyOperationId,
  delivery_state: ProxyDeliveryState,
  replay_state: ProxyReplayState,
  accounting_state: ProxyAccountingState,
  provider: z.string(),
  method: z.enum(['POST', 'PUT', 'PATCH', 'DELETE']),
  created_at: z.string().datetime(),
  dispatched_at: z.string().datetime().nullable(),
  response_received_at: z.string().datetime().nullable(),
  /** Set once the outcome stayed unknown for PROXY_OPERATION_UNRESOLVED_AFTER_DAYS with nothing settling it: never sent again. */
  unresolved_at: z.string().datetime().nullable(),
  provider_outcome: z.enum(['not_required', 'pending', 'confirmed', 'not_found', 'contradictory', 'expired']),
  provider_status: z.enum(['pending', 'requires_action', 'succeeded', 'failed', 'canceled']).nullable(),
  response: z.object({
    status: z.number(),
    headers: z.record(z.string()),
    body: z.unknown(),
  }).optional(),
});
export type ProxyOperationStatus = z.infer<typeof ProxyOperationStatus>;

export const ProxyResponse = z.object({
  operation_id: ProxyOperationId.optional(),
  status: z.number(),
  headers: z.record(z.string()),
  body: z.unknown(),
});
export type ProxyResponse = z.infer<typeof ProxyResponse>;
