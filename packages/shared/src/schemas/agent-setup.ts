import { z } from 'zod';
import { RegisterAgentInput } from './agent.js';
import { GrantAgentAccessInput } from './service.js';
import { oneLine, quotedText } from '../utils/approval-scope-lines.js';

/**
 * Setting up an agent is one decision, not three: its registration, its first grants on connections the owner
 * already made, and the hosts those connections' credentials may be sent to, asked of a person as one card that
 * lists all of it. The approval binds the whole request by its payload hash, so what runs is exactly what the
 * person saw, and nothing is hidden inside a combined request.
 */

/** A first grant: the grant input without the agent, which this request is about to make. */
export const AgentSetupGrant = GrantAgentAccessInput.omit({ agent_id: true });
export type AgentSetupGrant = z.infer<typeof AgentSetupGrant>;

/** The hosts one existing connection's credential may be sent to. */
export const AgentSetupHosts = z.object({
  service_connection_id: z.string().min(1),
  allowed_hosts: z.array(z.string().min(1).max(253)).min(1),
});
export type AgentSetupHosts = z.infer<typeof AgentSetupHosts>;

export const AgentSetupInput = z
  .object({
    agent: RegisterAgentInput,
    grants: z.array(AgentSetupGrant).default([]),
    allowed_hosts: z.array(AgentSetupHosts).default([]),
  })
  .superRefine((value, ctx) => {
    if (value.grants.length === 0 && value.allowed_hosts.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['grants'],
        message: 'A setup names at least one grant or one host list; to register an agent alone, register it',
      });
    }
    const seen = new Set<string>();
    value.grants.forEach((grant, index) => {
      if (seen.has(grant.service_connection_id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['grants', index, 'service_connection_id'],
          message: 'One grant per connection: list each connection once',
        });
      }
      seen.add(grant.service_connection_id);
    });
    const hostSeen = new Set<string>();
    value.allowed_hosts.forEach((entry, index) => {
      if (hostSeen.has(entry.service_connection_id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['allowed_hosts', index, 'service_connection_id'],
          message: 'One host list per connection: list each connection once',
        });
      }
      hostSeen.add(entry.service_connection_id);
    });
  });
export type AgentSetupInput = z.infer<typeof AgentSetupInput>;
export type AgentSetupRequest = z.input<typeof AgentSetupInput>;

/**
 * What the approval card shows of a setup: everything the request will do, with the names of the connections it
 * names. It is derived from the request and from the customer's own connections, never from the caller's words.
 */
export interface AgentSetupPreview {
  agent: {
    name: string;
    description: string | null;
    accountability_mode: string;
    on_warning: string;
    on_critical: string;
    credential_access: string;
    eval_traffic: boolean;
    /** Every other registration field the request sets (see `describeOtherAgentFields`). */
    other_fields?: Array<{ field: string; value: string }>;
  };
  grants: Array<{
    service_connection_id: string;
    /** The connection's name as the owner gave it, read when the approval was asked. Absent from an older approval. */
    connection_name?: string;
    service: string;
    scopes: string[];
    /** Every constraint, in full. Nothing is summarised away. */
    constraints: Array<{ path: string; op: string; value: unknown }>;
    intents: string[];
    /** Rules of which any one allows a call, each with its named actions and every constraint once expanded. */
    alternatives?: Array<{ intents: string[]; constraints: Array<{ path: string; op: string; value: unknown }> }>;
    allow_data_from: string[];
  }>;
  allowed_hosts: Array<{ service_connection_id: string; connection_name?: string; service: string; hosts: string[] }>;
}

/** The registration fields the card of a setup shows on a line of its own, in `AgentSetupPreview.agent`. */
export const SETUP_PREVIEW_SHOWN_AGENT_FIELDS: readonly string[] = [
  'name',
  'description',
  'accountability_mode',
  'on_warning',
  'on_critical',
  'credential_access',
  'eval_traffic',
];

const CLIP_AT = 80;

/**
 * One value as a person reads it: a text in quotes and on one line (a newline or a line that looks like another part of
 * the change stays inside the quotes), a flag or a number as it is, a list as each item, a value that is not set as `none`.
 * A long text is clipped with its length.
 */
function shownValue(value: unknown): string {
  if (value === null) return 'none';
  const item = (entry: unknown): string => {
    if (typeof entry !== 'string') return oneLine(JSON.stringify(entry) ?? String(entry));
    const text = oneLine(entry);
    return text.length > CLIP_AT * 1.25 ? `${quotedText(text.slice(0, CLIP_AT))}... (${text.length} characters)` : quotedText(text);
  };
  return (Array.isArray(value) ? value : [value]).map(item).join(', ');
}

/**
 * Every other field of the registration the request sets, as `{ field, value }`: whatever `RegisterAgentInput` binds
 * that the card does not list itself. It is read from the payload by the schema's own field list, never from a list
 * kept by hand, so a field added to the registration is on the card from the day it exists (the approval binds the
 * whole payload, and the person must be able to see all of it). A field left out is not shown; a value is clipped
 * with its length so a long one cannot bury the rest.
 */
export function describeOtherAgentFields(agent: RegisterAgentInput): Array<{ field: string; value: string }> {
  const out: Array<{ field: string; value: string }> = [];
  for (const field of Object.keys(RegisterAgentInput.shape)) {
    if (SETUP_PREVIEW_SHOWN_AGENT_FIELDS.includes(field)) continue;
    const value = (agent as Record<string, unknown>)[field];
    if (value === undefined) continue;
    out.push({ field, value: shownValue(value) });
  }
  return out;
}
