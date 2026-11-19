import { z } from 'zod';
import { ANY_OF_BUDGET_MESSAGE, ANY_OF_MAX_GROUPS, Constraint, PlainConstraint, withinAnyOfBudget } from './passport.js';
import { IntentRef } from '../intents/types.js';

/**
 * A provider key such as `slack`, `okta` or `zendesk`.
 *
 * Deliberately a string, not an enum: the service catalog (the `services` table,
 * seeded by `packages/shared/src/db/seed.ts`) is the source of truth
 * and holds far more providers than any list kept here could. An enum here
 * would reject every provider it forgot to name.
 */
export const ServiceProvider = z.string().min(1);
export type ServiceProvider = z.infer<typeof ServiceProvider>;

/**
 * The name a customer gives one connection of a service ("work", "Personal 2"). One line of letters, digits, spaces
 * and hyphens, at most 40 characters, and never the shape of an id (`scon_`), so a call's `connection` can be read as
 * an id or a name without guessing. Compared without case, which the database index and the resolver both do.
 */
export const CONNECTION_NAME_MAX_LENGTH = 40;
export const ConnectionName = z
  .string()
  .trim()
  .min(1)
  .max(CONNECTION_NAME_MAX_LENGTH)
  .regex(/^[A-Za-z0-9 -]+$/, 'Use letters, digits, spaces and hyphens on one line');
export type ConnectionName = z.infer<typeof ConnectionName>;

/** What a call passes to choose among several connections of one service: a connection id (`scon_...`) or a name. */
export const ConnectionSelector = z.string().trim().min(1).max(128);
export type ConnectionSelector = z.infer<typeof ConnectionSelector>;

export const Service = z.object({
  id: z.string(),
  provider: ServiceProvider,
  name: z.string(),
  description: z.string(),
  oauth_config: z.object({
    auth_url: z.string().url(),
    token_url: z.string().url(),
    scopes_available: z.array(z.string()),
  }),
  available: z.boolean(),
});
export type Service = z.infer<typeof Service>;

export const ConnectServiceInput = z.object({
  service_id: z.string(),
  scopes: z.array(z.string()).min(1),
  redirect_uri: z.string().url().optional(),
  /**
   * Hosts this connection's credential may be sent to.
   *
   * Needed only for a per-tenant provider (your Okta org, your Zendesk
   * subdomain, your self-hosted Grafana). STACK cannot know that host: it is
   * yours. The connect dialog asks for it as a required field alongside the
   * credential, so it is never a separate step and never a later failure.
   *
   * Omit it for any other provider. PROVIDER_API_HOSTS answers those.
   */
  allowed_hosts: z.array(z.string().min(1).max(253)).optional(),
  /**
   * The address of the service's MCP endpoint, when it speaks MCP over HTTP: `stack_service_tools` and
   * `stack_service_call_tool` send their calls there. https, and on one of this connection's allowed hosts (checked here,
   * and again by the proxy on every call). Omit it for a service that does not speak MCP, or one STACK knows (RentAHuman).
   */
  mcp_url: z.string().min(1).max(2048).optional(),
  /** What to call this connection. Omit it for the first connection of a service (it is named `default`); a second needs a name. */
  connection_name: ConnectionName.optional(),
});
export type ConnectServiceInput = z.infer<typeof ConnectServiceInput>;

export const ServiceConnection = z.object({
  id: z.string(),
  operator_id: z.string(),
  service_id: z.string(),
  provider: ServiceProvider,
  name: z.string(),
  scopes: z.array(z.string()),
  credential_ref: z.string(), // pointer to KMS-encrypted credential
  status: z.enum(['active', 'expired', 'revoked']),
  connected_at: z.date(),
  expires_at: z.date().nullable(),
});
export type ServiceConnection = z.infer<typeof ServiceConnection>;

export const ConnectCustomServiceInput = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  credential: z.union([
    z.string().min(1),
    z.record(z.string(), z.string().min(1)),
  ]).optional(), // Single credential string or key-value pairs (optional — enables "enable without connecting")
  scopes: z.array(z.string()).optional(), // free-form scopes the operator defines
  template: z.string().optional(), // If provided, validates credential fields against the named template
  oauth_auth_url: z.string().url().optional(),
  oauth_token_url: z.string().url().optional(),
  /**
   * Hosts this connection's credential may be sent to.
   *
   * A custom service is the one case STACK cannot know the destination for:
   * it is the operator's own API. Every catalogue provider is resolved from
   * PROVIDER_API_HOSTS, and every per-tenant provider is derived from the
   * credential itself, so this is the ONLY place the operator is ever asked.
   *
   * Optional on the wire because it can still be derived when the credential
   * carries a `base_url` / `url` / `host` field. `connectCustom` refuses when
   * it is neither supplied nor derivable, rather than creating a connection
   * that cannot proxy — the dashboard makes it a required field so an
   * operator meets this at the connect dialog, never as a later failure.
   */
  allowed_hosts: z.array(z.string().min(1).max(253)).optional(),
  /**
   * The address of the service's MCP endpoint, when it speaks MCP over HTTP: `stack_service_tools` and
   * `stack_service_call_tool` send their calls there. https, and on one of this connection's allowed hosts (checked here,
   * and again by the proxy on every call). Omit it for a service that does not speak MCP, or one STACK knows (RentAHuman).
   */
  mcp_url: z.string().min(1).max(2048).optional(),
  /** What to call this connection. Omit it for the first connection of a service (it is named `default`); a second needs a name. */
  connection_name: ConnectionName.optional(),
}).refine(
  (data) => {
    const hasAuth = !!data.oauth_auth_url;
    const hasToken = !!data.oauth_token_url;
    return hasAuth === hasToken; // both or neither
  },
  { message: 'oauth_auth_url and oauth_token_url must both be provided together', path: ['oauth_auth_url'] },
);
export type ConnectCustomServiceInput = z.infer<typeof ConnectCustomServiceInput>;

/**
 * One rule of a grant: a read rule, a post rule. A call is allowed when it
 * fits any ONE of a grant's rules (and the grant's own `intents` and
 * `constraints`, which every rule shares). Inside one rule everything must
 * hold, as in a flat list. A rule with no limits allows every call the
 * grant's own intents and constraints allow.
 */
export const AccessAlternative = z
  .object({
    intents: z.array(IntentRef).max(32).optional(),
    constraints: z.array(PlainConstraint).max(32).optional(),
  })
  .strict();
export type AccessAlternative = z.infer<typeof AccessAlternative>;

export const GrantAgentAccessInput = z.object({
  agent_id: z.string(),
  service_connection_id: z.string(),
  scopes: z.array(z.string()).min(1), // must be subset of connection scopes
  // Optional parameter-level constraints — the operator's baseline ceiling
  // for what this agent can do on this service. Passports issued against
  // this grant may add more constraints (tighten) but never loosen.
  constraints: z.array(Constraint).max(32).refine(withinAnyOfBudget, { message: ANY_OF_BUDGET_MESSAGE }).optional(),
  // Alternative surface: declare intents that expand server-side to
  // constraints. Merged with `constraints` before persisting. Combined
  // total after expansion must still be ≤ 32.
  intents: z.array(IntentRef).max(32).optional(),
  // Several rules on this connection, any one of which allows a call (a read
  // rule and a post rule, say). `intents` and `constraints` above apply to
  // every one of them. Two or more rules; one rule is the same as listing its
  // intents and constraints above.
  alternatives: z.array(AccessAlternative).min(1).max(ANY_OF_MAX_GROUPS).optional(),
  // Optional data-flow authority. Names the services whose content may flow
  // INTO this one. A Passport may inherit or narrow this list, never add to
  // it. `['*']` means every service currently granted to this agent; issue
  // resolves it to exact provider names before signing. Absent/empty means
  // no cross-service movement.
  allow_data_from: z
    .array(z.string().min(1).max(128))
    .max(32)
    .refine((items) => !items.includes('*') || items.length === 1, {
      message: 'allow_data_from "*" must be the only entry',
    })
    .optional(),
});
export type GrantAgentAccessInput = z.infer<typeof GrantAgentAccessInput>;

export const AgentServiceGrant = z.object({
  id: z.string(),
  agent_id: z.string(),
  service_connection_id: z.string(),
  scopes: z.array(z.string()),
  granted_at: z.date(),
  revoked_at: z.date().nullable(),
});
export type AgentServiceGrant = z.infer<typeof AgentServiceGrant>;
