// The wire constants of who an agent is, answered on request by STACK
// (spec/agent-identity/SPEC.md): the signed statement's type, audience, version and
// lifetimes, the closed lists, the machine files an agent has on STACK's domain and
// the numbers a public reader sees. They are the public specification's, so they
// live here, outside the hosted layer: the specification generator reads its
// constants table from this file, and STACK's own implementation imports the same.

/** The protected `typ` of a signed identity statement: no other STACK object has it, and a Passport has none. */
export const AGENT_IDENTITY_TYP = 'stack-agent-identity+jwt';
/** The `aud` of a signed identity statement: never a Passport's `stack:passport`. */
export const AGENT_IDENTITY_AUDIENCE = 'stack:agent-identity';
/** The version of the claim a statement carries. */
export const AGENT_IDENTITY_CLAIM_VERSION = 1;
/** How long a statement is good for, in seconds: a verifier asks again rather than keeping one. */
export const AGENT_IDENTITY_TTL_SECONDS = 300;
/** The longest a statement may be made good for, and the longest a verifier takes one to be. */
export const AGENT_IDENTITY_MAX_TTL_SECONDS = 900;

/** What an agent's account is doing. A closed agent is only ever named to someone who already holds its unguessable id. */
export const AGENT_IDENTITY_STATUSES = ['active', 'suspended', 'closed'] as const;
export type AgentIdentityStatus = (typeof AGENT_IDENTITY_STATUSES)[number];

/** What a lookup can be addressed by: something public that an outsider actually has. */
export const AGENT_IDENTITY_SELECTORS = ['key_id', 'site', 'agent_id'] as const;
export type AgentIdentitySelector = (typeof AGENT_IDENTITY_SELECTORS)[number];

export const AGENT_IDENTITY_ROUTES = {
  lookup: '/v1/agent-identity',
  files: '/v1/agent-identity/agents',
} as const;

/** The machine files of one agent, under `/v1/agent-identity/agents/{agent_id}/`. */
export const AGENT_IDENTITY_FILES = {
  agent_card: 'agent-card.json',
  mcp_server_card: 'mcp-server-card.json',
  key_directory: 'http-message-signatures-directory',
} as const;
export type AgentIdentityFile = keyof typeof AGENT_IDENTITY_FILES;

/** The A2A card and the MCP server card say this when the owner has not chosen to show the agent's name. */
export const AGENT_IDENTITY_ANONYMOUS_DESCRIPTION = 'An AI agent operated through STACK.';

/** What the owner can switch. The defaults are the minimum: the endpoint answers, the name is not shown. */
export const AGENT_IDENTITY_SETTING_DEFAULTS = { enabled: true, show_name: false } as const;

export const AGENT_IDENTITY_NAME_MAX = 120;
