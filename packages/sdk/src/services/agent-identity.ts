import type { HttpClient } from '../client.js';
import {
  AgentIdentityVerificationError,
  verifyAgentIdentity,
  type AgentIdentityClaims,
  type AgentIdentityFacts,
  type AgentIdentityKeySource,
  type AgentIdentityLookup,
} from '../verify-agent-identity.js';

/** What to ask by: the key id of a Web Bot Auth signature the agent made, the host name of its site, or its id. Exactly one. */
export type AgentIdentityBy = { keyId: string } | { site: string } | { agentId: string };

/** STACK's answer to "who is this agent?": the signed statement, and the same facts as plain JSON. */
export interface AgentIdentityAnswer extends AgentIdentityFacts {
  /** The compact JWS STACK signed. Check it with `verifyAgentIdentity` (or use `verified`) before relying on a fact. */
  statement: string;
  issued_at: number;
  expires_at: number;
}

/** A statement that checked out: its claims, and when it stops being good. */
export interface VerifiedAgentIdentity {
  claims: AgentIdentityClaims;
  /** The facts, taken from the signed statement, never from the plain JSON beside it. */
  facts: AgentIdentityFacts;
  validUntil: Date;
}

/** Where an agent's machine files are, on STACK's own domain. */
export interface AgentIdentityUrls {
  lookup: string;
  agentCard: string;
  mcpServerCard: string;
  keyDirectory: string;
}

function lookupOf(by: AgentIdentityBy): { query: Record<string, string>; expect: AgentIdentityLookup } {
  if ('keyId' in by) return { query: { key_id: by.keyId }, expect: { key_id: by.keyId } };
  if ('site' in by) return { query: { site: by.site }, expect: { site: by.site.toLowerCase() } };
  return { query: { agent_id: by.agentId }, expect: { agent_id: by.agentId } };
}

/**
 * Who an agent is, answered on request by STACK: public, and no credential is sent or needed. The
 * answer says which agent it is, whether its account is in use, and three yes-or-no facts of the
 * owner who stands behind it (identity verified and good standing); never its Passport,
 * and nothing else of the owner. An agent that does not exist, is closed, or whose owner switched
 * the answer off is a `404` (`AGENT_IDENTITY_NOT_FOUND`) that never says which.
 */
export class AgentIdentityService {
  constructor(private readonly client: HttpClient) {}

  /** Ask by the key id of a signed request, the host name of the agent's site, or its id. The statement is not checked: see `verified`. */
  async lookup(by: AgentIdentityBy): Promise<AgentIdentityAnswer> {
    return this.client.publicRequest<AgentIdentityAnswer>('GET', '/v1/agent-identity', { query: lookupOf(by).query });
  }

  /**
   * Ask, then check the statement against STACK's published keys (or the keys you pin with `keys`):
   * its signature, type, audience, issuer, expiry, and that it answers exactly what you asked. The
   * facts come from the signed statement. Throws {@link AgentIdentityVerificationError} when it does
   * not check out, and the API's error (a `404` for an agent that is not found) otherwise.
   */
  async verified(by: AgentIdentityBy, options: { keys?: AgentIdentityKeySource; now?: Date } = {}): Promise<VerifiedAgentIdentity> {
    const answer = await this.lookup(by);
    const keys = options.keys ?? { jwksUrl: `${this.client.apiBaseUrl}/v1/.well-known/jwks.json` };
    const claims = await verifyAgentIdentity(answer.statement, { ...keys, expect: lookupOf(by).expect, ...(options.now ? { now: options.now } : {}) });
    return { claims, facts: { agent: claims.identity.agent, owner: claims.identity.owner, lookup: claims.identity.lookup }, validUntil: new Date(claims.exp * 1000) };
  }

  /** The addresses of an agent's lookup and machine files (its signed A2A card, MCP server card and key directory). */
  urls(agentId: string): AgentIdentityUrls {
    const base = this.client.apiBaseUrl;
    const id = encodeURIComponent(agentId);
    return {
      lookup: `${base}/v1/agent-identity?agent_id=${id}`,
      agentCard: `${base}/v1/agent-identity/agents/${id}/agent-card.json`,
      mcpServerCard: `${base}/v1/agent-identity/agents/${id}/mcp-server-card.json`,
      keyDirectory: `${base}/v1/agent-identity/agents/${id}/http-message-signatures-directory`,
    };
  }
}

export { AgentIdentityVerificationError };
