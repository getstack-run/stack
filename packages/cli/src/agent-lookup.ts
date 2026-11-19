// Turning an agent's name into the agent. A name is unique among the agents that are not revoked, and can be used again
// once the agent that held it is deleted, while `GET /v1/agents` keeps the deleted one in its history as `revoked`. So a
// name always means the live agent: the first agent of that name in the list may be the old, revoked one. A server that
// reports no status (an older API) has no revoked agents to skip.

export function findAgentByName<T extends { name: string; status?: string | null }>(agents: readonly T[], name: string): T | undefined {
  return agents.find((agent) => agent.name === name && agent.status !== 'revoked');
}
