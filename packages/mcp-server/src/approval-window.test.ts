import { describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { GOVERNANCE_APPROVAL_TTL_SECONDS, GOVERNANCE_TENANT_APPROVAL_TTL_SECONDS } from '@stack/shared';
import { createStackMcpServer, type McpProfile } from './index.js';
import { approvalFlow } from './tools/shared.js';

// How long a person has to answer a governance approval is the API's number
// (GOVERNANCE_APPROVAL_TTL_SECONDS). A chat agent that raises one and a person who
// answers from the Console hours later need the window to be a day, and every
// place that states it has to say what the API does.

async function listTools(profile: McpProfile) {
  const server = createStackMcpServer('http://api.test', 'sk_test_unused', { profile });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'approval-window-test', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const { tools } = await client.listTools();
  await client.close();
  return tools;
}

const hours = (seconds: number) => `${seconds / 3600} hours`;

describe('the approval window', () => {
  it('is long enough for a person who answers later, for a customer and for a partner\'s tenant', () => {
    expect(GOVERNANCE_APPROVAL_TTL_SECONDS).toBeGreaterThanOrEqual(24 * 60 * 60);
    expect(GOVERNANCE_TENANT_APPROVAL_TTL_SECONDS).toBeGreaterThanOrEqual(24 * 60 * 60);
  });

  it('is the one the shared step-up sentence and the approval read tool both state', async () => {
    expect(approvalFlow).toContain(`expires after ${hours(GOVERNANCE_APPROVAL_TTL_SECONDS)}`);
    for (const profile of ['standard', 'directory'] as const) {
      const read = (await listTools(profile)).find((tool) => tool.name === 'stack_get_approval');
      expect(read?.description, profile).toContain(`An approval lasts ${hours(GOVERNANCE_APPROVAL_TTL_SECONDS)}`);
    }
  });

  it('is read by tools that are read-only and closed-world, in both profiles', async () => {
    for (const profile of ['standard', 'directory'] as const) {
      const tools = await listTools(profile);
      for (const name of ['stack_get_approval', 'stack_list_approvals']) {
        const read = tools.find((tool) => tool.name === name);
        expect(read, `${profile} ${name}`).toBeDefined();
        expect(read?.annotations?.readOnlyHint, `${profile} ${name}`).toBe(true);
        expect(read?.annotations?.openWorldHint, `${profile} ${name}`).toBe(false);
        expect(read?.description, `${profile} ${name}`).toMatch(/does not decide/);
        expect(read?.description, `${profile} ${name}`).toContain(`lasts ${hours(GOVERNANCE_APPROVAL_TTL_SECONDS)}`);
      }
    }
  });

  it('states no stale fifteen-minute window anywhere in the tool text', async () => {
    for (const tool of await listTools('standard')) {
      expect(`${tool.description ?? ''} ${JSON.stringify(tool.inputSchema)}`, tool.name).not.toMatch(/15[- ]minutes?[^.]*approv|approv[^.]*15[- ]minutes?/i);
    }
  });
});
