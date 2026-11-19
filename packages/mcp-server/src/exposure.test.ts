import { describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ToolListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { createStackMcpServer, ENGINE_TOOL_MODULES, exposureOf, LOAD_ON_DEMAND_META, ToolSetController } from './index.js';
import { exposureProblems } from './tool-modules.checks.js';

// The engine knows one piece, the fleet an agent belongs to; the rest are the hosted product's.
const ENGINE_PIECES = ['fleet'];

async function connect(server: ReturnType<typeof createStackMcpServer>, client = new Client({ name: 'exposure-test', version: '0.0.0' })) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

const names = (tools: { name: string }[]) => tools.map((tool) => tool.name);

describe('the engine\'s tool exposure', () => {
  it('is said by every module, for tools it registers, with pieces it knows', () => {
    expect(exposureProblems(ENGINE_TOOL_MODULES, ENGINE_PIECES)).toEqual([]);
  });

  it('resolves every tool the engine registers, and no tool twice', () => {
    const resolved = exposureOf(ENGINE_TOOL_MODULES);
    const annotated = ENGINE_TOOL_MODULES.flatMap((module) => Object.keys(module.annotations));
    expect(Object.keys(resolved).sort()).toEqual([...annotated].sort());
  });

  it('refuses a module that sets the exposure of a tool it does not annotate', () => {
    const wrong = { ...ENGINE_TOOL_MODULES[0]!, id: 'wrong-test', order: 9998, exposure: { audience: 'owner' as const, tools: { stack_nothing: { audience: 'both' as const } } } };
    expect(() => exposureOf([wrong])).toThrow(/does not annotate/);
  });

  it('lists every tool when the session has no tool set, as the SDK and the CLI see it', async () => {
    const client = await connect(createStackMcpServer('http://api.test', 'sk_test_unused'));
    const listed = names((await client.listTools()).tools);
    expect(listed.length).toBe(ENGINE_TOOL_MODULES.flatMap((module) => Object.keys(module.annotations)).length);
    await client.close();
  });

  it('lists an agent only the agent\'s tools and an owner none of the agent-only ones', async () => {
    const resolved = exposureOf(ENGINE_TOOL_MODULES);
    const agent = await connect(createStackMcpServer('http://api.test', 'sk_test_unused', { toolSet: new ToolSetController('agent', []) }));
    const agentNames = names((await agent.listTools()).tools);
    expect(agentNames.length).toBeGreaterThan(0);
    for (const name of agentNames) expect(resolved[name]!.audience, name).not.toBe('owner');
    expect(agentNames).toContain('stack_issue_passport');
    expect(agentNames).not.toContain('stack_activate_fleet');
    expect(agentNames).not.toContain('stack_list_members');
    // A fleet agent's Mission start is listed only while the agent is in a fleet.
    expect(agentNames).not.toContain('stack_start_mission');
    await agent.close();

    const fleetAgent = await connect(createStackMcpServer('http://api.test', 'sk_test_unused', { toolSet: new ToolSetController('agent', ['fleet']) }));
    expect(names((await fleetAgent.listTools()).tools)).toContain('stack_start_mission');
    await fleetAgent.close();

    const owner = await connect(createStackMcpServer('http://api.test', 'sk_test_unused', { toolSet: new ToolSetController('owner', []) }));
    const ownerNames = names((await owner.listTools()).tools);
    for (const name of ownerNames) expect(resolved[name]!.audience, name).not.toBe('agent');
    expect(ownerNames).toContain('stack_activate_fleet');
    expect(ownerNames).toContain('stack_list_members');
    expect(ownerNames).not.toContain('stack_checkpoint');
    await owner.close();
  });

  it('keeps the approval tools to a person: the API refuses an agent\'s context on every approval route', async () => {
    const resolved = exposureOf(ENGINE_TOOL_MODULES);
    const approvalTools = ['stack_get_approval', 'stack_list_approvals'];
    for (const name of approvalTools) expect(resolved[name]?.audience, name).toBe('owner');
    const agent = await connect(createStackMcpServer('http://api.test', 'sk_test_unused', { toolSet: new ToolSetController('agent', []) }));
    const agentNames = names((await agent.listTools()).tools);
    for (const name of approvalTools) expect(agentNames, name).not.toContain(name);
    await agent.close();
    const owner = await connect(createStackMcpServer('http://api.test', 'sk_test_unused', { toolSet: new ToolSetController('owner', []) }));
    const ownerNames = names((await owner.listTools()).tools);
    for (const name of approvalTools) expect(ownerNames, name).toContain(name);
    await owner.close();
  });

  it('refuses a call to a tool the session does not list, before its handler runs', async () => {
    const client = await connect(createStackMcpServer('http://api.test', 'sk_test_unused', { toolSet: new ToolSetController('agent', []) }));
    const refused = await client.callTool({ name: 'stack_list_members', arguments: {} });
    expect(refused.isError).toBe(true);
    expect(JSON.stringify(refused.content)).toMatch(/disabled/);
    await client.close();
  });

  it('marks a rarely used tool with the load-on-demand hint and no other tool', async () => {
    const resolved = exposureOf(ENGINE_TOOL_MODULES);
    const client = await connect(createStackMcpServer('http://api.test', 'sk_test_unused', { toolSet: new ToolSetController('owner', []) }));
    const tools = (await client.listTools()).tools;
    for (const tool of tools) {
      if (resolved[tool.name]!.deferred) expect(tool._meta, tool.name).toEqual(LOAD_ON_DEMAND_META);
      else expect(tool._meta, tool.name).toBeUndefined();
    }
    expect(tools.some((tool) => tool._meta)).toBe(true);
    expect(tools.some((tool) => !tool._meta)).toBe(true);
    await client.close();
  });

  it('never narrows or marks the directory profile, whatever tool set it is given', async () => {
    const plain = await connect(createStackMcpServer('http://api.test', 'sk_test_unused', { profile: 'directory' }));
    const narrowed = await connect(createStackMcpServer('http://api.test', 'sk_test_unused', { profile: 'directory', toolSet: new ToolSetController('agent', []) }));
    const a = (await plain.listTools()).tools;
    const b = (await narrowed.listTools()).tools;
    expect(b).toEqual(a);
    expect(b.some((tool) => tool._meta)).toBe(false);
    await plain.close();
    await narrowed.close();
  });

  it('sends one list-changed notice when the pieces change a list, and none when they do not', async () => {
    const toolSet = new ToolSetController('agent', []);
    let notices = 0;
    const client = new Client({ name: 'exposure-test', version: '0.0.0' });
    client.setNotificationHandler(ToolListChangedNotificationSchema, () => {
      notices += 1;
    });
    await connect(createStackMcpServer('http://api.test', 'sk_test_unused', { toolSet }), client);
    const before = names((await client.listTools()).tools);

    expect(toolSet.update(['fleet'])).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(notices).toBe(1);
    const after = names((await client.listTools()).tools);
    expect(after.filter((name) => !before.includes(name)).sort()).toEqual(['stack_renew_mission', 'stack_start_mission']);

    expect(toolSet.update(['fleet'])).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(notices).toBe(1);
    await client.close();
  });
});
