import { describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createStackMcpServer, directoryDescriptionsOf, DIRECTORY_EXCLUDED_TOOLS, ENGINE_TOOL_MODULES, TOOL_ANNOTATIONS } from './index.js';
import { annotationProblems, moduleListProblems, registeredToolNames } from './tool-modules.checks.js';

async function listed(server: ReturnType<typeof createStackMcpServer>): Promise<string[]> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'tool-modules-test', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const names = (await client.listTools()).tools.map((tool) => tool.name);
  await client.close();
  return names;
}

describe('the engine\'s tool modules', () => {
  it('annotate exactly the tools they register, each in its own module', () => {
    expect(annotationProblems(ENGINE_TOOL_MODULES)).toEqual([]);
  });

  it('are listed once each, in places of their own, and all served by the engine', () => {
    expect(moduleListProblems(ENGINE_TOOL_MODULES)).toEqual([]);
    expect(ENGINE_TOOL_MODULES.every((module) => module.servedBy === 'engine')).toBe(true);
  });

  it('give the engine\'s annotation and directory tables, with no tool outside them', () => {
    const registered = ENGINE_TOOL_MODULES.flatMap(registeredToolNames).sort();
    expect(Object.keys(TOOL_ANNOTATIONS).sort()).toEqual(registered);
    for (const name of Object.keys(DIRECTORY_EXCLUDED_TOOLS)) expect(registered, name).toContain(name);
  });

  it('are what createStackMcpServer registers when it is given no modules', async () => {
    const names = await listed(createStackMcpServer('http://api.test', 'sk_test_unused'));
    expect([...names].sort()).toEqual(ENGINE_TOOL_MODULES.filter((module) => !module.staffOnly).flatMap(registeredToolNames).sort());
  });

  it('refuse a tool that no module annotates', () => {
    const bare = { ...ENGINE_TOOL_MODULES[0]!, id: 'bare-test', order: 9999, annotations: {}, exposure: { audience: 'owner' as const } };
    expect(() => createStackMcpServer('http://api.test', 'sk_test_unused', { modules: [bare] })).toThrow(/has no annotation entry/);
  });
});

describe('a module\'s directory descriptions', () => {
  const security = ENGINE_TOOL_MODULES.find((module) => module.id === 'security')!;
  const withText = (text: string, name = 'stack_scan') => ({ ...security, directoryDescriptions: { [name]: text } });

  async function descriptionOf(modules: typeof ENGINE_TOOL_MODULES, profile: 'standard' | 'directory'): Promise<string | undefined> {
    const server = createStackMcpServer('http://api.test', 'sk_test_unused', { modules, profile });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'tool-modules-test', version: '0.0.0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    const description = (await client.listTools()).tools.find((tool) => tool.name === 'stack_scan')?.description;
    await client.close();
    return description;
  }

  it('replace a tool\'s description in the directory profile and leave the standard profile as it was', async () => {
    const own = withText('Scan with a classifier that runs elsewhere.');
    expect(await descriptionOf([own], 'directory')).toBe('Scan with a classifier that runs elsewhere.');
    expect(await descriptionOf([own], 'standard')).toBe(await descriptionOf([security], 'standard'));
    expect(await descriptionOf([security], 'directory')).toBe(await descriptionOf([security], 'standard'));
  });

  it('are checked: a name the module does not register, an empty text and a tool the directory leaves out are refused', () => {
    expect(annotationProblems([withText('Plain text.')])).toEqual([]);
    expect(annotationProblems([withText('Plain text.', 'stack_not_a_tool')])).toEqual([
      'security: gives stack_not_a_tool a directory description, which it does not register',
    ]);
    expect(annotationProblems([withText('  ')])).toEqual(['security: gives stack_scan an empty directory description']);
    expect(annotationProblems([{ ...withText('Plain text.'), directoryExcluded: { stack_scan: 'Left out on purpose.' } }])).toEqual([
      'security: gives stack_scan a directory description and leaves it out of the directory',
    ]);
  });

  it('cannot be set twice for one tool', () => {
    expect(() => directoryDescriptionsOf([withText('One.'), { ...withText('Two.'), id: 'security-again' }])).toThrow(/two directory descriptions/);
  });
});
