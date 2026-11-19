import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { createStackMcpServer } from './index.js';

type Schema = { type?: unknown; pattern?: unknown; const?: unknown; enum?: unknown; format?: unknown; minimum?: number; properties?: Record<string, Schema> };

// A value that would add a path segment, start a query and start a fragment
// if it reached a URL unencoded.
const HOSTILE = 'p/../q?r=s#t%u';

/** The server the tools under test are served by: the engine's, or STACK's hosted one. */
export type ServerFactory = typeof createStackMcpServer;

/** Every API path template in the tool sources of these folders that puts a raw value after a slash. */
export function rawPathInterpolations(dirs: string[]): string[] {
  const offenders: string[] = [];
  for (const dir of dirs.filter((candidate) => existsSync(candidate))) {
    const sources = readdirSync(dir)
      .filter((file) => file.endsWith('.ts') && !file.endsWith('.test.ts'))
      .map((file) => ({ file, text: readFileSync(join(dir, file), 'utf8') }));
    for (const { file, text } of sources) {
      for (const template of text.matchAll(/`\/v1\/[^`]*`/g)) {
        if (/\/\$\{(?!encodeURIComponent\()/.test(template[0])) offenders.push(`${file}: ${template[0]}`);
      }
    }
  }
  return offenders;
}

/**
 * Calls every tool the server serves with a hostile value in each of its string arguments and checks the URL keeps the
 * structure of the plain call. Returns how many URLs were probed.
 */
export async function probeEveryStringArgument(create: ServerFactory): Promise<number> {
  const urls: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    urls.push(url);
    return new Response('{"ok":true}', { status: 200 });
  }));
  const server = create('http://api.test', 'sk_test_key', { isPlatformStaff: true });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'path-encoding', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  const structure = (url: string) => {
    const parsed = new URL(url);
    return {
      segments: parsed.pathname.split('/').length,
      query: [...parsed.searchParams.keys()].sort(),
      hash: parsed.hash,
    };
  };
  const call = async (name: string, args: Record<string, unknown>) => {
    urls.length = 0;
    await client.callTool({ name, arguments: args });
    return urls[0];
  };

  let probed = 0;
  for (const tool of (await client.listTools()).tools) {
    const schema = tool.inputSchema as Schema;
    const properties: Record<string, Schema> = schema.properties ?? {};
    // Every property, so optional filters that reach the query string are covered too.
    const base: Record<string, unknown> = {};
    for (const [key, prop] of Object.entries(properties)) {
      if (prop.type === 'string' && !prop.pattern && !prop.const && !prop.enum && !prop.format) base[key] = 'id_1';
      else if (prop.type === 'integer' || prop.type === 'number') base[key] = prop.minimum ?? 1;
    }
    const baseline = await call(tool.name, base);
    if (!baseline) continue;
    for (const key of Object.keys(base)) {
      if (base[key] !== 'id_1') continue;
      const hostileUrl = await call(tool.name, { ...base, [key]: HOSTILE });
      if (!hostileUrl) continue;
      probed++;
      expect(structure(hostileUrl), `${tool.name}.${key}`).toEqual(structure(baseline));
      expect(hostileUrl, `${tool.name}.${key}`).not.toContain('#');
    }
  }
  await client.close();
  return probed;
}

/** Calls each named tool with a value that needs encoding and returns the URLs the API was asked for. */
export async function encodedPathsOf(
  create: ServerFactory,
  calls: Array<{ name: string; arguments: Record<string, unknown> }>,
): Promise<string[]> {
  const urls: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    urls.push(url);
    return new Response('{"ok":true}', { status: 200 });
  }));
  const server = create('http://api.test', 'sk_test_key');
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'path-encoding', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  for (const call of calls) await client.callTool(call);
  await client.close();
  return urls;
}
