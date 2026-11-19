import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';
import { StackError } from '../errors.js';

interface Sent {
  method: string;
  path: string;
  search: string;
  body: unknown;
  headers: Record<string, string>;
}

function stubFetch(reply: { status: number; body?: unknown } = { status: 200, body: {} }): Sent[] {
  const calls: Sent[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string; headers?: Record<string, string> }) => {
      const parsed = new URL(url);
      calls.push({
        method: init.method ?? 'GET',
        path: parsed.pathname,
        search: parsed.search,
        body: init.body ? JSON.parse(init.body) : undefined,
        headers: init.headers ?? {},
      });
      if (reply.status === 204) return new Response(null, { status: 204 });
      return new Response(JSON.stringify(reply.body ?? {}), {
        status: reply.status,
        headers: { 'content-type': 'application/json' },
      });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_memory_test', baseUrl: 'http://api.fixture' });
const EDGE = '11111111-2222-4333-8444-555555555555';
const EPISODE = '66666666-7777-4888-8999-aaaaaaaaaaaa';
const TOKEN = 'jwt.passport.token';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('MemoryService', () => {
  it('adds an episode as given, with the Passport only on an agent call, and returns its status', async () => {
    const calls = stubFetch({ status: 201, body: { message: "Episode 'Accountant' queued", uuid: EPISODE, status: 'queued' } });
    const added = await stack().memory.addMemory({ name: 'Accountant', episode_body: 'Maria is my accountant', source: 'message', saga: 'tax', previous_episode_uuids: [EPISODE] });
    await stack().memory.addMemory({ name: 'Note', episode_body: 'Check the invoice number' }, { passportToken: TOKEN });
    expect(added).toEqual({ message: "Episode 'Accountant' queued", uuid: EPISODE, status: 'queued' });
    expect(calls[0]).toMatchObject({
      method: 'POST',
      path: '/v1/memory/episodes',
      body: { name: 'Accountant', episode_body: 'Maria is my accountant', source: 'message', saga: 'tax', previous_episode_uuids: [EPISODE] },
    });
    expect(calls[0]!.headers['X-Passport-Token']).toBeUndefined();
    expect(calls[1]!.headers['X-Passport-Token']).toBe(TOKEN);
    expect(JSON.stringify(calls[1]!.body)).not.toContain(TOKEN);
  });

  it('writes a triplet and a saga summary', async () => {
    const calls = stubFetch();
    const memory = stack().memory;
    await memory.addTriplet({ source_node_name: 'Maria', edge_name: 'WORKS_FOR', fact: 'Maria works for Kvarnen', target_node_name: 'Kvarnen', source_node_uuid: EDGE }, { passportToken: TOKEN });
    await memory.summarizeSaga('tax');
    expect(calls.map((c) => [c.method, c.path])).toEqual([
      ['POST', '/v1/memory/triplets'],
      ['POST', '/v1/memory/sagas/summary'],
    ]);
    expect(calls[0]!.body).toEqual({ source_node_name: 'Maria', edge_name: 'WORKS_FOR', fact: 'Maria works for Kvarnen', target_node_name: 'Kvarnen', source_node_uuid: EDGE });
    expect(calls[0]!.headers['X-Passport-Token']).toBe(TOKEN);
    expect(calls[1]!.body).toEqual({ saga_name: 'tax' });
  });

  it('searches nodes and facts, and reads episodes, a fact and what episodes produced', async () => {
    const calls = stubFetch();
    const memory = stack().memory;
    await memory.searchNodes({ query: 'Maria', max_nodes: 5, entity_types: ['Person'], center_node_uuid: EDGE, field_filters: [{ field: 'employer', value: 'Kvarnen' }] });
    await memory.searchMemoryFacts({ query: 'where does Maria work', max_facts: 3, valid_at_after: '2026-01-01T00:00:00Z' }, { passportToken: TOKEN });
    await memory.getEpisodes({ maxEpisodes: 25 });
    await memory.getEpisodes();
    await memory.getEntityEdge(EDGE);
    await memory.getEpisodeEntities([EPISODE, EDGE]);
    expect(calls.map((c) => [c.method, c.path])).toEqual([
      ['POST', '/v1/memory/nodes/search'],
      ['POST', '/v1/memory/facts/search'],
      ['GET', '/v1/memory/episodes'],
      ['GET', '/v1/memory/episodes'],
      ['GET', `/v1/memory/facts/${EDGE}`],
      ['POST', '/v1/memory/episode-entities'],
    ]);
    expect(calls[0]!.body).toEqual({ query: 'Maria', max_nodes: 5, entity_types: ['Person'], center_node_uuid: EDGE, field_filters: [{ field: 'employer', value: 'Kvarnen' }] });
    expect(calls[1]!.body).toEqual({ query: 'where does Maria work', max_facts: 3, valid_at_after: '2026-01-01T00:00:00Z' });
    expect(calls[1]!.headers['X-Passport-Token']).toBe(TOKEN);
    expect(calls[2]!.search).toBe('?max_episodes=25');
    expect(calls[3]!.search).toBe('');
    expect(calls[5]!.body).toEqual({ episode_uuids: [EPISODE, EDGE] });
  });

  it('deletes an episode and a fact, with the Passport when an agent does', async () => {
    const calls = stubFetch({ status: 200, body: { message: 'deleted' } });
    const memory = stack().memory;
    expect(await memory.deleteEpisode(EPISODE, { passportToken: TOKEN })).toEqual({ message: 'deleted' });
    await memory.deleteEntityEdge(EDGE);
    expect(calls.map((c) => [c.method, c.path])).toEqual([
      ['DELETE', `/v1/memory/episodes/${EPISODE}`],
      ['DELETE', `/v1/memory/facts/${EDGE}`],
    ]);
    expect(calls[0]!.headers['X-Passport-Token']).toBe(TOKEN);
    expect(calls[1]!.headers['X-Passport-Token']).toBeUndefined();
  });

  it('reads the history a page at a time, from the cursor of the page before', async () => {
    const calls = stubFetch({ status: 200, body: { message: 'ok', writes: [], next_cursor: '41' } });
    const memory = stack().memory;
    const first = await memory.getHistory({ maxWrites: 2 });
    await memory.getHistory({ maxWrites: 2, cursor: first.next_cursor! }, { passportToken: TOKEN });
    await memory.getHistory();
    expect(calls.map((c) => [c.method, c.path, c.search])).toEqual([
      ['GET', '/v1/memory/history', '?max_writes=2'],
      ['GET', '/v1/memory/history', '?max_writes=2&cursor=41'],
      ['GET', '/v1/memory/history', ''],
    ]);
    expect(calls[1]!.headers['X-Passport-Token']).toBe(TOKEN);
  });

  it('writes an id into the path as one segment', async () => {
    const calls = stubFetch();
    await stack().memory.getEntityEdge('../../v1/accounts');
    expect(calls[0]!.path).toBe('/v1/memory/facts/..%2F..%2Fv1%2Faccounts');
  });

  it('reads and changes whether memory is on', async () => {
    const calls = stubFetch();
    const memory = stack().memory;
    await memory.getSettings();
    await memory.updateSettings({ enabled: false });
    expect(calls.map((c) => [c.method, c.path])).toEqual([
      ['GET', '/v1/memory/settings'],
      ['PUT', '/v1/memory/settings'],
    ]);
    expect(calls[1]!.body).toEqual({ enabled: false });
  });

  it("surfaces the API's refusals by code", async () => {
    stubFetch({ status: 409, body: { error: { code: 'MEMORY_DISABLED', message: 'Memory is off for this account.' } } });
    const error = await stack().memory.addMemory({ name: 'n', episode_body: 'x' }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(StackError);
    expect(error).toMatchObject({ code: 'MEMORY_DISABLED', status: 409 });
    vi.unstubAllGlobals();
    stubFetch({ status: 404, body: { error: { code: 'NOT_FOUND', message: 'not found' } } });
    expect(await stack().memory.getEntityEdge(EDGE).catch((e: unknown) => e)).toMatchObject({ code: 'NOT_FOUND', status: 404 });
  });
});
