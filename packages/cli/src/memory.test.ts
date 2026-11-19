import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { printJson } from './format.js';
import { cmdMemory } from './memory.js';

vi.mock('./api.js', async (importOriginal) => ({ ...(await importOriginal<object>()), api: vi.fn(async () => ({})) }));
vi.mock('./format.js', async (importOriginal) => ({ ...(await importOriginal<object>()), printJson: vi.fn() }));
vi.mock('./secret-input.js', () => ({ readSecretFromStdin: vi.fn(async () => 'passport-from-stdin') }));
vi.mock('node:fs', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  readFileSync: vi.fn(() => 'text from a file'),
}));

const EDGE = '11111111-2222-4333-8444-555555555555';
const EPISODE = '66666666-7777-4888-8999-aaaaaaaaaaaa';
const PASSPORT = { headers: { 'X-Passport-Token': 'passport-from-stdin' } };

beforeEach(() => vi.clearAllMocks());

describe('memory CLI wire contract', () => {
  it('adds an episode as the operator, or as the agent with its Passport from stdin', async () => {
    await cmdMemory(['add', 'Maria is my accountant', '--name', 'Accountant', '--source', 'message', '--source-description', 'chat', '--at', '2026-10-01T10:00:00Z', '--saga', 'tax', '--previous', EPISODE]);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/memory/episodes', {
      body: {
        name: 'Accountant',
        episode_body: 'Maria is my accountant',
        source: 'message',
        source_description: 'chat',
        reference_time: '2026-10-01T10:00:00Z',
        saga: 'tax',
        previous_episode_uuids: [EPISODE],
      },
    });
    await cmdMemory(['add', '--name', 'Note', '--file', '/work/note.txt', '--exclude-type', 'Event', '--exclude-type', 'Place', '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/memory/episodes', {
      body: { name: 'Note', episode_body: 'text from a file', excluded_entity_types: ['Event', 'Place'] },
      ...PASSPORT,
    });
    expect(printJson).toHaveBeenCalledTimes(2);
  });

  it('refuses what it cannot send, and never takes a Passport from argv', async () => {
    await expect(cmdMemory(['add', 'x', '--name', 'n', '--source', 'email'])).rejects.toThrow(/--source takes/);
    await expect(cmdMemory(['add', 'x'])).rejects.toThrow(/--name is required/);
    await expect(cmdMemory(['add', '--name', 'n'])).rejects.toThrow(/text is required/);
    await expect(cmdMemory(['search-nodes', 'x', '--max', 'ten'])).rejects.toThrow(/whole number/);
    await expect(cmdMemory(['search-nodes', '--passport', 'secret'])).rejects.toThrow(/must not be placed in argv/);
    await expect(cmdMemory(['search-facts', 'x', '--token=secret'])).rejects.toThrow(/must not be placed in argv/);
    expect(api).not.toHaveBeenCalled();
  });

  it('writes a triplet and summarizes a saga', async () => {
    await cmdMemory(['triplet', '--source', 'Maria', '--edge', 'WORKS_FOR', '--fact', 'Maria works for Kvarnen', '--target', 'Kvarnen', '--source-uuid', EDGE, '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/memory/triplets', {
      body: { source_node_name: 'Maria', edge_name: 'WORKS_FOR', fact: 'Maria works for Kvarnen', target_node_name: 'Kvarnen', source_node_uuid: EDGE },
      ...PASSPORT,
    });
    await expect(cmdMemory(['triplet', '--source', 'Maria'])).rejects.toThrow(/--edge is required/);
    await cmdMemory(['summarize-saga', 'tax']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/memory/sagas/summary', { body: { saga_name: 'tax' } });
  });

  it('searches and reads', async () => {
    await cmdMemory(['search-nodes', 'Maria', '--max', '5', '--type', 'Person', '--center', EDGE]);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/memory/nodes/search', { body: { query: 'Maria', max_nodes: 5, entity_types: ['Person'], center_node_uuid: EDGE } });
    await cmdMemory(['search-nodes', 'Invoice', '--type', 'Invoice', '--where', 'currency=EUR', '--where', 'amount=1200', '--where', 'paid=false', '--where', 'due=2026-11-30', '--where', 'number="5"', '--where', 'note=a=b']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/memory/nodes/search', {
      body: {
        query: 'Invoice',
        entity_types: ['Invoice'],
        field_filters: [
          { field: 'currency', value: 'EUR' },
          { field: 'amount', value: 1200 },
          { field: 'paid', value: false },
          { field: 'due', value: '2026-11-30' },
          { field: 'number', value: '5' },
          { field: 'note', value: 'a=b' },
        ],
      },
    });
    for (const bad of ['currency', '=EUR', 'currency=']) {
      await expect(cmdMemory(['search-nodes', 'x', '--type', 'Invoice', '--where', bad])).rejects.toThrow(/--where takes <field>=<value>/);
    }
    await cmdMemory(['search-facts', 'where does Maria work', '--max', '3', '--edge-type', 'WORKS_FOR', '--valid-after', '2026-01-01T00:00:00Z', '--invalid-before', '2026-12-31T00:00:00Z', '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/memory/facts/search', {
      body: { query: 'where does Maria work', max_facts: 3, edge_types: ['WORKS_FOR'], valid_at_after: '2026-01-01T00:00:00Z', invalid_at_before: '2026-12-31T00:00:00Z' },
      ...PASSPORT,
    });
    await cmdMemory(['episodes', '--max', '25']);
    expect(api).toHaveBeenLastCalledWith('GET', '/v1/memory/episodes', { query: { max_episodes: '25' } });
    await cmdMemory(['episodes']);
    expect(api).toHaveBeenLastCalledWith('GET', '/v1/memory/episodes', { query: {} });
    await cmdMemory(['fact', EDGE, '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('GET', `/v1/memory/facts/${EDGE}`, PASSPORT);
    await cmdMemory(['episode-entities', EPISODE, EDGE]);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/memory/episode-entities', { body: { episode_uuids: [EPISODE, EDGE] } });
    await expect(cmdMemory(['episode-entities'])).rejects.toThrow(/episode uuid is required/);
  });

  it('deletes an episode and a fact', async () => {
    await cmdMemory(['delete-episode', EPISODE, '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('DELETE', `/v1/memory/episodes/${EPISODE}`, PASSPORT);
    await cmdMemory(['delete-fact', EDGE]);
    expect(api).toHaveBeenLastCalledWith('DELETE', `/v1/memory/facts/${EDGE}`, {});
  });

  it('writes an id into the path as one segment', async () => {
    await cmdMemory(['fact', '../../v1/accounts']);
    expect(api).toHaveBeenLastCalledWith('GET', '/v1/memory/facts/..%2F..%2Fv1%2Faccounts', {});
  });

  it('reads and changes whether memory is on, as the owner', async () => {
    await cmdMemory(['settings']);
    expect(api).toHaveBeenLastCalledWith('GET', '/v1/memory/settings');
    await cmdMemory(['settings', '--enabled', 'off']);
    expect(api).toHaveBeenLastCalledWith('PUT', '/v1/memory/settings', { body: { enabled: false } });
    await expect(cmdMemory(['settings', '--enabled', 'maybe'])).rejects.toThrow(/on or off/);
    await cmdMemory(['settings', '--call-memory-access', 'off']);
    expect(api).toHaveBeenLastCalledWith('PUT', '/v1/memory/settings', { body: { call_memory_access: false } });
  });

  it('says what it takes when it is not given a command', async () => {
    await expect(cmdMemory([])).rejects.toThrow(/memory takes add, triplet/);
    await expect(cmdMemory(['remember', 'x'])).rejects.toThrow(/memory takes add/);
    await expect(cmdMemory(['fact'])).rejects.toThrow(/fact uuid is required/);
  });
});

describe('memory CLI: entity types, history and undo', () => {
  it("lists, adds, changes and retires the account's own types with the bodies the API takes", async () => {
    await cmdMemory(['types', '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('GET', '/v1/memory/entity-types', PASSPORT);
    await cmdMemory(['type-add', 'Invoice', '--description', 'A bill.', '--field', 'amount:number', '--field', 'currency:one_of:EUR,USD']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/memory/entity-types', {
      body: { name: 'Invoice', description: 'A bill.', fields: [{ name: 'amount', kind: 'number' }, { name: 'currency', kind: 'one_of', options: ['EUR', 'USD'] }] },
    });
    await cmdMemory(['type-change', 'Invoice', '--description', 'A bill sent.', '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('PATCH', '/v1/memory/entity-types/Invoice', { body: { description: 'A bill sent.' }, ...PASSPORT });
    await cmdMemory(['type-retire', 'Invoice']);
    expect(api).toHaveBeenLastCalledWith('DELETE', '/v1/memory/entity-types/Invoice', {});
  });

  it('reads the history and undoes a write, or only says what an undo would take', async () => {
    await cmdMemory(['history', '--max', '5']);
    expect(api).toHaveBeenLastCalledWith('GET', '/v1/memory/history', { query: { max_writes: '5' } });
    await cmdMemory(['history', '--max', '5', '--cursor', '57']);
    expect(api).toHaveBeenLastCalledWith('GET', '/v1/memory/history', { query: { max_writes: '5', cursor: '57' } });
    await cmdMemory(['undo', 'mmo_abcdefgh1234', '--dry-run', '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/memory/writes/mmo_abcdefgh1234/undo', { body: { dry_run: true }, ...PASSPORT });
    await cmdMemory(['undo', 'mmo_abcdefgh1234']);
    expect(api).toHaveBeenLastCalledWith('POST', '/v1/memory/writes/mmo_abcdefgh1234/undo', { body: { dry_run: false } });
  });

  it('refuses a field it cannot send, a change with nothing in it, and a missing description', async () => {
    await expect(cmdMemory(['type-add', 'Invoice', '--description', 'x', '--field', 'amount:money'])).rejects.toThrow(/--field takes/);
    await expect(cmdMemory(['type-add', 'Invoice'])).rejects.toThrow(/--description is required/);
    await expect(cmdMemory(['type-change', 'Invoice'])).rejects.toThrow(/give --description/);
    await expect(cmdMemory(['undo'])).rejects.toThrow(/write id is required/);
    expect(api).not.toHaveBeenCalled();
  });
});
