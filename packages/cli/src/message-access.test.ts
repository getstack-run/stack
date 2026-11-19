import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { cmdMessageAccess } from './message-access.js';
import { cmdMessages } from './messages.js';

vi.mock('./api.js', async importOriginal => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({})) }));
vi.mock('./format.js', async importOriginal => ({ ...await importOriginal<object>(), printJson: vi.fn() }));

beforeEach(() => vi.clearAllMocks());

describe('message-access CLI', () => {
  it('reads the account values and one agent values', async () => {
    await cmdMessageAccess(['get']);
    await cmdMessageAccess(['get', 'agt_one']);
    expect(api).toHaveBeenNthCalledWith(1, 'GET', '/v1/message-access');
    expect(api).toHaveBeenNthCalledWith(2, 'GET', '/v1/agents/agt_one/message-access');
  });

  it('sets one or both values for the account or an agent, and clears the named ones', async () => {
    await cmdMessageAccess(['set', '--read-only', 'true']);
    await cmdMessageAccess(['set', '--read-teammates', 'false', '--read-only', 'false', 'agt_one']);
    await cmdMessageAccess(['clear', 'agt_one', 'read-teammates', 'read-only']);
    expect(api).toHaveBeenNthCalledWith(1, 'PUT', '/v1/message-access', { body: { messages_read_only: true } });
    expect(api).toHaveBeenNthCalledWith(2, 'PUT', '/v1/agents/agt_one/message-access', { body: { read_teammates: false, messages_read_only: false } });
    expect(api).toHaveBeenNthCalledWith(3, 'PUT', '/v1/agents/agt_one/message-access', { body: { read_teammates: null, messages_read_only: null } });
  });

  it('refuses a bad value or command before any request', async () => {
    await expect(cmdMessageAccess(['set'])).rejects.toThrow(/set takes/);
    await expect(cmdMessageAccess(['set', '--read-only', 'yes'])).rejects.toThrow(/true or false/);
    await expect(cmdMessageAccess(['clear', 'agt_one'])).rejects.toThrow(/clear takes/);
    await expect(cmdMessageAccess(['clear', 'agt_one', 'everything'])).rejects.toThrow(/clear takes/);
    await expect(cmdMessageAccess(['purge'])).rejects.toThrow(/message-access takes/);
    expect(api).not.toHaveBeenCalled();
  });
});

describe('messages CLI', () => {
  it('searches with every filter in the query', async () => {
    await cmdMessages(['search', '--agent', 'agt_one', '--channel', 'email', '--sender', 'a@example.com', '--recipient', 'b@example.com', '--thread', 'th1', '--after', '2026-11-01T00:00:00Z', '--before', '2026-11-10T00:00:00Z', '--q', 'invoice', '--limit', '10', '--cursor', 'c1']);
    expect(api).toHaveBeenCalledWith('GET', '/v1/messages', {
      query: { agent_id: 'agt_one', channel: 'email', sender: 'a@example.com', recipient: 'b@example.com', thread_id: 'th1', after: '2026-11-01T00:00:00Z', before: '2026-11-10T00:00:00Z', q: 'invoice', limit: '10', cursor: 'c1' },
    });
  });

  it('reads an attachment through its message', async () => {
    await cmdMessages(['attachment', 'acct_1', 'amsg_1', 'drv_1']);
    expect(api).toHaveBeenCalledWith('GET', '/v1/accounts/acct_1/messages/amsg_1/attachments/drv_1');
  });

  it('refuses a stray word or missing id before any request', async () => {
    await expect(cmdMessages(['search', 'oops'])).rejects.toThrow(/unexpected/);
    await expect(cmdMessages(['attachment', 'acct_1'])).rejects.toThrow(/message id/);
    await expect(cmdMessages(['purge'])).rejects.toThrow(/messages takes/);
    expect(api).not.toHaveBeenCalled();
  });
});
