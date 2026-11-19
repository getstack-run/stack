import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createStackMcpServer } from './index.js';
import { createToolCallRunner, type ToolProgressNotification } from './tool-call.js';
import { TOOL_DEFAULT_DEADLINE_SECONDS, TOOL_PROGRESS_INTERVAL_MS } from './tool-deadlines.js';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const runner = () => createToolCallRunner({ pendingConfirmations: () => 0, confirmationTimeoutMs: 10 * 60 * 1000, api: vi.fn() as never });
const done = { content: [{ type: 'text', text: 'done' }] };

/** A handler that finishes when told to. */
function slowHandler() {
  const control = { finish: () => undefined as void };
  const handler = () => new Promise((resolve) => {
    control.finish = () => resolve(done);
  });
  return { control, handler };
}

function progressExtra(token: string | number | undefined, signal?: AbortSignal) {
  const sent: ToolProgressNotification[] = [];
  const sendNotification = vi.fn(async (notification: ToolProgressNotification) => {
    sent.push(notification);
  });
  return { sent, extra: { requestId: 1, ...(signal ? { signal } : {}), ...(token !== undefined ? { _meta: { progressToken: token } } : {}), sendNotification } };
}

describe('progress of a long tool call', () => {
  it('is sent every 20 seconds with the client\'s token and the seconds run, and stops when the call ends', async () => {
    vi.useFakeTimers();
    expect(TOOL_PROGRESS_INTERVAL_MS).toBe(20_000);
    const { sent, extra } = progressExtra('tok-1');
    const { control, handler } = slowHandler();
    const call = runner()('stack_list_agents', {}, extra, handler);
    await vi.advanceTimersByTimeAsync(19_000);
    expect(sent).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(26_000);
    expect(sent).toEqual([
      { method: 'notifications/progress', params: { progressToken: 'tok-1', progress: 20 } },
      { method: 'notifications/progress', params: { progressToken: 'tok-1', progress: 40 } },
    ]);
    control.finish();
    expect(await call).toEqual(done);
    await vi.advanceTimersByTimeAsync(5 * TOOL_PROGRESS_INTERVAL_MS);
    expect(sent).toHaveLength(2);
  });

  it('sends nothing when the client sent no progress token', async () => {
    vi.useFakeTimers();
    const { sent, extra } = progressExtra(undefined);
    const { control, handler } = slowHandler();
    const call = runner()('stack_list_agents', {}, extra, handler);
    await vi.advanceTimersByTimeAsync(50_000);
    control.finish();
    await call;
    expect(sent).toHaveLength(0);
  });

  it('sends nothing for a call that ends before 20 seconds', async () => {
    vi.useFakeTimers();
    const { sent, extra } = progressExtra(7);
    const { control, handler } = slowHandler();
    const call = runner()('stack_list_agents', {}, extra, handler);
    await vi.advanceTimersByTimeAsync(5_000);
    control.finish();
    await call;
    await vi.advanceTimersByTimeAsync(60_000);
    expect(sent).toHaveLength(0);
  });

  it('stops when the call passes its deadline', async () => {
    vi.useFakeTimers();
    const { sent, extra } = progressExtra(7);
    const call = runner()('stack_list_agents', {}, extra, () => new Promise(() => undefined));
    await vi.advanceTimersByTimeAsync(TOOL_DEFAULT_DEADLINE_SECONDS * 1000 + 10);
    expect((await call).isError).toBe(true);
    const atDeadline = sent.length;
    await vi.advanceTimersByTimeAsync(5 * TOOL_PROGRESS_INTERVAL_MS);
    expect(sent).toHaveLength(atDeadline);
    expect(sent.every((n) => n.params.progressToken === 7)).toBe(true);
  });

  it('stops when the client goes away, though the work is still running', async () => {
    vi.useFakeTimers();
    const gone = new AbortController();
    const { sent, extra } = progressExtra('tok-2', gone.signal);
    const { control, handler } = slowHandler();
    const call = runner()('stack_list_agents', {}, extra, handler);
    await vi.advanceTimersByTimeAsync(21_000);
    expect(sent).toHaveLength(1);
    gone.abort();
    await vi.advanceTimersByTimeAsync(3 * TOOL_PROGRESS_INTERVAL_MS);
    expect(sent).toHaveLength(1);
    control.finish();
    await call;
  });

  it('never fails the call when a notification cannot be sent', async () => {
    vi.useFakeTimers();
    const extra = { requestId: 1, _meta: { progressToken: 'tok-3' }, sendNotification: vi.fn(async () => { throw new Error('stream closed'); }) };
    const { control, handler } = slowHandler();
    const call = runner()('stack_list_agents', {}, extra, handler);
    await vi.advanceTimersByTimeAsync(41_000);
    expect(extra.sendNotification).toHaveBeenCalledTimes(2);
    control.finish();
    expect(await call).toEqual(done);
  });

  it('reaches a client that asked for progress over the protocol', async () => {
    vi.useFakeTimers();
    let answer: ((response: Response) => void) | undefined;
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>((resolve) => {
      answer = resolve;
    })));
    const server = createStackMcpServer('http://api.test', 'sk_test_unused');
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'tool-progress', version: '0.0.0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    const seen: number[] = [];
    // The SDK client puts a progress token on the call when it is given `onprogress`.
    const call = client.callTool({ name: 'stack_list_agents', arguments: {} }, undefined, {
      onprogress: (progress) => {
        seen.push(progress.progress);
      },
      timeout: 25_000,
      resetTimeoutOnProgress: true,
    });
    await vi.advanceTimersByTimeAsync(45_000);
    // Without the progress the client's own 25 second timeout would have ended the call by now.
    expect(seen).toEqual([20, 40]);
    answer!(new Response(JSON.stringify({ agents: [] }), { status: 200, headers: { 'content-type': 'application/json' } }));
    const result = await call;
    expect(result.isError).toBeFalsy();
  });
});
