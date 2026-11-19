import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { describe, expect, it, vi } from 'vitest';

const requestMock = vi.hoisted(() => vi.fn());

vi.mock('node:https', () => ({ request: requestMock }));

import {
  createAuthorityPresentationTransport,
  createAuthorityReceiverOriginVerifier,
} from './authority-network.js';

function mockHttpsResponse(status: number, body: string, headers: Record<string, string> = {}) {
  requestMock.mockImplementationOnce((_url, options, onResponse) => {
    const request = new EventEmitter() as EventEmitter & {
      setTimeout: ReturnType<typeof vi.fn>;
      write: ReturnType<typeof vi.fn>;
      end: ReturnType<typeof vi.fn>;
      destroy: ReturnType<typeof vi.fn>;
    };
    request.setTimeout = vi.fn();
    request.write = vi.fn();
    request.destroy = vi.fn((error?: Error) => {
      if (error) request.emit('error', error);
    });
    request.end = vi.fn(() => {
      const response = new PassThrough() as PassThrough & {
        statusCode: number;
        headers: Record<string, string>;
        complete: boolean;
      };
      response.statusCode = status;
      response.headers = headers;
      response.complete = true;
      onResponse(response);
      queueMicrotask(() => {
        response.end(body);
      });
    });

    const lookup = options.lookup as (
      hostname: string,
      options: Record<string, unknown>,
      callback: (error: Error | null, address: string, family: number) => void,
    ) => void;
    lookup('receiver.example', {}, (error, address, family) => {
      expect(error).toBeNull();
      expect(address).toBe('1.1.1.1');
      expect(family).toBe(4);
    });
    expect(options.servername).toBe('receiver.example');
    return request;
  });
}

describe('authority pinned receiver network', () => {
  it('pins the checked address and exposes redirects without following them', async () => {
    mockHttpsResponse(302, '', { location: 'https://elsewhere.example/' });
    const verifier = createAuthorityReceiverOriginVerifier();
    const result = await verifier.fetchWellKnown({
      url: 'https://receiver.example/.well-known/stack-receiver.json',
      resolvedAddresses: ['1.1.1.1'],
      redirect: 'manual',
    });
    expect(result).toEqual({
      status: 302,
      body: '',
      location: 'https://elsewhere.example/',
    });
    expect(requestMock).toHaveBeenCalledTimes(1);
  });

  it('delivers only the encrypted response and fails closed on non-2xx', async () => {
    mockHttpsResponse(204, '');
    const transport = createAuthorityPresentationTransport();
    const delivered = await transport.deliver({
      endpoint: 'https://receiver.example/direct-post',
      resolvedAddresses: ['1.1.1.1'],
      audience: 'https://receiver.example',
      compactJwe: 'opaque.compact.jwe',
      presentationId: 'prs_1',
    });
    expect(delivered.responseHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    const request = requestMock.mock.results.at(-1)!.value as { end: ReturnType<typeof vi.fn> };
    expect(request.end).toHaveBeenCalledWith(Buffer.from('response=opaque.compact.jwe'));

    mockHttpsResponse(409, 'duplicate');
    await expect(transport.deliver({
      endpoint: 'https://receiver.example/direct-post',
      resolvedAddresses: ['1.1.1.1'],
      audience: 'https://receiver.example',
      compactJwe: 'opaque.compact.jwe',
      presentationId: 'prs_2',
    })).rejects.toThrow('HTTP 409');
  });

  it('refuses delivery without an already checked address', async () => {
    await expect(createAuthorityPresentationTransport().deliver({
      endpoint: 'https://receiver.example/direct-post',
      resolvedAddresses: [],
      audience: 'https://receiver.example',
      compactJwe: 'opaque.compact.jwe',
      presentationId: 'prs_3',
    })).rejects.toThrow('pinned HTTPS destination');
  });
});
