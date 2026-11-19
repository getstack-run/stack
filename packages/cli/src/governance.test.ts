import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiRequestError } from './api.js';
import { governedApi } from './governance.js';

const approvalId = 'gvr_approved_123';
const approvalUrl = `https://getstack.run/app/approve/${approvalId}`;

function approvalRequired() {
  return new ApiRequestError(403, 'POST', '/v1/agents/agt_x/unblock', {
    error: {
      code: 'GOVERNANCE_APPROVAL_REQUIRED',
      message: 'approval required',
      details: { approval_id: approvalId, approval_url: approvalUrl },
    },
  });
}

function approval(status: 'pending' | 'approved' | 'rejected' | 'consumed' | 'expired') {
  return {
    approvals: [{
      id: approvalId,
      status,
      expires_at: '2026-08-28T12:15:00.000Z',
    }],
  };
}

describe('governedApi', () => {
  afterEach(() => vi.restoreAllMocks());

  it('opens the approval, waits, and retries the exact mutation once with its approval id', async () => {
    const body = { enabled: false, nested: { value: 1 } };
    const request = vi.fn()
      .mockRejectedValueOnce(approvalRequired())
      .mockResolvedValueOnce(approval('pending'))
      .mockResolvedValueOnce(approval('approved'))
      .mockResolvedValueOnce({ ok: true });
    const open = vi.fn();

    const result = await governedApi('POST', '/v1/agents/agt_x/unblock', { body }, {
      request,
      open,
      interactive: true,
      sleep: async () => undefined,
      now: () => Date.parse('2026-08-28T12:00:00.000Z'),
    });

    expect(result).toEqual({ ok: true });
    expect(open).toHaveBeenCalledWith(approvalUrl);
    expect(request).toHaveBeenNthCalledWith(1, 'POST', '/v1/agents/agt_x/unblock', { body });
    expect(request).toHaveBeenLastCalledWith('POST', '/v1/agents/agt_x/unblock', {
      body,
      headers: { 'X-Governance-Approval': approvalId },
    });
    expect(request).toHaveBeenCalledTimes(4);
  });

  it.each([
    ['rejected', 'was rejected'],
    ['expired', 'expired'],
    ['consumed', 'was already used'],
  ] as const)('stops when the approval is %s', async (status, message) => {
    const request = vi.fn()
      .mockRejectedValueOnce(approvalRequired())
      .mockResolvedValueOnce(approval(status));
    await expect(governedApi('POST', '/v1/agents/agt_x/unblock', { body: {} }, {
      request,
      interactive: false,
      now: () => Date.parse('2026-08-28T12:00:00.000Z'),
    })).rejects.toThrow(message);
    expect(request).toHaveBeenCalledTimes(2);
  });

  it('fails after a mismatched approved retry and never starts a second approval loop', async () => {
    const mismatch = new ApiRequestError(403, 'PUT', '/v1/pii/config', {
      error: { code: 'GOVERNANCE_APPROVAL_MISMATCH', message: 'payload mismatch' },
    });
    const request = vi.fn()
      .mockRejectedValueOnce(approvalRequired())
      .mockResolvedValueOnce(approval('approved'))
      .mockRejectedValueOnce(mismatch);
    await expect(governedApi('PUT', '/v1/pii/config', { body: { threshold: 0.9 } }, {
      request,
      interactive: false,
      now: () => Date.parse('2026-08-28T12:00:00.000Z'),
    })).rejects.toBe(mismatch);
    expect(request).toHaveBeenCalledTimes(3);
  });

  it('prints the URL on stderr without opening a browser or writing progress to stdout in headless use', async () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const open = vi.fn();
    const request = vi.fn()
      .mockRejectedValueOnce(approvalRequired())
      .mockResolvedValueOnce(approval('approved'))
      .mockResolvedValueOnce({ ok: true });

    await governedApi('POST', '/v1/agents/agt_x/unblock', { body: {} }, {
      request,
      open,
      interactive: false,
      now: () => Date.parse('2026-08-28T12:00:00.000Z'),
    });

    expect(open).not.toHaveBeenCalled();
    expect(stderr.mock.calls.flat().join('')).toContain(approvalUrl);
    expect(stdout).not.toHaveBeenCalled();
  });
});

describe('governedApi when its own wait ends', () => {
  afterEach(() => vi.restoreAllMocks());

  const start = Date.parse('2026-08-28T12:00:00.000Z');
  const dayLater = '2026-08-29T12:00:00.000Z';
  const pendingFor24h = { approvals: [{ id: approvalId, status: 'pending', expires_at: dayLater }] };

  /** A clock that moves only when the loop sleeps, a minute at a time. */
  function fakeClock() {
    let clock = start;
    return { now: () => clock, sleep: async () => { clock += 60_000; }, elapsedMinutes: () => (clock - start) / 60_000 };
  }

  it('says no decision was made yet, not "expired", when only its own 15 minutes ended', async () => {
    const clock = fakeClock();
    const request = vi.fn(async (method: string) => {
      if (method === 'GET') return pendingFor24h;
      throw approvalRequired();
    });
    const outcome = await governedApi('POST', '/v1/agents/agt_x/unblock', { body: {} }, {
      request: request as never,
      interactive: false,
      now: clock.now,
      sleep: clock.sleep,
      pollIntervalMs: 60_000,
    }).then(() => 'resolved', (error: Error) => error.message);

    expect(clock.elapsedMinutes()).toBeGreaterThanOrEqual(15);
    expect(outcome).not.toMatch(/expired/i);
    expect(outcome).toMatch(/no decision/i);
    expect(outcome).toContain(approvalUrl);
    expect(outcome).toContain(dayLater);
    expect(outcome).toMatch(/stays open/i);
    expect(outcome).toMatch(/same command again/i);
    expect(outcome).toContain(approvalId);
    expect(outcome).not.toMatch(/[\r\n]/);
  });

  it('still says expired when the API says the approval is expired', async () => {
    const clock = fakeClock();
    const request = vi.fn(async (method: string) => {
      if (method === 'GET') return approval('expired');
      throw approvalRequired();
    });
    await expect(governedApi('POST', '/v1/agents/agt_x/unblock', { body: {} }, {
      request: request as never, interactive: false, now: clock.now, sleep: clock.sleep,
    })).rejects.toThrow(/expired/);
  });

  it('takes a decision made in the last moment of the wait instead of giving up', async () => {
    const clock = fakeClock();
    const request = vi.fn(async (method: string) => {
      if (method !== 'GET') return { ok: true };
      // Pending through the whole wait, approved on the one read made after it.
      return clock.elapsedMinutes() <= 15 ? pendingFor24h : approval('approved');
    });
    const first = vi.fn().mockRejectedValueOnce(approvalRequired());
    const wrapped = async (method: string, path: string, opts?: unknown) => (first.mock.calls.length === 0 ? first(method, path, opts) : request(method));
    await expect(governedApi('POST', '/v1/agents/agt_x/unblock', { body: {} }, {
      request: wrapped as never, interactive: false, now: clock.now, sleep: clock.sleep, pollIntervalMs: 60_000,
    })).resolves.toEqual({ ok: true });
  });
});
