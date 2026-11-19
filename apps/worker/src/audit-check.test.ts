import { describe, expect, it, vi } from 'vitest';
import type { Redis } from 'ioredis';
import { runAuditCheck } from './audit-check.js';

function fixture(initial: Record<string, string> = {}) {
  const data = new Map(Object.entries(initial));
  const redis = {
    get: vi.fn(async (key: string) => data.get(key) ?? null),
    set: vi.fn(async (key: string, value: string, ...args: unknown[]) => {
      if (args.includes('NX') && data.has(key)) return null;
      data.set(key, value); return 'OK';
    }),
    eval: vi.fn(async (script: string, count: number, key: string, ...args: string[]) => {
      if (count === 2) {
        const [statusKey, token, value, release] = args;
        if (data.get(key) !== token) return 0;
        data.set(statusKey!, value!);
        if (release === '1') data.delete(key);
        return 1;
      }
      const token = args[0];
      if (data.get(key) !== token) return 0;
      if (script.includes('DEL')) data.delete(key);
      return 1;
    }),
  } as unknown as Redis;
  const deps = { listOperators: vi.fn(async () => [{ id: 'one' }, { id: 'two' }]), verify: vi.fn(async (_id: string) => ({ valid: true })), reportBroken: vi.fn() };
  return { redis, data, deps };
}

describe('audit reporting job', () => {
  it('records running and completed, preserving the full count', async () => {
    const f = fixture();
    const result = await runAuditCheck(f.redis, f.deps);
    expect(result).toMatchObject({ status: 'completed', checked: 2, broken: 0, failed: 0 });
    expect(f.redis.eval).toHaveBeenCalledWith(expect.stringContaining("redis.call('SET', KEYS[2]"), 2, 'audit_chain_check:running', 'audit_chain_status:latest', expect.any(String), expect.stringContaining('"status":"running"'), '0');
    expect(JSON.parse(f.data.get('audit_chain_status:latest')!).status).toBe('completed');
    expect(f.data.has('audit_chain_check:running')).toBe(false);
  });
  it('retains failures as partial rather than healthy', async () => {
    const f = fixture(); f.deps.verify.mockRejectedValueOnce(new Error('DB unavailable'));
    expect(await runAuditCheck(f.redis, f.deps)).toMatchObject({ status: 'partial', checked: 1, failed: 1 });
  });
  it('reports complete lookup failure', async () => {
    const f = fixture(); f.deps.listOperators.mockRejectedValue(new Error('DB unavailable'));
    expect(await runAuditCheck(f.redis, f.deps)).toMatchObject({ status: 'failed', checked: 0, failed: 1 });
  });
  it('reports broken chains and invokes the alert callback', async () => {
    const f = fixture(); f.deps.verify.mockResolvedValueOnce({ valid: false });
    expect(await runAuditCheck(f.redis, f.deps)).toMatchObject({ status: 'completed', broken: 1, broken_operator_ids: ['one'] });
    expect(f.deps.reportBroken).toHaveBeenCalledOnce();
  });
  it('does not unlock a concurrent run', async () => {
    const f = fixture({ 'audit_chain_check:running': 'other' });
    expect(await runAuditCheck(f.redis, f.deps)).toBeNull();
    expect(f.data.get('audit_chain_check:running')).toBe('other');
    expect(f.deps.verify).not.toHaveBeenCalled();
  });
  it('respects cadence and consumes explicit queued requests', async () => {
    const f = fixture({ 'audit_chain_check:lock': 'previous' });
    expect(await runAuditCheck(f.redis, f.deps)).toBeNull();
    f.data.set('audit_chain_check:request', 'manual');
    expect(await runAuditCheck(f.redis, f.deps)).toMatchObject({ status: 'completed' });
    expect(f.data.has('audit_chain_check:request')).toBe(false);
  });
  it('never publishes over or releases a replacement lease', async () => {
    const f = fixture();
    f.deps.verify.mockImplementation(async (id) => {
      if (id === 'two') {
        f.data.set('audit_chain_check:running', 'replacement');
        f.data.set('audit_chain_status:latest', '{"status":"running","started_at":"replacement"}');
      }
      return { valid: true };
    });
    expect(await runAuditCheck(f.redis, f.deps)).toBeNull();
    expect(f.data.get('audit_chain_check:running')).toBe('replacement');
    expect(f.data.get('audit_chain_status:latest')).toBe('{"status":"running","started_at":"replacement"}');
    expect(f.deps.reportBroken).not.toHaveBeenCalled();
  });
});
