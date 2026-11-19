import { randomUUID } from 'node:crypto';
import type { Redis } from 'ioredis';

export interface AuditCheckResult {
  status: 'running' | 'completed' | 'partial' | 'failed';
  checked: number;
  broken: number;
  failed: number;
  broken_operator_ids: string[];
  started_at: string;
  ran_at: string | null;
}

export interface AuditCheckDependencies {
  listOperators: () => Promise<Array<{ id: string }>>;
  verify: (id: string) => Promise<{ valid: boolean }>;
  reportBroken: (result: AuditCheckResult) => void;
  /** Operators left out of the counts (a deployment's demo account with a historical break). Absent: none. */
  skipOperatorIds?: readonly string[];
}

// The request is separate from the execution lease: repeated clicks never
// clear a running worker's lock. A lost worker leaves an expired lease, not
// a permanent "running" or successful result.
export async function runAuditCheck(redis: Redis, deps: AuditCheckDependencies) {
  const request = await redis.get('audit_chain_check:request');
  if (!request && await redis.get('audit_chain_check:lock')) return null;
  const lease = randomUUID();
  if (await redis.set('audit_chain_check:running', lease, 'EX', 60, 'NX') !== 'OK') return null;
  const started_at = new Date().toISOString();
  const result: AuditCheckResult = { status: 'running', checked: 0, broken: 0, failed: 0, broken_operator_ids: [], started_at, ran_at: null };
  const publish = async (release: boolean) => Number(await redis.eval(`
    if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
    redis.call('SET', KEYS[2], ARGV[2], 'EX', 86400)
    if ARGV[3] == '1' then redis.call('DEL', KEYS[1]) end
    return 1
  `, 2, 'audit_chain_check:running', 'audit_chain_status:latest', lease, JSON.stringify(result), release ? '1' : '0')) === 1;
  let leaseLost = false;
  let published = false;
  const timer = setInterval(() => {
    void redis.eval("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('EXPIRE',KEYS[1],60) else return 0 end", 1, 'audit_chain_check:running', lease)
      .then((renewed) => { if (!renewed) leaseLost = true; }).catch(() => { leaseLost = true; });
  }, 20_000);
  timer.unref();
  try {
    if (!await publish(false)) { leaseLost = true; throw new Error('Audit check lease lost'); }
    if (request) await redis.eval("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end", 1, 'audit_chain_check:request', request);
    await redis.set('audit_chain_check:lock', started_at, 'EX', 6 * 3600);
    const operators = await deps.listOperators();
    for (const operator of operators) {
      if (leaseLost) throw new Error('Audit check lease lost');
      if (deps.skipOperatorIds?.includes(operator.id)) continue;
      try {
        const verified = await deps.verify(operator.id);
        result.checked++;
        if (!verified.valid) { result.broken++; result.broken_operator_ids.push(operator.id); }
      } catch { result.failed++; }
    }
    result.status = result.failed > 0 ? result.checked > 0 ? 'partial' : 'failed' : 'completed';
  } catch {
    result.status = result.checked > 0 ? 'partial' : 'failed';
    result.failed++;
  } finally {
    clearInterval(timer);
    result.ran_at = new Date().toISOString();
    // A superseded worker must not overwrite the newer job's state.
    if (!leaseLost) published = await publish(true);
  }
  if (!published) return null;
  if (result.broken > 0) deps.reportBroken(result);
  return result;
}
