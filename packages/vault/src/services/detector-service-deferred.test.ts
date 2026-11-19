import { describe, expect, it, vi } from 'vitest';
import { DetectorService, type InputScanHandle, type InputScanResult } from './detector-service.js';

/**
 * a caller whose mode cannot block on the L3 verdict does not wait
 * for it, and an enforced caller can start the scan early and abandon it.
 * What blocks must not change: enforced mode always waits for the full
 * verdict, and an abandoned scan records nothing.
 */

interface EventRecord { signalType: string; severity: string; message: string; metadata?: Record<string, unknown> }

class FakeSecurityEvent {
  events: EventRecord[] = [];
  async record(input: EventRecord): Promise<void> { this.events.push({ ...input, metadata: { ...input.metadata } }); }
}

const CTX = { operatorId: 'op_t', agentId: 'agt_t', passportJti: 'pas_t', tier: 'business' };
const WARNING_MATCH = { pattern_id: 'ignore_prior', field_path: 'body', matched_text: 'ignore', severity: 'warning' as const };

function deferredL3() {
  let resolve!: (value: InputScanResult) => void;
  const l3 = new Promise<InputScanResult>((r) => { resolve = r; });
  return { l3, resolve };
}

function makeService(handle: () => InputScanHandle) {
  const rec = new FakeSecurityEvent();
  const starter = vi.fn(() => handle());
  const inputScanner = vi.fn(async () => { throw new Error('the two-phase starter must be used'); });
  const service = new DetectorService({
    securityEvent: rec as never,
    operatorDetectorConfig: { getForDetector: async () => undefined } as never,
    inputScanner,
    inputScanStarter: starter,
    outputScanner: () => null,
    outputRedactor: () => ({}),
  });
  return { service, rec, starter };
}

const l3Result = (verdict: InputScanResult['verdict'], llmVerdict: 'clean' | 'suspicious' | 'critical', match = null as InputScanResult['match']): InputScanResult => ({
  match,
  llm: { verdict: llmVerdict, confidence: llmVerdict === 'critical' ? 95 : 50, reasoning: 'r', degraded: false, duration_ms: 900, model: 'm' },
  verdict,
});

describe('DetectorService deferred L3 (non-enforced modes)', () => {
  it('standard mode returns the L1+L2 decision without waiting for L3', async () => {
    const pending = deferredL3();
    const abort = vi.fn();
    const { service, rec } = makeService(() => ({ l1l2: { match: null, llm: null, verdict: 'clean' }, l3: pending.l3, abort }));
    const result = await service.scanInput({ ctx: { ...CTX, mode: 'standard' }, body: 'x', deferL3: true });
    expect(result).toMatchObject({ verdict: 'clean', denyReason: null, l3Deferred: true });
    expect(service.pendingBackgroundScans).toBe(1);
    expect(rec.events).toHaveLength(0);

    // L3 lands later and escalates: recorded then, as its own event.
    pending.resolve(l3Result('critical', 'critical'));
    expect(await service.drainBackground(1_000)).toBe(0);
    expect(rec.events).toHaveLength(1);
    expect(rec.events[0]).toMatchObject({ signalType: 'prompt_injection', severity: 'critical' });
    expect(rec.events[0]!.metadata).toMatchObject({ blocked: false, l3_verdict: 'critical', l3_deferred: true });
    expect(abort).not.toHaveBeenCalled();
  });

  it('records the L1+L2 finding immediately, and no duplicate when L3 agrees', async () => {
    const pending = deferredL3();
    const { service, rec } = makeService(() => ({
      l1l2: { match: WARNING_MATCH, llm: null, verdict: 'warning' }, l3: pending.l3, abort: () => {},
    }));
    const result = await service.scanInput({ ctx: { ...CTX, mode: 'logged' }, body: 'x', deferL3: true });
    expect(result.verdict).toBe('warning');
    expect(rec.events).toHaveLength(1);
    expect(rec.events[0]!.metadata).toMatchObject({ l3_pending: true, pattern_id: 'ignore_prior' });
    pending.resolve(l3Result('warning', 'clean', WARNING_MATCH));
    await service.drainBackground(1_000);
    expect(rec.events).toHaveLength(1);
  });

  it('records a degraded L3 that lands later', async () => {
    const pending = deferredL3();
    const { service, rec } = makeService(() => ({ l1l2: { match: null, llm: null, verdict: 'clean' }, l3: pending.l3, abort: () => {} }));
    await service.scanInput({ ctx: { ...CTX, mode: 'standard' }, body: 'x', deferL3: true });
    pending.resolve({ match: null, verdict: 'clean', llm: { verdict: 'clean', confidence: 0, reasoning: 'degraded: llm_timeout', degraded: true, duration_ms: 5000, model: 'm' } });
    await service.drainBackground(1_000);
    expect(rec.events).toHaveLength(1);
    expect(rec.events[0]).toMatchObject({ severity: 'info', metadata: { l3_degraded: true } });
  });

  it('a failure while recording the deferred verdict is logged, never thrown', async () => {
    const pending = deferredL3();
    const { service } = makeService(() => ({ l1l2: { match: null, llm: null, verdict: 'clean' }, l3: pending.l3, abort: () => {} }));
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    await service.scanInput({ ctx: { ...CTX, mode: 'standard' }, body: 'x', deferL3: true });
    pending.resolve(Promise.reject(new Error('budget plumbing')) as never);
    await service.drainBackground(1_000);
    expect(error).toHaveBeenCalled();
    error.mockRestore();
  });

  it('without deferL3 the caller still waits (unchanged default)', async () => {
    const { service } = makeService(() => ({
      l1l2: { match: null, llm: null, verdict: 'clean' }, l3: Promise.resolve(l3Result('warning', 'suspicious')), abort: () => {},
    }));
    const result = await service.scanInput({ ctx: { ...CTX, mode: 'standard' }, body: 'x' });
    expect(result.verdict).toBe('warning');
    expect(result.l3Deferred).toBeUndefined();
  });
});

describe('DetectorService enforced mode is unchanged', () => {
  it('ignores deferL3 and waits for the full verdict, which blocks', async () => {
    const pending = deferredL3();
    const { service, rec } = makeService(() => ({ l1l2: { match: null, llm: null, verdict: 'clean' }, l3: pending.l3, abort: () => {} }));
    let settled = false;
    const decision = service.scanInput({ ctx: { ...CTX, mode: 'enforced' }, body: 'x', deferL3: true }).then((r) => { settled = true; return r; });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(settled).toBe(false);
    pending.resolve(l3Result('critical', 'critical'));
    const result = await decision;
    expect(result.denyReason).toMatch(/prompt-injection chain/);
    expect(result.l3Deferred).toBeUndefined();
    expect(rec.events).toHaveLength(1);
    expect(rec.events[0]!.metadata).toMatchObject({ blocked: true });
  });

  it('dry runs never defer (simulation needs the full prediction)', async () => {
    const { service, rec } = makeService(() => ({
      l1l2: { match: null, llm: null, verdict: 'clean' }, l3: Promise.resolve(l3Result('critical', 'critical')), abort: () => {},
    }));
    const result = await service.scanInput({ ctx: { ...CTX, mode: 'standard' }, body: 'x', dryRun: true, deferL3: true });
    expect(result.verdict).toBe('critical');
    expect(rec.events).toHaveLength(0);
  });
});

describe('DetectorService.beginInputScan', () => {
  it('starts the scanner immediately and records nothing until finish', async () => {
    const pending = deferredL3();
    const { service, rec, starter } = makeService(() => ({ l1l2: { match: null, llm: null, verdict: 'clean' }, l3: pending.l3, abort: () => {} }));
    const scan = service.beginInputScan({ ctx: { ...CTX, mode: 'enforced' }, body: 'x' });
    await vi.waitFor(() => expect(starter).toHaveBeenCalledTimes(1));
    pending.resolve(l3Result('critical', 'critical'));
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(rec.events).toHaveLength(0);
    const result = await scan.finish();
    expect(result.denyReason).not.toBeNull();
    expect(rec.events).toHaveLength(1);
  });

  it('abort cancels the in-flight L3 and records nothing', async () => {
    const pending = deferredL3();
    const abort = vi.fn();
    const { service, rec } = makeService(() => ({ l1l2: { match: WARNING_MATCH, llm: null, verdict: 'warning' }, l3: pending.l3, abort }));
    const scan = service.beginInputScan({ ctx: { ...CTX, mode: 'enforced' }, body: 'x' });
    await new Promise((resolve) => setTimeout(resolve, 5));
    scan.abort();
    await vi.waitFor(() => expect(abort).toHaveBeenCalledTimes(1));
    pending.resolve(l3Result('critical', 'critical', WARNING_MATCH));
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(rec.events).toHaveLength(0);
  });

  it('abort before the overrides load never starts the scanner', async () => {
    const { service, starter } = makeService(() => ({ l1l2: { match: null, llm: null, verdict: 'clean' }, l3: null, abort: () => {} }));
    const scan = service.beginInputScan({ ctx: { ...CTX, mode: 'enforced' }, body: 'x' });
    scan.abort();
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(starter).not.toHaveBeenCalled();
  });

  it('a scan that fails and is never finished does not raise an unhandled rejection', async () => {
    const rec = new FakeSecurityEvent();
    const service = new DetectorService({
      securityEvent: rec as never,
      operatorDetectorConfig: { getForDetector: async () => { throw new Error('config store down'); } } as never,
      inputScanner: async () => ({ match: null, llm: null, verdict: 'clean' }),
      outputScanner: () => null,
      outputRedactor: () => ({}),
    });
    const unhandled = vi.fn();
    process.on('unhandledRejection', unhandled);
    try {
      service.beginInputScan({ ctx: { ...CTX, mode: 'enforced' }, body: 'x' }).abort();
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(unhandled).not.toHaveBeenCalled();
    } finally {
      process.off('unhandledRejection', unhandled);
    }
  });
});
