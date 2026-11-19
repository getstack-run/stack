import { describe, it, expect } from 'vitest';
import {
  DetectorService,
  type DetectorOperatorOverrides,
  type InputScanResult,
  type OutputInjectionMatch,
} from './detector-service.js';

/**
 * Detector-service unit tests. Asserts orchestration behaviour: which
 * security events fire under which verdicts, when the deny/redact
 * decision triggers, and that L7 overrides flow through.
 *
 * The injected scanner functions are simulated via small fakes the
 * tests control — the real apps/api scanner files have their own
 * suites; here we only care that DetectorService calls them, hands
 * back the right structured decisions, and emits the right signals.
 */

interface EventRecord {
  operatorId: string;
  agentId: string;
  passportJti?: string;
  signalType: string;
  severity: string;
  message: string;
  metadata?: Record<string, unknown>;
}

class FakeSecurityEvent {
  events: EventRecord[] = [];
  async record(input: EventRecord): Promise<void> {
    this.events.push({ ...input, metadata: { ...input.metadata } });
  }
}

class FakeOpDetCfg {
  rows = new Map<string, {
    enabled: boolean;
    custom_patterns: unknown[];
    whitelist_patterns: unknown[];
    severity_overrides: Record<string, 'warning' | 'critical'>;
  } | undefined>();

  async getForDetector(operatorId: string, _key: string) {
    return this.rows.get(operatorId);
  }
}

const CTX = {
  operatorId: 'op_t',
  agentId: 'agt_t',
  passportJti: 'pas_t',
  tier: 'business',
};

function makeService(opts: {
  inputResult?: InputScanResult;
  outputMatch?: OutputInjectionMatch | null;
  redaction?: unknown;
  rec?: FakeSecurityEvent;
  cfg?: FakeOpDetCfg;
  inputScannerSpy?: (args: { body: unknown; fieldPath: string; overrides?: DetectorOperatorOverrides }) => void;
}) {
  const rec = opts.rec ?? new FakeSecurityEvent();
  const cfg = opts.cfg ?? new FakeOpDetCfg();
  const inputResult: InputScanResult = opts.inputResult ?? {
    match: null,
    llm: null,
    verdict: 'clean',
  };
  const service = new DetectorService({
    securityEvent: rec as never,
    operatorDetectorConfig: cfg as never,
    inputScanner: async (args) => {
      opts.inputScannerSpy?.(args);
      return inputResult;
    },
    outputScanner: () => opts.outputMatch ?? null,
    outputRedactor: () => opts.redaction ?? { redacted: true, reason: 'test redaction' },
  });
  return { service, rec, cfg };
}

describe('DetectorService.scanInput', () => {
  it('clean verdict: no events, denyReason null', async () => {
    const { service, rec } = makeService({
      inputResult: { match: null, llm: null, verdict: 'clean' },
    });
    const result = await service.scanInput({ ctx: CTX, body: 'hello' });
    expect(result.verdict).toBe('clean');
    expect(result.denyReason).toBeNull();
    expect(rec.events).toHaveLength(0);
  });

  it('warning verdict in logged mode: 1 event, no deny', async () => {
    const { service, rec } = makeService({
      inputResult: {
        match: { pattern_id: 'pi.ignore_rules', field_path: 'body', matched_text: 'ignore rules', severity: 'warning' },
        llm: null,
        verdict: 'warning',
      },
    });
    const result = await service.scanInput({ ctx: { ...CTX, mode: 'logged' }, body: 'ignore rules' });
    expect(result.verdict).toBe('warning');
    expect(result.denyReason).toBeNull();
    expect(rec.events).toHaveLength(1);
    expect(rec.events[0]!.signalType).toBe('prompt_injection');
    expect(rec.events[0]!.severity).toBe('warning');
    expect(rec.events[0]!.metadata?.pattern_id).toBe('pi.ignore_rules');
  });

  it('critical verdict in enforced mode: 1 event at critical, deny set', async () => {
    const { service, rec } = makeService({
      inputResult: {
        match: { pattern_id: 'pi.exfiltrate', field_path: 'body', matched_text: 'exfiltrate creds', severity: 'critical' },
        llm: null,
        verdict: 'critical',
      },
    });
    const result = await service.scanInput({ ctx: { ...CTX, mode: 'enforced' }, body: 'evil' });
    expect(result.verdict).toBe('critical');
    expect(result.denyReason).toMatch(/pi\.exfiltrate/);
    expect(rec.events).toHaveLength(1);
    expect(rec.events[0]!.severity).toBe('critical');
  });

  it('critical verdict in logged mode: 1 event at critical, no deny', async () => {
    const { service, rec } = makeService({
      inputResult: {
        match: { pattern_id: 'pi.exfiltrate', field_path: 'body', matched_text: 'exfiltrate', severity: 'critical' },
        llm: null,
        verdict: 'critical',
      },
    });
    const result = await service.scanInput({ ctx: { ...CTX, mode: 'logged' }, body: 'evil' });
    expect(result.denyReason).toBeNull();
    expect(rec.events).toHaveLength(1);
    expect(rec.events[0]!.severity).toBe('critical');
  });

  it('L3 degraded: separate info-level event fired alongside main verdict', async () => {
    const { service, rec } = makeService({
      inputResult: {
        match: null,
        llm: {
          verdict: 'clean',
          degraded: true,
          duration_ms: 9001,
          model: 'test-model',
          reasoning: 'timeout',
        },
        verdict: 'clean',
      },
    });
    await service.scanInput({ ctx: CTX, body: 'x' });
    expect(rec.events).toHaveLength(1);
    expect(rec.events[0]!.severity).toBe('info');
    expect(rec.events[0]!.metadata?.l3_degraded).toBe(true);
    expect(rec.events[0]!.metadata?.l3_duration_ms).toBe(9001);
  });

  it('L3 contributes to non-clean verdict: cause-bits include L3', async () => {
    const { service, rec } = makeService({
      inputResult: {
        match: null,
        llm: { verdict: 'critical', confidence: 0.95, degraded: false },
        verdict: 'critical',
      },
    });
    await service.scanInput({ ctx: { ...CTX, mode: 'enforced' }, body: 'subtle attack' });
    expect(rec.events).toHaveLength(1);
    expect(rec.events[0]!.metadata?.l3_verdict).toBe('critical');
    expect(rec.events[0]!.metadata?.l3_confidence).toBe(0.95);
    expect(rec.events[0]!.message).toMatch(/L3 critical@0.95/);
  });

  it('forwards L7 overrides to the injected scanner', async () => {
    const cfg = new FakeOpDetCfg();
    cfg.rows.set(CTX.operatorId, {
      enabled: false,
      custom_patterns: [{ id: 'cust.x', regex: '.*' } as never],
      whitelist_patterns: [],
      severity_overrides: {},
    });
    let receivedOverrides: DetectorOperatorOverrides | undefined;
    const { service } = makeService({
      cfg,
      inputScannerSpy: (args) => {
        receivedOverrides = args.overrides;
      },
    });
    await service.scanInput({ ctx: CTX, body: 'x' });
    expect(receivedOverrides).toBeDefined();
    expect(receivedOverrides?.enabled).toBe(false);
    expect(receivedOverrides?.custom_patterns).toHaveLength(1);
  });

  it('passes through caller metadata into the recorded event', async () => {
    const { service, rec } = makeService({
      inputResult: {
        match: { pattern_id: 'pi.x', field_path: 'body', matched_text: 'x', severity: 'warning' },
        llm: null,
        verdict: 'warning',
      },
    });
    await service.scanInput({
      ctx: { ...CTX, mode: 'logged' },
      body: 'x',
      metadata: { request_method: 'POST', request_service: 'github' },
    });
    expect(rec.events[0]!.metadata?.request_method).toBe('POST');
    expect(rec.events[0]!.metadata?.request_service).toBe('github');
  });

  it('event-emit failure is swallowed (does not throw)', async () => {
    const rec = new FakeSecurityEvent();
    // Force throws on record.
    (rec as unknown as { record: (...args: unknown[]) => Promise<void> }).record = async () => {
      throw new Error('downstream notification broke');
    };
    const { service } = makeService({
      rec,
      inputResult: {
        match: { pattern_id: 'pi.x', field_path: 'body', matched_text: 'x', severity: 'warning' },
        llm: null,
        verdict: 'warning',
      },
    });
    // Should NOT reject — the inline pre-extract code also didn't propagate
    // event-emit failures; preserving that contract.
    const result = await service.scanInput({ ctx: { ...CTX, mode: 'logged' }, body: 'x' });
    expect(result.verdict).toBe('warning');
  });

  // Regression, 2026-07-29. The tier decides the operator's included L3
  // allowance in the api wiring (`tier ?? 'free'`, and free includes zero), so
  // a tier that does not reach the scanner turns into "L3 runs only if this
  // operator holds wallet balance" for a customer whose plan already covers
  // thousands of calls. All four call sites omitted it and the classifier was
  // effectively off on the proxy and the LLM gateway. The field is required on
  // DetectorCtx now; this asserts it is actually forwarded.
  it('forwards the operator tier to the scanner, so L3 gets the right allowance', async () => {
    const seen: Array<Record<string, unknown>> = [];
    const { service } = makeService({
      inputScannerSpy: (args) => seen.push(args as unknown as Record<string, unknown>),
    });
    await service.scanInput({ ctx: { ...CTX, tier: 'studio' }, body: 'anything' });
    expect(seen).toHaveLength(1);
    expect(seen[0]!['tier']).toBe('studio');
    expect(seen[0]!['operatorId']).toBe('op_t');
  });
});

describe('DetectorService.scanOutput', () => {
  it('clean: no event, redactedBody null', async () => {
    const { service, rec } = makeService({ outputMatch: null });
    const result = await service.scanOutput({ ctx: CTX, body: 'all good', headers: {} });
    expect(result.match).toBeNull();
    expect(result.redactedBody).toBeNull();
    expect(rec.events).toHaveLength(0);
  });

  it('match in logged mode: event recorded, no redaction', async () => {
    const match: OutputInjectionMatch = {
      pattern_id: 'leak.aws_access_key',
      severity: 'critical',
      matched_text: 'AKIA...',
      field_path: 'body',
    };
    const { service, rec } = makeService({ outputMatch: match });
    const result = await service.scanOutput({
      ctx: { ...CTX, mode: 'logged' },
      body: 'AKIAIOSFODNN7EXAMPLE',
      headers: {},
    });
    expect(result.match).toEqual(match);
    expect(result.redactedBody).toBeNull();
    expect(rec.events).toHaveLength(1);
    expect(rec.events[0]!.signalType).toBe('prompt_injection_output');
    expect(rec.events[0]!.metadata?.redacted).toBe(false);
  });

  it('match in enforced+critical: event recorded AND redactedBody returned', async () => {
    const match: OutputInjectionMatch = {
      pattern_id: 'leak.stripe_secret',
      severity: 'critical',
      matched_text: 'sk_live_...',
      field_path: 'body',
    };
    const redaction = { redacted: true, reason: 'test', pattern_id: match.pattern_id, severity: match.severity };
    const { service, rec } = makeService({ outputMatch: match, redaction });
    const result = await service.scanOutput({
      ctx: { ...CTX, mode: 'enforced' },
      body: 'sk_live_abc',
      headers: {},
    });
    expect(result.redactedBody).toEqual(redaction);
    expect(rec.events[0]!.metadata?.redacted).toBe(true);
  });

  it('match warning severity in enforced mode: event but NO redaction (only critical redacts)', async () => {
    const match: OutputInjectionMatch = {
      pattern_id: 'leak.compliance_lang',
      severity: 'warning',
      matched_text: 'as you instructed',
      field_path: 'body',
    };
    const { service, rec } = makeService({ outputMatch: match });
    const result = await service.scanOutput({
      ctx: { ...CTX, mode: 'enforced' },
      body: 'as you instructed',
      headers: {},
    });
    expect(result.redactedBody).toBeNull();
    expect(rec.events[0]!.severity).toBe('warning');
    expect(rec.events[0]!.metadata?.redacted).toBe(false);
  });

  it('passes through caller metadata + match fields into the recorded event', async () => {
    const match: OutputInjectionMatch = {
      pattern_id: 'p.x',
      severity: 'warning',
      matched_text: 'm',
      field_path: 'body',
    };
    const { service, rec } = makeService({ outputMatch: match });
    await service.scanOutput({
      ctx: { ...CTX, mode: 'logged' },
      body: 'x',
      headers: {},
      metadata: { response_status: 200, request_service: 'slack' },
    });
    expect(rec.events[0]!.metadata?.pattern_id).toBe('p.x');
    expect(rec.events[0]!.metadata?.matched_length).toBe(1);
    expect(rec.events[0]!.metadata).not.toHaveProperty('matched_excerpt');
    expect(rec.events[0]!.metadata?.response_status).toBe(200);
    expect(rec.events[0]!.metadata?.request_service).toBe('slack');
  });
});
