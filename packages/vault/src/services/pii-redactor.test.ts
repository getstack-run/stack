import { describe, it, expect } from 'vitest';
import { PiiRedactor } from './pii-redactor.js';

describe('PiiRedactor.redact', () => {
  it('R1 single email is replaced with [REDACTED:email]', () => {
    const r = new PiiRedactor().redact('email me at jane@example.com please');
    expect(r.redactedText).toBe('email me at [REDACTED:email] please');
    expect(r.hits).toBe(1);
    expect(r.categories).toEqual(['email']);
  });

  it('R2 mixed PII (email + SSN) — all replaced, counts correct', () => {
    const r = new PiiRedactor().redact('a@x.com SSN 123-45-6789 and b@y.io c@z.org');
    expect(r.hits).toBe(4);
    expect(new Set(r.categories)).toEqual(new Set(['email', 'ssn_us']));
    expect(r.redactedText).toContain('[REDACTED:email]');
    expect(r.redactedText).toContain('[REDACTED:ssn_us]');
    // No raw PII left over.
    expect(r.redactedText).not.toContain('@');
    expect(r.redactedText).not.toContain('123-45-6789');
  });

  it('R3 clean text — no change, hits=0', () => {
    const r = new PiiRedactor().redact('absolutely no pii in this text');
    expect(r.redactedText).toBe('absolutely no pii in this text');
    expect(r.hits).toBe(0);
    expect(r.categories).toEqual([]);
  });

  it('R4 idempotency — redact(redact(x)) is no-op', () => {
    const redactor = new PiiRedactor();
    const r1 = redactor.redact('email a@x.com here');
    const r2 = redactor.redact(r1.redactedText);
    expect(r2.redactedText).toBe(r1.redactedText);
    expect(r2.hits).toBe(0);
  });

  it('R5 right-to-left replacement preserves earlier offsets', () => {
    // 3 emails at known positions. After redaction, all 3 should be
    // replaced with [REDACTED:email]. If the iteration went LTR we'd
    // see offset drift and miss the second + third.
    const r = new PiiRedactor().redact('a@x.com and b@y.com and c@z.com');
    expect(r.hits).toBe(3);
    expect(r.redactedText).toBe('[REDACTED:email] and [REDACTED:email] and [REDACTED:email]');
  });

  it('R6 Luhn-invalid credit card NOT redacted', () => {
    const r = new PiiRedactor().redact('Test 1234-5678-1234-5678 noise');
    expect(r.hits).toBe(0);
    expect(r.redactedText).toBe('Test 1234-5678-1234-5678 noise');
  });

  // ── scored scanning: operator options + near-miss reporting ──

  it('R7 reports a near-miss without redacting it', () => {
    // A valid Dutch BSN with nothing labelling it. Scores 0.25, under the
    // 0.4 default, so it is forwarded intact — and counted, so the operator
    // can find out their traffic contains these.
    const r = new PiiRedactor().redact('order 111222333 shipped');
    expect(r.hits).toBe(0);
    expect(r.redactedText).toBe('order 111222333 shipped');
    expect(r.nearMisses).toBe(1);
    expect(r.nearMissCategories).toContain('national_id');
  });

  it('R8 a labelled identifier is a hit, not a near-miss', () => {
    const r = new PiiRedactor().redact('bsn 111222333');
    expect(r.hits).toBe(1);
    expect(r.nearMisses).toBe(0);
    expect(r.redactedText).toBe('bsn [REDACTED:national_id]');
  });

  it('R9 a lowered threshold redacts what was a near-miss', () => {
    const r = new PiiRedactor().redact('order 111222333 shipped', { threshold: 0.2 });
    expect(r.hits).toBe(1);
    expect(r.nearMisses).toBe(0);
  });

  it('R10 country scope narrows what is scanned', () => {
    // A labelled Croatian OIB. An operator scoped to Sweden does not run the
    // Croatian scheme at all, so it is neither redacted NOR a near-miss:
    // the pattern never ran.
    const r = new PiiRedactor().redact('oib: 12345678903', { countries: ['SE'] });
    expect(r.hits).toBe(0);
    expect(r.nearMisses).toBe(0);
  });

  it('R11 near-miss counting never carries the matched text', () => {
    // The whole point is that we were unsure. Writing the string into a
    // diagnostic would leak exactly what the redactor exists to contain.
    const r = new PiiRedactor().redact('order 111222333 shipped');
    expect(JSON.stringify(r.nearMissCategories)).not.toContain('111222333');
    expect(Object.keys(r)).not.toContain('nearMissText');
  });
});
