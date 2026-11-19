import { describe, it, expect } from 'vitest';
import {
  contentFingerprints,
  collectStrings,
  evaluateDataFlow,
  FLOW_SERVICE_KEY_MAX_CHARS,
  flowServiceKey,
  flowSourceLabel,
  parseFlowSource,
  type ObservedItem,
} from './data-flow.js';

/**
 * The motivating case, verbatim:
 *
 *   "emailing the guestbook names to bob when our only job is to append to
 *    it, shouldn't pass. we have access to the guestbook + its names but we
 *    can only take one action and one action only with the guestbook."
 *
 * Both calls are individually in scope. The violation is the movement
 * between them. Note the names below are ORDINARY NAMES — they match no
 * pattern in the entity catalogue, which is exactly why an entity-only check
 * would miss this.
 */

const GUESTBOOK_PAGE = `
Welcome to the guestbook. Recent visitors:
Alice Johnson wrote: lovely to be here again this spring
Bob Vickers wrote: thanks for the tour of the old mill
Carol Danvers wrote: we will be back in the autumn for sure
`;

/** What the agent read from the guestbook, as the producer would record it. */
function observedFromGuestbook(): ObservedItem[] {
  return contentFingerprints(GUESTBOOK_PAGE).map((value) => ({
    value,
    kind: 'shingle' as const,
    service: 'guestbook',
  }));
}

describe('the guestbook rule', () => {
  it('REFUSES mailing the guestbook contents to someone else', () => {
    const violation = evaluateDataFlow({
      destinationService: 'resend',
      outboundEntities: ['bob@evil.com'],
      outboundText: [
        'Here are the recent visitors: Alice Johnson wrote: lovely to be here again this spring. ' +
          'Bob Vickers wrote: thanks for the tour of the old mill.',
      ],
      observed: observedFromGuestbook(),
    });

    expect(violation).not.toBeNull();
    expect(violation?.sourceService).toBe('guestbook');
    expect(violation?.destinationService).toBe('resend');
    expect(violation?.via).toBe('content');
  });

  it('catches it on ORDINARY NAMES, which no entity pattern recognises', () => {
    // Proves tier two is doing the work. If the entity catalogue could see
    // names, this test would be redundant; it cannot, so it is the point.
    const namesOnly = evaluateDataFlow({
      destinationService: 'resend',
      outboundEntities: [], // nothing the regex catalogue would extract
      outboundText: ['Alice Johnson wrote: lovely to be here again this spring'],
      observed: observedFromGuestbook(),
    });
    expect(namesOnly?.via).toBe('content');
  });

  it('allows appending to the guestbook, which is the granted action', () => {
    const violation = evaluateDataFlow({
      destinationService: 'guestbook',
      outboundEntities: [],
      outboundText: ['Dave Lister wrote: first time visiting, what a place'],
      observed: observedFromGuestbook(),
    });
    expect(violation).toBeNull();
  });

  it('allows writing content back to the SAME service it was read from', () => {
    // Ordinary read-then-write. The names came from the guestbook and are
    // going back to the guestbook.
    const violation = evaluateDataFlow({
      destinationService: 'guestbook',
      outboundEntities: [],
      outboundText: ['Alice Johnson wrote: lovely to be here again this spring'],
      observed: observedFromGuestbook(),
    });
    expect(violation).toBeNull();
  });

  it('allows an email that carries nothing the agent read elsewhere', () => {
    const violation = evaluateDataFlow({
      destinationService: 'resend',
      outboundEntities: ['bob@corp.com'],
      outboundText: ['The nightly job finished successfully with no errors to report.'],
      observed: observedFromGuestbook(),
    });
    expect(violation).toBeNull();
  });

  it('allows the movement once the operator declares the flow', () => {
    const violation = evaluateDataFlow({
      destinationService: 'resend',
      outboundEntities: [],
      outboundText: ['Alice Johnson wrote: lovely to be here again this spring'],
      observed: observedFromGuestbook(),
      declaredFlows: [{ from: 'guestbook', to: 'resend' }],
    });
    expect(violation).toBeNull();
  });

  it('does not let a declared flow in one direction permit the other', () => {
    const violation = evaluateDataFlow({
      destinationService: 'resend',
      outboundEntities: [],
      outboundText: ['Alice Johnson wrote: lovely to be here again this spring'],
      observed: observedFromGuestbook(),
      declaredFlows: [{ from: 'resend', to: 'guestbook' }],
    });
    expect(violation?.via).toBe('content');
  });

  it('never puts the carried text into the violation, only a count', () => {
    const violation = evaluateDataFlow({
      destinationService: 'resend',
      outboundEntities: [],
      outboundText: ['Alice Johnson wrote: lovely to be here again this spring'],
      observed: observedFromGuestbook(),
    });
    expect(JSON.stringify(violation)).not.toContain('Alice');
  });
});

describe('entity reuse', () => {
  const observed: ObservedItem[] = [
    { value: 'acct_1a2b3c4d5e', kind: 'entity', service: 'stripe' },
    { value: 'alice@corp.com', kind: 'entity', service: 'stripe' },
  ];

  it('refuses on a single exact match, which is decisive', () => {
    const v = evaluateDataFlow({
      destinationService: 'resend',
      outboundEntities: ['acct_1a2b3c4d5e'],
      outboundText: [],
      observed,
    });
    expect(v?.via).toBe('entity');
    expect(v?.sourceService).toBe('stripe');
  });

  it('is case-insensitive', () => {
    const v = evaluateDataFlow({
      destinationService: 'resend',
      outboundEntities: ['ALICE@CORP.COM'],
      outboundText: [],
      observed,
    });
    expect(v?.via).toBe('entity');
  });

  it('allows the entity back to its own service', () => {
    const v = evaluateDataFlow({
      destinationService: 'stripe',
      outboundEntities: ['acct_1a2b3c4d5e'],
      outboundText: [],
      observed,
    });
    expect(v).toBeNull();
  });
});

describe('content fingerprints', () => {
  it('matches the same text through different spacing and casing', () => {
    const a = contentFingerprints('The quick brown fox jumps over the lazy dog');
    const b = contentFingerprints('the   QUICK brown fox jumps   over the lazy dog');
    expect(a.some((h) => b.includes(h))).toBe(true);
  });

  it('produces nothing for text shorter than one shingle', () => {
    expect(contentFingerprints('too short')).toEqual([]);
  });

  it('does not match unrelated prose', () => {
    const a = contentFingerprints('The quick brown fox jumps over the lazy dog every morning');
    const b = contentFingerprints('Quarterly revenue increased by twelve percent across all regions');
    expect(a.some((h) => b.includes(h))).toBe(false);
  });

  it('is bounded, so a huge response cannot blow up what we carry', () => {
    const huge = 'word '.repeat(200_000);
    expect(contentFingerprints(huge).length).toBeLessThanOrEqual(512);
  });

  it('needs more than one coincidental run before prose counts', () => {
    const observed: ObservedItem[] = contentFingerprints(
      'please let me know if you have any questions about this',
    ).map((value) => ({ value, kind: 'shingle' as const, service: 'other' }));

    // Exactly five words is exactly one shingle — a single coincidental run.
    const oneRun = evaluateDataFlow({
      destinationService: 'resend',
      outboundEntities: [],
      outboundText: ['please let me know if'],
      observed,
    });
    expect(oneRun).toBeNull();
  });

  it('refuses once a verbatim span gets long enough to be deliberate', () => {
    const observed: ObservedItem[] = contentFingerprints(
      'the quarterly figures show a twelve percent rise across every region we track',
    ).map((value) => ({ value, kind: 'shingle' as const, service: 'other' }));

    const copied = evaluateDataFlow({
      destinationService: 'resend',
      outboundEntities: [],
      outboundText: ['the quarterly figures show a twelve percent rise across every region we track'],
      observed,
    });
    expect(copied?.via).toBe('content');
  });
});

describe('collectStrings', () => {
  it('finds free text anywhere in a body, not just the fields we expected', () => {
    const strings = collectStrings({
      subject: 'hello',
      nested: { deep: ['there', { deeper: 'and here' }] },
      count: 3,
    });
    expect(strings).toEqual(expect.arrayContaining(['hello', 'there', 'and here']));
    expect(strings).not.toContain(3);
  });
});

describe('source labels', () => {
  it('names a service alone, or a service with the connection it was read through', () => {
    expect(flowSourceLabel('cal_com')).toBe('cal_com');
    expect(flowSourceLabel('cal_com', null)).toBe('cal_com');
    expect(flowSourceLabel('cal_com', 'scon_abc123')).toBe('cal_com@scon_abc123');
  });

  it('parses a label back, splitting on the last @ only before a connection id', () => {
    expect(parseFlowSource('cal_com@scon_abc123')).toEqual({ service: 'cal_com', connectionId: 'scon_abc123' });
    expect(parseFlowSource('cal_com')).toEqual({ service: 'cal_com', connectionId: null });
    // Not a connection id after the @: the whole label is the service.
    expect(parseFlowSource('stack:account-messages@alice')).toEqual({ service: 'stack:account-messages@alice', connectionId: null });
    expect(parseFlowSource('a@scon_x@scon_y')).toEqual({ service: 'a@scon_x', connectionId: 'scon_y' });
    expect(parseFlowSource('@scon_x')).toEqual({ service: '@scon_x', connectionId: null });
  });

  it('round-trips every label it makes', () => {
    for (const [service, id] of [['cal_com', 'scon_Zx-_9'], ['custom_my_tool', 'scon_a'], ['stack:drive', null]] as const) {
      expect(parseFlowSource(flowSourceLabel(service, id))).toEqual({ service, connectionId: id });
    }
  });
});

describe('two connections of one service are two sources', () => {
  const read = 'alice.johnson@example.org';
  const fromWork: ObservedItem[] = [{ value: read, kind: 'entity', service: flowSourceLabel('cal_com', 'scon_work') }];
  const send = (over: Partial<Parameters<typeof evaluateDataFlow>[0]> = {}) => evaluateDataFlow({
    destinationService: 'cal_com',
    destinationConnectionId: 'scon_personal',
    outboundEntities: [read],
    outboundText: [],
    observed: fromWork,
    ...over,
  });

  it('allows content going back through the same connection', () => {
    expect(send({ destinationConnectionId: 'scon_work' })).toBeNull();
  });

  it('refuses content read through another connection of the same service', () => {
    expect(send()).toEqual({
      sourceService: 'cal_com',
      sourceConnectionId: 'scon_work',
      destinationService: 'cal_com',
      via: 'entity',
      detail: read,
    });
  });

  it('allows it when the service is declared', () => {
    expect(send({ declaredFlows: [{ from: 'cal_com', to: 'cal_com' }] })).toBeNull();
  });

  it('allows it when the full label is declared, and only that connection', () => {
    expect(send({ declaredFlows: [{ from: 'cal_com@scon_work', to: 'cal_com' }] })).toBeNull();
    expect(send({ declaredFlows: [{ from: 'cal_com@scon_other', to: 'cal_com' }] })?.sourceConnectionId).toBe('scon_work');
  });

  it('treats a bare legacy label as the same service, as before', () => {
    const legacy: ObservedItem[] = [{ value: read, kind: 'entity', service: 'cal_com' }];
    expect(send({ observed: legacy })).toBeNull();
    expect(send({ observed: legacy, destinationConnectionId: null })).toBeNull();
  });

  it('allows a destination that names no connection, whatever connection the content came through', () => {
    expect(send({ destinationConnectionId: null })).toBeNull();
    expect(send({ destinationConnectionId: undefined })).toBeNull();
  });

  it('leaves a different service as it was: refused unless declared, by the service or the label', () => {
    const fromSlack: ObservedItem[] = [{ value: read, kind: 'entity', service: flowSourceLabel('slack', 'scon_s1') }];
    expect(send({ destinationService: 'resend', destinationConnectionId: 'scon_r', observed: fromSlack })).toMatchObject({
      sourceService: 'slack', sourceConnectionId: 'scon_s1', destinationService: 'resend',
    });
    expect(send({ destinationService: 'resend', destinationConnectionId: 'scon_r', observed: fromSlack, declaredFlows: [{ from: 'slack', to: 'resend' }] })).toBeNull();
    expect(send({ destinationService: 'resend', destinationConnectionId: 'scon_r', observed: fromSlack, declaredFlows: [{ from: 'slack@scon_s1', to: 'resend' }] })).toBeNull();
    const bare: ObservedItem[] = [{ value: read, kind: 'entity', service: 'slack' }];
    expect(send({ destinationService: 'resend', observed: bare })).toMatchObject({ sourceService: 'slack', sourceConnectionId: null });
  });

  it('judges copied prose by the same rule', () => {
    const prose = 'the quarterly figures show a twelve percent rise across every region we track';
    const observed = contentFingerprints(prose).map((value) => ({ value, kind: 'shingle' as const, service: flowSourceLabel('cal_com', 'scon_work') }));
    expect(send({ outboundEntities: [], outboundText: [prose], observed })?.via).toBe('content');
    expect(send({ outboundEntities: [], outboundText: [prose], observed, destinationConnectionId: 'scon_work' })).toBeNull();
  });
});

// A custom provider is `custom_` and a slug of up to 100 characters; a connection id is `scon_` and 21.
const LONGEST_CUSTOM = `custom_${'a1b2c3d4e5'.repeat(10)}`;
const OTHER_LONG_CUSTOM = `custom_${'a1b2c3d4e5'.repeat(9)}a1b2c3d4e6`;
const CONNECTION_ID = (tail: string) => `scon_${tail.padEnd(21, 'x')}`;
const CLAIM_SOURCE_SERVICE_MAX = 128;

describe('flowServiceKey', () => {
  it('leaves a service of up to the limit as it is', () => {
    expect(flowServiceKey('cal_com')).toBe('cal_com');
    const atLimit = `custom_${'a'.repeat(FLOW_SERVICE_KEY_MAX_CHARS - 7)}`;
    expect(atLimit).toHaveLength(FLOW_SERVICE_KEY_MAX_CHARS);
    expect(flowServiceKey(atLimit)).toBe(atLimit);
  });

  it('keys a longer service by `custom~` and 40 hex characters of its SHA-256, never by a cut-off name', () => {
    const key = flowServiceKey(LONGEST_CUSTOM);
    expect(LONGEST_CUSTOM).toHaveLength(107);
    expect(key).toMatch(/^custom~[0-9a-f]{40}$/);
    expect(flowServiceKey(LONGEST_CUSTOM)).toBe(key);
    // Two names that share their first 100 characters are still two keys.
    expect(OTHER_LONG_CUSTOM.slice(0, 100)).toBe(LONGEST_CUSTOM.slice(0, 100));
    expect(flowServiceKey(OTHER_LONG_CUSTOM)).not.toBe(key);
    // A key is short and is its own key.
    expect(flowServiceKey(key)).toBe(key);
  });

  it('keeps the longest possible label within the published claim limit', () => {
    const label = flowSourceLabel(LONGEST_CUSTOM, CONNECTION_ID('real'));
    expect(label.length).toBeLessThanOrEqual(CLAIM_SOURCE_SERVICE_MAX);
    // A service at the key limit and a connection id is 100 + 1 + 26, with a character to spare.
    expect(flowSourceLabel(`custom_${'z'.repeat(FLOW_SERVICE_KEY_MAX_CHARS - 7)}`, CONNECTION_ID('a')).length).toBe(127);
    // Even a much longer name (a connect link takes up to 200 characters) is bounded.
    expect(flowSourceLabel(`custom_${'q'.repeat(200)}`, CONNECTION_ID('b')).length).toBeLessThanOrEqual(CLAIM_SOURCE_SERVICE_MAX);
  });

  it('parses a keyed label back to the key and the connection, and round-trips a slug of the maximum length', () => {
    const maxSlug = `custom_${'m'.repeat(FLOW_SERVICE_KEY_MAX_CHARS - 7)}`;
    expect(parseFlowSource(flowSourceLabel(maxSlug, CONNECTION_ID('c')))).toEqual({ service: maxSlug, connectionId: CONNECTION_ID('c') });
    expect(parseFlowSource(flowSourceLabel(LONGEST_CUSTOM, CONNECTION_ID('c')))).toEqual({
      service: flowServiceKey(LONGEST_CUSTOM),
      connectionId: CONNECTION_ID('c'),
    });
  });

  it('records a label with no connection as the service, so nothing recorded before changes meaning', () => {
    expect(flowSourceLabel(LONGEST_CUSTOM)).toBe(LONGEST_CUSTOM);
    expect(flowSourceLabel(LONGEST_CUSTOM, null)).toBe(LONGEST_CUSTOM);
  });
});

describe('a custom service with a long name is tracked per connection', () => {
  const read = 'alice.johnson@example.org';
  const work = CONNECTION_ID('work');
  const personal = CONNECTION_ID('personal');
  const fromWork: ObservedItem[] = [{ value: read, kind: 'entity', service: flowSourceLabel(LONGEST_CUSTOM, work) }];
  const key = flowServiceKey(LONGEST_CUSTOM);
  const send = (over: Partial<Parameters<typeof evaluateDataFlow>[0]> = {}) => evaluateDataFlow({
    destinationService: LONGEST_CUSTOM,
    destinationConnectionId: personal,
    outboundEntities: [read],
    outboundText: [],
    observed: fromWork,
    ...over,
  });

  it('allows the same connection and refuses the other', () => {
    expect(send({ destinationConnectionId: work })).toBeNull();
    expect(send()).toEqual({
      sourceService: key,
      sourceConnectionId: work,
      destinationService: LONGEST_CUSTOM,
      via: 'entity',
      detail: read,
    });
  });

  it('allows it when the service is declared by its name or by its key', () => {
    expect(send({ declaredFlows: [{ from: LONGEST_CUSTOM, to: LONGEST_CUSTOM }] })).toBeNull();
    expect(send({ declaredFlows: [{ from: key, to: LONGEST_CUSTOM }] })).toBeNull();
  });

  it('allows it when the connection is declared by its full label or its keyed label, and only that connection', () => {
    expect(send({ declaredFlows: [{ from: `${LONGEST_CUSTOM}@${work}`, to: LONGEST_CUSTOM }] })).toBeNull();
    expect(send({ declaredFlows: [{ from: `${key}@${work}`, to: LONGEST_CUSTOM }] })).toBeNull();
    expect(send({ declaredFlows: [{ from: `${key}@${CONNECTION_ID('other')}`, to: LONGEST_CUSTOM }] })?.sourceConnectionId).toBe(work);
    expect(send({ declaredFlows: [{ from: `${OTHER_LONG_CUSTOM}@${work}`, to: LONGEST_CUSTOM }] })?.sourceConnectionId).toBe(work);
  });

  it('still refuses a different long-named service, and allows it only when that one is declared', () => {
    const fromOther: ObservedItem[] = [{ value: read, kind: 'entity', service: flowSourceLabel(OTHER_LONG_CUSTOM, work) }];
    expect(send({ observed: fromOther })).toMatchObject({ sourceService: flowServiceKey(OTHER_LONG_CUSTOM), destinationService: LONGEST_CUSTOM });
    expect(send({ observed: fromOther, declaredFlows: [{ from: LONGEST_CUSTOM, to: LONGEST_CUSTOM }] })).not.toBeNull();
    expect(send({ observed: fromOther, declaredFlows: [{ from: OTHER_LONG_CUSTOM, to: LONGEST_CUSTOM }] })).toBeNull();
  });

  it('judges a long-named source going to a short service, declared by name or key', () => {
    const toResend = { destinationService: 'resend', destinationConnectionId: 'scon_r' } as const;
    expect(send(toResend)).toMatchObject({ sourceService: key, destinationService: 'resend' });
    expect(send({ ...toResend, declaredFlows: [{ from: LONGEST_CUSTOM, to: 'resend' }] })).toBeNull();
    expect(send({ ...toResend, declaredFlows: [{ from: `${key}@${work}`, to: 'resend' }] })).toBeNull();
  });

  it('leaves short names as they were', () => {
    const short: ObservedItem[] = [{ value: read, kind: 'entity', service: flowSourceLabel('custom_crm', work) }];
    expect(send({ destinationService: 'custom_crm', observed: short })).toMatchObject({ sourceService: 'custom_crm', sourceConnectionId: work });
    expect(send({ destinationService: 'custom_crm', observed: short, declaredFlows: [{ from: 'custom_crm', to: 'custom_crm' }] })).toBeNull();
    expect(send({ destinationService: 'custom_crm', observed: short, destinationConnectionId: work })).toBeNull();
  });
});
