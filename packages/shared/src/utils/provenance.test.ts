import { describe, it, expect } from 'vitest';
import { attributePayload, fingerprintPayload, inheritedObservations, observedKnowsEntity, provenanceSources, trailEntity, trailEntityDigest } from './provenance.js';
import { collectStrings, contentFingerprints, evaluateDataFlow, type ObservedItem } from './data-flow.js';
import { extractEntities } from './entity-extraction.js';

/** What the CFO agent read from the bank, recorded the way the proxy producer records it. */
const BANK_RESPONSE = {
  accounts: [
    { name: 'Operating', accountNumber: '123456789012', availableBalance: 48213.55 },
    { name: 'Reserve', accountNumber: '987654321098', availableBalance: 250000 },
  ],
};

function observedFrom(service: string, body: unknown): ObservedItem[] {
  const entities = extractEntities(body, { financial: service === 'mercury' }).map((e) => e.entity);
  const shingles = contentFingerprints(collectStrings(body).join(' '));
  return [
    ...entities.map((value) => ({ value, kind: 'entity' as const, service })),
    ...shingles.map((value) => ({ value, kind: 'shingle' as const, service })),
  ];
}

const AUDIT = {
  title: 'Monthly cash audit',
  summary: 'Operating holds $48,213.55 and the reserve holds $250,000.00 as of today.',
  channel_note: 'post to the exec channel',
};

describe('hand-off provenance', () => {
  const depositorObserved = [
    ...observedFrom('mercury', BANK_RESPONSE),
    ...observedFrom('slack', { channels: [{ name: 'exec-team', topic: 'leadership updates only please thanks' }] }),
  ];

  it('records the ORIGINAL source of a balance copied into a hand-off', () => {
    const provenance = attributePayload({ payload: AUDIT, missionId: 'ms_cfo', observed: depositorObserved });
    expect(provenance.sources).toEqual(['mercury']);
    expect(provenance.method).toBe('mission_observations');
    expect(JSON.stringify(provenance)).not.toContain('48213');
    expect(JSON.stringify(provenance)).not.toContain('48,213');
  });

  it('lets the collector be refused for posting it, as the reader would have been', () => {
    const provenance = attributePayload({ payload: AUDIT, missionId: 'ms_cfo', observed: depositorObserved });
    const inherited = inheritedObservations(AUDIT, JSON.parse(JSON.stringify(provenance)));
    expect(inherited.map((o) => o.source)).toEqual(['mercury']);
    const collectorObserved: ObservedItem[] = inherited.flatMap((o) => [
      ...o.entities.map((value) => ({ value, kind: 'entity' as const, service: o.source })),
      ...o.fingerprints.map((value) => ({ value, kind: 'shingle' as const, service: o.source })),
    ]);
    const post = { channel: 'C_EXEC', text: AUDIT.summary };
    const violation = evaluateDataFlow({
      destinationService: 'slack',
      outboundEntities: extractEntities(post, { financial: true }).map((e) => e.entity),
      outboundText: collectStrings(post),
      observed: collectorObserved,
    });
    expect(violation).toMatchObject({ sourceService: 'mercury', destinationService: 'slack', via: 'entity' });
  });

  it('does not taint the depositor\'s own writing', () => {
    const own = { note: 'Please remember to rotate the on-call schedule next week for everyone involved' };
    const provenance = attributePayload({ payload: own, missionId: 'ms_cfo', observed: depositorObserved });
    expect(provenance.sources).toEqual([]);
    expect(provenance.unattributed.fingerprints).toBeGreaterThan(0);
    expect(inheritedObservations(own, provenance)).toEqual([]);
  });

  it('records nothing without a depositor Mission, and says why', () => {
    const provenance = attributePayload({ payload: AUDIT, missionId: null, observed: depositorObserved });
    expect(provenance).toMatchObject({ method: 'no_mission', sources: [] });
  });

  it('fails closed when the item maps are gone: the whole payload is attributed to the recorded source', () => {
    const stripped = { v: 1, method: 'mission_observations', mission_id: 'ms_cfo', sources: ['mercury'], unattributed: { entities: 0, fingerprints: 0 } };
    const inherited = inheritedObservations(AUDIT, stripped);
    const all = fingerprintPayload(AUDIT);
    expect(inherited).toHaveLength(1);
    expect(inherited[0]!.entities).toEqual(all.entities.map((e) => e.entity));
    expect(inherited[0]!.fingerprints).toEqual(all.fingerprints);
  });

  it('chunks large inheritances to the observation claim caps', () => {
    const big = { rows: Array.from({ length: 1200 }, (_, i) => `contact${i}@corp.example`) };
    // Several reads of the source together cover more than one claim's worth.
    const read = fingerprintPayload(big);
    const observed: ObservedItem[] = [
      ...read.entities.map((e) => ({ value: e.entity, kind: 'entity' as const, service: 'hubspot' })),
      ...read.fingerprints.map((value) => ({ value, kind: 'shingle' as const, service: 'hubspot' })),
    ];
    const provenance = attributePayload({ payload: big, missionId: 'ms_x', observed });
    const inherited = inheritedObservations(big, provenance);
    expect(inherited.length).toBeGreaterThan(1);
    for (const chunk of inherited) {
      expect(chunk.entities.length).toBeLessThanOrEqual(256);
      expect(chunk.fingerprints.length).toBeLessThanOrEqual(512);
    }
  });

  it('ignores a malformed stored value', () => {
    expect(inheritedObservations(AUDIT, { v: 2, sources: ['mercury'] })).toEqual([]);
    expect(provenanceSources(null)).toEqual([]);
    expect(provenanceSources({ v: 1, sources: ['mercury', 7] })).toEqual(['mercury']);
  });
});

describe('one value read from two services', () => {
  it('is refused if ANY of its sources is not allowed, not just the last one recorded', () => {
    // The balance was read from Mercury and later echoed back by Slack. A
    // last-writer-wins map called it "from Slack" and let it go to Slack.
    const observed: ObservedItem[] = [
      { value: 'money:abc', kind: 'entity', service: 'mercury' },
      { value: 'money:abc', kind: 'entity', service: 'slack' },
    ];
    const violation = evaluateDataFlow({
      destinationService: 'slack',
      outboundEntities: ['money:abc'],
      outboundText: [],
      observed,
    });
    expect(violation).toMatchObject({ sourceService: 'mercury', via: 'entity' });
  });
});

describe('entities kept only as digests (an account\'s own mail)', () => {
  it('is a prefixed one-way digest that does not hold the entity', () => {
    const digest = trailEntityDigest('Sam.Partner@Acme.example');
    expect(digest).toMatch(/^h:[0-9a-f]{32}$/);
    expect(digest).not.toContain('acme');
    expect(trailEntityDigest('sam.partner@acme.example')).toBe(digest);
    expect(trailEntityDigest('someone.else@acme.example')).not.toBe(digest);
  });

  it('leaves a financial digest and an existing trail digest as they are', () => {
    const money = extractEntities({ balance: 48213.55 }, { financial: true }).find((e) => e.entity_type === 'money_amount')!;
    expect(trailEntity(money.entity)).toBe(money.entity);
    expect(trailEntity(trailEntityDigest('a@b.example'))).toBe(trailEntityDigest('a@b.example'));
    expect(trailEntity('a@b.example')).toBe(trailEntityDigest('a@b.example'));
  });

  it('is matched by the data-flow rule when the outbound side offers the digest too', () => {
    const observed: ObservedItem[] = [{ value: trailEntity('sam.partner@acme.example'), kind: 'entity', service: 'stack:account-messages' }];
    const violation = evaluateDataFlow({
      destinationService: 'slack',
      outboundEntities: ['sam.partner@acme.example', trailEntityDigest('sam.partner@acme.example')],
      outboundText: [],
      observed,
    });
    expect(violation).toMatchObject({ sourceService: 'stack:account-messages', via: 'entity' });
  });
});

describe('observedKnowsEntity', () => {
  it('knows an entity recorded as text, as a digest, or declared in lowercase, and nothing else', () => {
    const text = new Set(['sam.partner@acme.example']);
    const digest = new Set([trailEntityDigest('sam.partner@acme.example')]);
    for (const observed of [text, digest]) {
      expect(observedKnowsEntity(observed, 'sam.partner@acme.example')).toBe(true);
      expect(observedKnowsEntity(observed, 'Sam.Partner@ACME.example')).toBe(true);
      expect(observedKnowsEntity(observed, 'someone.else@acme.example')).toBe(false);
    }
    expect(observedKnowsEntity(new Set(), 'sam.partner@acme.example')).toBe(false);
  });

  it('knows a financial digest the trail kept as it was', () => {
    const money = extractEntities({ balance: 48213.55 }, { financial: true }).find((e) => e.entity_type === 'money_amount')!;
    expect(observedKnowsEntity(new Set([money.entity]), money.entity)).toBe(true);
  });
});
