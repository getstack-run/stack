import { describe, it, expect } from 'vitest';
import {
  ExternalAnchorService,
  NoopAnchorPublisher,
  type AnchorPublisher,
  type AnchorPayload,
} from './external-anchor-service.js';
import type { AuditService } from './audit-service.js';
import type { ExternalAnchorRepository, ExternalAnchorRow } from '../repositories/external-anchor-repo.js';
import type { ClaimSigner } from '../crypto/claim-signer.js';

/**
 * ExternalAnchorService invariants.
 *
 *   A1: anchorOperator with no chain → returns null (silent skip)
 *   A2: anchorOperator with chain → signs head, calls publisher, inserts row
 *   A3: signing surface is canonicalize({chain_head_hash, anchored_at_ms, chain_head_at_audit_position})
 *   A4: publisher receives the dateKey + operatorId + payload
 *   A5: STACK system co-sig present when wired; absent otherwise
 *   A6: publishedExternally=false when permalink starts with 'noop://'
 *   A7: publishedExternally=true when real registry returns non-noop permalink
 *   A8: insert row carries registry + permalink + commit_sha verbatim
 *   A9: getLatestAnchor delegates to repo.findLatest
 *   A10: getAnchorAtOrBefore delegates to repo.findAtOrBefore
 *   A11: rowToRef converts ExternalAnchorRow → external_chain_anchors[] entry shape
 *
 *   N1: NoopAnchorPublisher returns noop:// permalink + deterministic synthetic sha
 *   N2: NoopAnchorPublisher same input → same output (deterministic)
 *   N3: NoopAnchorPublisher registry = 'noop:local'
 */

function makeFixture(): {
  service: ExternalAnchorService;
  publisher: { calls: Array<{ operatorId: string; dateKey: string; payload: AnchorPayload }>; ref: AnchorPublisher };
  signBytesCalls: Array<{ data: string; signer: 'operator' | 'system' }>;
  inserted: Array<Record<string, unknown>>;
  chainHead: { value: { latest_entry_hash: string | null; latest_timestamp: number | null; total_entries: number } };
  withStackSig: (signer: ClaimSigner | undefined) => void;
  freezeNow: (ms: number) => void;
} {
  const publisher = {
    calls: [] as Array<{ operatorId: string; dateKey: string; payload: AnchorPayload }>,
    ref: {
      registry: 'github:example-org/audit-anchors',
      async publish(input: { operatorId: string; dateKey: string; payload: AnchorPayload }) {
        publisher.calls.push(input);
        return {
          permalink: `https://github.com/example-org/audit-anchors/blob/abc123/anchors/${input.operatorId}/${input.dateKey}.json`,
          commit_sha: 'abc123',
        };
      },
    } satisfies AnchorPublisher,
  };

  const signBytesCalls: Array<{ data: string; signer: 'operator' | 'system' }> = [];
  const operatorSigner = {
    signBytes: async (data: Buffer) => {
      signBytesCalls.push({ data: data.toString('utf8'), signer: 'operator' });
      return 'operator_sig_b64';
    },
  } as unknown as ClaimSigner;

  const stackSigHolder: { value: ClaimSigner | undefined } = { value: undefined };

  const inserted: Array<Record<string, unknown>> = [];
  const anchorRepo = {
    insert: async (row: Record<string, unknown>) => {
      inserted.push(row);
      return row as unknown as ExternalAnchorRow;
    },
    findLatest: async (operatorId: string) =>
      (inserted.filter((r) => r['operator_id'] === operatorId).pop() ?? null) as ExternalAnchorRow | null,
    findAtOrBefore: async (operatorId: string, tMs: number) =>
      (inserted
        .filter((r) => r['operator_id'] === operatorId && (r['anchored_at_ms'] as number) <= tMs)
        .pop() ?? null) as ExternalAnchorRow | null,
  } as unknown as ExternalAnchorRepository;

  const chainHead = {
    value: { latest_entry_hash: 'a'.repeat(64), latest_timestamp: 1000, total_entries: 42 },
  };
  const auditService = {
    getChainHead: async () => chainHead.value,
  } as unknown as AuditService;

  const nowHolder = { value: 5_000 };

  const service = new ExternalAnchorService({
    anchorRepo,
    auditService,
    operatorSignerResolver: async () => operatorSigner,
    get stackSystemSigner() {
      return stackSigHolder.value;
    },
    publisher: publisher.ref,
    now: () => nowHolder.value,
  });

  return {
    service,
    publisher,
    signBytesCalls,
    inserted,
    chainHead,
    withStackSig: (signer) => {
      stackSigHolder.value = signer;
      // If signer is wired, route signBytes via the same tracker.
      if (signer) {
        (signer as unknown as { signBytes: (data: Buffer) => Promise<string> }).signBytes = async (data: Buffer) => {
          signBytesCalls.push({ data: data.toString('utf8'), signer: 'system' });
          return 'system_sig_b64';
        };
      }
    },
    freezeNow: (ms: number) => {
      nowHolder.value = ms;
    },
  };
}

describe('ExternalAnchorService — anchorOperator', () => {
  it('A1 no chain → returns null', async () => {
    const fixture = makeFixture();
    fixture.chainHead.value = { latest_entry_hash: null, latest_timestamp: null, total_entries: 0 };
    const result = await fixture.service.anchorOperator('op_abc');
    expect(result).toBeNull();
  });

  it('A2 with chain → signs, publishes, inserts', async () => {
    const fixture = makeFixture();
    fixture.freezeNow(1_700_000_000_000);
    const result = await fixture.service.anchorOperator('op_abc');
    expect(result).not.toBeNull();
    expect(fixture.signBytesCalls).toHaveLength(1);
    expect(fixture.publisher.calls).toHaveLength(1);
    expect(fixture.inserted).toHaveLength(1);
  });

  it('A3 signing surface is canonicalize of (chain_head_hash, anchored_at_ms, chain_head_at_audit_position)', async () => {
    const fixture = makeFixture();
    fixture.freezeNow(1_700_000_000_000);
    await fixture.service.anchorOperator('op_abc');
    const signedString = fixture.signBytesCalls[0]!.data;
    // canonicalize sorts keys lexicographically
    expect(signedString).toBe(
      JSON.stringify({
        anchored_at_ms: 1_700_000_000_000,
        chain_head_at_audit_position: 42,
        chain_head_hash: 'a'.repeat(64),
      }),
    );
  });

  it('A4 publisher receives correct dateKey + operatorId + payload', async () => {
    const fixture = makeFixture();
    fixture.freezeNow(Date.UTC(2026, 4, 24, 12, 0, 0)); // 2026-05-24
    await fixture.service.anchorOperator('op_abc');
    const call = fixture.publisher.calls[0]!;
    expect(call.operatorId).toBe('op_abc');
    expect(call.dateKey).toBe('2026-05-24');
    expect(call.payload.operator_id).toBe('op_abc');
    expect(call.payload.chain_head_hash).toBe('a'.repeat(64));
    expect(call.payload.anchored_at_ms).toBe(Date.UTC(2026, 4, 24, 12, 0, 0));
    expect(call.payload.anchored_at_audit_position).toBe(42);
    expect(call.payload.chain_head_signature).toBe('operator_sig_b64');
  });

  it('A5 STACK system co-sig present when wired', async () => {
    const fixture = makeFixture();
    fixture.withStackSig({ signBytes: async () => 'system_sig_b64' } as unknown as ClaimSigner);
    await fixture.service.anchorOperator('op_abc');
    expect(fixture.publisher.calls[0]!.payload.stack_system_attestation).toBe('system_sig_b64');
    expect(fixture.signBytesCalls.filter((c) => c.signer === 'system')).toHaveLength(1);
  });

  it('A5b STACK system co-sig absent when not wired', async () => {
    const fixture = makeFixture();
    await fixture.service.anchorOperator('op_abc');
    expect(fixture.publisher.calls[0]!.payload.stack_system_attestation).toBeUndefined();
  });

  it('A6 publishedExternally=true when real registry returns non-noop permalink', async () => {
    const fixture = makeFixture();
    const result = await fixture.service.anchorOperator('op_abc');
    expect(result?.publishedExternally).toBe(true);
  });

  it('A7 publishedExternally=false when publisher returns noop:// permalink', async () => {
    const fixture = makeFixture();
    fixture.publisher.ref.publish = async () => ({
      permalink: 'noop://anchor/op_abc/2026-05-24',
      commit_sha: 'noopsha',
    });
    const result = await fixture.service.anchorOperator('op_abc');
    expect(result?.publishedExternally).toBe(false);
  });

  it('A8 insert row carries registry + permalink + commit_sha verbatim', async () => {
    const fixture = makeFixture();
    await fixture.service.anchorOperator('op_abc');
    const row = fixture.inserted[0]!;
    expect(row['registry']).toBe('github:example-org/audit-anchors');
    expect(row['permalink']).toContain('audit-anchors');
    expect(row['commit_sha']).toBe('abc123');
    expect(row['operator_id']).toBe('op_abc');
    expect(row['chain_head_hash']).toBe('a'.repeat(64));
    expect(row['chain_head_signature']).toBe('operator_sig_b64');
  });
});

describe('ExternalAnchorService — read paths', () => {
  it('A9 getLatestAnchor delegates to repo.findLatest', async () => {
    const fixture = makeFixture();
    fixture.freezeNow(1000);
    await fixture.service.anchorOperator('op_abc');
    const latest = await fixture.service.getLatestAnchor('op_abc');
    expect(latest).not.toBeNull();
    expect(latest?.operator_id).toBe('op_abc');
  });

  it('A10 getAnchorAtOrBefore delegates to repo.findAtOrBefore', async () => {
    const fixture = makeFixture();
    fixture.freezeNow(1000);
    await fixture.service.anchorOperator('op_abc');
    const found = await fixture.service.getAnchorAtOrBefore('op_abc', 2000);
    expect(found?.anchored_at_ms).toBe(1000);
    const notFound = await fixture.service.getAnchorAtOrBefore('op_abc', 500);
    expect(notFound).toBeNull();
  });

  it('A11 rowToRef converts to external_chain_anchors[] entry shape', () => {
    const row: ExternalAnchorRow = {
      id: 'anc_1',
      operator_id: 'op_abc',
      anchored_at_ms: 1000,
      chain_head_hash: 'a'.repeat(64),
      chain_head_at_audit_position: 42,
      registry: 'github:example-org/audit-anchors',
      permalink: 'https://github.com/example-org/audit-anchors/blob/sha/file.json',
      commit_sha: 'sha',
      chain_head_signature: 'sig',
      stack_system_attestation: null,
    };
    const ref = ExternalAnchorService.rowToRef(row);
    expect(ref).toEqual({
      registry: 'github:example-org/audit-anchors',
      permalink: 'https://github.com/example-org/audit-anchors/blob/sha/file.json',
      anchored_at_ms: 1000,
      anchored_chain_head_hash: 'a'.repeat(64),
    });
  });
});

describe('NoopAnchorPublisher', () => {
  it('N1 returns noop:// permalink + synthetic sha', async () => {
    const publisher = new NoopAnchorPublisher();
    const result = await publisher.publish({
      operatorId: 'op_abc',
      dateKey: '2026-05-24',
      payload: {
        operator_id: 'op_abc',
        chain_head_hash: 'a'.repeat(64),
        chain_head_signature: 'sig',
        anchored_at_ms: 1000,
        anchored_at_audit_position: 1,
      },
    });
    expect(result.permalink).toBe('noop://anchor/op_abc/2026-05-24');
    expect(result.commit_sha).toMatch(/^[0-9a-f]+$/);
  });

  it('N2 deterministic — same payload → same commit_sha', async () => {
    const publisher = new NoopAnchorPublisher();
    const payload = {
      operator_id: 'op_abc',
      chain_head_hash: 'a'.repeat(64),
      chain_head_signature: 'sig',
      anchored_at_ms: 1000,
      anchored_at_audit_position: 1,
    };
    const a = await publisher.publish({ operatorId: 'op_abc', dateKey: '2026-05-24', payload });
    const b = await publisher.publish({ operatorId: 'op_abc', dateKey: '2026-05-24', payload });
    expect(a.commit_sha).toBe(b.commit_sha);
  });

  it('N3 registry is noop:local', () => {
    expect(new NoopAnchorPublisher().registry).toBe('noop:local');
  });
});
