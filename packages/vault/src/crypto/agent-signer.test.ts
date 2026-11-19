import { describe, it, expect, beforeEach } from 'vitest';
import { generateKeyPair, exportJWK, type JWK } from 'jose';
import {
  AgentSigner,
  AgentSignerCustomerManagedError,
  AgentSignerNotCustomerManagedError,
  AgentSignerNoPubkeyError,
  AgentNotFoundError,
} from './agent-signer.js';
import { ClaimSigner } from './claim-signer.js';
import type { ClaimEnvelope } from '@stack/shared';

// ─── Test doubles ───────────────────────────────────────────────────

/**
 * In-memory AgentRepository double. Captures the rows fed in via the
 * constructor + mutations via update(); tests can read back to assert
 * provisioning landed correctly.
 */
class FakeAgentRepo {
  private rows = new Map<string, Record<string, unknown>>();

  constructor(initial: Array<Record<string, unknown> & { id: string }>) {
    for (const row of initial) this.rows.set(row.id, { ...row });
  }

  async findById(id: string) {
    const row = this.rows.get(id);
    return row ? ({ ...row } as unknown as { id: string; operator_id: string; key_mode: string; signing_key_encrypted: string | null; pubkey: unknown; enrolled_at: Date | null }) : undefined;
  }

  async update(id: string, data: Record<string, unknown>) {
    const row = this.rows.get(id);
    if (!row) return undefined;
    const updated = { ...row, ...data, updated_at: new Date() };
    this.rows.set(id, updated);
    return updated;
  }

  get(id: string) {
    return this.rows.get(id);
  }
}

/**
 * In-memory KMS double — identity encryption with a recognizable
 * prefix so tests can assert what got "wrapped." The real KMS produces
 * ciphertext bytes; for tests we just JSON-wrap with a sentinel + the
 * EncryptionContext so we can verify the AAD discipline was followed.
 */
class FakeKms {
  encryptCalls: Array<{ operatorId?: string; context?: Record<string, string> }> = [];
  decryptCalls: Array<{ operatorId?: string; expectedContext?: Record<string, string> }> = [];

  async encryptDirect(
    plaintext: Buffer,
    opts?: { operatorId?: string; context?: Record<string, string> },
  ): Promise<Buffer> {
    this.encryptCalls.push({ operatorId: opts?.operatorId, context: opts?.context });
    const wrapped = JSON.stringify({
      $fake: true,
      operatorId: opts?.operatorId,
      context: opts?.context,
      plaintext: plaintext.toString('base64'),
    });
    return Buffer.from(wrapped, 'utf8');
  }

  async decryptDirect(
    ciphertext: Buffer,
    opts?: { operatorId?: string; expectedContext?: Record<string, string> },
  ): Promise<Buffer> {
    this.decryptCalls.push({
      operatorId: opts?.operatorId,
      expectedContext: opts?.expectedContext,
    });
    const wrap = JSON.parse(ciphertext.toString('utf8')) as {
      plaintext: string;
      context?: Record<string, string>;
    };
    // Validate that the AAD context the caller passed matches what was
    // used at encrypt time (real KMS does this; the fake simulates it
    // so tests catch AAD-discipline violations).
    if (opts?.expectedContext && wrap.context) {
      const expected = JSON.stringify(opts.expectedContext);
      const actual = JSON.stringify(wrap.context);
      if (expected !== actual) {
        throw new Error(
          `Fake KMS: AAD context mismatch. expected=${expected} stored=${actual}`,
        );
      }
    }
    return Buffer.from(wrap.plaintext, 'base64');
  }
}

async function newEd25519KeyPair(): Promise<{ privateJwk: JWK; publicJwk: JWK }> {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', {
    crv: 'Ed25519',
    extractable: true,
  });
  return {
    privateJwk: await exportJWK(privateKey),
    publicJwk: await exportJWK(publicKey),
  };
}

function makeEnvelope(): ClaimEnvelope {
  return {
    envelope_version: 1,
    issuer: 'op_test',
    subject: 'stack://operator/op_test/passport/ppt_abc',
    issued_at: 1778600000000,
    claim_type: 'intent_claim',
    claim_version: 1,
    payload: { hello: 'world' },
    receipt: null,
    co_signatures: [],
  };
}

// ─── Tests ──────────────────────────────────────────────────────────

describe('AgentSigner', () => {
  let operatorKey: { privateJwk: JWK; publicJwk: JWK };
  let operatorClaimSigner: ClaimSigner;

  beforeEach(async () => {
    operatorKey = await newEd25519KeyPair();
    operatorClaimSigner = new ClaimSigner({
      privateKeyJwk: operatorKey.privateJwk,
      kid: 'op-test-kid',
    });
  });

  it('provisions + signs on first call for a stack_managed agent', async () => {
    const repo = new FakeAgentRepo([
      { id: 'ag_x', operator_id: 'op_test', key_mode: 'stack_managed', signing_key_encrypted: null, pubkey: null, enrolled_at: null },
    ]);
    const kms = new FakeKms();
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: kms as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    const cose = await signer.sign(makeEnvelope(), 'ag_x');
    expect(cose).toMatch(/^[A-Za-z0-9_-]+$/);

    // KMS encrypt was called once with the right context.
    expect(kms.encryptCalls).toHaveLength(1);
    expect(kms.encryptCalls[0]!.operatorId).toBe('op_test');
    expect(kms.encryptCalls[0]!.context).toEqual({
      store: 'agent_signing_key',
      agent_id: 'ag_x',
    });

    // Agent row was populated atomically: pubkey + signing_key_encrypted + enrolled_at.
    const row = repo.get('ag_x') as { pubkey: unknown; signing_key_encrypted: string; enrolled_at: Date };
    expect(row.pubkey).toBeTruthy();
    expect(row.signing_key_encrypted).toBeTruthy();
    expect(row.enrolled_at).toBeInstanceOf(Date);
  });

  it('verifies the signed envelope against the provisioned pubkey', async () => {
    const repo = new FakeAgentRepo([
      { id: 'ag_x', operator_id: 'op_test', key_mode: 'stack_managed', signing_key_encrypted: null, pubkey: null, enrolled_at: null },
    ]);
    const kms = new FakeKms();
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: kms as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    const cose = await signer.sign(makeEnvelope(), 'ag_x');
    const row = repo.get('ag_x') as { pubkey: { kty: string; crv: string; x: string } };

    // Reconstruct full JWK with alg/use for jose import.
    const jwk: JWK = { ...row.pubkey, alg: 'EdDSA', use: 'sig' };

    const verified = await ClaimSigner.verify(cose, async (kid) => {
      expect(kid).toBe('agent:ag_x:v1');
      return jwk;
    });

    expect(verified.valid).toBe(true);
    expect(verified.kid).toBe('agent:ag_x:v1');
  });

  it('caches the signer across consecutive signs (no second KMS call)', async () => {
    const repo = new FakeAgentRepo([
      { id: 'ag_x', operator_id: 'op_test', key_mode: 'stack_managed', signing_key_encrypted: null, pubkey: null, enrolled_at: null },
    ]);
    const kms = new FakeKms();
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: kms as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    await signer.sign(makeEnvelope(), 'ag_x');
    await signer.sign(makeEnvelope(), 'ag_x');
    await signer.sign(makeEnvelope(), 'ag_x');

    // First sign: 1 encrypt (provision), 0 decrypts
    // Subsequent signs hit the cache — no additional KMS calls.
    expect(kms.encryptCalls).toHaveLength(1);
    expect(kms.decryptCalls).toHaveLength(0);
  });

  it('refuses to sign for customer_managed agents', async () => {
    const repo = new FakeAgentRepo([
      { id: 'ag_cust', operator_id: 'op_test', key_mode: 'customer_managed', signing_key_encrypted: null, pubkey: { kty: 'OKP', crv: 'Ed25519', x: 'AAA' }, enrolled_at: new Date() },
    ]);
    const kms = new FakeKms();
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: kms as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    await expect(signer.sign(makeEnvelope(), 'ag_cust')).rejects.toBeInstanceOf(
      AgentSignerCustomerManagedError,
    );
    expect(kms.encryptCalls).toHaveLength(0);
  });

  it('uses operator ClaimSigner for op_stack_system agents (dogfood carve-out)', async () => {
    const repo = new FakeAgentRepo([
      { id: 'ag_sys', operator_id: 'op_stack_system', key_mode: 'stack_managed', signing_key_encrypted: null, pubkey: null, enrolled_at: null },
    ]);
    const kms = new FakeKms();
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: kms as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    const cose = await signer.sign(makeEnvelope(), 'ag_sys');

    // No per-agent provisioning happened — KMS untouched, agent row
    // unchanged (signing_key_encrypted still null).
    expect(kms.encryptCalls).toHaveLength(0);
    const row = repo.get('ag_sys') as { signing_key_encrypted: string | null; pubkey: unknown };
    expect(row.signing_key_encrypted).toBeNull();
    expect(row.pubkey).toBeNull();

    // Envelope signed by operator key — kid in protected header is
    // operator's kid, not agent's.
    const verified = await ClaimSigner.verify(cose, async (kid) => {
      expect(kid).toBe('op-test-kid');
      return operatorKey.publicJwk;
    });
    expect(verified.valid).toBe(true);
  });

  it('co_signed agents provision + sign with their own key (primary signature)', async () => {
    const repo = new FakeAgentRepo([
      { id: 'ag_co', operator_id: 'op_test', key_mode: 'co_signed', signing_key_encrypted: null, pubkey: null, enrolled_at: null },
    ]);
    const kms = new FakeKms();
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: kms as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    const primaryCose = await signer.sign(makeEnvelope(), 'ag_co');

    // Provisioning happened (agent's own key for the primary).
    expect(kms.encryptCalls).toHaveLength(1);
    const row = repo.get('ag_co') as { pubkey: unknown; signing_key_encrypted: string };
    expect(row.pubkey).toBeTruthy();
    expect(row.signing_key_encrypted).toBeTruthy();

    // The primary kid is the agent's kid.
    const verified = await ClaimSigner.verify(
      primaryCose,
      async () => ({ ...(row.pubkey as object), alg: 'EdDSA', use: 'sig' }) as JWK,
    );
    expect(verified.valid).toBe(true);
    expect(verified.kid).toBe('agent:ag_co:v1');
  });

  it('coSignAsOperator produces an operator_attestation co-signature compatible with the primary', async () => {
    const repo = new FakeAgentRepo([
      { id: 'ag_co', operator_id: 'op_test', key_mode: 'co_signed', signing_key_encrypted: null, pubkey: null, enrolled_at: null },
    ]);
    const kms = new FakeKms();
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: kms as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    const primaryCose = await signer.sign(makeEnvelope(), 'ag_co');
    const coSig = await signer.coSignAsOperator(primaryCose);

    expect(coSig.signer_kid).toBe('op-test-kid');
    expect(coSig.signer_role).toBe('operator_attestation');

    // Full verification: primary verifies under agent's pubkey AND
    // co-sig verifies under operator's pubkey.
    const row = repo.get('ag_co') as { pubkey: { kty: string; crv: string; x: string } };
    const agentJwk: JWK = { ...row.pubkey, alg: 'EdDSA', use: 'sig' };

    const verified = await ClaimSigner.verify(
      primaryCose,
      async (kid) => {
        if (kid === 'agent:ag_co:v1') return agentJwk;
        if (kid === 'op-test-kid') return operatorKey.publicJwk;
        return null;
      },
      [coSig],
    );

    expect(verified.valid).toBe(true);
    expect(verified.co_signature_results).toHaveLength(1);
    expect(verified.co_signature_results![0]!.valid).toBe(true);
  });

  it('evictAgent forces a re-load from KMS on next sign', async () => {
    const repo = new FakeAgentRepo([
      { id: 'ag_x', operator_id: 'op_test', key_mode: 'stack_managed', signing_key_encrypted: null, pubkey: null, enrolled_at: null },
    ]);
    const kms = new FakeKms();
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: kms as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    await signer.sign(makeEnvelope(), 'ag_x'); // provisions
    expect(kms.encryptCalls).toHaveLength(1);
    expect(kms.decryptCalls).toHaveLength(0);

    signer.evictAgent('ag_x');

    await signer.sign(makeEnvelope(), 'ag_x'); // re-loads from KMS (already provisioned, just decrypt)
    expect(kms.encryptCalls).toHaveLength(1); // no new provision
    expect(kms.decryptCalls).toHaveLength(1); // one decrypt
    expect(kms.decryptCalls[0]!.expectedContext).toEqual({
      store: 'agent_signing_key',
      agent_id: 'ag_x',
    });
  });

  it('throws AgentNotFoundError for unknown agent_id', async () => {
    const repo = new FakeAgentRepo([]);
    const kms = new FakeKms();
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: kms as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    await expect(signer.sign(makeEnvelope(), 'ag_nope')).rejects.toBeInstanceOf(
      AgentNotFoundError,
    );
  });

  it('passes operator_id to KMS for cross-operator isolation', async () => {
    const repo = new FakeAgentRepo([
      { id: 'ag_alice', operator_id: 'op_alice', key_mode: 'stack_managed', signing_key_encrypted: null, pubkey: null, enrolled_at: null },
      { id: 'ag_bob', operator_id: 'op_bob', key_mode: 'stack_managed', signing_key_encrypted: null, pubkey: null, enrolled_at: null },
    ]);
    const kms = new FakeKms();
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: kms as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    await signer.sign(makeEnvelope(), 'ag_alice');
    await signer.sign(makeEnvelope(), 'ag_bob');

    expect(kms.encryptCalls).toHaveLength(2);
    expect(kms.encryptCalls[0]!.operatorId).toBe('op_alice');
    expect(kms.encryptCalls[1]!.operatorId).toBe('op_bob');
    expect(kms.encryptCalls[0]!.context).toEqual({
      store: 'agent_signing_key',
      agent_id: 'ag_alice',
    });
    expect(kms.encryptCalls[1]!.context).toEqual({
      store: 'agent_signing_key',
      agent_id: 'ag_bob',
    });
  });

  it('uses the cached signer within cacheTtlMs but reloads after expiry', async () => {
    const repo = new FakeAgentRepo([
      { id: 'ag_x', operator_id: 'op_test', key_mode: 'stack_managed', signing_key_encrypted: null, pubkey: null, enrolled_at: null },
    ]);
    const kms = new FakeKms();
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: kms as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
      cacheTtlMs: 50, // 50ms TTL for the test
    });

    await signer.sign(makeEnvelope(), 'ag_x'); // provision
    expect(kms.encryptCalls).toHaveLength(1);

    // Wait for cache to expire.
    await new Promise((r) => setTimeout(r, 70));

    await signer.sign(makeEnvelope(), 'ag_x'); // should hit KMS for a decrypt
    expect(kms.encryptCalls).toHaveLength(1); // still 1 (no re-provision)
    expect(kms.decryptCalls).toHaveLength(1);
  });
});

// ─── verifyPreSigned ───────────────────────────────
//
// The verify path for customer_managed mode: customer holds the
// private key, signs a COSE_Sign1 locally, submits to STACK; STACK
// loads the enrolled pubkey + verifies before persisting the claim.

describe('AgentSigner.verifyPreSigned', () => {
  let operatorKey: { privateJwk: JWK; publicJwk: JWK };
  let operatorClaimSigner: ClaimSigner;

  beforeEach(async () => {
    operatorKey = await newEd25519KeyPair();
    operatorClaimSigner = new ClaimSigner({
      privateKeyJwk: operatorKey.privateJwk,
      kid: 'op-test-kid',
    });
  });

  /**
   * Build an AgentSigner + a customer keypair + an enrolled
   * customer_managed agent row pointing at the customer's pubkey.
   * The customer-side ClaimSigner uses kid `agent:<id>:v1` to match
   * what verifyPreSigned will look up.
   */
  async function setup(agentId = 'ag_cust') {
    const customerKey = await newEd25519KeyPair();
    const customerSigner = new ClaimSigner({
      privateKeyJwk: customerKey.privateJwk,
      kid: `agent:${agentId}:v1`,
    });
    const repo = new FakeAgentRepo([
      {
        id: agentId,
        operator_id: 'op_cust',
        key_mode: 'customer_managed',
        signing_key_encrypted: null,
        pubkey: { kty: customerKey.publicJwk.kty, crv: customerKey.publicJwk.crv, x: customerKey.publicJwk.x },
        enrolled_at: new Date(),
      },
    ]);
    const kms = new FakeKms();
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: kms as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });
    return { customerKey, customerSigner, repo, kms, signer, agentId };
  }

  it('verifies a customer-signed envelope under the enrolled pubkey', async () => {
    const { customerSigner, signer, agentId } = await setup();

    const cose = await customerSigner.sign(makeEnvelope());
    const result = await signer.verifyPreSigned(cose, agentId);

    expect(result.valid).toBe(true);
    expect(result.kid).toBe('agent:ag_cust:v1');
    expect(result.envelope?.claim_type).toBe('intent_claim');
  });

  it('rejects a forged envelope signed by a different keypair', async () => {
    const { signer, agentId } = await setup();

    // Attacker generates their own keypair + signs a COSE_Sign1 with
    // the same kid the agent uses. The kid matches; the signature does
    // not. ClaimSigner.verify reconstructs Sig_structure1 + runs
    // EdDSA verify which returns false because the bytes were signed
    // under a different private key.
    const attackerKey = await newEd25519KeyPair();
    const attackerSigner = new ClaimSigner({
      privateKeyJwk: attackerKey.privateJwk,
      kid: `agent:${agentId}:v1`, // same kid the agent uses
    });
    const forged = await attackerSigner.sign(makeEnvelope());

    const result = await signer.verifyPreSigned(forged, agentId);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('signature verification failed');
  });

  it('rejects an envelope whose kid points at a different agent', async () => {
    const { customerKey, signer, agentId } = await setup();

    // Customer accidentally (or maliciously) signs with the wrong kid
    // — e.g. claiming to be a different agent in their org. Resolver
    // only knows `agent:<this_agent_id>:v1`; anything else returns
    // null and verify fails with "kid not found in JWKS".
    const wrongKidSigner = new ClaimSigner({
      privateKeyJwk: customerKey.privateJwk,
      kid: 'agent:ag_other:v1', // wrong kid
    });
    const cose = await wrongKidSigner.sign(makeEnvelope());

    const result = await signer.verifyPreSigned(cose, agentId);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/not found in JWKS/);
  });

  it('rejects an envelope whose payload bytes were tampered post-signing', async () => {
    const { customerSigner, signer, agentId } = await setup();

    // Sign a valid envelope, then corrupt one byte of the COSE_Sign1
    // bytes (anywhere in the encoded form). Verify must fail.
    const cose = await customerSigner.sign(makeEnvelope());
    const buf = Buffer.from(cose, 'base64url');
    // Flip a bit roughly in the middle of the payload region.
    buf[Math.floor(buf.length / 2)]! ^= 0x01;
    const tampered = buf.toString('base64url');

    const result = await signer.verifyPreSigned(tampered, agentId);
    expect(result.valid).toBe(false);
  });

  it('throws AgentSignerNotCustomerManagedError on a stack_managed agent', async () => {
    const repo = new FakeAgentRepo([
      {
        id: 'ag_sm',
        operator_id: 'op_test',
        key_mode: 'stack_managed',
        signing_key_encrypted: 'fake-ciphertext',
        pubkey: { kty: 'OKP', crv: 'Ed25519', x: 'AAA' },
        enrolled_at: new Date(),
      },
    ]);
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: new FakeKms() as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    await expect(signer.verifyPreSigned('AA==', 'ag_sm')).rejects.toBeInstanceOf(
      AgentSignerNotCustomerManagedError,
    );
  });

  it('throws AgentSignerNotCustomerManagedError on a co_signed agent', async () => {
    const repo = new FakeAgentRepo([
      {
        id: 'ag_co',
        operator_id: 'op_test',
        key_mode: 'co_signed',
        signing_key_encrypted: 'fake-ciphertext',
        pubkey: { kty: 'OKP', crv: 'Ed25519', x: 'AAA' },
        enrolled_at: new Date(),
      },
    ]);
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: new FakeKms() as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    await expect(signer.verifyPreSigned('AA==', 'ag_co')).rejects.toBeInstanceOf(
      AgentSignerNotCustomerManagedError,
    );
  });

  it('throws AgentSignerNoPubkeyError when the customer_managed agent has not enrolled', async () => {
    const repo = new FakeAgentRepo([
      {
        id: 'ag_unenrolled',
        operator_id: 'op_cust',
        key_mode: 'customer_managed',
        signing_key_encrypted: null,
        pubkey: null,
        enrolled_at: null,
      },
    ]);
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: new FakeKms() as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    await expect(signer.verifyPreSigned('AA==', 'ag_unenrolled')).rejects.toBeInstanceOf(
      AgentSignerNoPubkeyError,
    );
  });

  it('throws AgentNotFoundError for an unknown agent_id', async () => {
    const repo = new FakeAgentRepo([]);
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: new FakeKms() as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    await expect(signer.verifyPreSigned('AA==', 'ag_nope')).rejects.toBeInstanceOf(
      AgentNotFoundError,
    );
  });

  it('returns a structured error on malformed COSE input', async () => {
    const { signer, agentId } = await setup();

    // Not a COSE_Sign1; just random base64.
    const garbage = Buffer.from('not-cose-at-all').toString('base64url');
    const result = await signer.verifyPreSigned(garbage, agentId);

    expect(result.valid).toBe(false);
    expect(result.error).toBeTruthy();
  });
});

// ─── signClaim + verifyClaim ───────────────────────
//
// The producer-facing one-shot path. signClaim returns the primary
// envelope_cose AND the co_signatures array in a single call;
// verifyClaim accepts both and enforces key_mode-specific gates
// (co_signed agents MUST have a verifying operator_attestation).

describe('AgentSigner.signClaim + verifyClaim (co_signed mode)', () => {
  let operatorKey: { privateJwk: JWK; publicJwk: JWK };
  let operatorClaimSigner: ClaimSigner;

  beforeEach(async () => {
    operatorKey = await newEd25519KeyPair();
    operatorClaimSigner = new ClaimSigner({
      privateKeyJwk: operatorKey.privateJwk,
      kid: 'op-test-kid',
    });
  });

  /**
   * Build a signer + a fresh co_signed agent in the repo. Returns the
   * AgentSigner and access to the underlying repo for verifying that
   * row state evolved as expected.
   */
  function setupCoSigned(agentId = 'ag_co') {
    const repo = new FakeAgentRepo([
      {
        id: agentId,
        operator_id: 'op_test',
        key_mode: 'co_signed',
        signing_key_encrypted: null,
        pubkey: null,
        enrolled_at: null,
      },
    ]);
    const kms = new FakeKms();
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: kms as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });
    return { repo, kms, signer, agentId };
  }

  it('signClaim on a co_signed agent returns primary + operator_attestation co-sig', async () => {
    const { signer, agentId } = setupCoSigned();
    const result = await signer.signClaim(makeEnvelope(), agentId);

    expect(result.envelope_cose).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(result.co_signatures).toHaveLength(1);
    expect(result.co_signatures[0]!.signer_role).toBe('operator_attestation');
    expect(result.co_signatures[0]!.signer_kid).toBe('op-test-kid');
    expect(result.co_signatures[0]!.cose_sign1).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('signClaim on a stack_managed agent returns primary with empty co_signatures', async () => {
    const repo = new FakeAgentRepo([
      { id: 'ag_sm', operator_id: 'op_test', key_mode: 'stack_managed', signing_key_encrypted: null, pubkey: null, enrolled_at: null },
    ]);
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: new FakeKms() as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    const result = await signer.signClaim(makeEnvelope(), 'ag_sm');
    expect(result.envelope_cose).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(result.co_signatures).toEqual([]);
  });

  it('signClaim on a customer_managed agent throws AgentSignerCustomerManagedError', async () => {
    const repo = new FakeAgentRepo([
      { id: 'ag_cust', operator_id: 'op_test', key_mode: 'customer_managed', signing_key_encrypted: null, pubkey: { kty: 'OKP', crv: 'Ed25519', x: 'AAA' }, enrolled_at: new Date() },
    ]);
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: new FakeKms() as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    await expect(signer.signClaim(makeEnvelope(), 'ag_cust')).rejects.toBeInstanceOf(
      AgentSignerCustomerManagedError,
    );
  });

  it('signClaim on a dogfood agent uses operator signer + no co-sig', async () => {
    const repo = new FakeAgentRepo([
      { id: 'ag_sys', operator_id: 'op_stack_system', key_mode: 'stack_managed', signing_key_encrypted: null, pubkey: null, enrolled_at: null },
    ]);
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: new FakeKms() as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    const result = await signer.signClaim(makeEnvelope(), 'ag_sys');
    expect(result.co_signatures).toEqual([]);

    // Envelope_cose was signed by operator's key (kid is operator's, not agent's).
    const verified = await ClaimSigner.verify(result.envelope_cose, async (kid) => {
      expect(kid).toBe('op-test-kid');
      return operatorKey.publicJwk;
    });
    expect(verified.valid).toBe(true);
  });

  it('verifyClaim accepts a freshly signed co_signed claim (round-trip)', async () => {
    const { signer, agentId } = setupCoSigned();
    const signed = await signer.signClaim(makeEnvelope(), agentId);

    const result = await signer.verifyClaim(
      signed.envelope_cose,
      signed.co_signatures,
      agentId,
    );

    expect(result.valid).toBe(true);
    expect(result.kid).toBe('agent:ag_co:v1');
    expect(result.co_signature_results).toHaveLength(1);
    expect(result.co_signature_results![0]!.valid).toBe(true);
    expect(result.co_signature_results![0]!.signer_role).toBe('operator_attestation');
  });

  it('verifyClaim rejects co_signed claim when operator co-sig is missing', async () => {
    const { signer, agentId } = setupCoSigned();
    const signed = await signer.signClaim(makeEnvelope(), agentId);

    // Drop the co-sig.
    const result = await signer.verifyClaim(signed.envelope_cose, [], agentId);

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/missing valid operator_attestation/);
  });

  it('verifyClaim rejects co_signed claim when the primary signature is tampered', async () => {
    const { signer, agentId } = setupCoSigned();
    const signed = await signer.signClaim(makeEnvelope(), agentId);

    // Flip a byte in the primary's COSE bytes.
    const buf = Buffer.from(signed.envelope_cose, 'base64url');
    buf[Math.floor(buf.length / 2)]! ^= 0x01;
    const tampered = buf.toString('base64url');

    const result = await signer.verifyClaim(tampered, signed.co_signatures, agentId);
    expect(result.valid).toBe(false);
  });

  it("verifyClaim rejects co_signed claim when the operator co-sig's payload differs from primary", async () => {
    const { signer, agentId } = setupCoSigned();
    const signed = await signer.signClaim(makeEnvelope(), agentId);

    // Hand-craft a co-sig over a DIFFERENT envelope but claiming the
    // same role — exercises ClaimSigner.verify's "co-sig payload must
    // equal primary payload" defense (claim-signer.ts buffersEqual
    // check). The verifier should reject because the co-sig's
    // payload bytes won't match the primary's.
    const wrongEnvelope = { ...makeEnvelope(), subject: 'stack://operator/op_test/passport/ppt_xyz_DIFFERENT' };
    const wrongCose = await operatorClaimSigner.sign(wrongEnvelope);
    const corruptCoSig = await operatorClaimSigner.coSign(wrongCose, 'operator_attestation');

    const result = await signer.verifyClaim(signed.envelope_cose, [corruptCoSig], agentId);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/operator_attestation co-signature failed/);
  });

  it('verifyClaim rejects co_signed claim when operator co-sig is signed by a different key', async () => {
    const { signer, agentId } = setupCoSigned();
    const signed = await signer.signClaim(makeEnvelope(), agentId);

    // Attacker forges a co-sig with same kid but their own private key.
    const attackerKey = await newEd25519KeyPair();
    const attackerSigner = new ClaimSigner({
      privateKeyJwk: attackerKey.privateJwk,
      kid: 'op-test-kid', // same kid the real operator uses
    });
    const forgedCoSig = await attackerSigner.coSign(signed.envelope_cose, 'operator_attestation');

    const result = await signer.verifyClaim(
      signed.envelope_cose,
      [forgedCoSig],
      agentId,
    );
    expect(result.valid).toBe(false);
  });

  it('verifyClaim on a stack_managed agent ignores absent co_signatures (no gate)', async () => {
    const repo = new FakeAgentRepo([
      { id: 'ag_sm', operator_id: 'op_test', key_mode: 'stack_managed', signing_key_encrypted: null, pubkey: null, enrolled_at: null },
    ]);
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: new FakeKms() as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    const signed = await signer.signClaim(makeEnvelope(), 'ag_sm');
    const result = await signer.verifyClaim(signed.envelope_cose, [], 'ag_sm');

    expect(result.valid).toBe(true);
  });

  it('verifyClaim resolves operator kid via the explicit operatorJwksResolver when supplied', async () => {
    const { signer, agentId } = setupCoSigned();
    const signed = await signer.signClaim(makeEnvelope(), agentId);

    let resolverCalls = 0;
    const explicitResolver = async (kid: string): Promise<JWK | null> => {
      resolverCalls += 1;
      if (kid === 'op-test-kid') return operatorKey.publicJwk;
      return null;
    };

    const result = await signer.verifyClaim(
      signed.envelope_cose,
      signed.co_signatures,
      agentId,
      { operatorJwksResolver: explicitResolver },
    );

    expect(result.valid).toBe(true);
    // Explicit resolver was consulted (at least once) for the
    // operator's kid lookup before the fallback path.
    expect(resolverCalls).toBeGreaterThanOrEqual(1);
  });

  it('verifyClaim throws AgentNotFoundError for unknown agent_id', async () => {
    const repo = new FakeAgentRepo([]);
    const signer = new AgentSigner({
      agentRepo: repo as never,
      kms: new FakeKms() as never,
      systemOperatorId: 'op_stack_system',
      operatorClaimSigner: async () => operatorClaimSigner,
    });

    await expect(signer.verifyClaim('AA==', [], 'ag_nope')).rejects.toBeInstanceOf(
      AgentNotFoundError,
    );
  });
});
