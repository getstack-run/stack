import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the AWS KMS SDK at module level. We track every call against a shared
// in-memory store keyed by the data-key plaintext, so an envelope encrypted
// under one "key" round-trips correctly regardless of which KmsService instance
// performs the decrypt — including across different `keyId` configurations.
// That is what the platform-key-rotation regression test is verifying.

interface FakeKmsCall {
  command: string;
  KeyId?: string;
  EncryptionContext?: Record<string, string>;
  region: string;
}

const fakeCalls: FakeKmsCall[] = [];
const dataKeyStore = new Map<string, Buffer>(); // ciphertextBlob (base64) → plaintext key
const constructedRegions: string[] = [];

vi.mock('@aws-sdk/client-kms', () => {
  class FakeKMSClient {
    private region: string;
    constructor(config: { region: string }) {
      this.region = config.region;
      constructedRegions.push(config.region);
    }
    async send(command: { __type: string; input: Record<string, unknown> }) {
      const type = command.__type;
      const input = command.input;
      if (type === 'GenerateDataKey') {
        fakeCalls.push({
          command: 'GenerateDataKey',
          KeyId: input.KeyId as string,
          EncryptionContext: input.EncryptionContext as Record<string, string> | undefined,
          region: this.region,
        });
        const plaintext = Buffer.from(crypto.getRandomValues(new Uint8Array(32)));
        const blob = Buffer.from(crypto.getRandomValues(new Uint8Array(48)));
        const blobB64 = blob.toString('base64');
        dataKeyStore.set(blobB64, plaintext);
        return { Plaintext: plaintext, CiphertextBlob: blob };
      }
      if (type === 'Decrypt') {
        fakeCalls.push({
          command: 'Decrypt',
          KeyId: input.KeyId as string | undefined,
          EncryptionContext: input.EncryptionContext as Record<string, string> | undefined,
          region: this.region,
        });
        const blobBuf = input.CiphertextBlob as Buffer;
        const blobB64 = blobBuf.toString('base64');
        const plaintext = dataKeyStore.get(blobB64);
        if (!plaintext) throw new Error('FakeKMS: unknown ciphertext blob');
        return { Plaintext: plaintext };
      }
      if (type === 'Encrypt') {
        fakeCalls.push({ command: 'Encrypt', KeyId: input.KeyId as string, region: this.region });
        const plain = input.Plaintext as Buffer;
        const blob = Buffer.concat([Buffer.from([0xab]), Buffer.from(crypto.getRandomValues(new Uint8Array(16))), plain]);
        // Direct-encrypt blobs also live in the dataKeyStore so the matching
        // Decrypt path round-trips. The "plaintext" returned by Decrypt for a
        // direct-encrypt blob is the original plaintext (not a data key).
        dataKeyStore.set(blob.toString('base64'), Buffer.from(plain));
        return { CiphertextBlob: blob };
      }
      throw new Error(`FakeKMS: unknown command ${type}`);
    }
  }

  class GenerateDataKeyCommand {
    __type = 'GenerateDataKey';
    constructor(public input: Record<string, unknown>) {}
  }
  class DecryptCommand {
    __type = 'Decrypt';
    constructor(public input: Record<string, unknown>) {}
  }
  class EncryptCommand {
    __type = 'Encrypt';
    constructor(public input: Record<string, unknown>) {}
  }

  return {
    KMSClient: FakeKMSClient,
    GenerateDataKeyCommand,
    DecryptCommand,
    EncryptCommand,
  };
});

// Imported AFTER vi.mock so the mock is in place.
const { KmsService, parseKmsRegion } = await import('./kms.js');

beforeEach(() => {
  fakeCalls.length = 0;
  dataKeyStore.clear();
  constructedRegions.length = 0;
});

describe('KmsService — envelope keyRef rotation safety', () => {
  it('decrypts an envelope written under key A using a KmsService configured with key B', async () => {
    // This is the regression test for the platform-key rotation footgun.
    // Before the fix, decrypt() passed `this.keyId` to KMS Decrypt, which AWS
    // rejects when it does not match the key actually used at encrypt time.
    // After the fix, Decrypt omits KeyId entirely and KMS derives it from
    // the ciphertext.

    const oldKms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'arn:aws:kms:eu-north-1:111:key/OLD' });
    const newKms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'arn:aws:kms:eu-north-1:111:key/NEW' });

    const { ciphertext, keyRef } = await oldKms.encrypt('hello world');
    expect(keyRef).toBe('arn:aws:kms:eu-north-1:111:key/OLD');

    const plaintext = await newKms.decrypt(ciphertext);
    expect(plaintext).toBe('hello world');

    const decryptCall = fakeCalls.find((c) => c.command === 'Decrypt');
    expect(decryptCall).toBeDefined();
    // The fix: Decrypt MUST NOT pin to the KmsService's configured keyId.
    expect(decryptCall?.KeyId).toBeUndefined();
  });

  it('preserves EncryptionContext through the rotation case', async () => {
    const oldKms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'OLD' });
    const newKms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'NEW' });

    const ctx = { operator_id: 'op_abc', provider: 'slack' };
    const { ciphertext } = await oldKms.encrypt('secret-token', ctx);

    const plaintext = await newKms.decrypt(ciphertext, ctx);
    expect(plaintext).toBe('secret-token');

    const decryptCall = fakeCalls.find((c) => c.command === 'Decrypt');
    expect(decryptCall?.EncryptionContext).toEqual(ctx);
  });

  it('decryptDirect also omits KeyId so direct-encrypt blobs survive rotation', async () => {
    const oldKms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'OLD' });
    const newKms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'NEW' });

    const blob = await oldKms.encryptDirect(Buffer.from('signing-key-material'));
    const recovered = await newKms.decryptDirect(blob);
    expect(recovered.toString('utf8')).toBe('signing-key-material');

    const decryptCall = fakeCalls.find((c) => c.command === 'Decrypt');
    expect(decryptCall?.KeyId).toBeUndefined();
  });

  it('encrypt still pins KeyId on GenerateDataKey (the encrypt path needs an explicit key)', async () => {
    const kms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'PLATFORM' });
    await kms.encrypt('payload');
    const gdkCall = fakeCalls.find((c) => c.command === 'GenerateDataKey');
    expect(gdkCall?.KeyId).toBe('PLATFORM');
  });

  it('context-bound envelope refuses to decrypt without expected context', async () => {
    const kms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'k' });
    const { ciphertext } = await kms.encrypt('secret', { operator_id: 'op_a' });
    await expect(kms.decrypt(ciphertext)).rejects.toThrow(/context-bound/);
  });

  it('context-bound envelope refuses to decrypt with mismatched context', async () => {
    const kms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'k' });
    const { ciphertext } = await kms.encrypt('secret', { operator_id: 'op_a' });
    await expect(kms.decrypt(ciphertext, { operator_id: 'op_b' })).rejects.toThrow(/does not match/);
  });
});

describe('KmsService — per-operator CMEK routing', () => {
  it('uses default key when status=none', async () => {
    const resolver = vi
      .fn<(operatorId: string) => Promise<{ keyArn: string | null; status: 'none' | 'active' | 'migrating' | 'revoking' | 'revoked' }>>()
      .mockResolvedValue({ keyArn: null, status: 'none' });
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM',
      resolveOperatorKey: resolver,
    });
    const { keyRef } = await kms.encrypt('p', { operator_id: 'op_a' });
    expect(keyRef).toBe('PLATFORM');
    expect(resolver).toHaveBeenCalledWith('op_a');
  });

  it('uses customer key when status=active', async () => {
    const resolver = vi.fn().mockResolvedValue({ keyArn: 'CUSTOMER_KEY', status: 'active' });
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM',
      resolveOperatorKey: resolver,
    });
    const { keyRef } = await kms.encrypt('p', { operator_id: 'op_a' });
    expect(keyRef).toBe('CUSTOMER_KEY');
  });

  it('uses customer key during migration (new writes go to customer key so backfill completes)', async () => {
    const resolver = vi.fn().mockResolvedValue({ keyArn: 'CUSTOMER_KEY', status: 'migrating' });
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM',
      resolveOperatorKey: resolver,
    });
    const { keyRef } = await kms.encrypt('p', { operator_id: 'op_a' });
    expect(keyRef).toBe('CUSTOMER_KEY');
  });

  it('uses default key during revoking (new writes go back to platform)', async () => {
    const resolver = vi.fn().mockResolvedValue({ keyArn: 'CUSTOMER_KEY', status: 'revoking' });
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM',
      resolveOperatorKey: resolver,
    });
    const { keyRef } = await kms.encrypt('p', { operator_id: 'op_a' });
    expect(keyRef).toBe('PLATFORM');
  });

  it('throws CmekRevokedError on encrypt when status=revoked', async () => {
    const resolver = vi.fn().mockResolvedValue({ keyArn: 'CUSTOMER_KEY', status: 'revoked' });
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM',
      resolveOperatorKey: resolver,
    });
    await expect(kms.encrypt('p', { operator_id: 'op_a' })).rejects.toMatchObject({
      code: 'CMEK_REVOKED',
      statusCode: 503,
    });
  });

  it('ignores resolver when context has no operator_id (system-scoped ciphertext stays under default)', async () => {
    const resolver = vi.fn();
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM',
      resolveOperatorKey: resolver,
    });
    const { keyRef } = await kms.encrypt('p');
    expect(keyRef).toBe('PLATFORM');
    expect(resolver).not.toHaveBeenCalled();
  });

  it('maps KMS AccessDeniedException on encrypt to CmekRevokedError when a customer key was selected', async () => {
    // Hijack the fake's send() for one call to simulate AccessDenied.
    const resolver = vi.fn().mockResolvedValue({ keyArn: 'CUSTOMER_KEY', status: 'active' });
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM',
      resolveOperatorKey: resolver,
    });

    // Patch the internal client.send to throw on next GenerateDataKey.
    // (Reach into the private via the JS escape hatch.)
    const sendOrig = (kms as unknown as { provider: { clients: Map<string, { send: unknown }> } }).provider.clients.get('eu-north-1')!.send;
    const sendSpy = vi.fn(async (cmd: { __type: string; input: Record<string, unknown> }) => {
      if (cmd.__type === 'GenerateDataKey') {
        const err = new Error('User not authorized to call kms:GenerateDataKey');
        (err as { name: string }).name = 'AccessDeniedException';
        throw err;
      }
      return (sendOrig as (c: unknown) => Promise<unknown>).call((kms as unknown as { provider: { clients: Map<string, object> } }).provider.clients.get('eu-north-1')!, cmd);
    });
    (kms as unknown as { provider: { clients: Map<string, { send: unknown }> } }).provider.clients.get('eu-north-1')!.send = sendSpy;

    await expect(kms.encrypt('p', { operator_id: 'op_a' })).rejects.toMatchObject({
      code: 'CMEK_REVOKED',
      statusCode: 503,
    });
  });

  it('maps KMS AccessDeniedException on decrypt to CmekRevokedError when the envelope is operator-bound', async () => {
    const kms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'PLATFORM' });
    const { ciphertext } = await kms.encrypt('secret', { operator_id: 'op_a' });

    // Hijack send() to throw AccessDenied on Decrypt.
    const sendSpy = vi.fn(async (cmd: { __type: string }) => {
      if (cmd.__type === 'Decrypt') {
        const err = new Error('AccessDenied on Decrypt');
        (err as { name: string }).name = 'AccessDeniedException';
        throw err;
      }
      throw new Error('unexpected command');
    });
    (kms as unknown as { provider: { clients: Map<string, { send: unknown }> } }).provider.clients.get('eu-north-1')!.send = sendSpy;

    await expect(kms.decrypt(ciphertext, { operator_id: 'op_a' })).rejects.toMatchObject({
      code: 'CMEK_REVOKED',
      statusCode: 503,
    });
  });
});

describe('KmsService — dogfood short-circuit', () => {
  it('routes op_stack_system to the platform key without calling the resolver', async () => {
    // If anything ever reaches kms.encrypt for op_stack_system bypassing
    // CmekService.enable + worker.tick, the resolver MUST NOT decide a
    // customer key here. Construction-time `stackSystemOperatorId` makes
    // the short-circuit a property of the resolver itself.
    const resolver = vi.fn(async () => {
      throw new Error('resolver must not be called for dogfood operator');
    });
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM',
      stackSystemOperatorId: 'op_stack_system',
      resolveOperatorKey: resolver,
    });
    const { keyRef } = await kms.encrypt('p', { operator_id: 'op_stack_system' });
    expect(keyRef).toBe('PLATFORM');
    expect(resolver).not.toHaveBeenCalled();
  });

  it('does not short-circuit non-dogfood operators when stackSystemOperatorId is set', async () => {
    const resolver = vi.fn().mockResolvedValue({ keyArn: 'CUSTOMER_KEY', status: 'active' });
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM',
      stackSystemOperatorId: 'op_stack_system',
      resolveOperatorKey: resolver,
    });
    const { keyRef } = await kms.encrypt('p', { operator_id: 'op_real_customer' });
    expect(keyRef).toBe('CUSTOMER_KEY');
    expect(resolver).toHaveBeenCalledWith('op_real_customer');
  });

  it('does not short-circuit anything when stackSystemOperatorId is unset', async () => {
    const resolver = vi.fn().mockResolvedValue({ keyArn: 'CUSTOMER_KEY', status: 'active' });
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM',
      // stackSystemOperatorId omitted
      resolveOperatorKey: resolver,
    });
    const { keyRef } = await kms.encrypt('p', { operator_id: 'op_stack_system' });
    expect(keyRef).toBe('CUSTOMER_KEY');
    expect(resolver).toHaveBeenCalledWith('op_stack_system');
  });
});

describe('KmsService — setOperatorKeyHandlers (cache eviction + telemetry)', () => {
  function buildAccessDeniedSpy(command: 'GenerateDataKey' | 'Decrypt' | 'Encrypt', fakeSendOrig: unknown) {
    return vi.fn(async (cmd: { __type: string; input: Record<string, unknown> }) => {
      if (cmd.__type === command) {
        const err = new Error(`AccessDenied on ${command}`);
        (err as { name: string }).name = 'AccessDeniedException';
        throw err;
      }
      return (fakeSendOrig as (c: unknown) => Promise<unknown>)(cmd);
    });
  }

  it('evicts cache before throwing CmekRevokedError on encrypt access-denied', async () => {
    const evict = vi.fn();
    const kms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'PLATFORM' });
    kms.setOperatorKeyHandlers({
      resolve: async () => ({ keyArn: 'CUSTOMER_KEY', status: 'active' }),
      evict,
    });

    const sendOrig = (kms as unknown as { provider: { clients: Map<string, { send: unknown }> } }).provider.clients.get('eu-north-1')!.send;
    const sendSpy = buildAccessDeniedSpy('GenerateDataKey', sendOrig);
    (kms as unknown as { provider: { clients: Map<string, { send: unknown }> } }).provider.clients.get('eu-north-1')!.send = sendSpy.bind(
      (kms as unknown as { provider: { clients: Map<string, object> } }).provider.clients.get('eu-north-1')!,
    );

    await expect(kms.encrypt('p', { operator_id: 'op_a' })).rejects.toMatchObject({
      code: 'CMEK_REVOKED',
    });
    expect(evict).toHaveBeenCalledWith('op_a');
    expect(evict).toHaveBeenCalledTimes(1);
  });

  it('evicts cache before throwing CmekRevokedError on decrypt access-denied', async () => {
    const evict = vi.fn();
    const kms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'PLATFORM' });
    kms.setOperatorKeyHandlers({
      resolve: async () => ({ keyArn: null, status: 'none' }),
      evict,
    });
    const { ciphertext } = await kms.encrypt('secret', { operator_id: 'op_a' });

    const sendSpy = vi.fn(async (cmd: { __type: string }) => {
      if (cmd.__type === 'Decrypt') {
        const err = new Error('AccessDenied on Decrypt');
        (err as { name: string }).name = 'AccessDeniedException';
        throw err;
      }
      throw new Error('unexpected command');
    });
    (kms as unknown as { provider: { clients: Map<string, { send: unknown }> } }).provider.clients.get('eu-north-1')!.send = sendSpy;

    await expect(kms.decrypt(ciphertext, { operator_id: 'op_a' })).rejects.toMatchObject({
      code: 'CMEK_REVOKED',
    });
    expect(evict).toHaveBeenCalledWith('op_a');
  });

  it('evicts cache before throwing CmekRevokedError on encryptDirect access-denied', async () => {
    const evict = vi.fn();
    const kms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'PLATFORM' });
    kms.setOperatorKeyHandlers({
      resolve: async () => ({ keyArn: 'CUSTOMER_KEY', status: 'active' }),
      evict,
    });

    const sendSpy = vi.fn(async (cmd: { __type: string }) => {
      if (cmd.__type === 'Encrypt') {
        const err = new Error('AccessDenied on Encrypt');
        (err as { name: string }).name = 'AccessDeniedException';
        throw err;
      }
      throw new Error('unexpected command');
    });
    (kms as unknown as { provider: { clients: Map<string, { send: unknown }> } }).provider.clients.get('eu-north-1')!.send = sendSpy;

    await expect(
      kms.encryptDirect(Buffer.from('material'), { operatorId: 'op_a' }),
    ).rejects.toMatchObject({ code: 'CMEK_REVOKED' });
    expect(evict).toHaveBeenCalledWith('op_a');
  });

  it('fires onLegacyFallback when decryptDirect succeeds via the no-context retry', async () => {
    const onLegacyFallback = vi.fn();
    const kms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'PLATFORM' });
    kms.setOperatorKeyHandlers({
      resolve: async () => ({ keyArn: null, status: 'none' }),
      onLegacyFallback,
    });

    // Encrypt a legacy-shape direct blob (no context) using the real path.
    const legacyBlob = await kms.encryptDirect(Buffer.from('legacy-material'));

    // Make the first Decrypt (with context) throw InvalidCiphertextException;
    // the second Decrypt (without context) should succeed via the real fake.
    const sendOrig = (kms as unknown as { provider: { clients: Map<string, { send: unknown }> } }).provider.clients.get('eu-north-1')!.send;
    let decryptCallNo = 0;
    const sendSpy = vi.fn(async (cmd: { __type: string; input: Record<string, unknown> }) => {
      if (cmd.__type === 'Decrypt') {
        decryptCallNo += 1;
        if (decryptCallNo === 1) {
          const err = new Error('AAD mismatch');
          (err as { name: string }).name = 'InvalidCiphertextException';
          throw err;
        }
      }
      return (sendOrig as (c: unknown) => Promise<unknown>).call(
        (kms as unknown as { provider: { clients: Map<string, object> } }).provider.clients.get('eu-north-1')!,
        cmd,
      );
    });
    (kms as unknown as { provider: { clients: Map<string, { send: unknown }> } }).provider.clients.get('eu-north-1')!.send = sendSpy;

    const recovered = await kms.decryptDirect(legacyBlob, {
      operatorId: 'op_a',
      expectedContext: { operator_id: 'op_a', column: 'input' },
    });
    expect(recovered.toString('utf8')).toBe('legacy-material');

    expect(onLegacyFallback).toHaveBeenCalledTimes(1);
    expect(onLegacyFallback).toHaveBeenCalledWith({
      operatorId: 'op_a',
      hasExpectedContext: true,
    });
  });

  it('does not fire onLegacyFallback on first-try success', async () => {
    const onLegacyFallback = vi.fn();
    const kms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'PLATFORM' });
    kms.setOperatorKeyHandlers({
      resolve: async () => ({ keyArn: null, status: 'none' }),
      onLegacyFallback,
    });

    // The fake KMS doesn't enforce EncryptionContext, so the first try
    // succeeds regardless of context shape. This asserts we don't emit
    // the breadcrumb on the hot path — only when the fallback runs.
    const blob = await kms.encryptDirect(Buffer.from('post-3.5'), {
      operatorId: 'op_a',
      context: { operator_id: 'op_a' },
    });
    const recovered = await kms.decryptDirect(blob, {
      operatorId: 'op_a',
      expectedContext: { operator_id: 'op_a' },
    });
    expect(recovered.toString('utf8')).toBe('post-3.5');
    expect(onLegacyFallback).not.toHaveBeenCalled();
  });
});

describe('KmsService — smokeTestCustomerKey', () => {
  it('succeeds when GenerateDataKey + Decrypt round-trip works', async () => {
    const kms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'PLATFORM' });
    await expect(kms.smokeTestCustomerKey('CUSTOMER_KEY', 'op_a')).resolves.toBeUndefined();
  });

  it('throws CmekRevokedError on AccessDenied', async () => {
    const kms = new KmsService({ region: 'eu-north-1', defaultKeyId: 'PLATFORM' });
    const sendSpy = vi.fn(async () => {
      const err = new Error('denied');
      (err as { name: string }).name = 'AccessDeniedException';
      throw err;
    });
    (kms as unknown as { provider: { clients: Map<string, { send: unknown }> } }).provider.clients.get('eu-north-1')!.send = sendSpy;

    await expect(kms.smokeTestCustomerKey('CUSTOMER_KEY', 'op_a')).rejects.toMatchObject({
      code: 'CMEK_REVOKED',
    });
  });
});

describe('parseKmsRegion', () => {
  it('parses region from a full key ARN', () => {
    expect(parseKmsRegion('arn:aws:kms:us-east-1:123456789012:key/abcd-1234')).toBe('us-east-1');
  });

  it('parses region from an alias ARN', () => {
    expect(parseKmsRegion('arn:aws:kms:eu-north-1:123456789012:alias/stack-test')).toBe('eu-north-1');
  });

  it('lower-cases mixed-case regions', () => {
    expect(parseKmsRegion('arn:aws:kms:EU-NORTH-1:111:key/x')).toBe('eu-north-1');
  });

  it('returns null for a bare UUID', () => {
    expect(parseKmsRegion('1234abcd-12ab-34cd-56ef-1234567890ab')).toBeNull();
  });

  it('returns null for a placeholder string', () => {
    expect(parseKmsRegion('PLATFORM')).toBeNull();
  });

  it('returns null for an empty string', () => {
    expect(parseKmsRegion('')).toBeNull();
  });

  it('returns null for a malformed ARN', () => {
    expect(parseKmsRegion('arn:aws:s3:::my-bucket')).toBeNull();
    expect(parseKmsRegion('arn:aws:kms:')).toBeNull();
  });
});

describe('KmsService — per-region client routing (Path B / chunk 8)', () => {
  it('routes GenerateDataKey to the region embedded in the resolved key ARN', async () => {
    const resolver = vi.fn().mockResolvedValue({
      keyArn: 'arn:aws:kms:us-east-1:123456789012:key/aaa-bbb',
      status: 'active',
    });
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM_UUID',
      resolveOperatorKey: resolver,
    });
    await kms.encrypt('secret', { operator_id: 'op_a' });

    const gdkCall = fakeCalls.find((c) => c.command === 'GenerateDataKey');
    expect(gdkCall?.region).toBe('us-east-1');
  });

  it('falls back to default region when the key id is a bare UUID', async () => {
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: '1234abcd-12ab-34cd-56ef-1234567890ab',
    });
    await kms.encrypt('secret');

    const gdkCall = fakeCalls.find((c) => c.command === 'GenerateDataKey');
    expect(gdkCall?.region).toBe('eu-north-1');
  });

  it('embeds keyRef in the envelope when the resolved key is a full ARN', async () => {
    const resolver = vi.fn().mockResolvedValue({
      keyArn: 'arn:aws:kms:us-east-1:123456789012:key/aaa',
      status: 'active',
    });
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM_UUID',
      resolveOperatorKey: resolver,
    });
    const { ciphertext } = await kms.encrypt('secret', { operator_id: 'op_a' });
    const envelope = JSON.parse(Buffer.from(ciphertext, 'base64').toString('utf8'));
    expect(envelope.keyRef).toBe('arn:aws:kms:us-east-1:123456789012:key/aaa');
  });

  it('omits keyRef in the envelope when the resolved key is a bare UUID', async () => {
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: '1234abcd-12ab-34cd-56ef-1234567890ab',
    });
    const { ciphertext } = await kms.encrypt('secret');
    const envelope = JSON.parse(Buffer.from(ciphertext, 'base64').toString('utf8'));
    expect(envelope.keyRef).toBeUndefined();
  });

  it('routes Decrypt to the envelope keyRef region — proves cross-region round-trip', async () => {
    const resolver = vi.fn().mockResolvedValue({
      keyArn: 'arn:aws:kms:us-east-1:123456789012:key/aaa',
      status: 'active',
    });
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM_UUID',
      resolveOperatorKey: resolver,
    });
    const { ciphertext } = await kms.encrypt('secret', { operator_id: 'op_a' });
    const plaintext = await kms.decrypt(ciphertext, { operator_id: 'op_a' });
    expect(plaintext).toBe('secret');

    const decryptCall = fakeCalls.find((c) => c.command === 'Decrypt');
    expect(decryptCall?.region).toBe('us-east-1');
  });

  it('routes Decrypt to default region for legacy envelopes without keyRef', async () => {
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM_UUID',
    });
    // Encrypt with no resolver + bare-UUID key → no keyRef in envelope.
    const { ciphertext } = await kms.encrypt('secret');
    fakeCalls.length = 0;
    await kms.decrypt(ciphertext);

    const decryptCall = fakeCalls.find((c) => c.command === 'Decrypt');
    expect(decryptCall?.region).toBe('eu-north-1');
  });

  it('caches per-region clients — repeated calls to the same region reuse one client', async () => {
    const resolver = vi.fn().mockResolvedValue({
      keyArn: 'arn:aws:kms:us-east-1:123456789012:key/aaa',
      status: 'active',
    });
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM_UUID',
      resolveOperatorKey: resolver,
    });
    await kms.encrypt('s1', { operator_id: 'op_a' });
    await kms.encrypt('s2', { operator_id: 'op_a' });
    await kms.encrypt('s3', { operator_id: 'op_a' });

    // One default-region client (from the constructor) plus one us-east-1
    // client (lazy on first encrypt). Three encrypts must not construct
    // three clients.
    expect(constructedRegions).toEqual(['eu-north-1', 'us-east-1']);
  });

  it('constructs separate clients for different regions', async () => {
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM_UUID',
    });
    // Two smoke-tests against two different regions — each gets its own client.
    await kms.smokeTestCustomerKey('arn:aws:kms:us-east-1:111:key/a', 'op_a');
    await kms.smokeTestCustomerKey('arn:aws:kms:ap-south-1:222:key/b', 'op_b');

    expect(constructedRegions).toEqual(['eu-north-1', 'us-east-1', 'ap-south-1']);
  });

  it('routes smokeTestCustomerKey to the ARN region (both GenerateDataKey + Decrypt)', async () => {
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM_UUID',
    });
    await kms.smokeTestCustomerKey('arn:aws:kms:us-east-1:123456789012:key/aaa', 'op_a');

    const gdkCall = fakeCalls.find((c) => c.command === 'GenerateDataKey');
    const decryptCall = fakeCalls.find((c) => c.command === 'Decrypt');
    expect(gdkCall?.region).toBe('us-east-1');
    expect(decryptCall?.region).toBe('us-east-1');
  });
});

describe('KmsService — direct-encrypt wrapper (Path B / chunk 8)', () => {
  it('wraps direct-encrypt bytes when the resolved key is a full ARN', async () => {
    const resolver = vi.fn().mockResolvedValue({
      keyArn: 'arn:aws:kms:us-east-1:123456789012:key/aaa',
      status: 'active',
    });
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM_UUID',
      resolveOperatorKey: resolver,
    });
    const blob = await kms.encryptDirect(Buffer.from('signing-material'), {
      operatorId: 'op_a',
      context: { operator_id: 'op_a' },
    });
    // Magic prefix is 0xDC 0xCE 0x4B 0x4D
    expect(blob[0]).toBe(0xdc);
    expect(blob[1]).toBe(0xce);
    expect(blob[2]).toBe(0x4b);
    expect(blob[3]).toBe(0x4d);
  });

  it('does NOT wrap direct-encrypt bytes when the key is a bare UUID — legacy shape preserved', async () => {
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: '1234abcd-12ab-34cd-56ef-1234567890ab',
    });
    const blob = await kms.encryptDirect(Buffer.from('material'));
    // Fake KMS direct-encrypt prefix is 0xab — not the wrapper magic.
    expect(blob[0]).toBe(0xab);
  });

  it('round-trips wrapped direct-encrypt across regions', async () => {
    const resolver = vi.fn().mockResolvedValue({
      keyArn: 'arn:aws:kms:us-east-1:123456789012:key/aaa',
      status: 'active',
    });
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: 'PLATFORM_UUID',
      resolveOperatorKey: resolver,
    });
    const blob = await kms.encryptDirect(Buffer.from('cross-region-payload'), {
      operatorId: 'op_a',
      context: { operator_id: 'op_a' },
    });
    fakeCalls.length = 0;
    const recovered = await kms.decryptDirect(blob, {
      operatorId: 'op_a',
      expectedContext: { operator_id: 'op_a' },
    });
    expect(recovered.toString('utf8')).toBe('cross-region-payload');

    const decryptCall = fakeCalls.find((c) => c.command === 'Decrypt');
    expect(decryptCall?.region).toBe('us-east-1');
  });

  it('decryptDirect routes legacy raw bytes to the default region', async () => {
    const kms = new KmsService({
      region: 'eu-north-1',
      defaultKeyId: '1234abcd-12ab-34cd-56ef-1234567890ab',
    });
    const blob = await kms.encryptDirect(Buffer.from('legacy-material'));
    fakeCalls.length = 0;
    const recovered = await kms.decryptDirect(blob);
    expect(recovered.toString('utf8')).toBe('legacy-material');

    const decryptCall = fakeCalls.find((c) => c.command === 'Decrypt');
    expect(decryptCall?.region).toBe('eu-north-1');
  });
});
