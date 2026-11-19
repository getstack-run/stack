import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { CmekRevokedError } from '@stack/shared';
import { KmsService } from './kms.js';
import {
  LocalKeyProvider,
  loadLocalKeys,
  parseKeyEncryptionKey,
  parseKeyList,
} from './local-key-provider.js';

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function tempFile(content: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'stack-kek-'));
  dirs.push(dir);
  const file = join(dir, 'kek');
  writeFileSync(file, content, { mode: 0o600 });
  return file;
}

function newKey(): Buffer {
  return randomBytes(32);
}

function localKms(keys: Buffer[] = [newKey()]): KmsService {
  return new KmsService({ provider: new LocalKeyProvider(keys), defaultKeyId: 'local' });
}

describe('local key provider under KmsService', () => {
  it('round-trips an envelope and binds the context into it', async () => {
    const kms = localKms();
    const ctx = { operator_id: 'op_a', provider: 'slack' };
    const { ciphertext } = await kms.encrypt('xoxb-secret', ctx);
    expect(ciphertext).not.toContain('xoxb-secret');
    await expect(kms.decrypt(ciphertext, ctx)).resolves.toBe('xoxb-secret');
    // A ciphertext moved to another row (different context) refuses to open.
    await expect(kms.decrypt(ciphertext, { operator_id: 'op_b', provider: 'slack' })).rejects.toThrow(
      /does not match/,
    );
  });

  it('refuses an envelope whose data key was re-bound to another context', async () => {
    const kms = localKms();
    const { ciphertext } = await kms.encrypt('secret', { operator_id: 'op_a', provider: 'slack' });
    const envelope = JSON.parse(Buffer.from(ciphertext, 'base64').toString('utf8')) as {
      ctx: Record<string, string>;
    };
    envelope.ctx['operator_id'] = 'op_b';
    const forged = Buffer.from(JSON.stringify(envelope)).toString('base64');
    await expect(kms.decrypt(forged, { operator_id: 'op_b', provider: 'slack' })).rejects.toThrow();
  });

  it('round-trips a direct wrap with and without a context', async () => {
    const kms = localKms();
    const secret = Buffer.from('-----BEGIN PRIVATE KEY-----');
    const ctx = { operator_id: 'op_x', purpose: 'passport_signing' };
    const wrapped = await kms.encryptDirect(secret, { context: ctx });
    expect(wrapped.equals(secret)).toBe(false);
    expect((await kms.decryptDirect(wrapped, { expectedContext: ctx })).equals(secret)).toBe(true);
    await expect(
      kms.decryptDirect(wrapped, { expectedContext: { operator_id: 'op_y', purpose: 'passport_signing' } }),
    ).rejects.toThrow();
    const plain = await kms.encryptDirect(secret);
    expect((await kms.decryptDirect(plain)).equals(secret)).toBe(true);
  });

  it('redeems a legacy direct wrap made without a context when the caller expects one', async () => {
    const kms = localKms();
    const legacy = await kms.encryptDirect(Buffer.from('old'));
    const seen: unknown[] = [];
    kms.setOperatorKeyHandlers({
      resolve: async () => ({ keyArn: null, status: 'none' }),
      onLegacyFallback: (info) => seen.push(info),
    });
    const out = await kms.decryptDirect(legacy, { expectedContext: { operator_id: 'op_a' } });
    expect(out.toString()).toBe('old');
    expect(seen).toHaveLength(1);
  });

  it('opens what an older key wrapped after a rotation, and wraps new data under the new key', async () => {
    const oldKey = newKey();
    const newer = newKey();
    const before = localKms([oldKey]);
    const { ciphertext } = await before.encrypt('kept', { operator_id: 'op_a' });
    const rotated = localKms([newer, oldKey]);
    await expect(rotated.decrypt(ciphertext, { operator_id: 'op_a' })).resolves.toBe('kept');
    const { ciphertext: fresh } = await rotated.encrypt('new', { operator_id: 'op_a' });
    // Once the old key is dropped, the old data is unreadable and the new data is not.
    const dropped = localKms([newer]);
    await expect(dropped.decrypt(fresh, { operator_id: 'op_a' })).resolves.toBe('new');
    await expect(dropped.decrypt(ciphertext, { operator_id: 'op_a' })).rejects.toThrow();
  });

  it('cannot open a ciphertext with a different key', async () => {
    const a = localKms();
    const b = localKms();
    const { ciphertext } = await a.encrypt('secret', { operator_id: 'op_a' });
    await expect(b.decrypt(ciphertext, { operator_id: 'op_a' })).rejects.toThrow();
  });

  it('does not support customer-managed keys and says so before touching anything', async () => {
    const kms = localKms();
    expect(kms.supportsCustomerKeys).toBe(false);
    expect(kms.providerKind).toBe('local');
    await expect(kms.smokeTestCustomerKey('arn:aws:kms:eu-north-1:111111111111:key/x', 'op_a')).rejects.not.toBeInstanceOf(
      CmekRevokedError,
    );
  });

  it('never stores a routing reference, so the envelope has no key reference', async () => {
    const kms = localKms();
    const { ciphertext } = await kms.encrypt('s', { operator_id: 'op_a' });
    const envelope = JSON.parse(Buffer.from(ciphertext, 'base64').toString('utf8')) as Record<string, unknown>;
    expect(envelope['keyRef']).toBeUndefined();
  });
});

describe('key-encryption key parsing', () => {
  it('accepts 32 bytes as hex or base64 and refuses everything else', () => {
    const key = newKey();
    expect(parseKeyEncryptionKey(key.toString('hex')).equals(key)).toBe(true);
    expect(parseKeyEncryptionKey(key.toString('base64')).equals(key)).toBe(true);
    expect(() => parseKeyEncryptionKey('too-short')).toThrow(/32 bytes/);
    expect(() => parseKeyEncryptionKey(randomBytes(16).toString('hex'))).toThrow(/32 bytes/);
    expect(() => parseKeyEncryptionKey('00'.repeat(32))).toThrow(/not random/);
  });

  it('reads several keys, skips comments, and refuses a duplicate', () => {
    const [a, b] = [newKey(), newKey()];
    const text = `# active\n${a.toString('hex')}\n\n${b.toString('base64')} # previous\n`;
    const keys = parseKeyList(text);
    expect(keys).toHaveLength(2);
    expect(keys[0]!.equals(a)).toBe(true);
    expect(() => parseKeyList(`${a.toString('hex')}\n${a.toString('hex')}`)).toThrow(/twice/);
    expect(() => parseKeyList('# nothing here')).toThrow(/No key/);
  });

  it('loads from a file, from a value, and refuses both or neither', () => {
    const key = newKey();
    const file = tempFile(`${key.toString('hex')}\n`);
    expect(loadLocalKeys({ file })[0]!.equals(key)).toBe(true);
    expect(loadLocalKeys({ inline: key.toString('base64') })[0]!.equals(key)).toBe(true);
    expect(() => loadLocalKeys({ file, inline: key.toString('hex') })).toThrow(/not both/);
    expect(() => loadLocalKeys({})).toThrow(/required/);
    expect(() => loadLocalKeys({ file: join(tmpdir(), 'stack-kek-does-not-exist') })).toThrow(/cannot be read/);
  });

  it('does not put the key in an error', () => {
    const secret = 'ab'.repeat(31); // 62 hex chars: wrong length
    try {
      parseKeyEncryptionKey(secret);
      expect.unreachable();
    } catch (err) {
      expect(String(err)).not.toContain(secret);
    }
  });
});
