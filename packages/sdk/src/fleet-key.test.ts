import { afterAll, describe, expect, it, vi } from 'vitest';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPublicKey, verify } from 'node:crypto';
import { prepareFleetEnrollmentKey } from './agent-auth.js';

const holder = vi.hoisted(() => ({ home: '' }));
vi.mock('node:os', async original => ({ ...await original<object>(), homedir: () => holder.home }));

describe('fleet local key custody', () => {
  afterAll(async () => { if (holder.home) await rm(holder.home, { recursive: true, force: true }); });
  it('reuses a private key for concurrent retry and signs enrollment proof locally', async () => {
    holder.home = await mkdtemp(join(tmpdir(), 'stack-fleet-key-'));
    const keys = await Promise.all(Array.from({ length: 8 }, () => prepareFleetEnrollmentKey('flp_fixture', 'worker-123')));
    expect(keys.every(key => key.publicKey.x === keys[0]!.publicKey.x)).toBe(true);
    const key = keys[0]!;
    const proof = key.sign('synthetic-challenge');
    expect(verify(null, Buffer.from('synthetic-challenge'), createPublicKey({ key: key.publicKey, format: 'jwk' }), Buffer.from(proof, 'base64url'))).toBe(true);
    expect(JSON.stringify(key.publicKey)).not.toContain('"d"');
    await key.persist('agt_fixture');
    const saved = JSON.parse(await readFile(join(holder.home, '.stack/agents/agt_fixture.json'), 'utf8'));
    expect(saved.publicKey.x).toBe(key.publicKey.x);
    expect(saved.privateKey.d).toBeTypeOf('string');
    expect((await readdir(join(holder.home, '.stack/agents'))).some(path => path.endsWith('.tmp'))).toBe(false);
    await expect(key.persist('../escape')).rejects.toThrow('Invalid input');
  });
});
