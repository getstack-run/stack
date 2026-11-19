import { describe, expect, it } from 'vitest';
import { AuditArchiveService, ArchiveErasureError } from './audit-archive-service.js';

class Store {
  readonly description = 'erasure test store';
  readonly durable = true;
  readonly objects = new Set<string>();
  /** Keys that survive a delete: a store that did not do what it was told. */
  stubborn = new Set<string>();

  async put(key: string): Promise<void> {
    this.objects.add(key);
  }
  async check(): Promise<void> {}
  async get(): Promise<Buffer | null> {
    return null;
  }
  async exists(key: string): Promise<boolean> {
    return this.objects.has(key);
  }
  async list(prefix: string): Promise<{ keys: string[] }> {
    return { keys: [...this.objects].filter((key) => key.startsWith(prefix)).sort() };
  }
  async delete(key: string): Promise<void> {
    if (!this.stubborn.has(key)) this.objects.delete(key);
  }
}

const tx = { delete: () => ({ where: async () => undefined }) } as never;

function archive(store: Store, extraErasePrefixes?: ConstructorParameters<typeof AuditArchiveService>[0]['extraErasePrefixes']) {
  return new AuditArchiveService({ db: {} as never, store, ...(extraErasePrefixes ? { extraErasePrefixes } : {}) });
}

describe('erasing an operator from the archive store', () => {
  it('deletes the audit segments and, with nothing registered, nothing else', async () => {
    const store = new Store();
    await store.put('audit/op_a/2026-01-01.gz');
    await store.put('audit/op_b/2026-01-01.gz');
    await store.put('drive/op_a/file_1');
    await archive(store).eraseOperatorArchive('op_a', tx);
    expect([...store.objects].sort()).toEqual(['audit/op_b/2026-01-01.gz', 'drive/op_a/file_1']);
  });

  it('deletes and verifies every prefix a deployment registered, for that operator only', async () => {
    const store = new Store();
    for (const key of ['audit/op_a/1.gz', 'drive/op_a/f1', 'drive/op_a/f2', 'drive/op_b/f1', 'audit/op_b/1.gz']) await store.put(key);
    await archive(store, [(operatorId) => [`drive/${operatorId}/`]]).eraseOperatorArchive('op_a', tx);
    expect([...store.objects].sort()).toEqual(['audit/op_b/1.gz', 'drive/op_b/f1']);
  });

  it('fails closed when a registered prefix still lists something after the delete', async () => {
    const store = new Store();
    await store.put('drive/op_a/f1');
    store.stubborn.add('drive/op_a/f1');
    await expect(archive(store, [(operatorId) => [`drive/${operatorId}/`]]).eraseOperatorArchive('op_a', tx))
      .rejects.toMatchObject({ code: 'archive_verify_failed' } satisfies Partial<ArchiveErasureError>);
  });
});
