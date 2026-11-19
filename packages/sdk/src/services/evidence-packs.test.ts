import { describe, expect, it, vi } from 'vitest';
import { EvidencePacksService } from './evidence-packs.js';

describe('EvidencePacksService.download', () => {
  it('returns the exact bytes from the immutable download route', async () => {
    const expected = new Uint8Array([0x7b, 0x7d, 0x0a]);
    const getBytes = vi.fn(async () => expected);
    const service = new EvidencePacksService({ getBytes } as never);

    const actual = await service.download('pck_exact/value');

    expect(actual).toBe(expected);
    expect(getBytes).toHaveBeenCalledWith(
      '/v1/evidence-packs/pck_exact%2Fvalue/download',
    );
  });
});
