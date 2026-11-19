import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

describe('offline activity source', () => {
  it('matches the shared canonical reconstruction source byte for byte', () => {
    const canonical = readFileSync(fileURLToPath(
      new URL('../../shared/src/utils/reconstruct-timeline.ts', import.meta.url),
    ), 'utf8');
    const verifier = readFileSync(fileURLToPath(new URL('./activity.ts', import.meta.url)), 'utf8');
    expect(verifier).toBe(canonical);
  });
});
