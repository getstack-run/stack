import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const source = readFileSync(fileURLToPath(new URL('./evidence-packs.ts', import.meta.url)), 'utf8');

describe('Signed record metering', () => {
  it('does not meter creation, reads, or downloads', () => {
    expect(source).not.toMatch(/\bmeterAction\s*\(/);
    expect(source).not.toMatch(/wallet\./);
  });

  it('keeps the export audit event', () => {
    expect(source).toContain("action: 'evidence_pack.export'");
    expect(source).toContain("outcome: 'success'");
  });
});
