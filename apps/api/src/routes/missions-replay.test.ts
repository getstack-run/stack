import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const source = readFileSync(fileURLToPath(new URL('./missions.ts', import.meta.url)), 'utf8');
const replayRoute = source.slice(
  source.indexOf("'/v1/missions/:id/replay'"),
  source.indexOf("'/v1/missions/:id/dossiers'"),
);

describe('mission activity metering', () => {
  it('does not meter the activity read', () => {
    expect(replayRoute).not.toMatch(/\bmeterAction\s*\(/);
    expect(replayRoute).not.toMatch(/wallet\./);
  });
});
