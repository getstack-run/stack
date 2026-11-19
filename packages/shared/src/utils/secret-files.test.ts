import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { loadSecretFiles } from './secret-files.js';

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function secretFile(content: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'stack-secret-'));
  dirs.push(dir);
  const file = join(dir, 'secret');
  writeFileSync(file, content);
  return file;
}

describe('loadSecretFiles', () => {
  it('fills a setting from its file and drops the trailing newline', () => {
    const env: Record<string, string | undefined> = { API_KEY_PEPPER_FILE: secretFile('abc123\n') };
    expect(loadSecretFiles(env)).toEqual(['API_KEY_PEPPER']);
    expect(env['API_KEY_PEPPER']).toBe('abc123');
  });

  it('leaves everything else alone, including names it does not know', () => {
    const env: Record<string, string | undefined> = {
      NODE_OPTIONS_FILE: secretFile('--inspect'),
      SOMETHING_ELSE_FILE: secretFile('x'),
      API_KEY_PEPPER: 'already',
    };
    expect(loadSecretFiles(env)).toEqual([]);
    expect(env['NODE_OPTIONS']).toBeUndefined();
    expect(env['API_KEY_PEPPER']).toBe('already');
  });

  it('refuses a setting given as a value and as a file', () => {
    expect(() => loadSecretFiles({ API_KEY_PEPPER: 'x', API_KEY_PEPPER_FILE: secretFile('y') })).toThrow(/not both/);
  });

  it('names the setting, not the path or the content, when a file cannot be read', () => {
    try {
      loadSecretFiles({ DATABASE_URL_FILE: join(tmpdir(), 'stack-secret-missing-file') });
      expect.unreachable();
    } catch (err) {
      expect((err as Error).message).toBe('[BOOT] DATABASE_URL_FILE cannot be read');
    }
  });
});
