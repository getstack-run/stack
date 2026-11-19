#!/usr/bin/env node
// Type-checks the reference tests that need a deployment's own layer, when there are
// any. Without them there is nothing to check and the script succeeds, so a
// repository that holds only the open parts still passes.

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
if (!existsSync(join(root, 'reference', 'hosted'))) {
  console.log('no hosted reference tests here; nothing to type-check');
  process.exit(0);
}
const run = spawnSync('pnpm', ['exec', 'tsc', '--noEmit', '-p', 'reference/tsconfig.json'], { cwd: root, stdio: 'inherit', shell: process.platform === 'win32' });
process.exit(run.status ?? 1);
