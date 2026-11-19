import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const canonicalPath = fileURLToPath(
  new URL('../../shared/src/utils/reconstruct-timeline.ts', import.meta.url),
);
const verifierPath = fileURLToPath(new URL('../src/activity.ts', import.meta.url));
const canonical = readFileSync(canonicalPath, 'utf8');
const verifier = readFileSync(verifierPath, 'utf8');

if (process.argv.includes('--write')) {
  writeFileSync(verifierPath, canonical, 'utf8');
  process.stdout.write('Synced verifier activity source.\n');
} else if (canonical !== verifier) {
  process.stderr.write(
    'Verifier activity source differs from the shared canonical source. ' +
    'Run pnpm run activity:sync in packages/verifier.\n',
  );
  process.exitCode = 1;
} else {
  process.stdout.write('Verifier activity source matches the shared canonical source.\n');
}
