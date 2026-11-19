import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

// Vitest 4 no longer excludes dist/ from test discovery (vitest 3 did). Without
// this, every compiled dist/**/*.test.js runs alongside its src/**/*.test.ts —
// doubling the suite and executing stale compiled copies. passWithNoTests keeps
// packages with no tests yet green under `turbo run test`.
//
// `@stack/shared` is private and is not a dependency of the published SDK (it is
// a development dependency, for these tests only). The wire-contract test imports
// it to check request bodies against the API's own schemas, so it resolves to the
// workspace source here instead of through package.json. Nothing under src/
// outside *.test.ts and src/test-support may import it. The hosted product's own
// schemas are read by the tests of those schemas, by path.
const schemas = fileURLToPath(new URL('../shared/src/schemas/index.ts', import.meta.url));
export default defineConfig({
  resolve: {
    alias: [{ find: '@stack/shared', replacement: schemas }],
  },
  test: {
    exclude: ['**/node_modules/**', '**/dist/**'],
    passWithNoTests: true,
  },
});
