import { defineConfig } from 'vitest/config';

// Vitest 4 no longer excludes dist/ from test discovery (vitest 3 did). Without
// this, every compiled dist/**/*.test.js runs alongside its src/**/*.test.ts —
// doubling the suite and executing stale compiled copies. passWithNoTests keeps
// packages with no tests yet green under `turbo run test`.
export default defineConfig({
  test: {
    exclude: ['**/node_modules/**', '**/dist/**'],
    passWithNoTests: true,
  },
});
