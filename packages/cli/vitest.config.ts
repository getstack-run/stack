import { defineConfig } from 'vitest/config';

// Matches packages/sdk/vitest.config.ts. Vitest 4 no longer excludes dist/
// from test discovery, so exclude it explicitly (the build tsconfig also
// excludes *.test.ts from dist, but this keeps discovery clean regardless).
// passWithNoTests keeps the package green under `turbo run test` before more
// tests land.
export default defineConfig({
  test: {
    exclude: ['**/node_modules/**', '**/dist/**'],
    passWithNoTests: true,
  },
});
