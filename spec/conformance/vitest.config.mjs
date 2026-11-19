import { defineConfig } from 'vitest/config';

// The reference implementations of this repository run the conformance suites
// here, in CI.
export default defineConfig({
  test: {
    include: ['reference/**/*.test.{mjs,ts}'],
    exclude: ['**/node_modules/**', '**/dist/**'],
    testTimeout: 30_000,
    passWithNoTests: true,
  },
});
