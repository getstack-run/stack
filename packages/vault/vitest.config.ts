import { defineConfig } from 'vitest/config';

// Vitest 4 no longer excludes dist/ from test discovery (vitest 3 did). Without
// this, every compiled dist/**/*.test.js runs alongside its src/**/*.test.ts —
// doubling the suite and executing stale compiled copies. passWithNoTests keeps
// packages with no tests yet green under `turbo run test`.
const BASE_EXCLUDE = ['**/node_modules/**', '**/dist/**'];

// *.postgres.test.ts files share one dedicated test database and some of them
// share tables with work that claims rows globally (the billing attribution outbox's
// deliverNext takes any due row, as the production worker does). They run one
// file at a time; every other file keeps full file parallelism. Vitest 4 runs
// the single-worker project as its own group after the parallel one.
const SHARED_DATABASE_TESTS = 'src/**/*.postgres.test.ts';

// These suites build real rows and erase whole operators against one shared database; on a busy machine that outlasts
// vitest's 5 s test and 10 s hook defaults. Only the postgres project gets the longer limits, so a unit test that
// hangs still fails in 5 s.
const POSTGRES_TIMEOUT_MS = 60_000;

//
// globalSetup refuses to start a run when the built @stack/shared the vault tests
// import is older than its source (see vitest.global-setup.ts).
export default defineConfig({
  test: {
    globalSetup: ['./vitest.global-setup.ts'],
    exclude: BASE_EXCLUDE,
    passWithNoTests: true,
    projects: [
      {
        extends: true,
        test: {
          name: 'unit',
          exclude: [...BASE_EXCLUDE, SHARED_DATABASE_TESTS],
        },
      },
      {
        extends: true,
        test: {
          name: 'postgres',
          include: [SHARED_DATABASE_TESTS],
          exclude: BASE_EXCLUDE,
          fileParallelism: false,
          testTimeout: POSTGRES_TIMEOUT_MS,
          hookTimeout: POSTGRES_TIMEOUT_MS,
        },
      },
    ],
  },
});
