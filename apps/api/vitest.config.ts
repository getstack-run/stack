import { defineConfig } from 'vitest/config';

// Vitest 4 no longer excludes dist/ from test discovery (vitest 3 did). Without
// this, every compiled dist/**/*.test.js runs alongside its src/**/*.test.ts —
// doubling the suite. passWithNoTests keeps test-less packages green.
//
// NODE_ENV=development: workload.test.ts boots full services via
// createServices(), which throws unless isDev or a signing key is set. Vitest
// otherwise forces NODE_ENV=test (isDev=false). Setting it here (applied before
// the import-time env snapshot) lets the integration suite boot with an
// ephemeral dev signing key + dev KMS mock, matching local dev.
//
// globalSetup refuses to start a run when a built workspace package (shared,
// vault, ...) was not built from its current source (a content hash, see
// tooling/build-stamp.mjs): the API tests import them from dist/,
// and a stale build tests the old code without saying so.
//
// The account end-to-end mode (`test:agent-account-e2e`) boots the whole service
// graph and tears it down in afterAll, which erases every operator the suite
// created; that takes longer than vitest's 10-second hook default under load, so
// the mode gives hooks two minutes.
//
// The `*.postgres.test.ts` suites build real rows and erase whole operators against the shared test database; on a
// busy machine that outlasts vitest's 5 s test and 10 s hook defaults, so only they get 60 s (the account end-to-end
// mode, which tears down the whole graph, keeps its two minutes for hooks). A unit test that hangs still fails in 5 s.
//
// Suites that cannot share the database with files running beside them run as groups of their own, one after the other
// and after every other test file has finished (`sequence.groupOrder`):
//   1. the security-monitoring exporter reads every audit and security row of the database, so its conformance run is
//      only meaningful while nothing else writes them (the identity, single sign-on and end-to-end suites do);
// Suites that change rows they did not create, or the schema, use a database of their own instead (`createOwnDatabase`,
// `src/test/own-database.ts`); these need the shared one.
//
// The `*.image.test.ts` suites start a fresh process that loads the whole compiled API, as a release script does on a
// deployed machine. That takes about 20 s on an idle machine and outlasted two minutes beside the rest of a full run, so they
// run last, one file at a time, in a group of their own.
const BASE_EXCLUDE = ['**/node_modules/**', '**/dist/**'];
const POSTGRES_TESTS = 'src/**/*.postgres.test.ts';
const EXCLUSIVE_POSTGRES_STAGES = [
  { name: 'postgres-exclusive', files: ['src/config/siem-export.conformance.postgres.test.ts'] },
];
const EXCLUSIVE_POSTGRES_TESTS = EXCLUSIVE_POSTGRES_STAGES.flatMap((stage) => stage.files);
const POSTGRES_TIMEOUT_MS = 60_000;
const IMAGE_SHAPE_TESTS = 'src/**/*.image.test.ts';

export default defineConfig(({ mode }) => ({
  test: {
    globalSetup: ['./vitest.global-setup.ts'],
    exclude: BASE_EXCLUDE,
    passWithNoTests: true,
    env: { NODE_ENV: 'development' },
    ...(mode === 'agent-account-e2e' ? { hookTimeout: 120_000 } : {}),
    projects: [
      {
        extends: true,
        test: {
          name: 'unit',
          exclude: [...BASE_EXCLUDE, POSTGRES_TESTS, IMAGE_SHAPE_TESTS],
        },
      },
      {
        extends: true,
        test: {
          name: 'image-shape',
          include: [IMAGE_SHAPE_TESTS],
          exclude: BASE_EXCLUDE,
          fileParallelism: false,
          sequence: { groupOrder: EXCLUSIVE_POSTGRES_STAGES.length + 1 },
        },
      },
      {
        extends: true,
        test: {
          name: 'postgres',
          include: [POSTGRES_TESTS],
          exclude: [...BASE_EXCLUDE, ...EXCLUSIVE_POSTGRES_TESTS],
          testTimeout: POSTGRES_TIMEOUT_MS,
          hookTimeout: mode === 'agent-account-e2e' ? 120_000 : POSTGRES_TIMEOUT_MS,
        },
      },
      ...EXCLUSIVE_POSTGRES_STAGES.map((stage, index) => ({
        extends: true as const,
        test: {
          name: stage.name,
          include: stage.files,
          exclude: BASE_EXCLUDE,
          testTimeout: POSTGRES_TIMEOUT_MS,
          hookTimeout: mode === 'agent-account-e2e' ? 120_000 : POSTGRES_TIMEOUT_MS,
          sequence: { groupOrder: index + 1 },
        },
      })),
    ],
  },
}));
