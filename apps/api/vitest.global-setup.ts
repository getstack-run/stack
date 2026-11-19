import { assertBuiltDependenciesFresh } from '../../tooling/build-stamp.mjs';

// Runs once before a vitest run of the API: refuse to test against a build that
// does not match its source (see tooling/build-stamp.mjs). The API imports these
// packages from their built output.
export default function setup(): void {
  assertBuiltDependenciesFresh({
    packages: ['shared', 'vault', 'mcp-server', 'dropoff', 'skills', 'verifier'],
    buildCommand: 'pnpm exec turbo build --filter=@stack/api^...',
  });
}
