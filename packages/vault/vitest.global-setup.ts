import { assertBuiltDependenciesFresh } from '../../tooling/build-stamp.mjs';

// Runs once before a vitest run of the vault: refuse to test against a build of
// @stack/shared that does not match its source (see tooling/build-stamp.mjs).
// The vault imports shared from its built output.
export default function setup(): void {
  assertBuiltDependenciesFresh({
    packages: ['shared'],
    buildCommand: 'pnpm exec turbo build --filter=@stack/vault^...',
  });
}
