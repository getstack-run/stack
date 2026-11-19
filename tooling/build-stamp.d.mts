export const STAMP_FILE: string;

export interface BuildInputs {
  hash: string;
  files: Record<string, string>;
}

export interface StaleBuild {
  /** The package directory name under `packages/`. */
  pkg: string;
  /** `unbuilt`: no readable stamp. `changed`: the source differs from what was built. */
  reason: 'unbuilt' | 'changed';
  /** For `changed`, the inputs (relative to the package) that differ, were added or were removed. */
  files: string[];
}

export function hashBuildInputs(packageDir: string): BuildInputs;
export function writeBuildStamp(packageDir: string): string;
export function findStaleBuilds(packagesDir: string, packages: readonly string[]): StaleBuild[];
export function staleBuildMessage(stale: readonly StaleBuild[], buildCommand: string): string;
export function assertBuiltDependenciesFresh(options: {
  packages: readonly string[];
  buildCommand: string;
  packagesDir?: string;
  env?: Record<string, string | undefined>;
}): void;
