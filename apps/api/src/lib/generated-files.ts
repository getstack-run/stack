import type { GeneratedFileSink } from '@stack/vault';
export type { GeneratedFileSink };

/**
 * Where a file a model made is saved. A deployment with an agent drive saves it
 * there, private to the agent; one without returns the bytes (small) or the
 * provider's link in the answer, which is `NO_GENERATED_FILES`.
 */
export const NO_GENERATED_FILES: GeneratedFileSink | null = null;
