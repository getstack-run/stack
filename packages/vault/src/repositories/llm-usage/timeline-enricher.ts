/**
 * Adds a deployment's own context to the rows of the LLM usage timeline.
 *
 * The timeline lists each model call. A deployment that runs a skills
 * marketplace can say which skill invocation a call belonged to and what that
 * skill is called; the engine lists the call without them. `null` means no
 * enrichment, which is what the engine does on its own.
 */
export interface TimelineEnrichment {
  skill: { id: string; name: string } | null;
  invocation: { id: string; status: string } | null;
}

export interface TimelineEnricher {
  /** The skill and invocation of each call, keyed by invocation id; a call it does not know is left out. */
  describe(
    operatorId: string,
    calls: ReadonlyArray<{ invocationId: string | null; skillId: string | null }>,
  ): Promise<ReadonlyMap<string, TimelineEnrichment>>;
}

/** The engine's timeline names nothing but the call itself. */
export const NO_TIMELINE_ENRICHER: TimelineEnricher | null = null;
