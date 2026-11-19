// The agents that delegated a Passport, for the policy check.
//
// A delegated Passport carries its parent's Mission, so a child that sends under a per-job rule must be held to the per-job
// rules of every agent above it, not only the agent the Mission was opened for (a Mission can be opened for none). Who a
// Passport was delegated by never changes once it is issued, so what is read stays true and the reader keeps the most
// recent chains in memory. A read that fails throws: the check then fails and the send is refused, never let through.

/** The depth a delegation can reach is four; a chain longer than this is a loop or corrupt, and is cut. */
const MAX_HOPS = 8;
/** How many chains the reader keeps. */
const KEPT = 2_000;

export interface PassportLineageRow {
  agent_id: string;
  parent_passport_id: string | null;
}

export interface PassportLineageSource {
  findLineageRow(operatorId: string, jti: string): Promise<PassportLineageRow | null>;
}

export class PassportLineageReader {
  private readonly kept = new Map<string, string[]>();

  constructor(private readonly source: PassportLineageSource) {}

  /** The agents of every Passport above this one, nearest first; empty for a Passport nobody delegated. */
  async agentsAbove(operatorId: string, passportJti: string): Promise<string[]> {
    const key = `${operatorId}\u0000${passportJti}`;
    const known = this.kept.get(key);
    if (known) return known;
    const found: string[] = [];
    const seen = new Set<string>([passportJti]);
    let current = await this.source.findLineageRow(operatorId, passportJti);
    for (let hop = 0; hop < MAX_HOPS && current?.parent_passport_id && !seen.has(current.parent_passport_id); hop++) {
      const parentJti = current.parent_passport_id;
      seen.add(parentJti);
      current = await this.source.findLineageRow(operatorId, parentJti);
      if (current) found.push(current.agent_id);
    }
    // A Passport that was not found is not remembered: it may be a read made before the row was visible.
    if (this.kept.size >= KEPT) this.kept.delete(this.kept.keys().next().value as string);
    this.kept.set(key, found);
    return found;
  }
}
