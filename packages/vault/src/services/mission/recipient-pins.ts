// Reads what a Mission pinned, and whose it is, for the policy check.
//
// A Mission's pins are written when it opens and change only when the owner adds recipients to it (which tells every
// machine to forget what it read, `forget`); the agent it was opened for never changes. The reader keeps the most recent
// ones in memory so a call under a per-job rule does not cost a database read each time. A Mission that is not the operator's, or does not exist,
// reads as pinning no one and belonging to no agent: a rule that leaves its recipients to each Mission then refuses the
// send.

import { readRecipientPins, type RecipientPin } from '@stack/shared';
import type { MissionRepository } from '../../repositories/mission-repo.js';

/** How many Missions the reader keeps. */
const KEPT = 2_000;

export interface MissionRecipients {
  /** What the Mission pinned; null when it pinned no one. */
  pins: RecipientPin[] | null;
  /** The agent the Mission was opened for; null when it was opened for none. */
  assignedAgentId: string | null;
}

const NOBODY: MissionRecipients = { pins: null, assignedAgentId: null };

export class MissionRecipientPinReader {
  private readonly kept = new Map<string, MissionRecipients>();

  constructor(private readonly repo: Pick<MissionRepository, 'findById'>) {}

  /** Drop what this machine read of one Mission, after its pins changed. */
  forget(operatorId: string, missionId: string): void {
    this.kept.delete(`${operatorId}\u0000${missionId}`);
  }

  async read(operatorId: string, missionId: string): Promise<MissionRecipients> {
    const key = `${operatorId}\u0000${missionId}`;
    const known = this.kept.get(key);
    if (known) return known;
    const row = await this.repo.findById(missionId);
    // A Mission that is gone is not remembered: it may be a read made before the row was visible.
    if (!row) return NOBODY;
    const found: MissionRecipients =
      row.operator_id === operatorId
        ? { pins: readRecipientPins(row.recipient_pins), assignedAgentId: row.assigned_agent_id ?? null }
        : NOBODY;
    if (this.kept.size >= KEPT) this.kept.delete(this.kept.keys().next().value as string);
    this.kept.set(key, found);
    return found;
  }
}
