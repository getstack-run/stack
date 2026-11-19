import type { HttpClient } from '../client.js';

/** What the customer's controls do with flagged content of one severity: keep it from the agent, or hand it over with its flag. */
export type FlaggedContentHandling = 'withhold' | 'deliver';

export interface FlaggedContentSettings {
  /** Content the detectors flag with a warning. */
  warning: FlaggedContentHandling;
  /** Content the detectors flag as critical. */
  critical: FlaggedContentHandling;
  /** Whether the setting applies now: it does only while the account has controls. */
  controls: boolean;
}

export interface SetFlaggedContentSettingsInput {
  warning?: FlaggedContentHandling;
  critical?: FlaggedContentHandling;
}

/**
 * What the customer's controls do with content the detectors flag in what reaches its agents (mail, texts, voicemail,
 * page text, tool output, drive files, memory writes), separately for a warning and a critical verdict: `withhold`
 * (the default for both) or `deliver` with its flag. With controls off flagged content is always delivered with its
 * flag. Owner or admin only; an agent is refused. A change applies at once, with no approval, and is recorded.
 */
export class FlaggedContentService {
  constructor(private readonly client: HttpClient) {}

  /** The setting in force, and whether controls are on. */
  async get(): Promise<FlaggedContentSettings> {
    return this.client.get<FlaggedContentSettings>('/v1/flagged-content/settings');
  }

  /** Change one severity or both; a severity left out keeps its value. Refused client-side when neither is named. */
  async set(input: SetFlaggedContentSettingsInput): Promise<FlaggedContentSettings> {
    if (input.warning === undefined && input.critical === undefined) {
      throw new Error('Invalid input: name warning, critical or both');
    }
    return this.client.put<FlaggedContentSettings>('/v1/flagged-content/settings', input);
  }
}
