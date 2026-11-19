import type { CheckoutInput, ReviewFlag } from '@stack/shared';
import type { ReviewAgent, ReviewCheckpoint, ReviewPassport } from './review-rules.js';

/**
 * What a grader of declared-versus-observed behaviour is given at checkout: the passport's declared intent and what the
 * agent then did. It is asked on every checkout, whatever the review rules raised.
 */
export interface IntentDeviationInput {
  passport: ReviewPassport;
  agent: ReviewAgent;
  checkpoints: readonly ReviewCheckpoint[];
  checkout: CheckoutInput;
  missionId: string | null;
}

/**
 * Signal 10, intent_deviation: a grade of how closely the observed behaviour matched the declared intent. The engine
 * keeps only this interface; a deployment that grades with a model passes its own (`AccountabilityService
 * .setIntentDeviationGrader`), the same way it passes the third detector layer's classifier. Best-effort: a grader that
 * cannot answer returns no flag, and a checkout never waits on it for a refusal.
 */
export interface IntentDeviationGrader {
  grade(input: IntentDeviationInput): Promise<ReviewFlag[]>;
}

/** An install grades nothing: the review rules alone decide. */
export const NO_INTENT_DEVIATION_GRADER: IntentDeviationGrader = {
  async grade() {
    return [];
  },
};
