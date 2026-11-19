import type { WorkerRuntime } from '../runtime.js';

/**
 * Signal 6 — checkpoint_silence
 * Find enforced passports where the last checkpoint (or issued_at) is older than 2x checkpoint_interval.
 */
export async function detectCheckpointSilence(
  deps: Pick<WorkerRuntime, 'passportRepo' | 'securityEvent'>,
): Promise<void> {
  const { passportRepo, securityEvent } = deps;
  const passports = await passportRepo.findCheckpointOverdue();
  const now = Date.now();

  for (const passport of passports) {
    const interval = passport.checkpoint_interval_seconds ?? 300;
    const lastActivity = passport.last_checkpoint_at ?? passport.issued_at;
    const silenceSecs = (now - lastActivity.getTime()) / 1000;

    if (silenceSecs > interval * 2) {
      // Deduplicate
      const exists = await securityEvent.existsForPassport(passport.jti, 'checkpoint_silence');
      if (!exists) {
        await securityEvent.record({
          operatorId: passport.operator_id,
          agentId: passport.agent_id,
          passportJti: passport.jti,
          signalType: 'checkpoint_silence',
          severity: 'warning',
          message: `No checkpoint for ${Math.round(silenceSecs / 60)}m (interval: ${Math.round(interval / 60)}m)`,
          metadata: { silence_seconds: Math.round(silenceSecs), interval_seconds: interval },
        });
        console.log(`Signal: checkpoint_silence for passport ${passport.jti}`);
      }
    }
  }
}

/**
 * Signal 7 — expired_no_checkout
 * Find passports that expired within the last 24h without a checkout.
 */
export async function detectExpiredNoCheckout(
  deps: Pick<WorkerRuntime, 'passportRepo' | 'securityEvent'>,
): Promise<void> {
  const { passportRepo, securityEvent } = deps;
  const passports = await passportRepo.findExpiredWithoutCheckout(24);

  for (const passport of passports) {
    const exists = await securityEvent.existsForPassport(passport.jti, 'expired_no_checkout');
    if (!exists) {
      await securityEvent.record({
        operatorId: passport.operator_id,
        agentId: passport.agent_id,
        passportJti: passport.jti,
        signalType: 'expired_no_checkout',
        severity: 'warning',
        message: `Passport expired at ${passport.expires_at.toISOString()} without checkout`,
      });
      console.log(`Signal: expired_no_checkout for passport ${passport.jti}`);
    }
  }
}
