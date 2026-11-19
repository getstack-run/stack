import { STAGING_SKIPPED_EMAIL_ID, staging, stagingRecipientAllowed } from '@stack/shared';

/**
 * The one place a staging deployment (`STACK_STAGING=true`) stops outbound
 * email to an address outside `STAGING_SIGNIN_ALLOWLIST`. Every sender STACK
 * builds (Resend for the hosted deployment, SMTP for an install) asks here
 * before it sends, so a test deployment never mails a stranger, whichever
 * path the mail took: the API's sign-in and notice mail, the worker's digest,
 * welcome and account notices.
 *
 * A skipped send resolves as sent, with `STAGING_SKIPPED_EMAIL_ID` for its id,
 * so a job that queued it finishes instead of retrying, and is logged without
 * the address. Outside staging this returns null and changes nothing.
 */
export function skipStagingRecipient(
  to: string,
  log: Pick<Console, 'warn'> = console,
): { id: string } | null {
  const config = staging();
  if (!config.enabled || stagingRecipientAllowed(to, config)) return null;
  log.warn('[STAGING] Skipped an email to an address outside STAGING_SIGNIN_ALLOWLIST.');
  return { id: STAGING_SKIPPED_EMAIL_ID };
}
