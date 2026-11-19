import { ResendEmailService } from '@stack/vault';

/**
 * The email sender behind the notices the worker sends (the completion of an
 * email transfer) and, in a deployment that has one, its daily digest.
 * Optional: it only exists when `RESEND_API_KEY` and a from-address
 * (`RESEND_FROM_NOTIFICATIONS` or `RESEND_FROM_EMAIL`) are set.
 */
export function buildWorkerEmail(): ResendEmailService | null {
  const from = process.env['RESEND_FROM_NOTIFICATIONS'] ?? process.env['RESEND_FROM_EMAIL'];
  return process.env['RESEND_API_KEY'] && from
    ? new ResendEmailService({
        apiKey: process.env['RESEND_API_KEY'],
        fromEmail: from,
        replyTo: process.env['RESEND_REPLY_TO'] ?? '',
        listUnsubscribe: process.env['RESEND_LIST_UNSUBSCRIBE'] ?? '',
      })
    : null;
}
