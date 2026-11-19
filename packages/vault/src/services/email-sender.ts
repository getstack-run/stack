import type { SendEmailOptions } from './resend-email-service.js';

/**
 * What STACK needs from outbound email: send one message to one address.
 * Resend (STACK's hosted deployment) and SMTP (a self-managed one) both
 * satisfy it, and a deployment with neither passes null where a sender is
 * optional, so a flow that needs email says so instead of pretending to send.
 */
export interface EmailSender {
  sendEmail(
    to: string,
    subject: string,
    text: string,
    html?: string,
    options?: SendEmailOptions,
  ): Promise<{ id: string }>;
}
