/**
 * What a notification needs to send a text message: a number and the words.
 * A deployment sends through its own phone provider account; an install
 * without a transport has none, and its SMS channel answers that delivery is
 * unavailable.
 */
export interface SmsTransport {
  sendSms(to: string, body: string): Promise<unknown>;
}

/** No SMS transport: the SMS channel is not available on this install. */
export const NO_SMS_TRANSPORT: SmsTransport | null = null;
