/**
 * Why a service connection has to be reconnected, when the cause is more than a
 * renewal that failed. The code rides in the reconnect event; the words are the
 * only ones a person is shown for it, in the Console, the email and the text.
 */
export const RECONNECT_REASONS = ['stack_oauth_app_retired', 'oauth_app_scopes_narrowed'] as const;
export type ReconnectReason = (typeof RECONNECT_REASONS)[number];

export const DEFAULT_RECONNECT_MESSAGE = 'Reconnect this service to continue.';

const RECONNECT_REASON_MESSAGES: Record<ReconnectReason, string> = {
  stack_oauth_app_retired:
    'The OAuth app this service was connected through is no longer in use. Reconnect it with an API key or token, or with your own OAuth app.',
  oauth_app_scopes_narrowed:
    'This connection holds more access than the app it was made through may now ask for. Reconnect it to continue.',
};

/** The message for a reconnect event, from its reason when it has a known one. */
export function reconnectMessage(reason: unknown): string {
  return typeof reason === 'string' && Object.hasOwn(RECONNECT_REASON_MESSAGES, reason)
    ? RECONNECT_REASON_MESSAGES[reason as ReconnectReason]
    : DEFAULT_RECONNECT_MESSAGE;
}
