// Who wrote a message an agent received, for a send that answers it.
//
// A Mission can be opened to reply to a message (`reply_to_message` on `POST /v1/missions`), and an account's own email,
// text or call can carry the same field under a per-job rule on the account's sends. Both read the sender from the stored
// message through the deployment's `messageSenders` registry (the engine has no messages, so it finds no one): an unknown
// id, another customer's message, an outbound or withheld one all read as nothing to reply to, a 404 that says nothing
// about which of them it was.

import { MessageSenderUnverifiedError, NotFoundError, POLICY_RECIPIENTS_PER_MISSION, buildRecipientPins, type RecipientPin } from '@stack/shared';
import type { Services } from '../config/services.js';

type SenderServices = Pick<Services, 'registries'>;

/** Does this agent's policy in force leave the account's own email, texts or calls to each send (per_mission)? */
export async function recipientsLeftPerJob(
  services: Pick<Services, 'controlPolicies'>,
  operatorId: string,
  agentId: string,
  kind: 'email' | 'sms' | 'call',
): Promise<boolean> {
  const effective = await services.controlPolicies.effective(operatorId, agentId);
  return effective?.definition.recipients[kind] === POLICY_RECIPIENTS_PER_MISSION;
}

/**
 * The addresses or numbers that wrote the message: a 404 when this agent has no such message to answer, and a plain
 * 422 when the message is one whose sender could not be verified.
 */
export async function sendersOfMessage(
  services: SenderServices,
  input: { operatorId: string; agentId: string; messageId: string },
): Promise<string[]> {
  for (const resolve of services.registries.messageSenders.list()) {
    const found = await resolve(input);
    if (found && 'unverified' in found) throw new MessageSenderUnverifiedError();
    if (found && found.recipients.length > 0) return found.recipients;
  }
  throw new NotFoundError('message', input.messageId);
}

/**
 * The pin a send carries when it answers a stored message: the list of who may receive it, as the `*` pin a Mission's
 * recipients are. `extra` adds addresses the stored message itself names (the original's To and Cc of a reply to everyone).
 */
export async function replyPinsFor(
  services: SenderServices,
  input: { operatorId: string; agentId: string; messageId: string },
  extra: readonly string[] = [],
): Promise<RecipientPin[]> {
  const senders = await sendersOfMessage(services, input);
  const pins = pinsOf([...senders, ...extra]);
  if (!pins) throw new NotFoundError('message', input.messageId);
  return pins;
}

/** The pin for people named by a message already read (a reply's own sender and, to everyone, the original's To and Cc). */
export function pinsOf(recipients: readonly string[]): RecipientPin[] | null {
  return recipients.length === 0 ? null : buildRecipientPins({ recipients: [...recipients] });
}
