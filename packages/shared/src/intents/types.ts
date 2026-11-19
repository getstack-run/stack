// Intent = named, parameterized shorthand that expands to a constraint
// array at passport-issue time. The intent catalog is first-party: one
// file per provider, each exporting a typed list of Intent definitions.
//
// Agents declare intents like `{name: "slack.post_to_channel", params:
// {channel: "C0123"}}`. The server looks each up in INTENT_REGISTRY,
// validates params with the intent's zod schema, and calls expand() to
// produce the raw Constraint[] that rides on the issued passport.
//
// At the proxy, only raw constraints matter. Intents are a declaration-
// time convenience — proxy enforcement is constraint-only.

import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';

/**
 * What an intent can do, at most. Every catalog intent declares one; the
 * classification test (`intent-effects.test.ts`) fails CI on an unclassified
 * intent or one whose class disagrees with its HTTP method.
 *
 * - `read`: retrieves data and changes nothing a person outside the account sees.
 * - `write`: changes data inside the connected account.
 * - `send`: delivers content or a notification to people outside the agent's
 *   own account (chat messages, email, SMS and calls, social posts, campaign
 *   and invoice emails, invitations, sharing with a person, mail forwarding).
 *   Editing a message already delivered is `write`: it cannot reach a new
 *   audience.
 * - `destructive`: deletes data, or may (an unconstrained method set).
 *
 * `send` outranks `destructive` when an intent can do both, because a send is
 * the effect a policy must bound by recipient.
 */
export type IntentEffect = 'read' | 'write' | 'send' | 'destructive';
export const INTENT_EFFECTS: readonly IntentEffect[] = ['read', 'write', 'send', 'destructive'];

export interface Intent {
  name: string;
  description: string;
  effect: IntentEffect;
  /**
   * For `send` intents: the request fields that decide who receives the
   * content, in constraint-path notation (`body.channel`, `body.to`,
   * `url.pathname` when the recipient is in the path, `body.to[].email` for
   * every element of an array, or `derived.email.recipients` for the
   * addresses inside an encoded Gmail or Outlook message). A policy rule that
   * allows the send must bind every one of them (see `findUnboundSendRules`).
   * Every path must be one the constraint engine reads (`isResolvablePath`;
   * `intent-effects.test.ts` proves it). Absent on a send intent means the
   * recipient cannot be bound, so such a send can only be reviewed or denied:
   * a reply, a public post, a stored campaign audience, a draft sent by id.
   */
  recipient_paths?: readonly string[];
  // Zod schema for the params object. `any` in the public type because
  // each intent's params shape is different; the `defineIntent` helper
  // preserves strong typing at the callsite.
  params: z.ZodType<unknown, z.ZodTypeDef, unknown>;
  expand: (params: unknown) => Constraint[];
}

/**
 * Typed helper for declaring intents. Infers the params type from the
 * zod schema so the `expand` callback gets a properly-typed argument.
 */
export function defineIntent<TSchema extends z.ZodType>(def: {
  name: string;
  description: string;
  effect: IntentEffect;
  recipient_paths?: readonly string[];
  params: TSchema;
  expand: (params: z.infer<TSchema>) => Constraint[];
}): Intent {
  return {
    name: def.name,
    description: def.description,
    effect: def.effect,
    ...(def.recipient_paths ? { recipient_paths: def.recipient_paths } : {}),
    params: def.params,
    expand: (raw) => def.expand(raw as z.infer<TSchema>),
  };
}

// Agent-side reference that travels over the wire. Server expands it.
export const IntentRef = z.object({
  name: z.string().min(1).max(128),
  params: z.record(z.unknown()).default({}),
});
export type IntentRef = z.infer<typeof IntentRef>;
