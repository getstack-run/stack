// A Mission's recipient pins: who this one job may send to.
//
// A policy send rule can leave its recipients to each Mission (`recipients: 'per_mission'`). Such a
// rule allows a send only inside a Mission that pins every recipient field the send names, with an
// exact value (`eq`) or a list of exact values (`in`), and only to them. A Mission without the pin
// is refused. The pins are set when the Mission is opened and never change.
//
// A pin names a request field (`body.to`, `derived.email.recipients`, `url.pathname`), or `*`: the
// shorthand "this list, at every recipient field a send names". `*` is how a Mission says "reply to
// this one person" without knowing which fields each provider calls its recipient. It also reaches a
// recipient that is part of the URL (`url.pathname`): the path matches when it, or one of its
// segments, is a listed value (a Slack or Discord channel id).

import { z } from 'zod';
import {
  MISSION_RECIPIENT_ANY_PATH,
  MISSION_RECIPIENT_PINS_MAX,
  MISSION_RECIPIENT_VALUES_MAX,
} from '../constants/control-policy.js';
import { isResolvablePath } from '../utils/constraints.js';

const PinText = z.string().trim().min(1).max(1024);

export const MissionRecipientPin = z
  .object({
    /** A request field, or `*` for every recipient field a send names. */
    path: z
      .string()
      .min(1)
      .max(128)
      .refine((path) => path === MISSION_RECIPIENT_ANY_PATH || isResolvablePath(path), 'Name a request field such as body.to, or *'),
    op: z.enum(['eq', 'in']),
    /** One exact value for `eq`, a list of exact values for `in`. */
    // Up to two spellings of each of MISSION_RECIPIENT_VALUES_MAX recipients: an address is kept as written and in lower case.
    value: z.union([PinText, z.number().finite(), z.array(PinText).min(1).max(MISSION_RECIPIENT_VALUES_MAX * 2)]),
  })
  .strict()
  .superRefine((pin, ctx) => {
    if (pin.op === 'in' && !Array.isArray(pin.value)) {
      ctx.addIssue({ code: 'custom', path: ['value'], message: 'op "in" takes a list of values' });
    }
    if (pin.op === 'eq' && Array.isArray(pin.value)) {
      ctx.addIssue({ code: 'custom', path: ['value'], message: 'op "eq" takes one value; use "in" for a list' });
    }
    if (pin.path === MISSION_RECIPIENT_ANY_PATH && typeof pin.value === 'number') {
      ctx.addIssue({ code: 'custom', path: ['value'], message: 'A pin on * lists text values; pin a number on its own field' });
    }
  });
export type MissionRecipientPin = z.infer<typeof MissionRecipientPin>;

export const MissionRecipientPins = z
  .array(MissionRecipientPin)
  .min(1)
  .max(MISSION_RECIPIENT_PINS_MAX)
  .superRefine((pins, ctx) => {
    const seen = new Set<string>();
    pins.forEach((pin, index) => {
      if (seen.has(pin.path)) ctx.addIssue({ code: 'custom', path: [index, 'path'], message: 'One pin per field' });
      seen.add(pin.path);
    });
  });
export type MissionRecipientPins = z.infer<typeof MissionRecipientPins>;

/**
 * The shorthand callers use when they only have the people: `recipients: ['ana@example.com']` is
 * the same Mission as one pin `{ path: '*', op: 'in', value: [...] }`.
 */
export const MissionRecipientList = z
  .array(PinText)
  .min(1)
  .max(MISSION_RECIPIENT_VALUES_MAX)
  // A recipient listed twice (in any case) is kept once, as first written.
  .transform((values) => values.filter((value, index) => values.findIndex((other) => other.toLowerCase() === value.toLowerCase()) === index));
export type MissionRecipientList = z.infer<typeof MissionRecipientList>;

/**
 * What a Mission opens with: the pins, written either way. Both together are one set of pins
 * (a field pin of its own beside the `*` list). Absent is a Mission with no pins.
 */
export const MissionRecipientsInput = {
  recipients: MissionRecipientList.optional(),
  recipient_pins: MissionRecipientPins.optional(),
} as const;
