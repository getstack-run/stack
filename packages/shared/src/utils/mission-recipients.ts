// A Mission's recipient pins, and how a send is judged against them.
//
// Pure. The pins are written when a Mission opens (see schemas/mission-recipients.ts) and never
// change, so a judgement needs only the pins and the call: parallel calls under one Mission all
// read the same immutable list, and no call can add to it.
//
// What "pinned" means for a send under a per-job rule:
//   - every recipient field the rule leaves open has a pin (its own, or the `*` list), else the
//     Mission "does not pin its recipients" and the send is refused;
//   - every recipient the request names at a pinned field is one of the pinned values, exactly;
//   - the request names at least one recipient, and a field the engine cannot read (an encoded
//     message, an array of the wrong shape) is refused, never skipped.
// A field the request does not carry is skipped: a send with `to` and no `cc` names no one at `cc`.

import { MISSION_RECIPIENT_ANY_PATH, MISSION_RECIPIENT_PINS_MAX } from '../constants/control-policy.js';
import type { Constraint, PlainConstraint } from '../schemas/passport.js';
import { MissionRecipientPin, MissionRecipientPins, type MissionRecipientList } from '../schemas/mission-recipients.js';
import { InvalidRequestError } from '../errors/index.js';
import { evaluateConstraint, resolvePath, type NormalizedRequest } from './constraints.js';

export type RecipientPin = MissionRecipientPin;

/** Why a send under a per-job rule was not allowed. */
export type RecipientJudgement =
  | { ok: true }
  | { ok: false; code: 'recipients_not_pinned' | 'recipient_not_allowed'; message: string };

export const MISSION_NOT_PINNED_MESSAGE =
  "This send is allowed only in a Mission that names who it may send to, and this Mission does not. Open a Mission with its recipients named.";
export const RECIPIENT_NOT_PINNED_MESSAGE = 'This recipient is not one this Mission may send to.';

/** An address is the same address in any case; keep what was written and add the lower-case form. */
function withLowerCaseForms(values: readonly string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of values) {
    for (const value of raw.includes('@') ? [raw, raw.toLowerCase()] : [raw]) {
      if (!seen.has(value)) {
        seen.add(value);
        out.push(value);
      }
    }
  }
  return out;
}

/**
 * The pins a Mission opens with, from the list shorthand and the field pins. The list becomes a
 * `*` pin (an address also stands in its lower-case form). Returns null for a Mission with none.
 * Throws a validation error for a list and a `*` pin together, or too many pins.
 */
export function buildRecipientPins(input: {
  recipients?: MissionRecipientList | undefined;
  recipient_pins?: readonly MissionRecipientPin[] | undefined;
}): RecipientPin[] | null {
  const pins: RecipientPin[] = [];
  if (input.recipients?.length) {
    pins.push({ path: MISSION_RECIPIENT_ANY_PATH, op: 'in', value: withLowerCaseForms(input.recipients) });
  }
  for (const pin of input.recipient_pins ?? []) {
    pins.push(
      Array.isArray(pin.value) ? { ...pin, value: pin.path === 'url.pathname' ? [...pin.value] : withLowerCaseForms(pin.value) } : { ...pin },
    );
  }
  if (pins.length === 0) return null;
  if (pins.length > MISSION_RECIPIENT_PINS_MAX) {
    throw new InvalidRequestError(`A Mission pins at most ${MISSION_RECIPIENT_PINS_MAX} recipient fields.`);
  }
  const parsed = MissionRecipientPins.safeParse(pins);
  if (!parsed.success) {
    throw new InvalidRequestError(
      parsed.error.issues.some((issue) => issue.message === 'One pin per field')
        ? 'Pin each recipient field once: the recipients list is the "*" pin, so give field pins for other fields.'
        : 'The Mission recipient pins are not valid.',
    );
  }
  return parsed.data;
}

/**
 * The pins a running Mission holds once the owner adds some: a pin on a field the Mission already pins adds its values
 * to that pin's list, a pin on a new field is added as it is. Only widens: nothing already pinned is taken away. Throws a
 * validation error for a number pin that would need a second value, or a result past the limits of one Mission.
 */
export function mergeRecipientPins(existing: readonly RecipientPin[] | null, added: readonly RecipientPin[]): RecipientPin[] {
  const merged: RecipientPin[] = (existing ?? []).map((pin) => ({ ...pin, value: Array.isArray(pin.value) ? [...pin.value] : pin.value }));
  for (const pin of added) {
    const index = merged.findIndex((known) => known.path === pin.path);
    if (index < 0) {
      merged.push({ ...pin, value: Array.isArray(pin.value) ? [...pin.value] : pin.value });
      continue;
    }
    const known = merged[index]!;
    const values = [...(Array.isArray(known.value) ? known.value : [known.value]), ...(Array.isArray(pin.value) ? pin.value : [pin.value])];
    if (values.some((value) => typeof value === 'number')) {
      if (values.every((value) => value === values[0])) continue;
      throw new InvalidRequestError(`The pin on ${pin.path} holds a number and takes one value.`);
    }
    const strings = [...new Set(values as string[])];
    merged[index] = strings.length === 1 ? { path: pin.path, op: 'eq', value: strings[0]! } : { path: pin.path, op: 'in', value: strings };
  }
  if (merged.length > MISSION_RECIPIENT_PINS_MAX) {
    throw new InvalidRequestError(`A Mission pins at most ${MISSION_RECIPIENT_PINS_MAX} recipient fields.`);
  }
  const parsed = MissionRecipientPins.safeParse(merged);
  if (!parsed.success) throw new InvalidRequestError('The Mission recipient pins are not valid.');
  return parsed.data;
}

/** Reads stored pins back, or null for none; a stored value that no longer parses is treated as no pins, never as a wider set. */
export function readRecipientPins(stored: unknown): RecipientPin[] | null {
  if (stored === null || stored === undefined) return null;
  const parsed = MissionRecipientPins.safeParse(stored);
  return parsed.success ? parsed.data : null;
}

export type AccountRecipientKind = 'email' | 'sms' | 'call';

/**
 * A phone number in E.164 form: spaces, dashes, dots and brackets dropped and a leading 00 read as +. Text that is not a
 * number once that is done is returned as it was, so it matches only itself.
 */
export function phoneE164(value: string): string {
  const compact = value.trim().replace(/[\s().-]/g, '').replace(/^00/, '+');
  return /^\+[1-9]\d{6,14}$/.test(compact) ? compact : value.trim();
}

/**
 * Judges a send from the account's own inbox or number under a per-job rule. The pins are the `*` list a call carries
 * (who wrote the message it answers, read from the stored message, or the Mission's own pins): an address is the same
 * address in any case, a number is compared in E.164 form. No pinned list is `recipients_not_pinned`; no recipient
 * named, or one outside the list, is `recipient_not_allowed`.
 */
export function judgeAccountRecipients(
  pins: readonly RecipientPin[] | null | undefined,
  kind: AccountRecipientKind,
  recipients: readonly string[] | null | undefined,
): RecipientJudgement {
  const any = pins?.find((pin) => pin.path === MISSION_RECIPIENT_ANY_PATH);
  if (!any) return { ok: false, code: 'recipients_not_pinned', message: MISSION_NOT_PINNED_MESSAGE };
  if (!recipients || recipients.length === 0) {
    return { ok: false, code: 'recipient_not_allowed', message: 'This send names no recipient this Mission may send to.' };
  }
  const fold = (value: string) => (kind === 'email' ? value.toLowerCase() : phoneE164(value));
  const allowed = new Set((Array.isArray(any.value) ? any.value : [any.value]).map((value) => fold(String(value))));
  for (const recipient of recipients) {
    if (!allowed.has(fold(recipient))) return { ok: false, code: 'recipient_not_allowed', message: RECIPIENT_NOT_PINNED_MESSAGE };
  }
  return { ok: true };
}

/** The pin that applies to one recipient field: its own, else the `*` list. */
function pinFor(pins: readonly RecipientPin[], path: string): RecipientPin | null {
  const own = pins.find((pin) => pin.path === path);
  if (own) return own;
  return pins.find((pin) => pin.path === MISSION_RECIPIENT_ANY_PATH) ?? null;
}

/**
 * A recipient inside the URL under the `*` list: the path matches when the whole path, or one of its segments, is one of
 * the listed values exactly (a channel id such as `C0123` in `/api/channels/C0123/messages`).
 */
function pathMatchesList(pin: RecipientPin, request: NormalizedRequest): boolean | undefined {
  const path = resolvePath(request, 'url.pathname');
  if (typeof path !== 'string') return undefined;
  const listed = new Set((Array.isArray(pin.value) ? pin.value : [pin.value]).map(String));
  return listed.has(path) || path.split('/').some((segment) => segment !== '' && listed.has(segment));
}

function asConstraint(pin: RecipientPin, path: string): PlainConstraint {
  return { path, op: pin.op, value: pin.value as PlainConstraint['value'] };
}

/**
 * Judges one call of a per-job rule. `enforced` is every recipient field of the rule's sends and
 * `required` the ones the rule's own constraints leave open (each must be pinned). `pins` is the
 * Mission's, null for a Mission with none.
 */
export function judgePerMissionSend(
  rule: { enforced: readonly string[]; required: readonly string[] },
  pins: readonly RecipientPin[] | null | undefined,
  request: NormalizedRequest,
): RecipientJudgement {
  if (!pins || pins.length === 0) return { ok: false, code: 'recipients_not_pinned', message: MISSION_NOT_PINNED_MESSAGE };
  const constraints: Constraint[] = [];
  let listedPath: RecipientPin | null = null;
  for (const path of rule.enforced) {
    const pin = pinFor(pins, path);
    if (pin && path === 'url.pathname' && pin.path === MISSION_RECIPIENT_ANY_PATH) listedPath = pin;
    else if (pin) constraints.push(asConstraint(pin, path));
    else if (rule.required.includes(path)) return { ok: false, code: 'recipients_not_pinned', message: MISSION_NOT_PINNED_MESSAGE };
  }
  // Every field the Mission could pin is already bound by the rule itself: the pins add nothing to check.
  if (constraints.length === 0 && listedPath === null) return { ok: true };
  let named = 0;
  if (listedPath) {
    const matched = pathMatchesList(listedPath, request);
    if (matched !== undefined) {
      named++;
      if (!matched) return { ok: false, code: 'recipient_not_allowed', message: RECIPIENT_NOT_PINNED_MESSAGE };
    }
  }
  for (const constraint of constraints) {
    const found = resolvePath(request, constraint.path);
    // What the engine cannot read is not "no recipient": an encoded message that does not decode has no readable address.
    if (found === undefined && !constraint.path.startsWith('derived.')) continue;
    named++;
    if (!evaluateConstraint(constraint, request)) return { ok: false, code: 'recipient_not_allowed', message: RECIPIENT_NOT_PINNED_MESSAGE };
  }
  if (named === 0) return { ok: false, code: 'recipient_not_allowed', message: 'This send names no recipient this Mission may send to.' };
  return { ok: true };
}

