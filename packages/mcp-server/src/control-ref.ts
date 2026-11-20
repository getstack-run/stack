/**
 * The retry of an action the owner approved. When a policy holds a call, the
 * API refuses it CONTROL_DENIED with reason_code review_required and a ref; once
 * the owner has approved, the agent sends the identical call again with the ref
 * in X-Control-Ref. Every tool whose route can hold an action takes an optional
 * `control_ref` and sends it through these helpers.
 */

import { z } from 'zod';

/** The header the API reads the ref from (CONTROL_REF_HEADER in @stack/shared; HTTP header names are case-insensitive). */
export const CONTROL_REF_REQUEST_HEADER = 'X-Control-Ref';

/** The one clause appended to the description of every tool that can be held for the owner. */
export const CONTROL_RETRY_NOTE = ' When refused CONTROL_DENIED with reason review_required, ask again with the same input and control_ref set to the ref once the owner approved.';

/** The optional input of such a tool. */
export const controlRef = z
  .string()
  .max(200)
  .optional()
  .describe('The ref of a refusal that held this action for the owner, sent as X-Control-Ref once the owner approved it; omit on the first request');

/** `{ 'X-Control-Ref': ref }` when a ref is given, otherwise nothing. */
export const controlRefHeader = (ref: string | undefined): Record<string, string> | undefined =>
  ref ? { [CONTROL_REF_REQUEST_HEADER]: ref } : undefined;

/**
 * The extra headers of a call that must be made as the account's agent (a payment from its wallet): `checkedHeaders`
 * plus, when a Passport is given, `Authorization: Bearer <Passport>`. The route accepts only an agent principal, so
 * the Passport is the credential of this one call and replaces the session's own (a person's token from a chat). The
 * API client lets an `Authorization` in the extra headers replace the session credential; no other tool sets one.
 */
export function agentCallHeaders(passportToken: string | undefined, ref: string | undefined): Record<string, string> | undefined {
  const headers = checkedHeaders(passportToken, ref);
  return passportToken ? { ...headers, Authorization: `Bearer ${passportToken}` } : headers;
}

/**
 * The extra headers of a call that can be held: the Passport when there is one
 * and the control ref when there is one, nothing at all (undefined) when neither.
 */
export function checkedHeaders(passportToken: string | undefined, ref: string | undefined): Record<string, string> | undefined {
  const headers: Record<string, string> = {
    ...(passportToken ? { 'X-Passport-Token': passportToken } : {}),
    ...(ref ? { [CONTROL_REF_REQUEST_HEADER]: ref } : {}),
  };
  return Object.keys(headers).length === 0 ? undefined : headers;
}
