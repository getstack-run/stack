/**
 * Subject identifier scheme for claim envelopes.
 *
 * Locked 2026-05-12: `stack://operator/{op_id}/passport/{ppt_jti}`.
 * Custom scheme, STACK-owned, no external standard makes federation
 * claims about it.
 *
 * NOT `spiffe://stack.run/...` — using the SPIFFE scheme implies we
 * are a SPIFFE trust domain at `stack.run`, and we are not (no SPIRE,
 * no Bundle endpoint, no SVID-bearing signing authority). Pre-pollutes
 * the Mission Layer Pillar 3 namespace for the future "global resolver"
 * play. See the claims registry design design decision
 * 2 for the full reasoning.
 *
 * Externally-issued SPIFFE IDs (e.g. inside an `svid_attestation`
 * payload) keep using `spiffe://...` because that usage records an
 * SVID issued by someone else, which is correct.
 */
import { z } from 'zod';

/**
 * Regex for the `stack://` subject scheme. Structured as:
 *   stack://{kind}/{id}[/{sub_kind}/{sub_id}]
 *
 * Examples (current + future):
 *   stack://operator/op_-Ex4mple.../passport/ppt_aB3xK9DfP2       ← SVID claims
 *   stack://operator/op_-Ex4mple.../mission/m_K7nQ4rW8oL          ← mission claims
 *   stack://operator/op_-Ex4mple...                                ← operator-scoped claim (no sub-resource)
 *
 * Identifier segment accepts the alphabet our id-generator uses
 * (nanoid: alphanumeric, hyphen, underscore).
 */
export const SUBJECT_URI_PATTERN = /^stack:\/\/[a-z]+\/[\w-]+(\/[a-z]+\/[\w-]+)?$/;

export const SubjectURI = z
  .string()
  .regex(SUBJECT_URI_PATTERN, 'subject must be a stack:// URI');
export type SubjectURI = z.infer<typeof SubjectURI>;

/**
 * Builder for the canonical passport-scoped subject URI.
 *
 * Use this in `ClaimRegistryService.registerClaim()` and anywhere
 * client code needs to address a claim by its passport subject. Never
 * hand-construct the string — the regex above catches typos but the
 * builder is the source of truth.
 */
export function subjectForPassport(operatorId: string, passportJti: string): string {
  return `stack://operator/${operatorId}/passport/${passportJti}`;
}

/**
 * Builder for an operator-scoped subject (no sub-resource). Used by
 * claim types that attach to the operator, not a specific passport
 * — currently none; reserved for future use cases like
 * operator-level behavioral aggregate claims.
 */
export function subjectForOperator(operatorId: string): string {
  return `stack://operator/${operatorId}`;
}

/**
 * Parse a subject URI into its components. Returns null if the string
 * does not match the expected shape (caller decides whether to throw
 * or fall through). Does NOT validate that the identifiers refer to
 * real records — pure syntactic parsing.
 */
export interface ParsedSubject {
  kind: string;
  id: string;
  sub_kind: string | null;
  sub_id: string | null;
}

export function parseSubjectURI(uri: string): ParsedSubject | null {
  const match = uri.match(SUBJECT_URI_PATTERN);
  if (!match) return null;
  // Strip "stack://" prefix, split on /
  const path = uri.slice('stack://'.length).split('/');
  return {
    kind: path[0]!,
    id: path[1]!,
    sub_kind: path[2] ?? null,
    sub_id: path[3] ?? null,
  };
}
