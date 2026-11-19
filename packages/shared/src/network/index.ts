import RE2 from 're2';

/**
 * What a self-managed install does with what STACK's hosted network sends it.
 *
 * The rule set arrives as a signed statement (`stack-detection-rules+jwt`, signed
 * by STACK's deployment key; see the network contract) that the install
 * checks against STACK's published keys, so a compromised proxy or mirror cannot
 * feed it rules. What it contains is only ever applied as data: patterns compiled
 * by a linear-time engine, never code. This is that engine's side of it.
 */

/** The most rules one set may carry; a larger set is refused whole. */
export const MAX_NETWORK_RULES = 500;
/** The longest pattern the install compiles; a longer one is dropped. */
export const MAX_NETWORK_PATTERN_LENGTH = 512;

/**
 * Compile a pattern with RE2, whose matching time is linear in the input: a
 * pattern that came over the network can never hang a scan. Returns null for
 * anything RE2 refuses (lookahead, backreferences) or that is too long.
 * RE2 instances answer `exec` and `test` like a RegExp, so the detectors use
 * them as one.
 */
export function compileLinearTimePattern(pattern: string, flags = 'iu'): RegExp | null {
  if (pattern.length === 0 || pattern.length > MAX_NETWORK_PATTERN_LENGTH) return null;
  try {
    return new RE2(pattern, flags) as unknown as RegExp;
  } catch {
    return null;
  }
}
