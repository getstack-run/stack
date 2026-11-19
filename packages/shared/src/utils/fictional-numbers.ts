/**
 * Telephone numbers for tests and examples.
 *
 * Sweden's telecom regulator, PTS (Post- och telestyrelsen), reserves numbers for
 * use in fiction (films, series, books) so that nobody's real line is rung. They
 * have no subscriber and will not be assigned. The mobile block is
 * 070-174 06 05 to 070-174 06 99, that is +46 70 174 06 05 to +46 70 174 06 99.
 * (The regulator also reserves four fixed-line blocks, in 031, 040, 08 and 0980,
 * which this file does not use.) Every Swedish number in this repository's tests
 * and examples comes from that block, and a test fails on any other.
 *
 * Where any number works and the point is that it is not a real one, a number
 * that cannot exist is better still: no Swedish national number starts with 0,
 * so +46 00 000 00 00 is invalid by construction.
 */

const FICTIONAL_MOBILE_FIRST = 701740605;
const FICTIONAL_MOBILE_LAST = 701740699;

/** How many numbers the reserved mobile block holds (95). */
export const FICTIONAL_SE_MOBILE_COUNT = FICTIONAL_MOBILE_LAST - FICTIONAL_MOBILE_FIRST + 1;

/** The n-th number of the reserved mobile block (0 to 94), in E.164 form. */
export function fictionalSwedishMobile(index = 0): string {
  if (!Number.isInteger(index) || index < 0 || index >= FICTIONAL_SE_MOBILE_COUNT) {
    throw new RangeError(`the reserved block holds ${FICTIONAL_SE_MOBILE_COUNT} numbers, so the index is 0 to ${FICTIONAL_SE_MOBILE_COUNT - 1}`);
  }
  return `+46${FICTIONAL_MOBILE_FIRST + index}`;
}

/** Is `value` a Swedish number from the block reserved for fiction? Spaces, dashes and a leading 0 or 0046 are read as such. */
export function isFictionalSwedishMobile(value: string): boolean {
  const digits = value.replace(/[\s-]/g, '');
  const national = digits.startsWith('+46') ? digits.slice(3) : digits.startsWith('0046') ? digits.slice(4) : digits.startsWith('0') ? digits.slice(1) : null;
  if (national === null || !/^\d{9}$/.test(national)) return false;
  const n = Number(national);
  return n >= FICTIONAL_MOBILE_FIRST && n <= FICTIONAL_MOBILE_LAST;
}
