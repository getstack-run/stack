// Check-digit primitives shared by the PII validators.

/** Plain Luhn over any digit string. Split out of luhnValidate, which gates
 *  on card length (13-19) and so could never accept the ten digits of a
 *  Swedish personnummer. */
export function luhnDigits(digits: string): boolean {
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

export function luhnValidate(s: string): boolean {
  const digits = s.replace(/[^\d]/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

/* ── European national-identifier validators ─────────────────────────
 *
 * Each takes the RAW matched text (separators included) and answers only
 * "is this a well-formed identifier of that country's scheme". They are
 * check-digit tests, not registry lookups: a number can pass here and
 * belong to nobody. That is the correct bar for redaction, where the cost
 * of a false positive is a placeholder and the cost of a false negative is
 * a personal identifier reaching a third-party model provider.
 */

export const digitsOf = (s: string): string => s.replace(/\D/g, '');

/** Weighted sum of a digit string against a weight vector of equal length. */
export function weightedSum(d: string, weights: readonly number[]): number {
  let sum = 0;
  for (let i = 0; i < weights.length; i++) sum += weights[i]! * Number(d[i]);
  return sum;
}

/** ISO 7064 MOD 11,10 over the leading `len` digits, returning the expected
 *  check digit. Shared by the German Steuer-ID and the Croatian OIB. */
export function iso7064Mod1110(d: string, len: number): number {
  let product = 10;
  for (let i = 0; i < len; i++) {
    let sum = (Number(d[i]) + product) % 10;
    if (sum === 0) sum = 10;
    product = (2 * sum) % 11;
  }
  const check = 11 - product;
  return check === 10 ? 0 : check;
}

/** Two-pass mod-11 used by the Baltic personal codes: weight vector one, and
 *  on a remainder of 10 fall back to vector two, and on 10 again the check is
 *  zero. */
export function balticMod11(d: string, w1: readonly number[], w2: readonly number[]): number {
  let r = weightedSum(d, w1) % 11;
  if (r === 10) r = weightedSum(d, w2) % 11;
  return r === 10 ? 0 : r;
}

/** DDMMYY / YYMMDD plausibility. Century is unknowable from six digits, so
 *  only day and month ranges are checked. */
export function isDayMonth(dd: number, mm: number): boolean {
  return mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31;
}
