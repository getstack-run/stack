// National-identifier validators: Southern Europe.

import { luhnDigits, digitsOf, weightedSum, iso7064Mod1110, isDayMonth } from './checks.js';

/** Spain — DNI and NIE. Letter is index (number mod 23) into a fixed table;
 *  NIE maps its leading X/Y/Z to 0/1/2. */
const DNI_TABLE = 'TRWAGMYFPDXBNJZSQVHLCKE';

export function validateDniEs(match: string): boolean {
  const s = match.toUpperCase().replace(/[\s-]/g, '');
  const m = /^([XYZ]?)(\d{7,8})([A-Z])$/.exec(s);
  if (!m) return false;
  const [, nie, digits, letter] = m;
  const prefix = nie === 'X' ? '0' : nie === 'Y' ? '1' : nie === 'Z' ? '2' : '';
  if (!nie && digits!.length !== 8) return false;
  if (nie && digits!.length !== 7) return false;
  return DNI_TABLE[Number(prefix + digits!) % 23] === letter;
}

/** Italy — codice fiscale. Sixteen characters; the final letter is a check
 *  over odd and even positions against two fixed tables. */
const CF_EVEN = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

const CF_ODD = [1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23];

export function validateCodiceFiscaleIt(match: string): boolean {
  const s = match.toUpperCase();
  if (!/^[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]$/.test(s)) return false;
  // Positions are 1-indexed in the scheme: odd positions use the CF_ODD
  // table, even positions their plain alphabet index. Digits map to the
  // letter at the same index (0 -> A).
  const valueAt = (ch: string, odd: boolean): number => {
    const idx = /\d/.test(ch) ? Number(ch) : CF_EVEN.indexOf(ch);
    return odd ? CF_ODD[idx]! : idx;
  };
  let sum = 0;
  for (let i = 0; i < 15; i++) sum += valueAt(s[i]!, i % 2 === 0);
  return CF_EVEN[sum % 26] === s[15];
}

/** Croatia — OIB. Eleven digits, ISO 7064 MOD 11,10. */
export function validateOibHr(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 11) return false;
  return iso7064Mod1110(d, 10) === Number(d[10]);
}

/** Greece — ΑΜΚΑ. Eleven digits opening with a DDMMYY date, Luhn checked. */
export function validateAmkaGr(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 11) return false;
  if (!isDayMonth(Number(d.slice(0, 2)), Number(d.slice(2, 4)))) return false;
  return luhnDigits(d);
}

/** Malta — identity card number. Seven digits plus a category letter. The
 *  scheme carries no check digit, so the letter is all the specificity there
 *  is; see the false-positive note on the pattern entry. */
export function validateIdCardMt(match: string): boolean {
  return /^\d{7}[MGAPLHBZmgaplhbz]$/.test(match.replace(/\s/g, ''));
}

/** Portugal — NIF. Nine digits, weights 9..2, mod 11 with 10 folding to zero.
 *  The leading digit is the taxpayer class, and only some classes are people:
 *  1, 2 and 3 are individuals, 45 a non-resident individual, 8 a sole trader.
 *  5 (companies), 6 (public bodies), 7 and 9 (other entities) are excluded,
 *  because a company tax number is not personal data and matching it only
 *  bought false positives. */
export function validateNifPt(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 9) return false;
  const personal = '1238'.includes(d[0]!) || d.slice(0, 2) === '45';
  if (!personal) return false;
  const r = 11 - (weightedSum(d, [9, 8, 7, 6, 5, 4, 3, 2]) % 11);
  return (r >= 10 ? 0 : r) === Number(d[8]);
}

/** Slovenia — EMŠO. Thirteen digits, weighted mod 11. Shared historically
 *  with the other former-Yugoslav registers. */
export function validateEmsoSi(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 13) return false;
  if (!isDayMonth(Number(d.slice(0, 2)), Number(d.slice(2, 4)))) return false;
  const m = 11 - (weightedSum(d, [7, 6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2]) % 11);
  if (m === 10) return false;
  return (m === 11 ? 0 : m) === Number(d[12]);
}
