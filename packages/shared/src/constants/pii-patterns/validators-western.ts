// National-identifier validators: Western Europe.

import { luhnDigits, digitsOf, weightedSum, isDayMonth } from './checks.js';

/** Netherlands — burgerservicenummer. Nine digits, "elfproef". */
export function validateBsnNl(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 9) return false;
  const weights = [9, 8, 7, 6, 5, 4, 3, 2, -1];
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += weights[i]! * Number(d[i]);
  return sum % 11 === 0;
}

/** Germany — steuerliche Identifikationsnummer. Eleven digits, ISO 7064
 *  MOD 11,10, and the first ten must repeat exactly one digit (either one
 *  digit twice, or one digit three times consecutively). */
export function validateSteuerIdDe(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 11 || d[0] === '0') return false;
  const counts = new Map<string, number>();
  for (const c of d.slice(0, 10)) counts.set(c, (counts.get(c) ?? 0) + 1);
  const repeated = [...counts.values()].filter((v) => v > 1);
  if (repeated.length !== 1 || repeated[0]! > 3) return false;
  let product = 10;
  for (let i = 0; i < 10; i++) {
    let sum = (Number(d[i]) + product) % 10;
    if (sum === 0) sum = 10;
    product = (2 * sum) % 11;
  }
  const check = 11 - product;
  return (check === 10 ? 0 : check) === Number(d[10]);
}

/** France — NIR (numéro de sécurité sociale). Thirteen digits plus a two
 *  digit key of 97 minus the number modulo 97. Corsican departments carry
 *  2A / 2B, which map to 19 / 18 before the arithmetic. */
export function validateNirFr(match: string): boolean {
  const s = match.toUpperCase().replace(/\s/g, '');
  const m = /^(\d{6})(2[AB]|\d{2})(\d{5})(\d{2})$/.exec(s);
  if (!m) return false;
  const [, head, dept, tail, key] = m;
  const deptNum = dept === '2A' ? '19' : dept === '2B' ? '18' : dept;
  const body = BigInt(head! + deptNum + tail!);
  return Number(97n - (body % 97n)) === Number(key);
}

/** Austria — Sozialversicherungsnummer. Ten digits NNNC DDMMYY; the check
 *  sits at index 3 and is the weighted sum of the other nine mod 11. */
export function validateSvnrAt(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 10) return false;
  if (!isDayMonth(Number(d.slice(4, 6)), Number(d.slice(6, 8)))) return false;
  const r = weightedSum(d, [3, 7, 9, 0, 5, 8, 4, 2, 1, 6]) % 11;
  return r !== 10 && r === Number(d[3]);
}

/** Belgium — Rijksregisternummer. Eleven digits; the last two are 97 minus
 *  the first nine mod 97. People born from 2000 prefix a 2 before the
 *  arithmetic, so both readings are accepted. */
export function validateRrnBe(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 11) return false;
  if (!isDayMonth(Number(d.slice(4, 6)), Number(d.slice(2, 4)))) return false;
  const check = Number(d.slice(9));
  const body = Number(d.slice(0, 9));
  return 97 - (body % 97) === check || 97 - (Number('2' + d.slice(0, 9)) % 97) === check;
}

/** Luxembourg — matricule. Thirteen digits: position 12 is a Luhn check over
 *  the first eleven, position 13 a Verhoeff check over the same. */
const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

function verhoeffCheck(digits: string): number {
  let c = 0;
  const rev = [...digits].reverse();
  for (let i = 0; i < rev.length; i++) c = VERHOEFF_D[c]![VERHOEFF_P[(i + 1) % 8]![Number(rev[i])]!]!;
  return [0, 4, 3, 2, 1, 5, 6, 7, 8, 9][c]!;
}

export function validateMatriculeLu(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 13) return false;
  if (!isDayMonth(Number(d.slice(6, 8)), Number(d.slice(4, 6)))) return false;
  if (!luhnDigits(d.slice(0, 12))) return false;
  return verhoeffCheck(d.slice(0, 11)) === Number(d[12]);
}
