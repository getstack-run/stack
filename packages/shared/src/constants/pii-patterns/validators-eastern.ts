// National-identifier validators: Central and Eastern Europe.

import { digitsOf, weightedSum, isDayMonth } from './checks.js';

/** Bulgaria — ЕГН. Ten digits YYMMDD + serial + check, weighted mod 11 with
 *  10 folding to zero. The month carries +40 for births from 2000 and +20 for
 *  births before 1900. Shipped without the date test at first, which made it
 *  the single largest source of false positives in the catalog (22.5% of
 *  them) because a bare check digit alone passes about one run in eleven. */
export function validateEgnBg(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 10) return false;
  let mm = Number(d.slice(2, 4));
  if (mm > 40) mm -= 40;
  else if (mm > 20) mm -= 20;
  if (!isDayMonth(Number(d.slice(4, 6)), mm)) return false;
  const r = weightedSum(d, [2, 4, 8, 5, 10, 9, 7, 3, 6]) % 11;
  return (r === 10 ? 0 : r) === Number(d[9]);
}

/** Czechia and Slovakia — rodné číslo. Ten digits divisible by 11, with the
 *  pre-1985 nine-digit form excluded (too short to tell from anything else).
 *  Month carries +20/+50/+70 offsets for women and for exhausted ranges. */
export function validateRodneCisloCzSk(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 10) return false;
  let mm = Number(d.slice(2, 4));
  for (const off of [70, 50, 20]) if (mm > off) mm -= off;
  if (!isDayMonth(Number(d.slice(4, 6)), mm)) return false;
  return Number(d) % 11 === 0;
}

/** Hungary — személyi azonosító. Eleven digits, weights 1..10 mod 11. */
export function validateSzemelyiHu(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 11) return false;
  if (d[0] === '0' || Number(d[0]) > 8) return false;
  if (!isDayMonth(Number(d.slice(5, 7)), Number(d.slice(3, 5)))) return false;
  const r = weightedSum(d, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) % 11;
  return r !== 10 && r === Number(d[10]);
}

/** Poland — PESEL. Eleven digits, weighted mod 10. Month carries a century
 *  offset in steps of twenty. */
export function validatePeselPl(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 11) return false;
  let mm = Number(d.slice(2, 4));
  while (mm > 12) mm -= 20;
  if (!isDayMonth(Number(d.slice(4, 6)), mm)) return false;
  const sum = weightedSum(d, [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]);
  return (10 - (sum % 10)) % 10 === Number(d[10]);
}

/** Romania — CNP. Thirteen digits against a fixed key, mod 11 with 10
 *  folding to one. */
export function validateCnpRo(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 13) return false;
  if (d[0] === '0') return false;
  if (!isDayMonth(Number(d.slice(5, 7)), Number(d.slice(3, 5)))) return false;
  const r = weightedSum(d, [2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9]) % 11;
  return (r === 10 ? 1 : r) === Number(d[12]);
}
