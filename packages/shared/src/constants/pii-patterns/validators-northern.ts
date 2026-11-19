// National-identifier validators: Nordic and Baltic states, the UK and Ireland.

import { luhnDigits, digitsOf, weightedSum, balticMod11, isDayMonth } from './checks.js';

/** Sweden — personnummer / samordningsnummer. Luhn over the ten digits
 *  YYMMDDNNNC. Samordningsnummer add 60 to the day, so the day range runs
 *  to 91. Accepts an optional century prefix (19/20) which is excluded from
 *  the Luhn window. */
export function validatePersonnummerSe(match: string): boolean {
  let d = digitsOf(match);
  if (d.length === 12) d = d.slice(2);
  if (d.length !== 10) return false;
  const mm = Number(d.slice(2, 4));
  let dd = Number(d.slice(4, 6));
  if (dd > 60) dd -= 60; // samordningsnummer
  if (!isDayMonth(dd, mm)) return false;
  return luhnDigits(d);
}

/** Norway — fødselsnummer. Eleven digits, two mod-11 control digits. */
export function validateFodselsnummerNo(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 11) return false;
  const n = [...d].map(Number) as number[];
  if (!isDayMonth(Number(d.slice(0, 2)), Number(d.slice(2, 4)))) return false;
  const w1 = [3, 7, 6, 1, 8, 9, 4, 5, 2];
  const w2 = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
  // Each control digit is 11 minus the weighted sum modulo 11; a remainder
  // of 10 makes the number invalid rather than carrying.
  const mod11 = (weights: number[]): number => {
    let sum = 0;
    for (let i = 0; i < weights.length; i++) sum += weights[i]! * n[i]!;
    const r = 11 - (sum % 11);
    return r === 11 ? 0 : r === 10 ? -1 : r;
  };
  const k1 = mod11(w1);
  if (k1 < 0 || k1 !== n[9]) return false;
  const k2 = mod11(w2);
  return k2 >= 0 && k2 === n[10];
}

/** Denmark — CPR. The modulus-11 test was abandoned in 2007 (numbers issued
 *  since then can fail it), so only the DDMMYY date is checked. */
export function validateCprDk(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 10) return false;
  return isDayMonth(Number(d.slice(0, 2)), Number(d.slice(2, 4)));
}

/** Finland — henkilötunnus. DDMMYY + century sign + ZZZ + check character,
 *  the check taken from a 31-symbol alphabet indexed by DDMMYYZZZ mod 31. */
const HETU_ALPHABET = '0123456789ABCDEFHJKLMNPRSTUVWXY';

export function validateHetuFi(match: string): boolean {
  const m = /^(\d{6})([-+A-FYXWVU])(\d{3})([0-9A-Y])$/.exec(match.trim());
  if (!m) return false;
  const [, ddmmyy, , zzz, check] = m;
  if (!isDayMonth(Number(ddmmyy!.slice(0, 2)), Number(ddmmyy!.slice(2, 4)))) return false;
  return HETU_ALPHABET[Number(ddmmyy! + zzz!) % 31] === check;
}

/** United Kingdom — National Insurance number. Format-only: there is no
 *  check digit in the scheme. */
export function validateNinoUk(match: string): boolean {
  const s = match.toUpperCase().replace(/\s/g, '');
  if (!/^[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]?$/.test(s)) return false;
  return !['BG', 'GB', 'NK', 'KN', 'TN', 'NT', 'ZZ'].includes(s.slice(0, 2));
}

/** Estonia — isikukood. Eleven digits, two-pass mod 11. First digit is a
 *  century-and-sex marker in 1-8. */
export function validateIsikukoodEe(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 11) return false;
  if (d[0] === '0' || d[0] === '9') return false;
  if (!isDayMonth(Number(d.slice(5, 7)), Number(d.slice(3, 5)))) return false;
  const check = balticMod11(d, [1, 2, 3, 4, 5, 6, 7, 8, 9, 1], [3, 4, 5, 6, 7, 8, 9, 1, 2, 3]);
  return check === Number(d[10]);
}

/** Ireland — PPS number. Seven digits, a check letter over weights 8..2, and
 *  an optional second letter which is excluded from the arithmetic. */
const PPSN_TABLE = 'WABCDEFGHIJKLMNOPQRSTUV';

export function validatePpsnIe(match: string): boolean {
  const s = match.toUpperCase().replace(/\s/g, '');
  const m = /^(\d{7})([A-W])([A-IW])?$/.exec(s);
  if (!m) return false;
  const [, digits, check, second] = m;
  let sum = weightedSum(digits!, [8, 7, 6, 5, 4, 3, 2]);
  if (second && second !== 'W') sum += (PPSN_TABLE.indexOf(second) || 0) * 9;
  return PPSN_TABLE[sum % 23] === check;
}

/** Latvia — personas kods, pre-2017 DDMMYY-NNNNN form only. Codes issued
 *  since 2017 open with 32 and carry no check digit, so they are not
 *  redactable by arithmetic and are deliberately not matched. */
export function validatePersonasKodsLv(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 11) return false;
  if (d.slice(0, 2) === '32') return false;
  if (!isDayMonth(Number(d.slice(0, 2)), Number(d.slice(2, 4)))) return false;
  const r = (1101 - weightedSum(d, [1, 6, 3, 7, 9, 10, 5, 8, 4, 2])) % 11;
  return r % 10 === Number(d[10]);
}

/** Lithuania — asmens kodas. Eleven digits, two-pass mod 11, leading digit
 *  is a century-and-sex marker in 1-6. */
export function validateAsmensKodasLt(match: string): boolean {
  const d = digitsOf(match);
  if (d.length !== 11) return false;
  if (Number(d[0]) < 1 || Number(d[0]) > 6) return false;
  if (!isDayMonth(Number(d.slice(5, 7)), Number(d.slice(3, 5)))) return false;
  const check = balticMod11(d, [1, 2, 3, 4, 5, 6, 7, 8, 9, 1], [3, 4, 5, 6, 7, 8, 9, 1, 2, 3]);
  return check === Number(d[10]);
}
