import { readFileSync } from 'node:fs';
import { takeFlag } from './api.js';
import { readSecretFromStdin } from './secret-input.js';

// Argument helpers shared by the agent-account commands (`account ...`):
// flags that take a value, positionals, and the account agent's Passport,
// which is a secret and so is read from stdin and never from argv.

export function flag(args: string[], name: string): string | undefined {
  const value = takeFlag(args, name);
  if (value === true) throw new Error(`${name} needs a value`);
  return typeof value === 'string' ? value : undefined;
}

export function required(args: string[], name: string): string {
  const value = flag(args, name);
  if (value === undefined) throw new Error(`${name} is required`);
  return value;
}

export function wholeNumber(args: string[], name: string): number | undefined {
  const value = flag(args, name);
  if (value === undefined) return undefined;
  if (!/^\d+$/.test(value)) throw new Error(`${name} must be a whole number`);
  return Number(value);
}

/** A flag that never takes a value, so it cannot swallow the positional after it. */
export function takeSwitch(args: string[], name: string): boolean {
  const index = args.indexOf(name);
  if (index === -1) return false;
  args.splice(index, 1);
  return true;
}

export function accountPath(args: string[]): string {
  const id = args.shift();
  if (!id || id.startsWith('--')) throw new Error('Invalid input: account id is required');
  return `/v1/accounts/${encodeURIComponent(id)}`;
}

export function positional(args: string[], what: string): string {
  const value = args[0] && !args[0].startsWith('--') ? args.shift() : undefined;
  if (!value) throw new Error(`Invalid input: ${what} is required`);
  return value;
}

export const PASSPORT_ARGV_FLAGS = new Set(['--passport', '--passport-token', '--token']);

export function refusePassportInArgv(args: string[]): void {
  if (args.some((arg) => PASSPORT_ARGV_FLAGS.has(arg.split('=')[0] ?? arg))) {
    throw new Error('Passport tokens must not be placed in argv. Pipe the token on stdin or type it at the hidden prompt.');
  }
}

export async function readPassport(): Promise<string> {
  const token = await readSecretFromStdin('Passport token: ');
  if (!token) throw new Error("No Passport token: pipe the account agent's Passport on stdin or type it at the prompt");
  return token;
}

export function passportHeaders(token: string | undefined): { headers?: Record<string, string> } {
  return token === undefined ? {} : { headers: { 'X-Passport-Token': token } };
}

/** A JSON object read from `--file`; anything else is refused. */
export function readJsonObjectFile(file: string): Record<string, unknown> {
  const value: unknown = JSON.parse(readFileSync(file, 'utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid input: --file must hold a JSON object');
  return value as Record<string, unknown>;
}

/**
 * A budget in dollars (`25`, `25.5`, `25.50`) as whole USD cents, or `null` for `none`. Read as a decimal string, so
 * there is no floating-point error. Zero, negative, non-numeric and more than two decimals are refused.
 */
export function budgetCents(value: string): number | null {
  if (value === 'none') return null;
  const match = /^(\d+)(?:\.(\d{1,2}))?$/.exec(value);
  if (!match) throw new Error('Invalid input: the budget is dollars with at most two decimals (25 or 25.50), or none to remove it');
  const cents = Number(match[1]) * 100 + Number((match[2] ?? '').padEnd(2, '0'));
  if (!Number.isSafeInteger(cents) || cents <= 0) throw new Error('Invalid input: the budget must be more than zero, or none to remove it');
  return cents;
}
