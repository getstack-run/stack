import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { CLI_COMMAND, invokeHint } from './auth.js';
import {
  COMMAND_ALIASES,
  COMMAND_GROUPS,
  OPTION_SECTIONS,
  commandPath,
  commandVerb,
  registeredVerbs,
  routedVerbs,
} from './commands.js';
import { README_BEGIN, README_END, renderHelp, renderReadmeCommands } from './help.js';

const SRC_DIR = fileURLToPath(new URL('.', import.meta.url));
const README_PATH = fileURLToPath(new URL('../README.md', import.meta.url));
const PACKAGE_JSON_PATH = fileURLToPath(new URL('../package.json', import.meta.url));

function read(path: string): string {
  return readFileSync(path, 'utf8').replaceAll('\r\n', '\n');
}

/** Source files that ship in the CLI: every .ts file except the tests. */
function shippedSources(): Array<{ name: string; lines: string[] }> {
  return readdirSync(SRC_DIR)
    .filter((name) => name.endsWith('.ts') && !name.endsWith('.test.ts'))
    .map((name) => ({ name, lines: read(`${SRC_DIR}${name}`).split('\n') }));
}

/** Drops whole-line comments, which may legitimately name commands loosely. */
function codeLines(lines: string[]): string[] {
  return lines.filter((line) => !/^\s*(\/\/|\/\*|\*)/.test(line));
}

describe('command registry', () => {
  it('has a unique usage and a non-empty summary for every entry', () => {
    const usages = new Set<string>();
    for (const group of COMMAND_GROUPS) {
      expect(group.entries.length, group.title).toBeGreaterThan(0);
      for (const entry of group.entries) {
        expect(entry.summary.trim(), entry.usage).not.toBe('');
        expect(commandPath(entry.usage), entry.usage).not.toBe('');
        expect(usages.has(entry.usage), `duplicate usage: ${entry.usage}`).toBe(false);
        usages.add(entry.usage);
      }
    }
    const titles = [...COMMAND_GROUPS, ...OPTION_SECTIONS].map((section) => section.title);
    expect(new Set(titles).size).toBe(titles.length);
  });

  it('keeps raw angle brackets out of summaries so the README cannot render them as HTML', () => {
    for (const group of COMMAND_GROUPS) {
      for (const entry of group.entries) expect(entry.summary, entry.usage).not.toMatch(/[<>]/);
    }
    for (const section of OPTION_SECTIONS) {
      for (const option of section.entries) expect(option.description, option.name).not.toMatch(/[<>]/);
    }
  });

  it('derives the verb path from the words before the first argument', () => {
    expect(commandPath('agent show <name|id>')).toBe('agent show');
    expect(commandPath('usage --period <p>')).toBe('usage');
    expect(commandPath('skill post-request "<desc>"')).toBe('skill post-request');
    expect(commandPath('scan "<content>" | --file <path>')).toBe('scan');
    expect(commandPath("llm anthropic messages '<body-json>' [--stream]")).toBe('llm anthropic messages');
    expect(commandVerb('fleet enroll <id> --file <path>')).toBe('fleet');
  });

  it('only aliases verbs the registry documents', () => {
    const verbs = new Set(registeredVerbs());
    for (const [verb, aliases] of Object.entries(COMMAND_ALIASES)) {
      expect(verbs.has(verb), `alias target ${verb} is not a registered verb`).toBe(true);
      for (const alias of aliases) expect(verbs.has(alias), `${alias} is also a verb`).toBe(false);
    }
  });
});

describe('router parity', () => {
  it('dispatches exactly the verbs and aliases the registry lists', () => {
    const router = read(`${SRC_DIR}index.ts`);
    const dispatched = new Set([...router.matchAll(/command === '([a-z-]+)'/g)].map((match) => match[1] as string));
    const registered = new Set(routedVerbs());
    expect([...dispatched].filter((verb) => !registered.has(verb)), 'routed but not in the registry').toEqual([]);
    expect([...registered].filter((verb) => !dispatched.has(verb)), 'in the registry but not routed').toEqual([]);
  });
});

describe('invocation name', () => {
  it('prints the documented npx form from one place', () => {
    expect(CLI_COMMAND).toBe('npx @getstackrun/cli');
    expect(invokeHint('auth login')).toBe('npx @getstackrun/cli auth login');
  });

  it('keeps the published bin name, which is not the printed form', () => {
    const manifest = JSON.parse(read(PACKAGE_JSON_PATH)) as { bin: Record<string, string> };
    expect(Object.keys(manifest.bin)).toEqual(['stack-cli']);
  });

  it('never hard-codes a program name outside invokeHint', () => {
    const offenders: string[] = [];
    const verbs = routedVerbs().join('|');
    const bareStack = new RegExp(`\\bstack (${verbs})\\b`);
    for (const { name, lines } of shippedSources()) {
      if (name === 'auth.ts') continue; // defines CLI_COMMAND
      codeLines(lines).forEach((line, index) => {
        if (line.includes('stack-cli') || bareStack.test(line)) offenders.push(`${name}: ${line.trim()} (#${index})`);
      });
    }
    expect(offenders).toEqual([]);
  });

  it('routes every usage line through invokeHint', () => {
    const offenders: string[] = [];
    for (const { name, lines } of shippedSources()) {
      for (const line of codeLines(lines)) {
        // A printed usage line starts a string literal or follows a "\n"; a bare
        // `usage:` is an object key or a parameter type.
        if (/(?:[`'"]|\\n)usage: /i.test(line) && !line.includes('invokeHint(')) offenders.push(`${name}: ${line.trim()}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('only hints at verbs the router dispatches', () => {
    const verbs = new Set(routedVerbs());
    const unknown: string[] = [];
    for (const { name, lines } of shippedSources()) {
      for (const line of codeLines(lines)) {
        for (const match of line.matchAll(/invokeHint\(\s*[`'"]([a-z-]+)/g)) {
          const verb = match[1] as string;
          if (!verbs.has(verb)) unknown.push(`${name}: ${verb}`);
        }
      }
    }
    expect(unknown).toEqual([]);
  });
});

describe('help', () => {
  const plain = renderHelp();

  it('lists every registered usage and every option', () => {
    for (const group of COMMAND_GROUPS) {
      expect(plain).toContain(group.title);
      for (const entry of group.entries) expect(plain, entry.usage).toContain(entry.usage);
    }
    for (const section of OPTION_SECTIONS) {
      expect(plain).toContain(section.title);
      for (const option of section.entries) expect(plain, option.name).toContain(option.name);
    }
  });

  it('opens with the invocation form and never prints another program name', () => {
    expect(plain).toContain(`  ${CLI_COMMAND} <command> [options]`);
    expect(plain).not.toContain('stack-cli');
    expect(plain.endsWith('\n')).toBe(true);
  });

  it('renders every code span whole, even when its text wraps', () => {
    expect(plain).not.toContain('`');
    expect(plain).not.toMatch(/auth\n\s+login/);
    expect(plain).toMatch(/Uses your\s+auth login session/);
  });

  it('substitutes the API URL into option text', () => {
    expect(renderHelp(undefined, 'https://api.example.test')).toContain('https://api.example.test/v1/public/events');
    expect(plain).not.toContain('{apiUrl}');
  });

  it('keeps the same layout when colour is on', () => {
    const palette = { reset: '\u001b[0m', dim: '\u001b[2m', gray: '\u001b[90m', cyan: '\u001b[36m', white: '\u001b[37m' };
    // eslint-disable-next-line no-control-regex
    const stripped = renderHelp(palette).replace(/\u001b\[[0-9;]*m/g, '');
    expect(stripped).toBe(plain);
  });

  it('aligns summaries in one column', () => {
    const line = plain.split('\n').find((candidate) => candidate.startsWith('  agent show <name|id>'));
    expect(line?.indexOf('Detail on one agent')).toBe(35);
  });
});

describe('README', () => {
  const readme = read(README_PATH);

  it('carries the command reference rendered from the registry', () => {
    const begin = readme.indexOf(README_BEGIN);
    const end = readme.indexOf(README_END);
    expect(begin, 'README is missing the generated-block begin marker').toBeGreaterThanOrEqual(0);
    expect(end, 'README is missing the generated-block end marker').toBeGreaterThan(begin);
    const expected = renderReadmeCommands();
    if (process.env['UPDATE_README'] === '1') {
      const updated = `${readme.slice(0, begin)}${expected}${readme.slice(end + README_END.length)}`;
      writeFileSync(README_PATH, updated);
      return;
    }
    const actual = readme.slice(begin, end + README_END.length);
    expect(
      actual,
      'README command reference is stale: run `UPDATE_README=1 pnpm --filter @getstackrun/cli test` and commit the result',
    ).toBe(expected);
  });

  it('only shows commands the router dispatches', () => {
    const verbs = new Set(routedVerbs());
    const prose = readme.slice(0, readme.indexOf(README_BEGIN)) + readme.slice(readme.indexOf(README_END));
    const unknown: string[] = [];
    for (const match of prose.matchAll(/npx @getstackrun\/cli (?!--)([a-z-]+)/g)) {
      const verb = match[1] as string;
      if (!verbs.has(verb)) unknown.push(verb);
    }
    expect(unknown).toEqual([]);
  });
});
