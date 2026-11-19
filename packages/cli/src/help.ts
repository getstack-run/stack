// Renders the command registry (commands.ts) as `--help` text and as the
// command reference in README.md. Pure functions: no process access, so
// commands.test.ts can call them directly.

import { CLI_COMMAND, invokeHint } from './auth.js';
import {
  COMMAND_GROUPS,
  HELP_EXAMPLES,
  OPTION_SECTIONS,
  commandPath,
  type CommandEntry,
} from './commands.js';

export interface Palette {
  readonly reset: string;
  readonly dim: string;
  readonly gray: string;
  readonly cyan: string;
  readonly white: string;
}

export const PLAIN_PALETTE: Palette = { reset: '', dim: '', gray: '', cyan: '', white: '' };

/** The default API base URL, shown in option text when none is supplied. */
export const DEFAULT_API_URL = 'https://api.getstack.run';

const TOTAL_WIDTH = 100;
// Summaries start at this column, so a usage of up to SUMMARY_COLUMN - 2
// characters (two spaces of indent) fits on the same line.
const SUMMARY_COLUMN = 35;
const OPTION_COLUMN = 27;

const NO_BREAK_SPACE = ' ';

/**
 * Greedy word wrap to `width` columns; never splits a word or a `code` span.
 * Spaces inside a code span come back as no-break spaces: `highlight` turns
 * them into plain spaces once the span is coloured.
 */
function wrap(text: string, width: number): string[] {
  const lines: string[] = [];
  let current = '';
  const protectedText = text.replace(/`[^`]+`/g, (span) => span.replaceAll(' ', NO_BREAK_SPACE));
  for (const word of protectedText.split(/ +/).filter(Boolean)) {
    if (current && current.length + 1 + word.length > width) {
      lines.push(current);
      current = word;
    } else {
      current = current ? `${current} ${word}` : word;
    }
  }
  if (current) lines.push(current);
  return lines;
}

/** Highlight `code` spans in `--help` output. */
function highlight(text: string, p: Palette): string {
  return text
    .replace(/`([^`]+)`/g, (_, code: string) => `${p.cyan}${code}${p.reset}`)
    .replaceAll(NO_BREAK_SPACE, ' ');
}

/** The text column for one entry: `left` occupies the indent and `column` wide. */
function renderColumns(left: string, leftVisible: number, column: number, text: readonly string[]): string[] {
  const [first, ...rest] = text;
  const pad = ' '.repeat(column);
  if (first === undefined) return [left];
  const lines: string[] = [];
  if (leftVisible < column) {
    lines.push(`${left}${' '.repeat(column - leftVisible)}${first}`);
  } else {
    lines.push(left, `${pad}${first}`);
  }
  for (const line of rest) lines.push(`${pad}${line}`);
  return lines;
}

function renderEntry(entry: CommandEntry, p: Palette): string[] {
  const path = commandPath(entry.usage);
  const left = `  ${p.cyan}${path}${p.reset}${entry.usage.slice(path.length)}`;
  const width = TOTAL_WIDTH - SUMMARY_COLUMN;
  const text = [...wrap(entry.summary, width), ...(entry.notes ?? []).flatMap((note) => wrap(note, width))];
  return renderColumns(left, 2 + entry.usage.length, SUMMARY_COLUMN, text.map((line) => highlight(line, p)));
}

/** The full `--help` text. */
export function renderHelp(p: Palette = PLAIN_PALETTE, apiUrl: string = DEFAULT_API_URL): string {
  const out: string[] = [
    'STACK. Command over every AI agent you deploy, from your terminal.',
    `${p.gray}https://getstack.run${p.reset}`,
    '',
    `${p.white}Usage${p.reset}`,
    `  ${CLI_COMMAND} ${p.cyan}<command>${p.reset} [options]`,
    '',
  ];

  for (const group of COMMAND_GROUPS) {
    out.push(`${p.white}${group.title}${p.reset}`);
    for (const entry of group.entries) out.push(...renderEntry(entry, p));
    if (group.footnote) {
      out.push('');
      for (const line of group.footnote.split('\n')) out.push(`${p.dim}${line}${p.reset}`);
    }
    out.push('');
  }

  for (const section of OPTION_SECTIONS) {
    out.push(`${p.white}${section.title}${p.reset}`);
    for (const option of section.entries) {
      const text = wrap(option.description.replaceAll('{apiUrl}', apiUrl), TOTAL_WIDTH - OPTION_COLUMN).map((line) =>
        highlight(line, p),
      );
      out.push(...renderColumns(`  ${option.name}`, 2 + option.name.length, OPTION_COLUMN, text));
    }
    out.push('');
  }

  out.push(`${p.white}Examples${p.reset}`);
  HELP_EXAMPLES.forEach((example, index) => {
    for (const line of example.comment) out.push(`  ${p.gray}# ${line}${p.reset}`);
    for (const step of example.steps) out.push(`  ${'cli' in step ? invokeHint(step.cli) : step.shell}`);
    if (index < HELP_EXAMPLES.length - 1) out.push('');
  });

  return `${out.join('\n')}\n`;
}

// ── README ──────────────────────────────────────────────────────────

export const README_BEGIN = '<!-- commands:begin (generated from src/commands.ts by help.ts; do not edit by hand) -->';
export const README_END = '<!-- commands:end -->';

function tableCell(text: string): string {
  return text.replaceAll('|', '\\|');
}

function codeCell(text: string): string {
  return `\`${tableCell(text)}\``;
}

/** The generated command reference that lives between the README markers. */
export function renderReadmeCommands(apiUrl: string = DEFAULT_API_URL): string {
  const out: string[] = [README_BEGIN, ''];

  for (const group of COMMAND_GROUPS) {
    out.push(`#### ${group.title}`, '', '| Command | What it does |', '| --- | --- |');
    for (const entry of group.entries) {
      const detail = [tableCell(entry.summary), ...(entry.notes ?? []).map(codeCell)].join('<br>');
      out.push(`| ${codeCell(entry.usage)} | ${detail} |`);
    }
    out.push('');
  }

  for (const section of OPTION_SECTIONS) {
    out.push(`#### ${section.title}`, '', '| Name | What it does |', '| --- | --- |');
    for (const option of section.entries) {
      out.push(`| ${codeCell(option.name)} | ${tableCell(option.description.replaceAll('{apiUrl}', apiUrl))} |`);
    }
    out.push('');
  }

  out.push(README_END);
  return out.join('\n');
}
