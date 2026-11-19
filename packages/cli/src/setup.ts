import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { stdout, stderr } from 'node:process';
import { createInterface } from 'node:readline/promises';
import { invokeHint } from './auth.js';

const STACK_MCP_URL = 'https://mcp.getstack.run/mcp';

export type SupportedMcpClient = 'claude' | 'codex' | 'cursor';

interface DetectedClient {
  id: SupportedMcpClient;
  label: string;
  executable: string;
}

interface CommandResult {
  status: number;
  stdout: string;
  stderr: string;
}

const CLIENTS: ReadonlyArray<{ id: SupportedMcpClient; label: string; commands: string[] }> = [
  { id: 'claude', label: 'Claude Code', commands: ['claude'] },
  { id: 'codex', label: 'Codex', commands: ['codex'] },
  { id: 'cursor', label: 'Cursor', commands: ['cursor'] },
];

/**
 * One Windows command line for a .cmd/.bat shim. Node can only start those
 * through cmd.exe, and passing an argument array with `shell: true` joins it
 * unquoted (Node warns DEP0190): `--add-mcp {"name":"stack",...}` reaches the
 * client mangled. Every argument here is a fixed string from this file, so
 * each is quoted for the C runtime that parses it, and anything cmd.exe would
 * still expand inside quotes is refused rather than escaped.
 */
export function windowsCommandLine(executable: string, args: readonly string[]): string {
  const quote = (value: string): string => {
    if (/[%!\r\n\0]/.test(value)) throw new Error('setup argument contains a character cmd.exe would expand.');
    return `"${value.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, '$1$1')}"`;
  };
  return [executable, ...args].map(quote).join(' ');
}

function run(
  executable: string,
  args: string[],
  inherit = false,
): CommandResult {
  const viaShell = process.platform === 'win32' && /\.(cmd|bat)$/i.test(executable);
  const result: SpawnSyncReturns<string> = viaShell
    ? spawnSync(windowsCommandLine(executable, args), {
      encoding: 'utf8',
      stdio: inherit ? 'inherit' : 'pipe',
      shell: true,
      windowsVerbatimArguments: true,
    })
    : spawnSync(executable, args, {
      encoding: 'utf8',
      stdio: inherit ? 'inherit' : 'pipe',
    });
  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? result.error?.message ?? '',
  };
}

function findExecutable(command: string): string | undefined {
  const locator = process.platform === 'win32' ? 'where.exe' : 'which';
  const result = run(locator, [command]);
  if (result.status !== 0) return undefined;
  return result.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .sort((a, b) => {
      const rank = (value: string): number =>
        /\.exe$/i.test(value) ? 0 : /\.cmd$/i.test(value) ? 1 : /\.bat$/i.test(value) ? 2 : 3;
      return rank(a) - rank(b);
    })[0];
}

/**
 * The value of `--clients`: every argument after the flag up to the next flag,
 * joined with commas. PowerShell splits `--clients claude,cursor` into
 * separate arguments, so the CLI sees `claude cursor`. `--clients=a,b` works too.
 */
export function clientsArgument(args: string[]): string | undefined {
  const missing = '--clients requires at least one client: claude, codex, cursor or all.';
  const joined = args.find((arg) => arg.startsWith('--clients='));
  if (joined !== undefined) {
    const value = joined.slice('--clients='.length);
    if (!value.trim()) throw new Error(missing);
    return value;
  }
  const index = args.indexOf('--clients');
  if (index === -1) return undefined;
  const values: string[] = [];
  for (const arg of args.slice(index + 1)) {
    if (arg.startsWith('--')) break;
    values.push(arg);
  }
  if (values.length === 0) throw new Error(missing);
  return values.join(',');
}

export function parseClientSelection(
  value: string,
  detected: ReadonlyArray<Pick<DetectedClient, 'id'>>,
): SupportedMcpClient[] {
  const available = new Set(detected.map((client) => client.id));
  const normalized = value.trim().toLowerCase();
  if (normalized === 'all') return [...available];

  const selected: SupportedMcpClient[] = [];
  for (const item of normalized.split(/[\s,]+/).filter(Boolean)) {
    const id = item as SupportedMcpClient;
    if (!CLIENTS.some((client) => client.id === id)) {
      throw new Error(`unsupported MCP client "${item}". Use claude, codex, or cursor.`);
    }
    if (!available.has(id)) {
      throw new Error(`${id} is not installed or is not on PATH.`);
    }
    if (!selected.includes(id)) selected.push(id);
  }
  if (selected.length === 0) throw new Error('select at least one MCP client.');
  return selected;
}

export function setupCommands(client: SupportedMcpClient): ReadonlyArray<ReadonlyArray<string>> {
  if (client === 'claude') {
    return [
      ['mcp', 'add', '--transport', 'http', '--scope', 'user', 'stack', STACK_MCP_URL],
      ['mcp', 'login', 'stack'],
      ['mcp', 'get', 'stack'],
    ];
  }
  if (client === 'codex') {
    return [
      ['mcp', 'add', 'stack', '--url', STACK_MCP_URL],
      ['mcp', 'login', 'stack'],
      ['mcp', 'get', 'stack', '--json'],
    ];
  }
  // Cursor is configured by file (mergeCursorMcpConfig), not by a command:
  // its `--add-mcp` flag is inherited from VS Code and writes a VS Code
  // `mcp.servers` entry to settings.json, which Cursor's MCP client never reads.
  return [];
}

/** Cursor's user-level MCP configuration file. */
export function cursorMcpConfigPath(home = homedir()): string {
  return join(home, '.cursor', 'mcp.json');
}

/**
 * Add STACK to Cursor's mcp.json text, keeping every other server and key.
 * Returns null when STACK is already configured at the same URL. Refuses to
 * touch a file it cannot parse, or a different server already named stack,
 * rather than overwriting the user's configuration.
 */
export function mergeCursorMcpConfig(existing: string | null): string | null {
  let config: Record<string, unknown> = {};
  if (existing !== null && existing.trim() !== '') {
    try {
      config = JSON.parse(existing) as Record<string, unknown>;
    } catch {
      throw new Error(`${cursorMcpConfigPath()} is not valid JSON. Fix or move it, then run setup again.`);
    }
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
      throw new Error(`${cursorMcpConfigPath()} is not a JSON object. Fix or move it, then run setup again.`);
    }
  }
  const servers = config['mcpServers'] ?? {};
  if (!servers || typeof servers !== 'object' || Array.isArray(servers)) {
    throw new Error(`mcpServers in ${cursorMcpConfigPath()} is not an object. Fix it, then run setup again.`);
  }
  const current = (servers as Record<string, unknown>)['stack'] as { url?: unknown } | undefined;
  if (current !== undefined) {
    if (current && typeof current === 'object' && current.url === STACK_MCP_URL) return null;
    throw new Error('Cursor already has an MCP server named stack with a different configuration. Remove or rename it first.');
  }
  return `${JSON.stringify({ ...config, mcpServers: { ...servers, stack: { url: STACK_MCP_URL } } }, null, 2)}\n`;
}

function inspectCommand(client: SupportedMcpClient): string[] | undefined {
  if (client === 'claude') return ['mcp', 'get', 'stack'];
  if (client === 'codex') return ['mcp', 'get', 'stack', '--json'];
  return undefined;
}

function detectClients(): DetectedClient[] {
  return CLIENTS.flatMap((client) => {
    for (const command of client.commands) {
      const executable = findExecutable(command);
      if (executable) return [{ id: client.id, label: client.label, executable }];
    }
    return [];
  });
}

async function chooseClients(detected: DetectedClient[], requested?: string): Promise<DetectedClient[]> {
  if (requested) {
    const selected = new Set(parseClientSelection(requested, detected));
    return detected.filter((client) => selected.has(client.id));
  }

  if (!process.stdin.isTTY) {
    throw new Error('use --clients claude,codex,cursor (commas or spaces) when setup has no interactive terminal.');
  }

  stdout.write('\nDetected MCP clients:\n\n');
  detected.forEach((client, index) => stdout.write(`  ${index + 1}. ${client.label}\n`));
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = (await rl.question('\nChoose one or several clients. Use numbers separated by commas: ')).trim();
    const selectedIndexes = new Set(
      answer.split(',').map((part) => Number.parseInt(part.trim(), 10) - 1),
    );
    if ([...selectedIndexes].some((index) => !Number.isInteger(index) || !detected[index])) {
      throw new Error('the client selection is not valid.');
    }
    return detected.filter((_client, index) => selectedIndexes.has(index));
  } finally {
    rl.close();
  }
}

function configuredAtStackUrl(client: DetectedClient): boolean {
  const inspect = inspectCommand(client.id);
  if (!inspect) return false;
  const result = run(client.executable, inspect);
  if (result.status !== 0) return false;
  if (!result.stdout.includes(STACK_MCP_URL)) {
    throw new Error(
      `${client.label} already has an MCP server named stack with a different URL. Remove or rename it first.`,
    );
  }
  if (client.id === 'claude' && !/^\s*Scope:\s*User\b/im.test(result.stdout)) {
    return false;
  }
  return true;
}

function claudeConnectionIsLive(client: DetectedClient): boolean {
  if (client.id !== 'claude') return false;
  const result = run(client.executable, ['mcp', 'get', 'stack']);
  return result.status === 0 && /^\s*Status:\s*.*Connected\b/im.test(result.stdout);
}

/**
 * The stack server's auth_status from `codex mcp list --json`, or undefined
 * when it cannot be read. Codex signs in by itself when `mcp add` detects
 * OAuth, so setup must not start a second sign-in after it.
 */
export function codexAuthStatus(listJson: string): string | undefined {
  try {
    const servers = JSON.parse(listJson) as Array<{ name?: unknown; auth_status?: unknown }>;
    const stack = Array.isArray(servers) ? servers.find((server) => server?.name === 'stack') : undefined;
    return typeof stack?.auth_status === 'string' ? stack.auth_status : undefined;
  } catch {
    return undefined;
  }
}

/** Signed in only when Codex reports a status other than not_logged_in. Unknown counts as signed out. */
export function codexIsSignedIn(status: string | undefined): boolean {
  return status !== undefined && status !== 'not_logged_in' && status !== 'unsupported';
}

function codexConnectionIsLive(client: DetectedClient): boolean {
  if (client.id !== 'codex') return false;
  const result = run(client.executable, ['mcp', 'list', '--json']);
  return result.status === 0 && codexIsSignedIn(codexAuthStatus(result.stdout));
}

/**
 * `claude mcp login` refuses to start when stdin is not a terminal, which is
 * the case whenever an AI client runs setup for the user. Setup then leaves
 * the sign-in to the user's next Claude Code session instead of failing.
 */
export function signInMode(client: SupportedMcpClient, stdinIsTTY: boolean): 'login' | 'hand-off' {
  return client === 'claude' && !stdinIsTTY ? 'hand-off' : 'login';
}

export function claudeSignInHandOff(): string {
  return [
    '  Claude Code signs in only from an interactive terminal, so STACK is added but not signed in yet.',
    '  Open a new Claude Code session, run /mcp, choose stack and sign in.',
    '  Or run in a terminal: claude mcp login stack',
    '  Then in Claude Code, enter: List my STACK agents.',
    '',
  ].join('\n');
}

function configureClient(client: DetectedClient): void {
  const commands = setupCommands(client.id);
  const commandAt = (index: number): string[] => {
    const command = commands[index];
    if (!command) throw new Error(`no setup command exists for ${client.label}.`);
    return [...command];
  };
  stdout.write(`\n${client.label}:\n`);

  if (client.id === 'cursor') {
    const path = cursorMcpConfigPath();
    const existing = existsSync(path) ? readFileSync(path, 'utf8') : null;
    const merged = mergeCursorMcpConfig(existing);
    if (merged === null) {
      stdout.write(`  STACK already uses ${STACK_MCP_URL} in ${path}.\n`);
    } else {
      mkdirSync(dirname(path), { recursive: true });
      const temp = `${path}.${process.pid}.tmp`;
      writeFileSync(temp, merged, 'utf8');
      renameSync(temp, path);
      stdout.write(`  Added STACK at ${STACK_MCP_URL} to ${path}.\n`);
    }
    stdout.write('  Restart Cursor, or open Settings > MCP, and sign in to stack when asked.\n');
    stdout.write('  Then in Cursor chat, enter: List my STACK agents.\n');
    return;
  }

  if (configuredAtStackUrl(client)) {
    stdout.write(`  STACK already uses ${STACK_MCP_URL}.\n`);
  } else {
    const add = run(client.executable, commandAt(0), true);
    if (add.status !== 0) throw new Error(`${client.label} did not accept the MCP configuration.`);
    stdout.write(`  Added STACK at ${STACK_MCP_URL}.\n`);
  }

  if (claudeConnectionIsLive(client) || codexConnectionIsLive(client)) {
    stdout.write('  The STACK sign-in is active.\n');
  } else if (signInMode(client.id, process.stdin.isTTY === true) === 'hand-off') {
    stdout.write(claudeSignInHandOff());
    return;
  } else {
    stdout.write('  Starting STACK sign-in.\n');
    const login = run(client.executable, commandAt(1), true);
    if (login.status !== 0) throw new Error(`${client.label} did not complete STACK sign-in.`);
  }

  const verify = run(client.executable, commandAt(2));
  if (verify.status !== 0) throw new Error(`${client.label} could not read the STACK MCP configuration.`);
  if (client.id === 'claude') {
    if (!/^\s*Status:\s*.*Connected\b/im.test(verify.stdout)) {
      throw new Error('Claude Code did not report a live STACK connection.');
    }
    stdout.write('  Claude Code confirmed the STACK server connection.\n');
    stdout.write('  Claude Code does not expose its live MCP tool list through this command.\n');
    stdout.write('  In Claude Code, enter: List my STACK agents.\n');
  } else {
    stdout.write('  Codex confirmed the STACK server configuration.\n');
    stdout.write('  Codex does not expose live MCP tool discovery through its CLI.\n');
    stdout.write('  Start a new Codex session. Then enter: List my STACK agents.\n');
  }
}

/**
 * What setup says when no MCP client is installed: both ways forward, each a
 * command the user can run now.
 */
export function noClientMessage(): string {
  return [
    'error: no supported MCP client was found.',
    `  To use STACK from this terminal, sign in: ${invokeHint('auth login')}`,
    `  To use STACK from an AI client, install Claude Code, Codex or Cursor, then run: ${invokeHint('setup')}`,
    '',
  ].join('\n');
}

export async function cmdSetup(args: string[]): Promise<void> {
  let requested: string | undefined;
  try {
    requested = clientsArgument(args);
  } catch (error) {
    stderr.write(`error: ${(error as Error).message}\n`);
    process.exitCode = 2;
    return;
  }

  const detected = detectClients();
  if (detected.length === 0) {
    stderr.write(noClientMessage());
    process.exitCode = 1;
    return;
  }

  let selected: DetectedClient[];
  try {
    selected = await chooseClients(detected, requested);
  } catch (error) {
    stderr.write(`error: ${(error as Error).message}\n`);
    process.exitCode = 2;
    return;
  }

  let failures = 0;
  for (const client of selected) {
    try {
      configureClient(client);
    } catch (error) {
      failures += 1;
      stderr.write(`  error: ${(error as Error).message}\n`);
    }
  }
  if (failures > 0) process.exitCode = 1;
}
