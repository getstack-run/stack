import { describe, expect, it } from 'vitest';
import {
  claudeSignInHandOff, clientsArgument, codexAuthStatus, codexIsSignedIn, cursorMcpConfigPath, mergeCursorMcpConfig, noClientMessage,
  parseClientSelection, setupCommands, signInMode, windowsCommandLine,
} from './setup.js';

describe('Claude Code sign-in when setup has no terminal', () => {
  it('hands the sign-in to the next Claude Code session instead of running a login that cannot start', () => {
    expect(signInMode('claude', false)).toBe('hand-off');
    expect(signInMode('claude', true)).toBe('login');
    expect(signInMode('codex', false)).toBe('login');
    const text = claudeSignInHandOff();
    expect(text).toContain('run /mcp, choose stack and sign in');
    expect(text).toContain('claude mcp login stack');
  });
});

describe('setup with no MCP client installed', () => {
  it('names a command that signs in from the terminal, and how to add a client later', () => {
    const message = noClientMessage();
    expect(message).toContain('npx @getstackrun/cli auth login');
    expect(message).toContain('then run: npx @getstackrun/cli setup');
    expect(message).toMatch(/Claude Code, Codex or Cursor/);
  });
});

describe('setup client selection', () => {
  const detected = [{ id: 'claude' as const }, { id: 'codex' as const }, { id: 'cursor' as const }];

  it('accepts one or several installed clients', () => {
    expect(parseClientSelection('claude,codex', detected)).toEqual(['claude', 'codex']);
    expect(parseClientSelection('all', detected)).toEqual(['claude', 'codex', 'cursor']);
  });

  it('splits on spaces as well as commas', () => {
    expect(parseClientSelection('claude cursor', detected)).toEqual(['claude', 'cursor']);
    expect(parseClientSelection('claude, cursor', detected)).toEqual(['claude', 'cursor']);
  });

  it('reads several values after --clients, as PowerShell delivers a comma list', () => {
    expect(clientsArgument(['--clients', 'claude', 'cursor'])).toBe('claude,cursor');
    expect(clientsArgument(['--clients', 'claude,cursor'])).toBe('claude,cursor');
    expect(clientsArgument(['--clients', 'claude,', 'cursor'])).toBe('claude,,cursor');
    expect(clientsArgument(['--clients', 'claude,codex', 'cursor'])).toBe('claude,codex,cursor');
    expect(clientsArgument(['--clients', 'claude', 'cursor', '--other'])).toBe('claude,cursor');
    expect(clientsArgument(['--clients=claude,cursor'])).toBe('claude,cursor');
    expect(clientsArgument(['--other'])).toBeUndefined();
    expect(clientsArgument([])).toBeUndefined();
    expect(() => clientsArgument(['--clients'])).toThrow('--clients requires at least one client');
    expect(() => clientsArgument(['--clients', '--x'])).toThrow('--clients requires at least one client');
    expect(() => clientsArgument(['--clients='])).toThrow('--clients requires at least one client');
    const value = clientsArgument(['--clients', 'claude', 'cursor'])!;
    expect(parseClientSelection(value, detected)).toEqual(['claude', 'cursor']);
  });

  it('rejects unsupported and missing clients', () => {
    expect(() => parseClientSelection('windsurf', detected)).toThrow('unsupported MCP client');
    expect(() => parseClientSelection('cursor', detected.slice(0, 2))).toThrow('not installed');
  });
});

describe('setup native commands', () => {
  it('uses Claude Code user configuration and OAuth', () => {
    expect(setupCommands('claude')).toEqual([
      ['mcp', 'add', '--transport', 'http', '--scope', 'user', 'stack', 'https://mcp.getstack.run/mcp'],
      ['mcp', 'login', 'stack'],
      ['mcp', 'get', 'stack'],
    ]);
  });

  it('uses Codex streamable HTTP configuration and OAuth', () => {
    expect(setupCommands('codex')).toEqual([
      ['mcp', 'add', 'stack', '--url', 'https://mcp.getstack.run/mcp'],
      ['mcp', 'login', 'stack'],
      ['mcp', 'get', 'stack', '--json'],
    ]);
  });

  it('configures Cursor by file, not through the VS Code --add-mcp flag', () => {
    expect(setupCommands('cursor')).toEqual([]);
  });
});

describe('codex sign-in detection', () => {
  const listed = (auth_status: string) => JSON.stringify([
    { name: 'other', auth_status: 'o_auth' },
    { name: 'stack', enabled: true, auth_status },
  ]);

  it('skips the second sign-in when codex mcp add already signed in', () => {
    expect(codexIsSignedIn(codexAuthStatus(listed('o_auth')))).toBe(true);
    expect(codexIsSignedIn(codexAuthStatus(listed('bearer_token')))).toBe(true);
  });

  it('signs in when codex reports stack signed out, or cannot be read', () => {
    expect(codexIsSignedIn(codexAuthStatus(listed('not_logged_in')))).toBe(false);
    expect(codexIsSignedIn(codexAuthStatus(listed('unsupported')))).toBe(false);
    expect(codexIsSignedIn(codexAuthStatus('[{"name":"other","auth_status":"o_auth"}]'))).toBe(false);
    expect(codexIsSignedIn(codexAuthStatus('not json'))).toBe(false);
    expect(codexIsSignedIn(codexAuthStatus('{}'))).toBe(false);
  });
});

describe('windows command line for .cmd client shims', () => {
  it('quotes every argument so a JSON argument arrives intact', () => {
    const exe = 'C:\\Program Files\\Claude\\claude.cmd';
    expect(windowsCommandLine(exe, ['mcp', '{"name":"stack"}', 'C:\\dir\\']))
      .toBe('"C:\\Program Files\\Claude\\claude.cmd" "mcp" "{\\"name\\":\\"stack\\"}" "C:\\dir\\\\"');
  });

  it('refuses characters cmd.exe expands inside quotes', () => {
    expect(() => windowsCommandLine('claude.cmd', ['%PATH%'])).toThrow();
    expect(() => windowsCommandLine('claude.cmd', ['a!b'])).toThrow();
  });
});

describe('cursor mcp.json', () => {
  const url = 'https://mcp.getstack.run/mcp';

  it('lives in the user .cursor folder', () => {
    expect(cursorMcpConfigPath('/home/u').replace(/\\/g, '/')).toBe('/home/u/.cursor/mcp.json');
  });

  it('creates the file when it does not exist', () => {
    expect(JSON.parse(mergeCursorMcpConfig(null)!)).toEqual({ mcpServers: { stack: { url } } });
    expect(JSON.parse(mergeCursorMcpConfig('  ')!)).toEqual({ mcpServers: { stack: { url } } });
  });

  it('keeps every existing server and top-level key', () => {
    const existing = JSON.stringify({ other: 1, mcpServers: { github: { command: 'gh', args: ['mcp'] } } });
    expect(JSON.parse(mergeCursorMcpConfig(existing)!)).toEqual({
      other: 1,
      mcpServers: { github: { command: 'gh', args: ['mcp'] }, stack: { url } },
    });
  });

  it('does nothing when STACK is already configured', () => {
    expect(mergeCursorMcpConfig(JSON.stringify({ mcpServers: { stack: { url } } }))).toBeNull();
  });

  it('never overwrites a file it cannot read or a different stack server', () => {
    expect(() => mergeCursorMcpConfig('{ not json')).toThrow('not valid JSON');
    expect(() => mergeCursorMcpConfig('[]')).toThrow('not a JSON object');
    expect(() => mergeCursorMcpConfig('{"mcpServers": []}')).toThrow('mcpServers');
    expect(() => mergeCursorMcpConfig(JSON.stringify({ mcpServers: { stack: { url: 'https://evil.example/mcp' } } })))
      .toThrow('different configuration');
  });
});
