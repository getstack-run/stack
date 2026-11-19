// Conformance suite for which tools an MCP server lists to a session (spec/mcp-tools/SPEC.md
// section 11): the audience and pieces rules, the load-on-demand hint in `_meta`, the
// directory profile that is never narrowed, and `notifications/tools/list_changed`.
//
// You give it a way to open a session on your server and the catalog it is to be judged against
// (the `tools.json` of the specification, or the part of it your server serves). The kit
// implements the listing rule itself, from the specification, and compares what your server
// lists with it, tool by tool.
//
//   open({ audience, pieces, profile })   opens a session and returns it:
//     {
//       listTools(): Promise<{ name: string, _meta?: object }[]>,   every page of `tools/list`
//       callTool(name, args): Promise<{ isError?: boolean }>,        rejecting, or isError, for a tool not listed
//       onToolListChanged(handler): void,                            handler runs for each `notifications/tools/list_changed`
//       setPieces?(pieces: string[]): Promise<void>,                 makes the account's pieces these; absent: the change checks are skipped
//       close?(): Promise<void>,
//     }
//   `audience` is `agent` or `owner`, `pieces` the account pieces that are on, `profile` `standard` or `directory`.
//
// A check that needs a handle you did not provide is reported as skipped, never as passed.

import { assert, runChecks, skip } from './harness.mjs';

export const ALWAYS_LOAD_KEY = 'anthropic/alwaysLoad';

/**
 * The listing rule of section 11, written from the specification. An `owner` tool is for an owner's
 * or a member's session only and is listed whether or not its piece is on; an `agent` tool is for an
 * agent's session only; a tool with no pieces is the core; a tool of pieces is listed while a piece
 * it names is on.
 */
export function isListed(tool, session) {
  if (tool.audience === 'owner') return session.audience === 'owner';
  if (tool.audience === 'agent' && session.audience !== 'agent') return false;
  if (tool.pieces.length === 0) return true;
  return tool.pieces.some((piece) => session.pieces.includes(piece));
}

const sorted = (names) => [...names].sort();
const sameNames = (a, b) => {
  const left = sorted(a);
  const right = sorted(b);
  return left.length === right.length && left.every((name, i) => name === right[i]);
};

function diff(expected, actual) {
  const e = new Set(expected);
  const a = new Set(actual);
  const missing = [...e].filter((n) => !a.has(n));
  const extra = [...a].filter((n) => !e.has(n));
  const show = (names) => names.slice(0, 5).join(', ') + (names.length > 5 ? `, and ${names.length - 5} more` : '');
  return [missing.length ? `not listed but should be: ${show(missing)}` : '', extra.length ? `listed but should not be: ${show(extra)}` : ''].filter(Boolean).join('; ');
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * @param {{
 *   open: (options: { audience: 'agent' | 'owner', pieces: string[], profile: 'standard' | 'directory' }) => Promise<object>,
 *   catalog: { tools: Array<{ name: string, audience: string, pieces: string[], on_demand: boolean, profiles: string[] }> } | Array<object>,
 *   settleMs?: number,
 * }} options
 */
export async function runMcpListingSuite(options) {
  const { open, settleMs = 300 } = options;
  const tools = Array.isArray(options.catalog) ? options.catalog : options.catalog.tools;
  if (typeof open !== 'function' || !Array.isArray(tools) || tools.length === 0) throw new Error('give the mcp-listing suite an open function and a catalog with tools');
  const names = new Set(tools.map((t) => t.name));
  const standard = tools.filter((t) => t.profiles.includes('standard'));
  const pieces = sorted(new Set(tools.flatMap((t) => t.pieces)));

  const sessions = [];
  async function session(audience, piecesOn, profile = 'standard') {
    const s = await open({ audience, pieces: piecesOn, profile });
    sessions.push(s);
    return s;
  }
  /** The names of catalog tools a session lists (tools the catalog does not know are not judged). */
  const listedOf = async (s) => (await s.listTools()).filter((t) => names.has(t.name));
  const expectedFor = (audience, piecesOn) => standard.filter((t) => isListed(t, { audience, pieces: piecesOn })).map((t) => t.name);

  const checkRule = async (audience, piecesOn) => {
    const s = await session(audience, piecesOn);
    const actual = (await listedOf(s)).map((t) => t.name);
    const expected = expectedFor(audience, piecesOn);
    assert(sameNames(expected, actual), `${audience} session, pieces [${piecesOn.join(', ')}]: ${diff(expected, actual)}`);
  };

  const report = await runChecks('mcp tool listing', [
    {
      id: 'ML01', level: 'MUST', title: 'an agent session with no piece on lists the core tools for agents and nothing that is for owners',
      run: () => checkRule('agent', []),
    },
    {
      id: 'ML02', level: 'MUST', title: 'an owner session with no piece on lists the owner tools and the core tools that are not agent-only',
      run: () => checkRule('owner', []),
    },
    {
      id: 'ML03', level: 'MUST', title: 'an agent session with every piece on lists every tool that is not owner-only',
      run: () => checkRule('agent', pieces),
    },
    {
      id: 'ML04', level: 'MUST', title: 'an owner session with every piece on lists the owner tools and the shared tools of every piece, and the owner tools need no piece',
      async run() {
        await checkRule('owner', pieces);
        const none = new Set((await listedOf(await session('owner', []))).map((t) => t.name));
        for (const t of standard.filter((x) => x.audience === 'owner')) assert(none.has(t.name), `the owner tool ${t.name} is not listed to an owner session with no piece on`);
      },
    },
    {
      id: 'ML05', level: 'MUST', title: 'each piece lists its tools to an agent while it is on, and not otherwise',
      async run() {
        for (const piece of pieces) await checkRule('agent', [piece]);
      },
    },
    {
      id: 'ML06', level: 'MUST', title: 'a tool that is not listed is not callable in the session',
      async run() {
        const s = await session('agent', []);
        const unlisted = standard.find((t) => !isListed(t, { audience: 'agent', pieces: [] }));
        assert(unlisted, 'the catalog has no tool that an agent with no piece does not list');
        // A call that is refused either fails or comes back as a tool error.
        const refused = await s.callTool(unlisted.name, {}).then((outcome) => outcome?.isError === true, () => true);
        assert(refused, `${unlisted.name} is not listed to this session and its call was not refused`);
      },
    },
    {
      id: 'ML07', level: 'MUST', title: 'a rarely used tool (on_demand) carries _meta "anthropic/alwaysLoad": false',
      async run() {
        const s = await session('owner', pieces);
        const listed = await listedOf(s);
        const wanted = listed.filter((t) => tools.find((c) => c.name === t.name).on_demand);
        assert(wanted.length > 0, 'the catalog has no on_demand tool that an owner session lists');
        const wrong = wanted.filter((t) => t._meta?.[ALWAYS_LOAD_KEY] !== false).map((t) => t.name);
        assert(wrong.length === 0, `on_demand tools without the hint: ${wrong.slice(0, 5).join(', ')}`);
      },
    },
    {
      id: 'ML08', level: 'MUST', title: 'no tool is marked alwaysLoad true: the server does not override the person\'s own configuration',
      async run() {
        const s = await session('owner', pieces);
        const wrong = (await s.listTools()).filter((t) => t._meta?.[ALWAYS_LOAD_KEY] === true).map((t) => t.name);
        assert(wrong.length === 0, `tools marked alwaysLoad true: ${wrong.slice(0, 5).join(', ')}`);
      },
    },
    {
      id: 'ML09', level: 'SHOULD', title: 'a tool that is not on_demand carries no alwaysLoad hint',
      async run() {
        const s = await session('owner', pieces);
        const wrong = (await listedOf(s)).filter((t) => !tools.find((c) => c.name === t.name).on_demand && t._meta?.[ALWAYS_LOAD_KEY] !== undefined).map((t) => t.name);
        assert(wrong.length === 0, `tools with a hint that are not on_demand: ${wrong.slice(0, 5).join(', ')}`);
      },
    },
    {
      id: 'ML10', level: 'MUST', title: 'the directory profile is never narrowed and carries no hint: the same list for an agent with nothing on and an owner with everything on',
      async run() {
        const a = await session('agent', [], 'directory');
        const b = await session('owner', pieces, 'directory');
        const listedA = (await a.listTools()).map((t) => t.name);
        const listedB = (await b.listTools()).map((t) => t.name);
        assert(sameNames(listedA, listedB), `the directory list depends on the session: ${diff(listedA, listedB)}`);
        const expected = tools.filter((t) => t.profiles.includes('directory')).map((t) => t.name);
        const inCatalog = listedA.filter((n) => names.has(n));
        assert(sameNames(expected, inCatalog), `the directory list differs from the catalog's: ${diff(expected, inCatalog)}`);
        const hinted = (await a.listTools()).filter((t) => t._meta?.[ALWAYS_LOAD_KEY] !== undefined).map((t) => t.name);
        assert(hinted.length === 0, `directory tools with a load hint: ${hinted.slice(0, 5).join(', ')}`);
      },
    },
    {
      id: 'ML11', level: 'MUST', title: 'when a piece comes on, tools/list answers the new set and a tools/list_changed notice is sent',
      async run() {
        const s = await session('agent', []);
        if (typeof s.setPieces !== 'function') return skip('needs setPieces on the session');
        const piece = pieces.find((p) => standard.some((t) => t.audience !== 'owner' && t.pieces.includes(p) && !isListed(t, { audience: 'agent', pieces: [] })));
        assert(piece, 'the catalog has no piece that adds a tool for an agent');
        let notices = 0;
        s.onToolListChanged(() => {
          notices += 1;
        });
        await s.setPieces([piece]);
        await wait(settleMs);
        assert(notices >= 1, 'no notifications/tools/list_changed was sent when a piece came on');
        const actual = (await listedOf(s)).map((t) => t.name);
        const expected = expectedFor('agent', [piece]);
        assert(sameNames(expected, actual), `after the change: ${diff(expected, actual)}`);
      },
    },
    {
      id: 'ML12', level: 'MUST', title: 'when the pieces go off, the tools they listed leave the list and a tools/list_changed notice is sent',
      async run() {
        const s = await session('agent', pieces);
        if (typeof s.setPieces !== 'function') return skip('needs setPieces on the session');
        let notices = 0;
        s.onToolListChanged(() => {
          notices += 1;
        });
        await s.setPieces([]);
        await wait(settleMs);
        assert(notices >= 1, 'no notifications/tools/list_changed was sent when the pieces went off');
        const actual = (await listedOf(s)).map((t) => t.name);
        const expected = expectedFor('agent', []);
        assert(sameNames(expected, actual), `after the change: ${diff(expected, actual)}`);
      },
    },
    {
      id: 'ML13', level: 'SHOULD', title: 'sends one notice for one change, and none when the list does not change',
      async run() {
        const s = await session('agent', []);
        if (typeof s.setPieces !== 'function') return skip('needs setPieces on the session');
        let notices = 0;
        s.onToolListChanged(() => {
          notices += 1;
        });
        await s.setPieces([]);
        await wait(settleMs);
        assert(notices === 0, `a change that changed nothing sent ${notices} notice(s)`);
        const piece = pieces.find((p) => standard.some((t) => t.audience !== 'owner' && t.pieces.includes(p) && !isListed(t, { audience: 'agent', pieces: [] })));
        await s.setPieces([piece]);
        await wait(settleMs);
        assert(notices === 1, `one change sent ${notices} notice(s)`);
      },
    },
  ]);
  for (const s of sessions) {
    try {
      await s.close?.();
    } catch {
      // Closing is best effort.
    }
  }
  return report;
}
