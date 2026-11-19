import { describe, it, expect } from 'vitest';
import type { RouteScanner } from '../test/route-scan.js';

/**
 * Every action an agent account takes is put to the customer's decider
 * (`decideControl`, apps/api/src/lib/control-decision.ts) after Mission
 * admission and before it spends, sends or acts. A call site that forgets it
 * works; it is just not under the customer's controls. So the coverage is
 * pinned structurally, the way routes/mission-admission-coverage.test.ts pins
 * Mission admission:
 *
 *   1. Every `beginAgentRuntime(` call site is classified here: asked, or never
 *      asked with the reason. A new site fails until someone decides.
 *   2. Every asked route calls its decision stage after its admission gate and
 *      before the first real sink (the send, the spend, the credential read, the
 *      call to a provider), and names its action kind.
 *   3. Every sink that sends or spends on the account path sits in a file that
 *      has asked routes, so a new route in a new file cannot reach one unasked.
 *   4. Every action kind in CONTROL_ACTION_TYPES is wired somewhere.
 *
 * The checks are written once, here, and run by two scanners over two sets of
 * tables: `control-socket-coverage.test.ts` for the engine's routes and
 * the deployment's own test for its own routes.
 */

export interface Asked {
  file: string;
  /** Marker for the start of the handler (or the helper it delegates to). */
  region: string;
  /** What admits the caller; the decision must come after it. Omitted when the route admits nothing (an owner-only route). */
  gate?: string;
  /** The call that asks. */
  ask: string;
  action: string;
  /** Where the real work starts: the decision must come before each. */
  sinks: string[];
  /** For a stage module: the file that must hold `decideControl(` with the action. */
  stage?: string;
}

export interface NeverAsked {
  file: string;
  region: string;
  reason: string;
}

/** What one scanner is checked against. */
export interface ControlSocketTables {
  asked: Record<string, Asked>;
  neverAsked: Record<string, NeverAsked>;
  /**
   * Every `beginAgentRuntime(` call site, by file and enclosing unit, and whether
   * its file holds asked routes. A new call site must be added here.
   */
  sites: Record<string, 'asked' | 'never'>;
  /** What sends or spends on an account's behalf. A file holding one must hold asked routes. */
  accountSinks: readonly string[];
}

/**
 * The action kinds only a hosted route asks. The kinds stay in the protocol (`CONTROL_ACTION_TYPES`: a customer's
 * decision server receives them), but the engine does not carry those routes, so the public tree does not check that
 * a route asks them; the hosted test checks that one does.
 */
export const HOSTED_ASKED_ONLY: readonly string[] = [
  'account.open',
  'brain.add',
  'browser.navigate',
  'browser.session.start',
  'call.answer',
  'call.start',
  'card.checkout',
  'drive.share',
  'drive.upload',
  'email.send',
  'letter.send',
  'meeting.join',
  'making.order',
  'making.quote',
  'memory.delete',
  'memory.write',
  'payment.request',
  'post.forward',
  'post.scan',
  'post.shred',
  'site.publish',
  'skill.invoke',
  'sms.send',
  'telegram.send',
  'tool.run',
  'wake.deliver',
  'wallet.payment',
  'workspace.exec',
];

/** The action kinds the tables' asked routes name. */
export function askedActions(tables: Pick<ControlSocketTables, 'asked'>): Set<string> {
  return new Set(Object.values(tables.asked).map((spec) => spec.action));
}

export function defineControlSocketCoverage(scanner: RouteScanner, tables: ControlSocketTables): void {
  const read = (file: string): string => scanner.readLf(file);

  /** The route path or function name a position in a file belongs to. */
  function unitAt(src: string, index: number): string {
    const before = src.slice(0, index);
    const decl = [...before.matchAll(/app\.(?:post|get|put|patch|delete)(?:<[^>]*>)?\(\s*'([^']+)'/g)].pop();
    const fn = [...before.matchAll(/\n(?:export )?(?:async )?function (\w+)\(/g)].pop();
    const inner = [...before.matchAll(/\n {2}(?:async )?function (\w+)\(/g)].pop();
    const candidates = [
      decl ? { at: decl.index ?? 0, name: decl[1]! } : null,
      fn ? { at: fn.index ?? 0, name: fn[1]! } : null,
      inner ? { at: inner.index ?? 0, name: inner[1]! } : null,
    ].filter((c): c is { at: number; name: string } => c !== null);
    return candidates.sort((a, b) => b.at - a.at)[0]?.name ?? '(top level)';
  }

  /** The handler region an entry names: from the marker to the next route or top-level function. */
  function region(file: string, marker: string): string {
    const src = read(file);
    const start = src.indexOf(marker);
    if (start === -1) return '';
    const rest = src.slice(start + marker.length);
    const ends = [rest.search(/\n {2}app\.(post|put|patch|delete|get)\b/), rest.search(/\n(?:export )?(?:async )?function /)]
      .filter((i) => i !== -1);
    return src.slice(start, start + marker.length + (ends.length ? Math.min(...ends) : rest.length));
  }

  function callSites(): string[] {
    const found = new Set<string>();
    for (const file of scanner.allFiles()) {
      const src = read(file);
      for (const m of src.matchAll(/beginAgentRuntime\(/g)) {
        const lineStart = src.lastIndexOf('\n', m.index) + 1;
        const line = src.slice(lineStart, src.indexOf('\n', m.index));
        if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
        found.add(`${file}::${unitAt(src, m.index ?? 0)}`);
      }
    }
    return [...found].sort();
  }

  describe(`control socket coverage (${scanner.name})`, () => {
    it('classifies every beginAgentRuntime call site, so a new one cannot skip the customer\'s decider', () => {
      const found = callSites();
      const unclassified = found.filter((site) => !(site in tables.sites));
      expect(
        unclassified,
        'a new beginAgentRuntime call site: ask the customer\'s decider after it (decideControl) and add it to ASKED and SITES, ' +
          'or add it to NEVER_ASKED and SITES with the reason it is not an action',
      ).toEqual([]);
      expect(Object.keys(tables.sites).filter((site) => !found.includes(site)), 'listed call sites that no longer exist').toEqual([]);
    });

    for (const [route, spec] of Object.entries(tables.asked)) {
      it(`${route} asks ${spec.action} after admission and before it acts`, () => {
        const body = region(spec.file, spec.region);
        expect(body, `${spec.file}: cannot find region ${spec.region}`).not.toBe('');
        const ask = body.indexOf(spec.ask);
        expect(ask, `${route} (${spec.file}) no longer asks the customer's decider (${spec.ask}). It is not under their controls.`).toBeGreaterThan(-1);
        // A stage module names its own action kind (checked below).
        if (!spec.stage) expect(body, `${route} does not name its action kind ${spec.action}`).toContain(`'${spec.action}'`);
        if (spec.gate) {
          const gate = body.indexOf(spec.gate);
          expect(gate, `${route}: cannot find its admission ${spec.gate}`).toBeGreaterThan(-1);
          expect(gate < ask, `${route}: the decider is asked BEFORE admission (${spec.gate}); STACK's own refusals must never wait on a customer's server`).toBe(true);
        }
        for (const sink of spec.sinks) {
          const at = body.indexOf(sink);
          expect(at, `${spec.file}: sink ${sink} not found; update this test with the real call`).toBeGreaterThan(-1);
          expect(ask < at, `${route}: the decider is asked AFTER ${sink}. A refusal after that point is not a refusal.`).toBe(true);
        }
        if (spec.stage) {
          const stage = read(spec.stage);
          expect(stage, `${spec.stage} no longer calls decideControl`).toContain('decideControl(');
          expect(stage, `${spec.stage} does not name ${spec.action}`).toContain(`'${spec.action}'`);
        }
      });
    }

    for (const [route, spec] of Object.entries(tables.neverAsked)) {
      it(`${route} is never asked, and says why`, () => {
        const body = region(spec.file, spec.region);
        expect(body, `${spec.file}: cannot find region ${spec.region}`).not.toBe('');
        expect(spec.reason.length).toBeGreaterThan(20);
        expect(body, `${route} asks the decider now: move it to ASKED`).not.toMatch(/decideControl\(|await decide\(/);
      });
    }

    it('every route that sends or spends on an account\'s behalf lives in a file that asks', () => {
      const askedFiles = new Set(Object.values(tables.asked).map((spec) => spec.file));
      const offenders: string[] = [];
      for (const file of scanner.allFiles()) {
        const src = read(file);
        for (const sink of tables.accountSinks) {
          if (src.includes(sink) && !askedFiles.has(file)) offenders.push(`${file}: ${sink}`);
        }
      }
      expect(offenders, 'an account send or spend sink outside every asked route: ask the decider before it').toEqual([]);
    });
  });
}
