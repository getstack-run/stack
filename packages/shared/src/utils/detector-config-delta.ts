// direction classification for detector-config writes.
//
// The operate-vs-govern doctrine (dashboard-definition.md §5) splits
// detector-config changes by DIRECTION: tightening (more detection) is
// safety-increasing and may be automated by agents; loosening (less
// detection) is scope-expanding and requires the human governance
// ceremony. This pure function is the single source of truth for that
// split — the API route gates on its verdict, and the audit row records
// it, so the classification can never drift between enforcement and
// forensics.
//
// Field rules (operator_detector_config):
//   LOOSENING  — enabled true→false · whitelist pattern ADDED · severity
//                override downgraded (critical→warning) or a downgrade
//                ADDED · custom pattern REMOVED · custom pattern's own
//                severity downgraded
//   TIGHTENING — the exact reverses
//   UNCHANGED  — no effective difference
//   MIXED      — both directions present. Callers treat mixed as
//                loosening (fail closed): one hidden loosening inside a
//                "mostly tightening" write must not slip the gate.

import type { OperatorCustomPattern, OperatorWhitelistPattern } from '../db/schema/index.js';

export type DetectorConfigDirection = 'tightening' | 'loosening' | 'mixed' | 'unchanged';

export interface DetectorConfigState {
  enabled: boolean;
  custom_patterns: OperatorCustomPattern[];
  whitelist_patterns: OperatorWhitelistPattern[];
  severity_overrides: Record<string, 'warning' | 'critical'>;
}

/** The catalog default: detector on, no custom state. Used when no row exists. */
export const DETECTOR_CONFIG_DEFAULTS: DetectorConfigState = {
  enabled: true,
  custom_patterns: [],
  whitelist_patterns: [],
  severity_overrides: {},
};

export interface DetectorConfigDelta {
  direction: DetectorConfigDirection;
  /** Human/audit-facing list of what changed, e.g. "enabled: true→false". */
  changes: string[];
}

const SEVERITY_RANK: Record<'warning' | 'critical', number> = { warning: 1, critical: 2 };

/**
 * Classify prior → next. Pure, deterministic, exhaustive over the four
 * config fields. `prior` may be undefined (no row yet) — classified
 * against DETECTOR_CONFIG_DEFAULTS.
 */
export function classifyDetectorConfigDelta(
  prior: DetectorConfigState | undefined,
  next: DetectorConfigState,
): DetectorConfigDelta {
  const from = prior ?? DETECTOR_CONFIG_DEFAULTS;
  let tightens = false;
  let loosens = false;
  const changes: string[] = [];

  // enabled
  if (from.enabled !== next.enabled) {
    changes.push(`enabled: ${from.enabled}→${next.enabled}`);
    if (next.enabled) tightens = true;
    else loosens = true;
  }

  // custom patterns — keyed by id. Added = tightening; removed = loosening;
  // severity change follows rank; regex/description edits are treated as
  // remove+add of detection surface → mixed-shaped, classified as both.
  const fromCustom = new Map(from.custom_patterns.map((p) => [p.id, p]));
  const nextCustom = new Map(next.custom_patterns.map((p) => [p.id, p]));
  for (const [id, p] of nextCustom) {
    const was = fromCustom.get(id);
    if (!was) {
      changes.push(`custom_pattern added: ${id}`);
      tightens = true;
    } else {
      if (SEVERITY_RANK[p.severity] > SEVERITY_RANK[was.severity]) {
        changes.push(`custom_pattern ${id} severity: ${was.severity}→${p.severity}`);
        tightens = true;
      } else if (SEVERITY_RANK[p.severity] < SEVERITY_RANK[was.severity]) {
        changes.push(`custom_pattern ${id} severity: ${was.severity}→${p.severity}`);
        loosens = true;
      }
      if (p.regex !== was.regex) {
        // A changed regex both removes the old detection surface and adds
        // a new one — direction is not statically knowable. Fail closed.
        changes.push(`custom_pattern ${id} regex changed`);
        tightens = true;
        loosens = true;
      }
    }
  }
  for (const id of fromCustom.keys()) {
    if (!nextCustom.has(id)) {
      changes.push(`custom_pattern removed: ${id}`);
      loosens = true;
    }
  }

  // whitelist patterns — added = loosening (suppresses hits); removed = tightening.
  const fromWl = new Map(from.whitelist_patterns.map((p) => [p.id, p]));
  const nextWl = new Map(next.whitelist_patterns.map((p) => [p.id, p]));
  for (const [id, p] of nextWl) {
    const was = fromWl.get(id);
    if (!was) {
      changes.push(`whitelist_pattern added: ${id}`);
      loosens = true;
    } else if (p.regex !== was.regex) {
      // Broadened-or-narrowed is not statically knowable. Fail closed.
      changes.push(`whitelist_pattern ${id} regex changed`);
      tightens = true;
      loosens = true;
    }
  }
  for (const id of fromWl.keys()) {
    if (!nextWl.has(id)) {
      changes.push(`whitelist_pattern removed: ${id}`);
      tightens = true;
    }
  }

  // severity overrides (built-in pattern id → severity). A downgrade
  // (or adding a downgrade vs the built-in's own severity — which we
  // can't see here, so ANY added 'warning' mapping counts as a
  // downgrade) = loosening; upgrades / removing a downgrade = tightening.
  const keys = new Set([...Object.keys(from.severity_overrides), ...Object.keys(next.severity_overrides)]);
  for (const key of keys) {
    const was = from.severity_overrides[key];
    const now = next.severity_overrides[key];
    if (was === now) continue;
    changes.push(`severity_override ${key}: ${was ?? '(none)'}→${now ?? '(none)'}`);
    if (now === undefined) {
      // Removing an override restores the built-in severity: removing a
      // 'warning' downgrade tightens; removing a 'critical' upgrade loosens.
      if (was === 'warning') tightens = true;
      else loosens = true;
    } else if (was === undefined) {
      if (now === 'critical') tightens = true;
      else loosens = true;
    } else {
      if (SEVERITY_RANK[now] > SEVERITY_RANK[was]) tightens = true;
      else loosens = true;
    }
  }

  const direction: DetectorConfigDirection =
    tightens && loosens ? 'mixed' : tightens ? 'tightening' : loosens ? 'loosening' : 'unchanged';
  return { direction, changes };
}
