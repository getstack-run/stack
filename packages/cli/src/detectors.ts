// detectors subcommands — per-operator detector customization (L7).
//
// API shape (apps/api/src/routes/detector-config.ts):
//   GET    /v1/detectors/config                  → { configs: [...] }
//   GET    /v1/detectors/:detector_key/config    → single row (404 if none)
//   PUT    /v1/detectors/:detector_key/config    → upsert
//   DELETE /v1/detectors/:detector_key/config    → reset to defaults
//
// PUT body (UpsertInput; a write needs controls, 402 CONTROLS_REQUIRED otherwise):
//   {
//     custom_patterns?:      [{id, regex, severity: 'warning'|'critical', description}],
//     whitelist_patterns?:   [{id, regex, description}],
//     severity_overrides?:   { <pattern_id>: 'warning'|'critical' },
//     enabled?:              boolean
//   }
//
// The earlier CLI used the wrong URL pattern (`/v1/detectors/configs`
// plural, with detector_id IN the body), the wrong method (POST instead
// of PUT), and a fictitious flat body shape (severity / threshold).
// All four CLI subcommands would have 404'd or 400'd today.

import { stdout, stderr, exit } from 'node:process';
import { readFile } from 'node:fs/promises';
import { api, takeFlag } from './api.js';
import { invokeHint } from './auth.js';
import { printJson, printTable, printRecord, fmt } from './format.js';
import { governedApi } from './governance.js';

interface DetectorConfigRow {
  detector_key: string;
  enabled?: boolean;
  custom_patterns?: unknown[];
  whitelist_patterns?: unknown[];
  severity_overrides?: Record<string, string>;
}

async function cmdList(json: boolean): Promise<void> {
  const out = await api<{ configs?: DetectorConfigRow[] } | DetectorConfigRow[]>(
    'GET', '/v1/detectors/config',
  );
  const list = Array.isArray(out) ? out : (out?.configs ?? []);
  if (json) return printJson(list);
  if (!Array.isArray(list) || list.length === 0) {
    stdout.write('(no detector configs — every detector running on defaults)\n');
    return;
  }
  const rows = list.map((d) => {
    const customCount = Array.isArray(d.custom_patterns) ? d.custom_patterns.length : 0;
    const whitelistCount = Array.isArray(d.whitelist_patterns) ? d.whitelist_patterns.length : 0;
    const overrideCount = d.severity_overrides ? Object.keys(d.severity_overrides).length : 0;
    return [
      d.detector_key,
      d.enabled === false ? fmt.dim('off') : fmt.ok('on'),
      String(customCount),
      String(whitelistCount),
      String(overrideCount),
    ];
  });
  printTable(['DETECTOR', 'STATE', 'CUSTOM', 'WHITELIST', 'OVERRIDES'], rows);
}

async function cmdShow(detectorKey: string, json: boolean): Promise<void> {
  const out = await api('GET', `/v1/detectors/${encodeURIComponent(detectorKey)}/config`);
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdEnable(detectorKey: string, enabled: boolean, json: boolean): Promise<void> {
  const out = await governedApi('PUT', `/v1/detectors/${encodeURIComponent(detectorKey)}/config`, {
    body: { enabled },
  });
  if (json) return printJson(out);
  stdout.write(`${detectorKey} → ${enabled ? 'enabled' : 'disabled'}\n`);
}

async function cmdConfigure(detectorKey: string, args: string[], json: boolean): Promise<void> {
  // Free-form config edits go through --from-file because the shape
  // (custom_patterns / whitelist_patterns / severity_overrides) is too
  // structured for ergonomic CLI flags.
  const fromFile = takeFlag(args, '--from-file');
  if (typeof fromFile !== 'string') {
    stderr.write(
      `usage: ${invokeHint(`detector configure ${detectorKey} --from-file <config.json>`)}\n`
      + `Body shape: { custom_patterns?: [{id, regex, severity, description}],\n`
      + `              whitelist_patterns?: [{id, regex, description}],\n`
      + `              severity_overrides?: { <pattern_id>: 'warning'|'critical' },\n`
      + `              enabled?: boolean }\n`,
    );
    exit(2);
  }
  const body = JSON.parse(await readFile(fromFile, 'utf8'));
  const out = await governedApi('PUT', `/v1/detectors/${encodeURIComponent(detectorKey)}/config`, { body });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdReset(detectorKey: string, json: boolean): Promise<void> {
  const out = await governedApi('DELETE', `/v1/detectors/${encodeURIComponent(detectorKey)}/config`);
  if (json) return printJson(out);
  stdout.write(`reset ${detectorKey} to defaults\n`);
}

export async function cmdDetector(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const sub = args[0];
  const arg1 = args[1];

  if (sub === 'list' || sub === 'ls') return cmdList(json);
  if (sub === 'show' || sub === 'get') {
    if (!arg1) { stderr.write(`usage: ${invokeHint('detector show <detector-key>')}\n`); exit(2); }
    return cmdShow(arg1, json);
  }
  if (sub === 'enable') {
    if (!arg1) { stderr.write(`usage: ${invokeHint('detector enable <detector-key>')}\n`); exit(2); }
    return cmdEnable(arg1, true, json);
  }
  if (sub === 'disable') {
    if (!arg1) { stderr.write(`usage: ${invokeHint('detector disable <detector-key>')}\n`); exit(2); }
    return cmdEnable(arg1, false, json);
  }
  if (sub === 'configure' || sub === 'upsert' || sub === 'set') {
    if (!arg1) { stderr.write(`usage: ${invokeHint('detector configure <detector-key> --from-file <config.json>')}\n`); exit(2); }
    return cmdConfigure(arg1, args.slice(2), json);
  }
  if (sub === 'reset') {
    if (!arg1) { stderr.write(`usage: ${invokeHint('detector reset <detector-key>')}\n`); exit(2); }
    return cmdReset(arg1, json);
  }
  stderr.write(
    `error: unknown detector subcommand "${sub ?? ''}".\nUse list | show | enable | disable | configure | reset\n`
    + `(configure/enable/disable/reset need controls on the account)\n`,
  );
  exit(2);
}
