import { z } from 'zod';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson, controlsFeature } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const SECURITY_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  stack_scan: hint.write('Scan content for prompt injection'),
  stack_scan_usage: hint.read('Get scan usage'),
  // Security events and detectors
  stack_list_security_events: hint.read('List security events'),
  stack_get_security_event: hint.read('Get security event'),
  stack_resolve_security_event: hint.destructive('Resolve security event'),
  stack_list_detector_configs: hint.read('List detector configurations'),
  stack_get_detector_config: hint.read('Get detector configuration'),
  stack_upsert_detector_config: hint.destructive('Set detector configuration'),
  stack_reset_detector_config: hint.destructive('Reset detector configuration'),
  stack_get_pii_config: hint.read('Get PII redaction settings'),
  stack_set_pii_config: hint.destructive('Set PII redaction settings'),
  stack_reset_pii_config: hint.destructive('Reset PII redaction settings'),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const SECURITY_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  stack_resolve_security_event: 'Needs security-events:write, withheld from directory tokens: it marks an event reviewed with no approval.',
};

/** Content scan, security events, detector configuration and PII redaction configuration. */
export function registerSecurityTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  // ─── Content Scan Tools (L4 — prompt-injection scan for retrieved content) ─
  server.tool(
    'stack_scan',
    'Scan text or a JSON object (an email, document, web page, API response or similar) for prompt-injection markers. Detection uses a regex pattern catalog plus encoding-aware normalization (base64, URL, hex, leetspeak, unicode homoglyphs, zero-width characters, ROT13, reversed text), plus an optional classifier layer that can also run. STACK keeps the verdict and snippets, never the scanned content: a suspicious or critical verdict records a security event with the matched excerpt (up to 80 characters), a short reasoning note and the source label, and every scan writes an audit row that holds at most the matched pattern id and field path, never the scanned text. Returns verdict ("clean", "suspicious" or "critical"), match details, scan_id and duration_ms. Each scan is metered.',
    {
      content: z
        .union([z.string(), z.record(z.unknown())])
        .describe('The content to scan. Strings scanned directly; objects walked one level deep.'),
      context: z
        .enum(['email', 'document', 'webpage', 'chat_log', 'api_response', 'calendar', 'other'])
        .optional()
        .describe(
          'Optional context tag, recorded in security event metadata for filtering by retrieval source.',
        ),
      source: z
        .string()
        .optional()
        .describe(
          'Optional source identifier (URL / sender / filename). Truncated to 256 chars in security event metadata.',
        ),
      passport_token: z
        .string()
        .optional()
        .describe('Optional passport JWT for attribution to a specific agent context.'),
    },
    async ({ content, context, source, passport_token }) => {
      const headers: Record<string, string> = {};
      if (passport_token) headers['X-Passport-Token'] = passport_token;
      const body: Record<string, unknown> = { content };
      if (context) body.context = context;
      if (source) body.source = source;
      const result = await api('POST', '/v1/scan', body, headers);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_scan_usage',
    "Get the account's content-scan usage and remaining quota for the current month, with the plan the account is on (platform, internal, contract or none).",
    {},
    async () => {
      const result = await api('GET', '/v1/scan/usage');
      return toolJson(result);
    },
  );

  // ─── Security Event Tools ───────────────────────────────────────────

  server.tool(
    'stack_list_security_events',
    "List the account's unresolved security events, such as credential misuse, delegation violations and checkpoint failures, optionally filtered by agent.",
    {
      agent_id: z.string().optional().describe('Filter by agent ID'),
      page: z.number().optional().describe('Page number (default 1)'),
      limit: z.number().optional().describe('Results per page (default 50)'),
    },
    async ({ agent_id, page, limit }) => {
      const params = new URLSearchParams();
      if (agent_id) params.set('agent_id', agent_id);
      if (page) params.set('page', String(page));
      if (limit) params.set('limit', String(limit));
      const qs = params.toString();
      const result = await api('GET', `/v1/security-events${qs ? `?${qs}` : ''}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_get_security_event',
    'Get one security event by id with its full metadata: signal type, severity, the agent and Passport it fired on, and detector context.',
    {
      event_id: z.string().describe('Security event ID'),
    },
    async ({ event_id }) => {
      const result = await api('GET', `/v1/security-events/${encodeURIComponent(event_id)}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_resolve_security_event',
    'Mark one security event resolved, as reviewed. The event stays in the record and an audit entry names who resolved it. Only the account owner can resolve events: a team member is refused. To dismiss all the open warnings of one agent at once, use stack_dismiss_agent_warnings.',
    {
      event_id: z.string().min(1).describe('Security event id, from stack_list_security_events'),
    },
    async ({ event_id }) => toolJson(await api('POST', `/v1/security-events/${encodeURIComponent(event_id)}/resolve`, {})),
  );

  // ─── Detector Configuration (L7) ───────────────────────────────────

  server.tool(
    'stack_list_detector_configs',
    controlsFeature("List the account's per-detector customizations. An empty array means every detector runs on built-in defaults. Available on every plan."),
    {},
    async () => {
      const result = await api('GET', '/v1/detectors/config');
      return toolJson(result);
    },
  );

  server.tool(
    'stack_get_detector_config',
    controlsFeature("Get the account's customization for one detector. Returns 404 when none exists, which means the detector runs on built-in defaults. Available on every plan."),
    {
      detector_key: z.string().describe('Detector key, e.g. "prompt_injection"'),
    },
    async ({ detector_key }) => {
      const result = await api('GET', `/v1/detectors/${encodeURIComponent(detector_key)}/config`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_upsert_detector_config',
    "Set the account's customization for one detector: custom regex patterns (custom_patterns), suppression of false-positive matched_text values (whitelist_patterns), severity remaps for built-in patterns (severity_overrides) and a master switch (enabled). Detector settings are a controls feature: with controls on a change applies at once, with no approval; without controls the API answers 402 CONTROLS_REQUIRED. A self-managed install has every controls feature.",
    {
      detector_key: z.string().describe('Detector key, e.g. "prompt_injection"'),
      custom_patterns: z
        .array(
          z.object({
            id: z.string().describe('Pattern id (1-64 chars)'),
            regex: z.string().describe('JS regex (case-insensitive, ≤512 chars)'),
            severity: z.enum(['warning', 'critical']).describe('Severity if this pattern matches'),
            description: z.string().describe('What this pattern catches (≤256 chars)'),
          }),
        )
        .max(50)
        .optional()
        .describe('Up to 50 operator-specific patterns'),
      whitelist_patterns: z
        .array(
          z.object({
            id: z.string().describe('Whitelist id (1-64 chars)'),
            regex: z.string().describe('JS regex matched against built-in matched_text values'),
            description: z.string().describe('Why this is a known false positive (≤256 chars)'),
          }),
        )
        .max(50)
        .optional()
        .describe('Up to 50 suppression rules'),
      severity_overrides: z
        .record(z.string(), z.enum(['warning', 'critical']))
        .optional()
        .describe('Map of built-in pattern_id → desired severity'),
      enabled: z
        .boolean()
        .optional()
        .describe('Master switch — set false to disable this detector entirely for your operator'),
    },
    async ({ detector_key, ...rest }) => {
      const result = await api('PUT', `/v1/detectors/${encodeURIComponent(detector_key)}/config`, rest);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_reset_detector_config',
    "Reset a detector to built-in defaults by deleting the account's customization. Detector settings are a controls feature: with controls on a reset applies at once, with no approval; without controls the API answers 402 CONTROLS_REQUIRED. A self-managed install has every controls feature.",
    {
      detector_key: z.string().describe('Detector key, e.g. "prompt_injection"'),
    },
    async ({ detector_key }) => {
      const result = await api('DELETE', `/v1/detectors/${encodeURIComponent(detector_key)}/config`);
      return toolJson(result);
    },
  );

  // ─── PII Redaction Config ───────────────────────────────────────────

  server.tool(
    'stack_get_pii_config',
    controlsFeature("Get the account's PII redaction settings for the LLM gateway: confidence threshold and country scope. An account with no settings gets the built-in defaults with configured=false. Available on every plan."),
    {},
    async () => {
      const result = await api('GET', '/v1/pii/config');
      return toolJson(result);
    },
  );

  server.tool(
    'stack_set_pii_config',
    controlsFeature(`Set how the LLM gateway redacts personal data from prompts before they reach the model provider. threshold is the confidence required before redacting, 0-1; a higher value redacts less (default 0.4). countries lists ISO 3166-1 alpha-2 codes whose national-identifier schemes run; null runs every country. Scoping to the countries the account works in lets a lower threshold redact bare-format personal numbers (Dutch BSN, Croatian OIB, Portuguese NIF) without also matching order numbers. Email, card, IBAN and IP always scan. An omitted field is left unchanged; null resets it to the default. Available on every plan. A change applies at once and asks no one, loosening included (redaction off, a higher threshold, a narrower country list).`),
    {
      enabled: z
        .boolean()
        .optional()
        .describe('Master switch for PII redaction across the account'),
      threshold: z
        .number()
        .min(0)
        .max(1)
        .nullable()
        .optional()
        .describe('Confidence needed to redact, 0-1. Higher redacts less. null resets to 0.4'),
      countries: z
        .array(z.string().length(2))
        .max(64)
        .nullable()
        .optional()
        .describe('ISO 3166-1 alpha-2 codes, e.g. ["SE","NO","DK"]. null means every country'),
    },
    async (rest) => {
      const result = await api('PUT', '/v1/pii/config', rest);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_reset_pii_config',
    controlsFeature(`Reset PII redaction to built-in defaults (a 0.4 threshold across every country) by deleting the account's settings. It applies at once and asks no one.`),
    {},
    async () => {
      const result = await api('DELETE', '/v1/pii/config');
      return toolJson(result);
    },
  );
}
