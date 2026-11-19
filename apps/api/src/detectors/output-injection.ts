/**
 * Output-side prompt-injection detector — L6 of the prompt-injection
 * defense stack.
 *
 * The L1-L5 chain catches injection attempts on the way INTO the agent
 * (proxy request bodies, skill inputs, scanned content). L6 catches
 * the agent's behavior on the way OUT — proxied responses that look
 * like a compromised assistant complying with an injection.
 *
 * Scope:
 *   - Assistant-compliance language returned by an upstream that
 *     evidently treated us as an LLM and got a leaked-content
 *     response back. ("Here is the system prompt you asked for...",
 *     "As you instructed, I will...", "I will help you exfiltrate...")
 *   - Credential-shaped strings in response bodies, suggesting an
 *     upstream service responded with a leaked secret.
 *   - System-prompt-leak markers ("My instructions are:", "I was
 *     told to:", "<system>...</system>" templates).
 *
 * What this is NOT:
 *   - A general DLP scan. Credit card / SSN / health-record detection
 *     is a separate product surface; doing it here would require a
 *     much wider pattern catalog and a different threat model.
 *   - A safety classifier. We do not score whether the upstream
 *     response is "harmful" — only whether it carries markers of
 *     having been steered by a successful injection.
 *
 * Severity policy:
 *   - critical : credential-shape leak (high-confidence — these
 *     patterns rarely appear in legitimate API responses).
 *   - warning  : assistant-compliance / system-prompt-leak language
 *     (more false-positive-prone — could be a legitimate "explain
 *     your prompt" feature on an LLM upstream).
 *
 * Enforcement:
 *   - logged   → record event, forward response to caller as-is.
 *   - enforced → record event; on critical, REDACT the response body
 *                before returning to the agent so a leaked credential
 *                does not reach the agent runtime. Status code is
 *                preserved so caller flow stays intact.
 *   - standard → record event, forward as-is.
 *
 * Deliberately NOT auto-revoking in enforced mode. A leaked credential
 * in a response body is suspicious but does NOT mean this passport's
 * agent did something wrong — the upstream might just be misbehaving.
 * Operators decide via the security event review.
 */

export interface OutputInjectionMatch {
  pattern_id: string;
  severity: 'warning' | 'critical';
  matched_text: string;
  /** "body" or "headers.X-Some-Header"; coarse-grained location only. */
  field_path: string;
}

interface PatternDef {
  id: string;
  severity: 'warning' | 'critical';
  re: RegExp;
}

// Patterns kept conservative — false-positive on a legitimate API
// response degrades trust faster than missing a clever leak.
const PATTERNS: PatternDef[] = [
  // ── Assistant-compliance leak language ──────────────────────────────
  // The upstream "agent" complied with an injection and is narrating
  // it back. Mirror of the input-side override patterns; here they
  // appear in the RESPONSE because the upstream is the LLM.
  { id: 'compliance_here_is_system_prompt', severity: 'warning',
    re: /\bhere\s+(?:is|are)\s+(?:the\s+|my\s+|your\s+|its\s+)?(?:full\s+|complete\s+|original\s+|hidden\s+)?(?:system\s+prompt|initial\s+instructions?|hidden\s+instructions?|original\s+instructions?)\b/i },
  { id: 'compliance_my_instructions_are', severity: 'warning',
    re: /\b(?:my|the)\s+(?:original\s+|hidden\s+|secret\s+|system\s+|initial\s+)?(instructions?|prompt|directives?|rules?)\s+(?:are|is|were|read|state|say|begin)\b/i },
  { id: 'compliance_as_you_instructed', severity: 'warning',
    re: /\bas\s+(?:you\s+)?(?:instructed|requested|asked|directed|commanded|ordered)\s*[,:.]?\s*(i\s+(?:will|am|have|'ll|am\s+going\s+to)|here\s+(?:is|are))\b/i },
  { id: 'compliance_will_help_exfiltrate', severity: 'warning',
    re: /\bi(?:\s+will|'ll|\s+am\s+going\s+to|\s+am\s+about\s+to)\s+(?:help\s+(?:you\s+)?|now\s+)?(exfiltrate|leak|reveal|disclose|share|expose|extract|dump|forward|send)\s+(?:the\s+|your\s+|my\s+|its\s+)?(?:credentials?|tokens?|secrets?|api\s+keys?|system\s+prompt|password|private)\b/i },

  // ── System-prompt-leak template markers ─────────────────────────────
  // Returned content with explicit <system>...</system> or
  // [SYSTEM]...[/SYSTEM] tags is almost always a leaked prompt.
  { id: 'leak_system_tag_open', severity: 'warning',
    re: /<\s*(system|systemprompt|instructions?)\s*>/i },
  { id: 'leak_bracket_system_marker', severity: 'warning',
    re: /\[\s*(SYSTEM|SYSTEM\s*PROMPT|INSTRUCTIONS?|HIDDEN|INTERNAL)\s*\]/ },

  // ── Credential-shaped strings in response bodies ────────────────────
  // High-precision patterns for well-known credential formats. These
  // rarely appear in legitimate API responses unless the upstream is
  // itself a credential-store interface — operators with that use
  // case can whitelist via L7.
  { id: 'leak_aws_access_key', severity: 'critical',
    re: /\b(AKIA|ASIA)[A-Z0-9]{16}\b/ },
  { id: 'leak_stripe_secret_key', severity: 'critical',
    re: /\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b/ },
  { id: 'leak_openai_key', severity: 'critical',
    re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/ },
  { id: 'leak_github_token', severity: 'critical',
    re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/ },
  { id: 'leak_slack_token', severity: 'critical',
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: 'leak_private_key_pem', severity: 'critical',
    re: /-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|ENCRYPTED|PRIVATE)\s*PRIVATE\s+KEY-----/ },
  { id: 'leak_jwt_shape', severity: 'warning',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
];

/**
 * The built-in rules as data, for the network's signed rule set. A self-hosted
 * install compiles the same patterns with `new RegExp(pattern, flags)`.
 */
export function outputInjectionRules(): Array<{ id: string; severity: 'warning' | 'critical'; pattern: string; flags: string }> {
  return PATTERNS.map((p) => ({ id: p.id, severity: p.severity, pattern: p.re.source, flags: p.re.flags }));
}

/**
 * Scan a proxied response for output-side injection markers.
 *
 * The response body is already bounded by the proxy's 10 MiB transport
 * ceiling. Scan the complete serialized body rather than a prefix so a
 * credential cannot bypass retention screening by appearing late or deeply
 * nested. Headers are scanned separately so the caller can remove a matched
 * header before storing or returning the permitted envelope.
 *
 * Returns the strongest match (critical wins over warning, lexically
 * first within severity) or null on a clean response.
 */
export function scanResponseForOutputInjection(
  body: unknown,
  headers?: Record<string, string>,
): OutputInjectionMatch | null {
  let best: OutputInjectionMatch | null = null;

  const candidates: Array<{ text: string; path: string }> = [];

  if (typeof body === 'string') candidates.push({ text: body, path: 'body' });
  else if (body && typeof body === 'object') candidates.push({ text: JSON.stringify(body), path: 'body' });

  if (headers) {
    for (const [key, val] of Object.entries(headers)) {
      if (typeof val === 'string') candidates.push({ text: val, path: `headers.${key}` });
    }
  }

  for (const { text, path } of candidates) {
    for (const pattern of PATTERNS) {
      const match = pattern.re.exec(text);
      if (!match) continue;
      const candidate: OutputInjectionMatch = {
        pattern_id: pattern.id,
        severity: pattern.severity,
        matched_text: match[0].slice(0, 80),
        field_path: path,
      };
      if (best === null || (best.severity === 'warning' && candidate.severity === 'critical')) {
        best = candidate;
      }
      if (best.severity === 'critical') return best;
    }
  }

  return best;
}

/**
 * Build a redacted version of a proxy response for the
 * enforced-mode-critical case. The agent gets the original status
 * code + headers but a synthetic body so a leaked credential doesn't
 * reach the agent runtime.
 */
export function redactResponseBody(match: OutputInjectionMatch): {
  redacted: true;
  reason: string;
  pattern_id: string;
  severity: 'warning' | 'critical';
} {
  return {
    redacted: true,
    reason: 'STACK output-side detector caught a credential-shape leak in the upstream response. Body redacted by enforced-mode policy.',
    pattern_id: match.pattern_id,
    severity: match.severity,
  };
}
