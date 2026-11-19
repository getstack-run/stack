import { MAX_NETWORK_RULES, compileLinearTimePattern } from '@stack/shared';
import type { ReviewFlag } from '@stack/shared';
import { declaredAndObservedOf, type IntentDeviationGrader, type IntentDeviationInput } from '@stack/vault';
import { L3_TIMEOUT_MS, type L3ClassificationResult, type L3Classifier } from '../detectors/l3-classifier.js';
import { StatementError, verifyRuleSetStatement, type StatementKeySource } from './network-statement.js';

/**
 * STACK's hosted network, as seen from a self-managed install. Both services
 * are clients only and off unless configured:
 *
 *   rules       the live detection rules: a signed set of patterns that
 *               extends the built-in rule set. Without it the install runs the
 *               built-in rules, which are complete on their own.
 *   classifier  the L3 classifier: content the pattern layers could not settle
 *               is sent to STACK's hosted classifier. This sends the content
 *               off the install, so it is a separate switch and off unless
 *               STACK_NETWORK_CLASSIFIER=true. Without it there is no L3,
 *               and no intent_deviation either: the same switch has STACK grade
 *               each checkout's declared intent against what the agent did.
 *
 *   STACK_NETWORK_URL         STACK's API (https), e.g. https://api.getstack.run
 *   STACK_NETWORK_KEY         what the calls are made with: a STACK account's API
 *                             key, or the install's licence key when STACK issued
 *                             it to a STACK account (docs/self-managed/network-services.md)
 *   STACK_NETWORK_RULES       true or false; defaults to true when configured
 *   STACK_NETWORK_CLASSIFIER  true to use the hosted classifier; default false
 *
 * The contract is the network's own (the network contract):
 *   POST /v1/network/detection/rules     -> { version, revision, expires_at, statement }, the statement a JWS signed by STACK
 *   POST /v1/network/detection/classify  { content } -> the verdict, with the classifier's part under `llm`
 *   POST /v1/network/detection/intent-deviation  { declared, observed } -> { graded, score, flag }
 *   GET  /v1/network/jwks.json           STACK's public keys, which the statement is checked against
 */

export interface NetworkClientConfig {
  url: string;
  key: string;
  rules: boolean;
  classifier: boolean;
}

function flag(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value === '') return fallback;
  return value === 'true' || value === '1';
}

export function readNetworkClientConfig(env: Record<string, string | undefined>): NetworkClientConfig | null {
  const url = env['STACK_NETWORK_URL']?.trim();
  const key = env['STACK_NETWORK_KEY']?.trim();
  if (!url && !key) return null;
  if (!url || !key) {
    throw new Error('[BOOT] STACK_NETWORK_URL and STACK_NETWORK_KEY are set together or not at all');
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('[BOOT] STACK_NETWORK_URL is not a valid URL');
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
  if ((parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) || parsed.username || parsed.password) {
    throw new Error('[BOOT] STACK_NETWORK_URL must be an https URL');
  }
  return {
    url: parsed.origin,
    key,
    rules: flag(env['STACK_NETWORK_RULES'], true),
    classifier: flag(env['STACK_NETWORK_CLASSIFIER'], false),
  };
}

export interface CompiledNetworkRule {
  id: string;
  severity: 'warning' | 'critical';
  re: RegExp;
}

type Log = Pick<Console, 'log' | 'warn'>;

const HOUR_MS = 60 * 60 * 1000;
/** A rule set is never trusted for longer than this, whatever it says. */
const MAX_RULE_SET_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 10_000;

export class DetectionRulesFeed {
  private set: { revision: number; expiresAt: number; rules: CompiledNetworkRule[] } | null = null;
  private lastLine: string | undefined;

  constructor(
    private readonly config: Pick<NetworkClientConfig, 'url' | 'key'>,
    private readonly deps: {
      fetchImpl?: typeof fetch;
      /** Where STACK's public keys come from. Default: the network's own `jwks.json`. */
      keys?: StatementKeySource;
      now?: () => number;
      log?: Log;
    } = {},
  ) {}

  private now(): number {
    return (this.deps.now ?? Date.now)();
  }

  /** The rules in force: the fetched set while it is current, else none (the built-in rules alone). */
  current(): readonly CompiledNetworkRule[] {
    if (!this.set || this.set.expiresAt <= this.now()) return [];
    return this.set.rules;
  }

  /** Which set is in force, for health output. */
  status(): { revision: number | null; rules: number; expires_at: string | null } {
    const active = this.set !== null && this.set.expiresAt > this.now();
    return {
      revision: active && this.set ? this.set.revision : null,
      rules: this.current().length,
      expires_at: active && this.set ? new Date(this.set.expiresAt).toISOString() : null,
    };
  }

  /** Fetch, verify and apply the latest set. Never throws: the set in force stays when anything is wrong. */
  async refresh(): Promise<void> {
    try {
      const response = await (this.deps.fetchImpl ?? fetch)(`${this.config.url}/v1/network/detection/rules`, {
        method: 'POST',
        headers: { authorization: `Bearer ${this.config.key}`, 'content-type': 'application/json', accept: 'application/json' },
        body: '{}',
        redirect: 'error',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (!response.ok) {
        this.report(`[network] The detection rules could not be fetched (HTTP ${response.status}); keeping the rules in force.`, true);
        return;
      }
      const statement = ((await response.json()) as { statement?: unknown }).statement;
      if (typeof statement !== 'string') {
        this.report('[network] A detection rule set was malformed and was refused.', true);
        return;
      }
      let verified;
      try {
        verified = await verifyRuleSetStatement(statement, {
          keys: this.deps.keys ?? { jwksUrl: `${this.config.url}/v1/network/jwks.json` },
          now: new Date(this.now()),
          ...(this.set ? { heldRevision: this.set.revision } : {}),
        });
      } catch (error) {
        if (error instanceof StatementError && error.reason === 'revision_too_old') {
          // An install never moves back to an older set.
          this.report('[network] An older detection rule set was refused; keeping the one in force.', true);
        } else if (error instanceof StatementError && error.reason === 'expired') {
          this.report('[network] A detection rule set had already expired and was refused.', true);
        } else {
          this.report('[network] A detection rule set failed its signature check and was refused.', true);
        }
        return;
      }
      const now = this.now();
      const expiresAt = Math.min(verified.expiresAt.getTime(), now + MAX_RULE_SET_LIFETIME_MS);
      if (expiresAt <= now) {
        this.report('[network] A detection rule set had already expired and was refused.', true);
        return;
      }
      // The install scans what comes in, so the input packs apply; the output packs are for a scan of what goes out.
      const offered = verified.packs.filter((pack) => pack.direction === 'input').flatMap((pack) => pack.rules);
      if (offered.length > MAX_NETWORK_RULES) {
        this.report('[network] A detection rule set was too large and was refused.', true);
        return;
      }
      const rules: CompiledNetworkRule[] = [];
      for (const rule of offered) {
        if (!/^[a-z0-9_.-]{1,64}$/.test(rule.id) || (rule.severity !== 'warning' && rule.severity !== 'critical')) continue;
        // RE2 takes the flags that mean the same in an ECMAScript pattern; anything else is not asked for.
        const kept = [...new Set(rule.flags.split('').filter((flag) => 'imsu'.includes(flag)))].join('');
        const re = compileLinearTimePattern(rule.pattern, kept.includes('u') ? kept : `${kept}u`);
        if (re) rules.push({ id: rule.id, severity: rule.severity, re });
      }
      if (this.set && verified.revision === this.set.revision) {
        // The same set again: only its lifetime moves.
        this.set = { ...this.set, expiresAt };
        return;
      }
      this.set = { revision: verified.revision, expiresAt, rules };
      this.report(`[network] Detection rules revision ${verified.revision} applied (${rules.length} rules).`, false);
    } catch {
      this.report('[network] The detection rules could not be fetched; keeping the rules in force.', true);
    }
  }

  /** Fetch now and then every hour. Returns the function that stops it. */
  start(): () => void {
    void this.refresh();
    const timer = setInterval(() => void this.refresh(), HOUR_MS);
    timer.unref();
    return () => clearInterval(timer);
  }

  private report(line: string, warn: boolean): void {
    if (line === this.lastLine) return;
    this.lastLine = line;
    const log = this.deps.log ?? console;
    if (warn) log.warn(line);
    else log.log(line);
  }
}

/**
 * The L3 classifier at STACK: the engine's only third layer. What is sent is
 * the sampled content the scan hands over, and what comes back is the
 * classifier's verdict, confidence and reasoning. No prompt, no model name and
 * no operator or agent identifier leaves the install, and the prompt itself is
 * STACK's, not this codebase's.
 *
 * STACK answers a verdict of its own: the pattern layers' match, if any, and the
 * classifier's verdict, confidence and reasoning under `llm`. Only the
 * classifier's part is used here. An answer without it (the classifier was
 * down, or could not decide), a refusal, a timeout or a cancelled scan is a
 * degraded result, so the detectors fall back to their own L1 and L2 verdict
 * and record that the third layer did not contribute.
 */
export class NetworkClassifier implements L3Classifier {
  /** STACK owns the prompt and the model; a verdict is only as old as STACK's configuration of the day, which the hour's cache accepts. */
  readonly cacheIdentity = { identity: 'stack-network', model: 'stack-network' };

  constructor(
    private readonly config: Pick<NetworkClientConfig, 'url' | 'key'>,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async classify(
    content: string,
    options?: { timeoutMs?: number; signal?: AbortSignal },
  ): Promise<L3ClassificationResult> {
    const start = Date.now();
    try {
      const timeout = AbortSignal.timeout(options?.timeoutMs ?? L3_TIMEOUT_MS);
      const response = await this.fetchImpl(`${this.config.url}/v1/network/detection/classify`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${this.config.key}`,
          'content-type': 'application/json',
          accept: 'application/json',
        },
        body: JSON.stringify({ content }),
        redirect: 'error',
        signal: options?.signal ? AbortSignal.any([timeout, options.signal]) : timeout,
      });
      if (!response.ok) throw new Error(`network classifier answered ${response.status}`);
      const body = (await response.json()) as {
        llm?: { verdict?: unknown; confidence?: unknown; reasoning?: unknown; model?: unknown } | null;
      };
      const llm = body.llm;
      if (!llm || typeof llm.verdict !== 'string' || typeof llm.confidence !== 'number' || !Number.isFinite(llm.confidence)) {
        throw new Error('network classifier answered without a verdict');
      }
      const verdict = llm.verdict === 'suspicious' || llm.verdict === 'critical' ? llm.verdict : 'clean';
      return {
        verdict,
        confidence: Math.max(0, Math.min(100, llm.confidence)),
        reasoning: typeof llm.reasoning === 'string' ? llm.reasoning.slice(0, 200) : '',
        degraded: false,
        duration_ms: Date.now() - start,
        model: typeof llm.model === 'string' ? llm.model.slice(0, 128) : 'stack-network',
        // STACK bills the call to the key's account; the install has no token count to report.
        cost_cents: 0,
        tokens_input: 0,
        tokens_output: 0,
      };
    } catch (error) {
      return {
        verdict: 'clean',
        confidence: 0,
        reasoning: `degraded: ${error instanceof Error ? error.message : 'unknown'}`,
        degraded: true,
        duration_ms: Date.now() - start,
        model: 'stack-network',
      };
    }
  }
}

/** How long a checkout waits for STACK's grade before it carries on without one. */
const INTENT_DEVIATION_TIMEOUT_MS = 15_000;

/**
 * intent_deviation on a self-hosted install: STACK grades the checkout with the grader a hosted checkout uses. What is
 * sent is the passport's declared intent (summary and services) and what the agent did (the services it used, its tool
 * calls, the action count and the checkout's summary); no passport, operator or agent identifier leaves the install.
 * Best-effort like every grader: a refusal, a timeout or an answer STACK could not grade adds no flag.
 */
export class NetworkIntentDeviationGrader implements IntentDeviationGrader {
  constructor(
    private readonly config: Pick<NetworkClientConfig, 'url' | 'key'>,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async grade(input: IntentDeviationInput): Promise<ReviewFlag[]> {
    const read = declaredAndObservedOf(input);
    if (!read) return [];
    try {
      const response = await this.fetchImpl(`${this.config.url}/v1/network/detection/intent-deviation`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${this.config.key}`,
          'content-type': 'application/json',
          accept: 'application/json',
        },
        body: JSON.stringify({
          declared: { summary: read.declared.summary, services: read.declared.services },
          observed: {
            services_used: read.observed.servicesUsed,
            tool_calls: read.observed.toolCalls.map((tc) => ({ service: tc.service, method: tc.method, ...(tc.target ? { target: tc.target } : {}) })),
            actions_count: read.observed.actionsCount,
            ...(read.observed.summary ? { summary: read.observed.summary } : {}),
          },
        }),
        redirect: 'error',
        signal: AbortSignal.timeout(INTENT_DEVIATION_TIMEOUT_MS),
      });
      if (!response.ok) return [];
      const body = (await response.json()) as { flag?: { severity?: unknown; message?: unknown } | null };
      const flag = body.flag;
      if (!flag || (flag.severity !== 'warning' && flag.severity !== 'critical') || typeof flag.message !== 'string') return [];
      return [{ type: 'intent_deviation', severity: flag.severity, message: flag.message }];
    } catch {
      return [];
    }
  }
}

export interface NetworkClientServices {
  rules: DetectionRulesFeed | null;
  classifier: NetworkClassifier | null;
  /** The install's intent_deviation grader: on with the classifier, off without it. */
  intentDeviation: NetworkIntentDeviationGrader | null;
}

export function createNetworkClientServices(
  config: NetworkClientConfig | null,
  log: Log = console,
): NetworkClientServices {
  if (!config) return { rules: null, classifier: null, intentDeviation: null };
  log.log(
    `[network] Using STACK's network: ${[config.rules && 'detection rules', config.classifier && 'classifier'].filter(Boolean).join(' and ') || 'nothing enabled'}.`,
  );
  return {
    rules: config.rules ? new DetectionRulesFeed(config) : null,
    classifier: config.classifier ? new NetworkClassifier(config) : null,
    intentDeviation: config.classifier ? new NetworkIntentDeviationGrader(config) : null,
  };
}
