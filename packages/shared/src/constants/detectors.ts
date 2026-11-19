/**
 * Detector catalog — the product-facing names, descriptions, and status of every
 * signal STACK can raise. Covers both the real-time security-event stream
 * (pipeline 1) and the post-hoc review-engine flags (pipeline 2).
 *
 * The raw signal/flag keys are the wire format and stay snake_case. The
 * display_name + description on each entry are the strings that should appear
 * in the dashboard, docs, API responses, and marketing surfaces.
 */

export type DetectorStatus = 'live' | 'roadmap';
export type DetectorPipeline = 'security_event' | 'review_flag' | 'both';
export type DetectorSeverity = 'info' | 'warning' | 'critical';

export interface DetectorDefinition {
  /** The wire format enum value — used in DB, API, audit logs. */
  key: string;
  /** Product-facing display name. */
  display_name: string;
  /** One-sentence description for tooltips, docs, cards. Written for someone
   *  who already knows the system. */
  description: string;
  /**
   * THE ATTACKER'S MOVE, in the attacker's words. What someone was trying to
   * pull, named the way they would name it — not a description of what the
   * detector saw, and not an explanation of the mechanic.
   *
   * Two failed registers to avoid. Engineer-facing: `description` above, which
   * opens 'Synchronous boundary rule' and loses the reader on word one.
   * Pandering: 'Someone hid an instruction in the text it was reading', which
   * explains prompt injection to a reader who came to this page precisely
   * because they already know what it is, and so reads as condescending.
   *
   * Assume competence. Short, active, no trailing full stop. Wit where it lands
   * on its own, never forced — a page of 27 jokes is its own kind of tell.
   *
   * EVERY detector carries one, so a public surface never hand-writes a label
   * per signal: it looks the line up by key, counts the rows, renders. A new
   * detector arrives with its own and needs no edit anywhere else.
   */
  attempt: string;
  /** Which pipeline emits this detector. */
  pipeline: DetectorPipeline;
  /**
   * The severity the detector raises when it first fires in an enforced-mode
   * mission. It is the label a surface shows before anything has fired, such
   * as the notification event list. The fire point can still grade it: a
   * logged-mode agent lowers it, and a detector that scores magnitude (a
   * longer overrun, a larger action count) raises it above this default.
   */
  severity: DetectorSeverity;
  /** Whether the detector is wired up today, or roadmap-only. */
  status: DetectorStatus;
}

const DETECTOR_CATALOG = {
  // ── Real-time security-event stream ───────────────────────────────
  credential_burst: {
    key: 'credential_burst',
    display_name: 'Credential Burst Detector',
    description: 'Flags when an agent pulls credentials faster than its baseline rate.',
    attempt: 'Pull every key it has, as fast as it will go',
    pipeline: 'security_event',
    severity: 'critical',
    status: 'live',
  },
  credential_outside_scope: {
    key: 'credential_outside_scope',
    display_name: 'Scope Violation Detector',
    description: 'Synchronous boundary rule: denies any proxy call to a service the passport did not declare in its intent or grant. Pairs with Scope Drift, which scores the behavioral pattern across calls.',
    attempt: 'Point it at a service nobody granted',
    pipeline: 'security_event',
    severity: 'critical',
    status: 'live',
  },
  scope_drift: {
    key: 'scope_drift',
    display_name: 'Scope Drift Detector',
    description: 'Scores each call\'s drift from the passport\'s declared intent. Accumulates across the session and fires before a hard scope violation occurs, when cumulative drift or single-call novelty crosses threshold.',
    attempt: 'Walk it out one harmless step at a time',
    pipeline: 'security_event',
    severity: 'warning',
    status: 'live',
  },
  credential_after_checkout: {
    key: 'credential_after_checkout',
    display_name: 'Post-Checkout Access Detector',
    description: 'Flags credential access after a passport has been checked out.',
    attempt: 'Use the key after the job is closed',
    pipeline: 'security_event',
    severity: 'critical',
    status: 'live',
  },
  delegation_without_intent: {
    key: 'delegation_without_intent',
    display_name: 'Undeclared Delegation Detector',
    description: 'Fires when a child passport is issued without the parent declaring delegation intent.',
    attempt: 'Hand the work to another agent, quietly',
    pipeline: 'security_event',
    severity: 'critical',
    status: 'live',
  },
  delegation_downgrade: {
    key: 'delegation_downgrade',
    display_name: 'Delegation Downgrade Detector',
    description: 'Catches delegation chains that attempt to drop accountability mode along the chain.',
    attempt: 'Pass it down with the rules loosened',
    pipeline: 'security_event',
    severity: 'critical',
    status: 'live',
  },
  checkpoint_silence: {
    key: 'checkpoint_silence',
    display_name: 'Checkpoint Silence Detector',
    description: 'Flags active passports that fail to submit checkpoints at their configured interval.',
    attempt: 'Keep it busy so it never checks in',
    pipeline: 'security_event',
    severity: 'warning',
    status: 'live',
  },
  checkpoint_self_report_divergence: {
    key: 'checkpoint_self_report_divergence',
    display_name: 'Checkpoint Self-Report Divergence Detector',
    description: 'Fires when a checkpoint’s self-reported services_used / actions_count diverges from the verified intent_claim emissions on the passport since the previous checkpoint. The substrate-enabled answer to "agent lying in its own checkpoint summary" — a divergent self-report against signed Intent history is detectable post-hoc.',
    attempt: 'Have it report one thing and do another',
    pipeline: 'security_event',
    severity: 'warning',
    status: 'live',
  },
  expired_no_checkout: {
    key: 'expired_no_checkout',
    display_name: 'Unchecked-Out Passport Detector',
    description: 'Fires when a passport expires without the agent submitting a checkout summary.',
    attempt: 'Run past the expiry and never sign off',
    pipeline: 'security_event',
    severity: 'warning',
    status: 'live',
  },
  upstream_not_found: {
    key: 'upstream_not_found',
    display_name: 'Upstream 404 Detector',
    description: 'Informational signal: the upstream provider returned 404 on a proxied call. Often indicates a hallucinated or stale endpoint path, useful for spotting intents whose URL patterns are wrong.',
    attempt: 'Send it somewhere that does not exist',
    pipeline: 'security_event',
    severity: 'info',
    status: 'live',
  },
  prompt_injection_output: {
    key: 'prompt_injection_output',
    display_name: 'Output Injection Detector',
    description: 'Scans proxied response bodies + headers for markers of a successful prompt injection: assistant-compliance language ("Here is the system prompt you asked for…", "As you instructed, I will…"), system-prompt-leak templates (<system>, [SYSTEM] markers), and credential-shape strings (AWS access keys, Stripe / OpenAI / GitHub / Slack tokens, PEM private keys, JWT triplets). Severity: critical for credential-shape leaks, warning for compliance / system-prompt language. In enforced mode, critical hits redact the response body before returning to the agent so a leaked secret never reaches the agent runtime.',
    attempt: 'Poison the reply instead of the request',
    pipeline: 'security_event',
    severity: 'warning',
    status: 'live',
  },
  behavior_drift: {
    key: 'behavior_drift',
    display_name: 'Behavior Drift Detector',
    description: 'Per-passport cross-call drift signal. Tracks running mean + standard deviation of body length and Shannon entropy across every proxy call within a session, fires when the current call exceeds 3σ on either dimension. Cold-start gate (≥5 prior calls) prevents false positives on warming sessions. Catches the case where a successful EARLIER injection silently steered the agent and subsequent traffic looks materially different from baseline. Severity: warning. Does not auto-revoke.',
    attempt: 'Change what it does, slowly enough to miss',
    pipeline: 'security_event',
    severity: 'warning',
    status: 'live',
  },
  prompt_injection: {
    key: 'prompt_injection',
    display_name: 'Prompt Injection Detector',
    description: 'Three-layer detector that scans proxy request bodies, skill invocation inputs, AND retrieved content (via /v1/scan) for prompt-injection attempts. L1 = regex pattern catalog (instruction overrides, role-play breakouts, jailbreak names). L2 = encoding-aware normalization (decodes base64 / URL / hex / leetspeak / unicode homoglyphs / zero-width chars / ROT13 / reverse before re-running L1). L3 = an optional classifier layer for semantic-novel attacks the regex layer cannot see — paraphrased overrides, authority impersonation, polite-format <INFORMATION> wrappers, indirect injection in retrieved content, multilingual variants. When the classifier layer is unavailable the verdict falls back to L1 and L2. Pro and above can customize behavior per-detector via /v1/detectors/:key/config: add domain-specific custom regex, whitelist false-positive matched_text values, remap built-in severities, or master-disable the detector entirely.',
    attempt: '"Ignore all previous instructions" and its thousand cousins',
    pipeline: 'security_event',
    severity: 'warning',
    status: 'live',
  },

  // ── Post-hoc review-engine flags ──────────────────────────────────
  undeclared_service: {
    key: 'undeclared_service',
    display_name: 'Undeclared Service Detector',
    description: 'At checkout, flags services used during the mission that were not in the declared intent.',
    attempt: 'Use a service it never put on the list',
    pipeline: 'review_flag',
    severity: 'warning',
    status: 'live',
  },
  undeclared_delegation: {
    key: 'undeclared_delegation',
    display_name: 'Undeclared Delegation Detector (post-hoc)',
    description: 'At checkout, flags delegations that happened without matching delegation intent.',
    attempt: 'Bring in an agent nobody declared',
    pipeline: 'review_flag',
    severity: 'critical',
    status: 'live',
  },
  duration_exceeded: {
    key: 'duration_exceeded',
    display_name: 'Duration Overrun Detector',
    description: 'Flags missions that ran significantly longer than their estimated duration.',
    attempt: 'Keep it running long past the job',
    pipeline: 'review_flag',
    severity: 'info',
    status: 'live',
  },
  no_checkpoints: {
    key: 'no_checkpoints',
    display_name: 'Missing Checkpoints Detector',
    description: 'At checkout, flags enforced-mode missions that submitted no checkpoints at all.',
    attempt: 'Never check in at all',
    pipeline: 'review_flag',
    severity: 'warning',
    status: 'live',
  },
  checkpoint_gap: {
    key: 'checkpoint_gap',
    display_name: 'Checkpoint Gap Detector',
    description: 'Flags missions with abnormally long gaps between checkpoints.',
    attempt: 'Check in just often enough to look busy',
    pipeline: 'review_flag',
    severity: 'info',
    status: 'live',
  },
  high_action_volume: {
    key: 'high_action_volume',
    display_name: 'Action Volume Detector',
    description: 'Flags missions with unusually high action counts, suggesting runaway behavior.',
    attempt: 'Do a hundred small things instead of one big one',
    pipeline: 'review_flag',
    severity: 'info',
    status: 'live',
  },
  scope_escalation_pattern: {
    key: 'scope_escalation_pattern',
    display_name: 'Scope Escalation Pattern Detector',
    description: 'Detects monotonic growth in an agent\'s intent-service scope across successive missions.',
    attempt: 'Ask for a little more, every time',
    pipeline: 'review_flag',
    severity: 'warning',
    status: 'live',
  },
  credential_unreported: {
    key: 'credential_unreported',
    display_name: 'Undeclared Access Detector',
    description: 'At checkout, flags credentials the agent accessed but never reported in any checkpoint.',
    attempt: 'Use the key and leave it out of the report',
    pipeline: 'review_flag',
    severity: 'warning',
    status: 'live',
  },

  // ── substrate-aware detectors ─────────────
  undeclared_target: {
    key: 'undeclared_target',
    display_name: 'Undeclared Target Detector',
    description: 'On every live proxy call, extracts entity references (URLs, emails, account ids, file paths) from the outbound request and checks each against the passport\'s observed-entity set from prior calls, plus any counterparties the operator pre-declared on the bound mission. Fires as a flag (not a denial) when the call reaches a counterparty the passport has never dealt with — a first-ever payment to a stranger, an email to a new recipient. Fire-and-forget, so it never adds latency or blocks the call.',
    attempt: 'Slip a new address into the conversation',
    pipeline: 'security_event',
    severity: 'warning',
    status: 'live',
  },
  simulation_divergence: {
    key: 'simulation_divergence',
    display_name: 'Simulation Divergence Detector',
    description: 'When an intent_outcome lands, compares it to the paired intent_simulation (linked via intent_claim_ref). Fires when the simulator predicted allowed=true but execution failed, predicted allowed=false but execution succeeded, or actual wallet cost diverges from the simulated cost by more than 50%.',
    attempt: 'Rehearse one plan, run another',
    pipeline: 'security_event',
    severity: 'warning',
    status: 'live',
  },

  // ── Skill access control ──────────────────────────────────────────
  unauthorized_skill_access: {
    key: 'unauthorized_skill_access',
    display_name: 'Unauthorized Skill Access Detector',
    description: 'Fires when an agent attempts to invoke a skill its skill_access_mode does not permit (none-mode blocks everything; custom-mode checks the allowed_skills list).',
    attempt: 'Reach for a skill it was never given',
    pipeline: 'security_event',
    severity: 'critical',
    status: 'live',
  },

  // ── Formerly-roadmap, now wired (review-engine + genome) ──────────
  intent_deviation: {
    key: 'intent_deviation',
    display_name: 'Intent Deviation Detector',
    description: 'At checkout, an LLM compares the passport\'s declared natural-language intent to the mission\'s observed behavior (services used, tool calls, summary) and grades semantic drift. Fires when the score crosses threshold.',
    attempt: 'Talk it into a different job',
    pipeline: 'review_flag',
    severity: 'warning',
    status: 'live',
  },
  behavioral_anomaly: {
    key: 'behavioral_anomaly',
    display_name: 'Behavioral Anomaly Detector',
    description: 'At checkout, compares the current mission\'s action count, services-used count, and duration against the agent\'s rolling baseline (last 20 completed checkouts). Fires when any dimension exceeds 3σ of the baseline or 3× the baseline mean.',
    attempt: 'Act nothing like it usually does',
    pipeline: 'review_flag',
    severity: 'info',
    status: 'live',
  },
  // passport-scoped genome drift. Distinct from
  // `behavioral_anomaly` above (mission-scoped at checkout) AND from
  // `behavior_drift` (per-call L6 entropy outlier). This detector
  // fires post-persist on every behavioral_genome claim by comparing
  // it to the prior genome on the same passport via z-score + L2 norm.
  // A controls feature: genomes are signed only for accounts with controls on.
  genome_drift: {
    key: 'genome_drift',
    display_name: 'Genome Drift Detector',
    description: 'Compares each new behavioral_genome claim against the prior genome on the same passport. Fires when any scalar dimension breaches 3σ or the composite L2 norm breaches 5.0. A controls feature. Fires once per passport per 24h to prevent alert fatigue when an agent legitimately shifts baseline.',
    attempt: 'Become a different agent, gradually',
    pipeline: 'security_event',
    severity: 'warning',
    status: 'live',
  },
} satisfies Record<string, DetectorDefinition>;

/** Wire key of every detector in the catalog. */
export type DetectorKey = keyof typeof DETECTOR_CATALOG;

/** Every detector key, as a non-empty tuple so it can feed `z.enum`. */
export const DETECTOR_KEYS = Object.keys(DETECTOR_CATALOG) as [DetectorKey, ...DetectorKey[]];

export const DETECTORS: Record<string, DetectorDefinition> = DETECTOR_CATALOG;

/** Look up a detector definition by its wire key. Returns null for unknown keys. */
export function getDetector(key: string): DetectorDefinition | null {
  return DETECTORS[key] ?? null;
}

/** Convenience: get display_name for a detector key, falling back to the key itself. */
export function getDetectorDisplayName(key: string): string {
  return DETECTORS[key]?.display_name ?? key;
}

/** Convenience: get description for a detector key. */
export function getDetectorDescription(key: string): string | null {
  return DETECTORS[key]?.description ?? null;
}

/** Every live detector, useful for docs/landing pages. */
export function listLiveDetectors(): DetectorDefinition[] {
  return Object.values(DETECTORS).filter((d) => d.status === 'live');
}
