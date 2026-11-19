import { sendUnauthenticated } from './client.js';
import { InstallKey, passportDigest, type NetworkProofAction } from './network-install-key.js';
import type { NetworkRevocation, NetworkRevocationKind, NetworkRevocationReason } from './services/network.js';
import { verifyDetectionRules, type DetectionRuleSet, type NetworkKeySource } from './verify-network.js';

// What a self-hosted install calls. An install holds no account credential:
// every request carries a fresh proof signed with the install's own key, so a
// leaked key can call the network and nothing else, and revoking it ends that
// at once. Each proof is good for one request.

export interface InstallClientOptions {
  /** The install's id (`ins_...`), from `stack.network.installs.register`. */
  installId: string;
  /** The install's key. Load it with `InstallKey.fromPem`. */
  key: InstallKey;
  /** The API base URL. Defaults to `STACK_API_URL`, then https://api.getstack.run. */
  baseUrl?: string;
  /**
   * STACK's public keys, for checking what STACK signs. Fetched from the API's
   * `/v1/network/jwks.json` when omitted; pin them to trust nothing the network
   * serves about itself.
   */
  keys?: NetworkKeySource;
}

/** What an agent declared for its passport and what it then did: what STACK grades for intent deviation. */
export interface IntentDeviationInput {
  declared: { summary: string; services: string[] };
  observed: {
    services_used: string[];
    tool_calls: Array<{ service: string; method: string; target?: string }>;
    actions_count: number;
    summary?: string;
  };
}

/** STACK's grade of a checkout: a score from 0 (matched the intent) to 1 (unrelated), and a flag from 0.4. */
export interface IntentDeviationResult {
  request_id: string;
  /** False when no model could grade it; `score` and `flag` are then null. */
  graded: boolean;
  score: number | null;
  flag: { severity: 'warning' | 'critical'; message: string } | null;
  duration_ms: number;
}

export interface ClassifyResult {
  verdict: 'clean' | 'suspicious' | 'critical';
  request_id: string;
  duration_ms: number;
  rules_version: string;
  /** The rule that fired, with up to about 80 characters of the text that matched. */
  match: { pattern_id: string; severity: string; field_path: string; matched_excerpt: string; encoding?: string } | null;
  /** The model's verdict, when it ran. */
  llm: { verdict: string; confidence: number; reasoning: string; model: string } | null;
  /** Set when the model could not answer: the verdict is the pattern layers' alone. */
  l3_degraded: { reason: string; duration_ms: number } | null;
}

export interface Countersignature {
  id: string;
  /** The compact JWS. Hand it, with the passport, to whoever needs to trust it. */
  countersignature: string;
  expires_at: string;
  install: string;
  passport_digest: string;
}

export interface FetchedRules extends DetectionRuleSet {
  /** The signed statement as served, to keep alongside the rules. */
  statement: string;
}

export class InstallClient {
  private readonly baseUrl: string;
  private keysPromise: Promise<NetworkKeySource> | null = null;

  constructor(private readonly options: InstallClientOptions) {
    this.baseUrl = (options.baseUrl ?? process.env['STACK_API_URL'] ?? 'https://api.getstack.run').replace(/\/$/, '');
  }

  /**
   * The current detection rule set, checked against STACK's keys. Pass the highest
   * `revision` you already run as `heldRevision`: a lower one is refused, and so is
   * an expired set. Metered as one action.
   */
  async rules(options: { heldRevision?: number } = {}): Promise<FetchedRules> {
    const response = await this.call<{ statement: string }>('POST', '/v1/network/detection/rules', 'rules', {}, {});
    const rules = await verifyDetectionRules(response.statement, { ...(await this.keys()), ...options });
    return { ...rules, statement: response.statement };
  }

  /**
   * Send content to STACK's classifier and get a verdict. The content leaves the
   * install: at most its first 2,500 and last 1,500 characters reach the model, and
   * STACK keeps none of it. Metered as one action, plus the model call at cost.
   */
  async classify(content: string | Record<string, unknown>, context?: 'email' | 'document' | 'webpage' | 'chat_log' | 'api_response' | 'calendar' | 'other'): Promise<ClassifyResult> {
    return this.call<ClassifyResult>('POST', '/v1/network/detection/classify', 'classify', {}, { content, ...(context ? { context } : {}) });
  }

  /**
   * Have STACK grade a checkout for intent deviation: what the agent declared against what it did. The declared intent
   * and the observed behaviour leave the install, with no identifier; STACK keeps none of it. Metered as one action,
   * plus the model call at cost. Signed with a proof for `classify`.
   */
  async gradeIntentDeviation(input: IntentDeviationInput): Promise<IntentDeviationResult> {
    return this.call<IntentDeviationResult>('POST', '/v1/network/detection/intent-deviation', 'classify', {}, input);
  }

  /**
   * Have STACK countersign a passport this install issued. Only the passport's digest
   * is sent. The install's key must be the one that signed the passport. Ask again
   * when you refresh the passport. Metered as one action.
   */
  async countersign(input: { passport: string; agent?: string; passportId?: string; ttlSeconds?: number }): Promise<Countersignature> {
    return this.call<Countersignature>(
      'POST',
      '/v1/network/countersignatures',
      'countersign',
      {
        pd: passportDigest(input.passport),
        ...(input.passportId ? { pjti: input.passportId } : {}),
        ...(input.agent ? { agent: input.agent } : {}),
        ...(input.ttlSeconds !== undefined ? { ttl: input.ttlSeconds } : {}),
      },
      {},
    );
  }

  /**
   * Publish a revocation of one of this install's passports (subject: its digest),
   * agents, its key (subject: its thumbprint) or the install. Public: the subject
   * and reason appear on the list counterparties read. Never metered.
   */
  async publishRevocation(input: { kind: NetworkRevocationKind; subject: string; reason?: NetworkRevocationReason }): Promise<NetworkRevocation> {
    return this.call<NetworkRevocation>(
      'POST',
      '/v1/network/revocations',
      'revoke',
      { kind: input.kind, subject: input.subject, ...(input.reason ? { reason: input.reason } : {}) },
      {},
    );
  }

  private keys(): Promise<NetworkKeySource> {
    if (this.options.keys) return Promise.resolve(this.options.keys);
    this.keysPromise ??= sendUnauthenticated<{ keys: import('jose').JWK[] }>(`${this.baseUrl}/v1/network/jwks.json`, 'GET').then((jwks) => ({ jwks }));
    return this.keysPromise;
  }

  private async call<T>(method: string, path: string, act: NetworkProofAction, claims: Record<string, unknown>, body: unknown): Promise<T> {
    const proof = await this.options.key.signProof(this.options.installId, { act, ...claims });
    return sendUnauthenticated<T>(`${this.baseUrl}${path}`, method, body, { Authorization: `Bearer ${proof}` });
  }
}
