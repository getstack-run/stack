import type { HttpClient } from '../client.js';

// The control socket: who decides for your agents' actions, and where their
// record is streamed. A decision address is your own server, asked to allow or
// refuse each checked action; an events address receives the whole record,
// signed. Both sign with a Standard Webhooks secret that is shown once, when
// it is created or rotated (see `verifyControlSocketRequest` and
// `signControlSocketAnswer` for the server side).
//
// Every change is an owner or admin decision and never available to an agent.
// An address change, a rotation and anything that loosens (clearing an
// enforcing decision address, unchecking an action kind, turning hosted
// controls off or switching away from your own server) is a governance action:
// without a dashboard session it throws `GovernanceApprovalRequiredError`
// first; once a person approves at its link, send the same call again with its
// `approvalId`. Tightening applies at once. None of it is metered.

export const CONTROL_ACTION_TYPES = [
  'model.call',
  'proxy.call',
  'tool.run',
  'email.send',
  'sms.send',
  'telegram.send',
  'call.start',
  'call.answer',
  'meeting.join',
  'browser.session.start',
  'browser.navigate',
  'card.checkout',
  'wallet.payment',
  'workspace.exec',
  'account.open',
  'dropoff.create',
  'dropoff.deposit',
  'a2a.send',
  'skill.invoke',
  'passport.delegate',
  'wake.deliver',
  'drive.upload',
  'drive.share',
  'memory.write',
  'memory.delete',
  'brain.add',
  'site.publish',
  'payment.request',
  'letter.send',
  'post.scan',
  'post.forward',
  'post.shred',
  'making.quote',
  'making.order',
] as const;
/** A kind of action a decision address can be asked about. */
export type ControlActionType = (typeof CONTROL_ACTION_TYPES)[number];

/** Which address a call is about. */
export type ControlSocketTarget = 'decision' | 'events';
/** Who decides: STACK's hosted controls, your own server, or nobody. */
export type ControlDecider = 'none' | 'hosted' | 'remote';
/** What was chosen; `auto` is hosted checks while controls are on, none otherwise. */
export type ControlModeSetting = 'auto' | 'none' | 'hosted' | 'remote';
/** The modes a call can switch to. Your own server is switched on by verifying its address. */
export type ControlSocketMode = 'none' | 'hosted';
export type ControlDecisionStatus = 'unverified' | 'enforcing' | 'paused';
export type ControlEventsStatus = 'off' | 'unverified' | 'active' | 'failing';
export type ControlVerdict = 'allow' | 'deny' | 'unavailable';
/** What happens when your own decision server does not answer in time. */
export type ControlOnUnavailable = 'refuse' | 'allow';
export type ControlUnavailableCause =
  | 'timeout'
  | 'unreachable'
  | 'unsafe_address'
  | 'http_status'
  | 'bad_signature'
  | 'bad_body'
  | 'mismatch'
  | 'busy'
  | 'breaker_open'
  | 'unverified'
  | 'paused'
  | 'secret_unavailable'
  | 'hosted_failure';

export interface ControlAddressView {
  url: string | null;
  /** A new address that is set but not yet verified; the current one keeps deciding until it is. */
  pending_url: string | null;
  status: string;
  verified_at: string | null;
  secret_set: boolean;
  secret_rotated_at: string | null;
}

export interface ControlSocket {
  socket_id: string | null;
  mode_setting: ControlModeSetting;
  /** Who decides right now: `remote` only while the decision address is enforcing. */
  effective_mode: ControlDecider;
  /** Whether STACK's hosted controls are on for this account. */
  controls_enabled: boolean;
  decision: ControlAddressView & { status: ControlDecisionStatus; timeout_ms: number; on_unavailable: ControlOnUnavailable };
  events: ControlAddressView & {
    status: ControlEventsStatus;
    last_acknowledged_seq: number;
    pending_events: number;
    dead_events: number;
    last_error: string | null;
  };
  /** The action kinds checked right now. */
  checked_types: ControlActionType[];
  /** True when every kind is checked, which also covers kinds added later. */
  checks_all_types: boolean;
}

export interface SetDecisionAddressInput {
  url: string;
  /** How long STACK waits for your answer, 300 to 2000 ms. The default is 1500. */
  timeout_ms?: number;
}

export interface SetEventsAddressInput {
  url: string;
}

/** The socket after a change, and the signing secret when this call created it. */
export interface ControlAddressChange {
  socket: ControlSocket;
  /** Present only when this call created the signing secret. Store it now; it is not shown again. */
  secret: string | null;
  /** Instead of `secret`, for an OAuth token: the Console link where the person reads the new secret once. */
  secret_reveal: ControlSecretReveal | null;
}

/** Where a person reads a signing secret created for a caller that must not hold it. Single use, one hour. */
export interface ControlSecretReveal {
  url: string;
  expires_at: string;
}

export interface RotatedControlSecret {
  target: ControlSocketTarget;
  /** The new signing secret, shown once. Null for an OAuth token, which gets `secret_reveal` instead. */
  secret: string | null;
  secret_reveal: ControlSecretReveal | null;
  /** The rotated-out secret keeps verifying until then (24 hours). */
  previous_valid_until: string | null;
}

export interface ControlTestResult {
  target: ControlSocketTarget;
  ok: boolean;
  latency_ms: number;
  /** For a decision address: the verdict your server gave. */
  verdict: 'allow' | 'deny' | null;
  cause: ControlUnavailableCause | null;
  /** Set by `verify`: the address is now in use. */
  activated: boolean;
}

export interface ControlDecision {
  id: string;
  account_id: string | null;
  agent_id: string | null;
  action_type: string;
  decider: ControlDecider;
  verdict: ControlVerdict;
  reason_code: string | null;
  cause: string | null;
  latency_ms: number;
  charged: boolean;
  request_digest: string;
  /** The request as sent, for a refusal or an unreachable server, within its retention. */
  request: Record<string, unknown> | null;
  /** Which rule of a hosted policy refused (policy_id, policy_revision, section, rule, code, detail?): its side only, never a value from the call. Null otherwise. */
  evidence: Record<string, unknown> | null;
  created_at: string;
}

export interface ListControlDecisionsQuery {
  /** 1 to 200; 50 when omitted. */
  limit?: number;
  account_id?: string;
  verdict?: ControlVerdict;
  /** An ISO timestamp: only decisions made before it, for the next page. */
  before?: string;
}

export interface ListControlDecisionsResult {
  decisions: ControlDecision[];
}

/** Changes a human approves first when the credential is not a dashboard session. */
export interface ControlSocketGovernedOptions {
  /** The approval id from `GovernanceApprovalRequiredError`, once a human approved it. Call again with the same input. */
  governanceApprovalId?: string;
}

const seg = encodeURIComponent;

function governed(options?: ControlSocketGovernedOptions): { headers: Record<string, string> } | undefined {
  return options?.governanceApprovalId ? { headers: { 'X-Governance-Approval': options.governanceApprovalId } } : undefined;
}

/** The decisions made through the socket. Reads; never governed, never metered. */
export class ControlDecisionsService {
  constructor(private readonly client: HttpClient) {}

  /** Decisions newest first, filtered by account or verdict; page back with `before`. */
  async list(query: ListControlDecisionsQuery = {}): Promise<ListControlDecisionsResult> {
    return this.client.get<ListControlDecisionsResult>('/v1/control-decisions', {
      limit: query.limit !== undefined ? String(query.limit) : undefined,
      account_id: query.account_id,
      verdict: query.verdict,
      before: query.before,
    });
  }

  /** One decision, with its request while it is within its retention. */
  async get(id: string): Promise<ControlDecision> {
    return this.client.get<ControlDecision>(`/v1/control-decisions/${seg(id)}`);
  }
}

/**
 * Your control socket.
 *
 * @example
 * ```ts
 * const { secret } = await stack.controlSocket.setDecisionAddress({ url: 'https://control.example.com/decide' });
 * // Store `secret` now: it is not shown again. Then run the setup check:
 * const result = await stack.controlSocket.verify('decision');
 * if (result.activated) console.log('your server now decides');
 * ```
 */
export class ControlSocketService {
  readonly decisions: ControlDecisionsService;

  constructor(private readonly client: HttpClient) {
    this.decisions = new ControlDecisionsService(client);
  }

  /** The socket as configured, with who decides now. */
  async get(): Promise<ControlSocket> {
    return this.client.get<ControlSocket>('/v1/control-socket');
  }

  /**
   * Set or change the decision address. The first call creates the signing
   * secret and returns it once in `secret`. The address decides nothing until
   * `verify('decision')` passes; the current one keeps deciding meanwhile.
   * A governance action.
   */
  async setDecisionAddress(input: SetDecisionAddressInput, options?: ControlSocketGovernedOptions): Promise<ControlAddressChange> {
    return this.client.put<ControlAddressChange>(
      '/v1/control-socket/decision',
      { url: input.url, ...(input.timeout_ms !== undefined ? { timeout_ms: input.timeout_ms } : {}) },
      governed(options),
    );
  }

  /**
   * Set or change the events address that receives your agents' record. The
   * first call creates the signing secret and returns it once in `secret`.
   * Run `verify('events')` to start delivery. A governance action.
   */
  async setEventsAddress(input: SetEventsAddressInput, options?: ControlSocketGovernedOptions): Promise<ControlAddressChange> {
    return this.client.put<ControlAddressChange>('/v1/control-socket/events', { url: input.url }, governed(options));
  }

  /**
   * Remove the decision or events address. A governance action; clearing an
   * address that is deciding is a loosening and its approval says so.
   */
  async clear(target: ControlSocketTarget, options?: ControlSocketGovernedOptions): Promise<ControlSocket> {
    return this.client.delete<ControlSocket>(`/v1/control-socket/${seg(target)}`, governed(options));
  }

  /**
   * The setup check: one real exchange with the address. When it passes, the
   * address is put into use (`activated: true`). Switching from hosted
   * controls to your own server is a governance action.
   */
  async verify(target: ControlSocketTarget, options?: ControlSocketGovernedOptions): Promise<ControlTestResult> {
    return this.client.post<ControlTestResult>(`/v1/control-socket/${seg(target)}/verify`, undefined, governed(options));
  }

  /** One test exchange with the address; nothing changes. */
  async test(target: ControlSocketTarget): Promise<ControlTestResult> {
    return this.client.post<ControlTestResult>(`/v1/control-socket/${seg(target)}/test`);
  }

  /**
   * Replace the signing secret. The new one is returned once; the old one
   * keeps verifying for 24 hours. A governance action.
   */
  async rotateSecret(target: ControlSocketTarget, options?: ControlSocketGovernedOptions): Promise<RotatedControlSecret> {
    return this.client.post<RotatedControlSecret>(`/v1/control-socket/${seg(target)}/secret/rotate`, undefined, governed(options));
  }

  /**
   * Switch between STACK's hosted controls and none. `hosted` needs controls
   * on (`CONTROLS_NOT_ENABLED` otherwise). Turning controls off, or leaving
   * your own server for hosted controls, is a governance action.
   */
  async setMode(mode: ControlSocketMode, options?: ControlSocketGovernedOptions): Promise<ControlSocket> {
    return this.client.put<ControlSocket>('/v1/control-socket/mode', { mode }, governed(options));
  }

  /**
   * What happens when your own decision server does not answer in time: `'refuse'` (the default: the action is refused) or
   * `'allow'` (it goes through). Only an answer that never came follows it: a forged or garbled answer, a blocked address and a
   * server not verified or paused are refused whatever it says. `'allow'` loosens a control, so it is a governance action;
   * `'refuse'` applies at once.
   */
  async setOnUnavailable(onUnavailable: ControlOnUnavailable, options?: ControlSocketGovernedOptions): Promise<ControlSocket> {
    return this.client.put<ControlSocket>('/v1/control-socket/on-unavailable', { on_unavailable: onUnavailable }, governed(options));
  }

  /**
   * Which action kinds are checked. `null` checks every kind, including kinds
   * added later. Removing a kind is a governance action.
   */
  async setCheckedTypes(types: readonly ControlActionType[] | null, options?: ControlSocketGovernedOptions): Promise<ControlSocket> {
    return this.client.put<ControlSocket>('/v1/control-socket/checked-types', { types: types === null ? null : [...types] }, governed(options));
  }
}
