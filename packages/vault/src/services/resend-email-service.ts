/**
 * Resend email service — uses Resend REST API directly (no SDK dependency).
 * Same pattern as the text-message service.
 *
 * Deliverability hygiene applied to every send:
 *   - Identifying signature footer (text + html), when the deployment has
 *     one (its email chrome): strict spam filters penalise short,
 *     link-heavy bodies; the footer adds real text and declares sender
 *     provenance. Opt out per-send via skipSignature.
 *   - Reply-To header — strict filters (Fastmail / ProtonMail / SpamAssassin)
 *     penalise noreply@-style mail without a reply path. Defaults from
 *     constructor; per-send override allowed.
 *   - List-Unsubscribe + List-Unsubscribe-Post (one-click) — Gmail/Yahoo
 *     bulk-sender rules (Feb 2024) strongly recommend these even on
 *     transactional mail. Defaults from constructor; per-send override
 *     allowed.
 */

import { emailChrome } from '@stack/shared';
import { skipStagingRecipient } from './staging-email-guard.js';

const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

export interface SendEmailOptions {
  /** Override the default from address for this send. */
  from?: string;
  /** Override the default Reply-To for this send. Empty string disables it. */
  replyTo?: string;
  /** Override the default List-Unsubscribe value for this send. Empty string disables it. */
  listUnsubscribe?: string;
  /** Provider idempotency key for safe retries of the same logical send. */
  idempotencyKey?: string;
  /** Skip the identifying signature footer. Use only when the body already
      provides its own branded footer (e.g. the daily digest renders one). */
  skipSignature?: boolean;
}

/** The provider answered with a non-success status. Nothing about the recipient is in it. */
export class ResendEmailError extends Error {
  constructor(readonly status: number) {
    super(`Resend email failed (${status})`);
    this.name = 'ResendEmailError';
  }
}

/**
 * Whether Resend's answer says this message can never be sent, however often it
 * is tried: the request or the recipient is invalid (400, 404, 410, 413, 422).
 * Everything else, including a refused key (401, 403), a rate limit (429), an
 * idempotency conflict (409) and any 5xx, can come right on a later try.
 */
export function isPermanentEmailRejection(status: number): boolean {
  return status === 400 || status === 404 || status === 410 || status === 413 || status === 422;
}

/** What one real send to Resend came to: it answered 2xx, answered another status, or did not answer (`status` null). */
export type ResendSendOutcome = { ok: true } | { ok: false; status: number | null };

let sendObserver: ((outcome: ResendSendOutcome) => void) | null = null;

/**
 * Registers the one observer of every real send of this process (a deployment's monitoring). It is called without the recipient or any
 * content, never awaited, and an observer that throws is ignored: observing a send must not change it.
 */
export function observeResendSends(observer: ((outcome: ResendSendOutcome) => void) | null): void {
  sendObserver = observer;
}

function observeSend(outcome: ResendSendOutcome): void {
  try {
    sendObserver?.(outcome);
  } catch {
    // Observing a send never changes it.
  }
}

export class ResendEmailService {
  private apiKey: string;
  private fromEmail: string;
  private replyTo: string | undefined;
  private listUnsubscribe: string | undefined;
  private requestTimeoutMs: number;

  constructor(config: {
    apiKey: string;
    fromEmail: string;
    replyTo?: string;
    listUnsubscribe?: string;
    requestTimeoutMs?: number;
  }) {
    this.apiKey = config.apiKey;
    this.fromEmail = config.fromEmail;
    this.replyTo = config.replyTo || undefined;
    this.listUnsubscribe = config.listUnsubscribe || undefined;
    this.requestTimeoutMs = config.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  }

  async sendEmail(
    to: string,
    subject: string,
    text: string,
    html?: string,
    options?: SendEmailOptions,
  ): Promise<{ id: string }> {
    const skipped = skipStagingRecipient(to);
    if (skipped) return skipped;
    const from = options?.from ?? this.fromEmail;
    const replyTo = options?.replyTo !== undefined ? options.replyTo : this.replyTo;
    const listUnsubscribe =
      options?.listUnsubscribe !== undefined ? options.listUnsubscribe : this.listUnsubscribe;
    const skipSignature = options?.skipSignature === true;

    // The footer is the deployment's: none unless it registered one with its email chrome.
    const signature = skipSignature ? null : emailChrome().signature();
    const finalText = signature ? text + signature.text : text;
    const finalHtml = html === undefined ? undefined : signature ? html + signature.html : html;

    const headers: Record<string, string> = {};
    if (listUnsubscribe) {
      headers['List-Unsubscribe'] = listUnsubscribe;
      headers['List-Unsubscribe-Post'] = 'List-Unsubscribe=One-Click';
    }

    const body: Record<string, unknown> = {
      from,
      to: [to],
      subject,
      text: finalText,
    };
    if (finalHtml !== undefined) body['html'] = finalHtml;
    if (replyTo) body['reply_to'] = replyTo;
    if (Object.keys(headers).length > 0) body['headers'] = headers;

    const requestHeaders: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json',
    };
    if (options?.idempotencyKey) requestHeaders['Idempotency-Key'] = options.idempotencyKey;

    let response: Response;
    try {
      response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: requestHeaders,
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.requestTimeoutMs),
      });
    } catch (error) {
      observeSend({ ok: false, status: null });
      throw error;
    }
    observeSend(response.ok ? { ok: true } : { ok: false, status: response.status });

    if (!response.ok) {
      throw new ResendEmailError(response.status);
    }

    const result = (await response.json()) as { id: string };
    return { id: result.id };
  }
}
