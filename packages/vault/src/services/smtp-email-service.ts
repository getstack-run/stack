import nodemailer, { type Transporter } from 'nodemailer';
import type { EmailSender } from './email-sender.js';
import type { SendEmailOptions } from './resend-email-service.js';
import { skipStagingRecipient } from './staging-email-guard.js';

/**
 * Email through the customer's own SMTP relay, for a deployment that does not
 * use Resend. The transport is nodemailer: STARTTLS negotiation, AUTH and
 * MIME encoding are the parts of SMTP that are easy to get subtly wrong by
 * hand (dot-stuffing, header injection, encoded words), so none of it is
 * written here.
 *
 * Posture:
 *   - the connection is encrypted: implicit TLS (`secure`, port 465), or
 *     STARTTLS required and never downgraded. Plain SMTP is accepted only to a
 *     loopback host, or when the operator says so (`allowInsecure`), because
 *     credentials and message bodies cross that wire;
 *   - the server's certificate is verified;
 *   - nothing STACK-branded is appended: the message is exactly what the
 *     caller composed.
 */

export interface SmtpConfig {
  host: string;
  port: number;
  /** Implicit TLS from the first byte (port 465). Otherwise STARTTLS is required. */
  secure: boolean;
  user?: string | undefined;
  password?: string | undefined;
  /** The From address of every message that names no other. */
  from: string;
  replyTo?: string | undefined;
  /** Plain, unencrypted SMTP to a non-loopback host. Off unless the operator turns it on. */
  allowInsecure?: boolean | undefined;
  requestTimeoutMs?: number | undefined;
}

/** The relay refused a message, or could not be reached. Nothing about the recipient is in it. */
export class SmtpEmailError extends Error {
  /** The SMTP reply code when the relay answered, else 0. 5xx is a rejection a retry cannot fix. */
  constructor(readonly code: number) {
    super(code > 0 ? `SMTP email failed (${code})` : 'SMTP email failed (unreachable)');
    this.name = 'SmtpEmailError';
  }

  get permanent(): boolean {
    return this.code >= 500 && this.code < 600;
  }
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);
const ADDRESS = /^[^\s<>()",;:\\\r\n]+@[^\s<>()",;:\\\r\n]+$/;

/** `smtps://user:pass@host:465` or `smtp://user:pass@host:587`, plus the sender address. */
export function smtpConfigFromUrl(
  url: string,
  rest: { from: string; replyTo?: string | undefined; allowInsecure?: boolean | undefined },
): SmtpConfig {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('[BOOT] SMTP_URL is not a valid URL');
  }
  if (parsed.protocol !== 'smtp:' && parsed.protocol !== 'smtps:') {
    throw new Error('[BOOT] SMTP_URL must start with smtp:// or smtps://');
  }
  const secure = parsed.protocol === 'smtps:';
  return {
    host: parsed.hostname,
    port: parsed.port ? Number(parsed.port) : secure ? 465 : 587,
    secure,
    ...(parsed.username ? { user: decodeURIComponent(parsed.username) } : {}),
    ...(parsed.password ? { password: decodeURIComponent(parsed.password) } : {}),
    from: rest.from,
    ...(rest.replyTo ? { replyTo: rest.replyTo } : {}),
    ...(rest.allowInsecure ? { allowInsecure: true } : {}),
  };
}

export function assertSmtpConfig(config: SmtpConfig): void {
  if (!config.host) throw new Error('[BOOT] SMTP host is required');
  if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
    throw new Error('[BOOT] SMTP port is invalid');
  }
  if (!config.from.trim()) throw new Error('[BOOT] EMAIL_FROM is required to send mail over SMTP');
  if ((config.user && !config.password) || (!config.user && config.password)) {
    throw new Error('[BOOT] SMTP user and password must be set together');
  }
}

export class SmtpEmailService implements EmailSender {
  private readonly transporter: Transporter;
  private readonly from: string;
  private readonly replyTo: string | undefined;

  constructor(
    config: SmtpConfig,
    /** Test seam: a prepared transport. Production builds its own. */
    transporter?: Transporter,
  ) {
    assertSmtpConfig(config);
    this.from = config.from;
    this.replyTo = config.replyTo || undefined;
    // Plain SMTP only to this machine, or where the operator named an
    // unencrypted relay on purpose.
    const plainAllowed = Boolean(config.allowInsecure) || LOOPBACK.has(config.host.toLowerCase());
    this.transporter =
      transporter ??
      nodemailer.createTransport({
        host: config.host,
        port: config.port,
        secure: config.secure,
        // Without implicit TLS, STARTTLS is required and never downgraded.
        requireTLS: !config.secure && !plainAllowed,
        ignoreTLS: !config.secure && plainAllowed,
        ...(config.user ? { auth: { user: config.user, pass: config.password! } } : {}),
        tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' },
        connectionTimeout: config.requestTimeoutMs ?? 10_000,
        greetingTimeout: config.requestTimeoutMs ?? 10_000,
        socketTimeout: (config.requestTimeoutMs ?? 10_000) * 2,
        disableFileAccess: true,
        disableUrlAccess: true,
      });
  }

  async sendEmail(
    to: string,
    subject: string,
    text: string,
    html?: string,
    options?: SendEmailOptions,
  ): Promise<{ id: string }> {
    if (!ADDRESS.test(to)) throw new SmtpEmailError(0);
    const skipped = skipStagingRecipient(to);
    if (skipped) return skipped;
    const replyTo = options?.replyTo !== undefined ? options.replyTo : this.replyTo;
    const listUnsubscribe =
      options?.listUnsubscribe !== undefined ? options.listUnsubscribe : undefined;
    try {
      const info = (await this.transporter.sendMail({
        from: options?.from ?? this.from,
        to,
        subject,
        text,
        ...(html !== undefined ? { html } : {}),
        ...(replyTo ? { replyTo } : {}),
        ...(listUnsubscribe
          ? { list: { unsubscribe: { url: listUnsubscribe, comment: 'Unsubscribe' } } }
          : {}),
        // The idempotency key is a Resend feature; a stable Message-ID is the
        // closest an SMTP relay offers for de-duplicating a retried message.
        ...(options?.idempotencyKey
          ? { messageId: `<${options.idempotencyKey.replace(/[^A-Za-z0-9._-]/g, '')}@stack.local>` }
          : {}),
      })) as { messageId?: string };
      return { id: info.messageId ?? '' };
    } catch (err) {
      const code = (err as { responseCode?: unknown } | null)?.responseCode;
      throw new SmtpEmailError(typeof code === 'number' ? code : 0);
    }
  }
}
