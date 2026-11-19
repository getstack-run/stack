import {
  ResendEmailService,
  SmtpEmailService,
  smtpConfigFromUrl,
  type EmailSender,
  type SmtpConfig,
} from '@stack/vault';

/**
 * How this deployment sends mail.
 *
 * STACK's hosted deployment sends through Resend, as it always has. A
 * self-managed deployment picks one of three, by `STACK_EMAIL_TRANSPORT`, or
 * by what is configured when that is omitted (a Resend key, else SMTP, else
 * none):
 *
 *   resend  RESEND_API_KEY
 *   smtp    SMTP_URL (smtp:// with STARTTLS, or smtps://) or SMTP_HOST,
 *           SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_SECURE; and EMAIL_FROM
 *   none    no mail leaves this install. A flow that needs mail says so (a
 *           service that sends is null) rather than appearing to send.
 */
export type EmailTransport =
  | { kind: 'resend'; apiKey: string }
  | { kind: 'smtp'; config: SmtpConfig }
  | { kind: 'none' };

export interface EmailTransportEnv {
  selfManaged: boolean;
  transport?: string | undefined;
  resendKey?: string | undefined;
  smtpUrl?: string | undefined;
  smtpHost?: string | undefined;
  smtpPort?: string | undefined;
  smtpUser?: string | undefined;
  smtpPassword?: string | undefined;
  smtpSecure?: string | undefined;
  smtpAllowInsecure?: string | undefined;
  emailFrom?: string | undefined;
  replyTo?: string | undefined;
}

function flag(value: string | undefined): boolean {
  return value === 'true' || value === '1';
}

export function resolveEmailTransport(env: EmailTransportEnv): EmailTransport {
  const resendKey = env.resendKey?.trim() ?? '';
  // The hosted deployment has one provider and no choice to make.
  if (!env.selfManaged) return resendKey ? { kind: 'resend', apiKey: resendKey } : { kind: 'none' };

  const smtpConfigured = Boolean(env.smtpUrl?.trim() || env.smtpHost?.trim());
  const requested = env.transport?.trim() || undefined;
  if (requested && requested !== 'resend' && requested !== 'smtp' && requested !== 'none') {
    throw new Error('[BOOT] STACK_EMAIL_TRANSPORT must be "resend", "smtp" or "none"');
  }
  const kind = (requested ?? (resendKey ? 'resend' : smtpConfigured ? 'smtp' : 'none')) as 'resend' | 'smtp' | 'none';

  if (kind === 'none') return { kind };
  if (kind === 'resend') {
    if (!resendKey) throw new Error('[BOOT] STACK_EMAIL_TRANSPORT=resend needs RESEND_API_KEY');
    return { kind, apiKey: resendKey };
  }
  if (!smtpConfigured) throw new Error('[BOOT] STACK_EMAIL_TRANSPORT=smtp needs SMTP_URL or SMTP_HOST');
  const from = env.emailFrom?.trim() ?? '';
  if (!from) throw new Error('[BOOT] EMAIL_FROM is required to send mail over SMTP');
  const rest = {
    from,
    replyTo: env.replyTo,
    allowInsecure: flag(env.smtpAllowInsecure),
  };
  if (env.smtpUrl?.trim()) return { kind, config: smtpConfigFromUrl(env.smtpUrl.trim(), rest) };
  const secure = flag(env.smtpSecure);
  const port = env.smtpPort?.trim() ? Number(env.smtpPort) : secure ? 465 : 587;
  return {
    kind,
    config: {
      host: env.smtpHost!.trim(),
      port,
      secure,
      ...(env.smtpUser ? { user: env.smtpUser } : {}),
      ...(env.smtpPassword ? { password: env.smtpPassword } : {}),
      ...rest,
    },
  };
}

export interface EmailSenders {
  /** Operator-facing alerts and security events. */
  notifications: EmailSender | null;
  /** Sign-in and invitation mail. */
  auth: EmailSender | null;
  /** Account notices and transfers. */
  account: EmailSender | null;
}

/**
 * The senders the services take. Resend keeps the three from-addresses and the
 * deliverability headers it has always had; SMTP uses the one `EMAIL_FROM`.
 */
export function createEmailSenders(
  transport: EmailTransport,
  resend: {
    fromNotifications: string;
    fromAuth: string;
    replyTo: string;
    listUnsubscribe: string;
  },
): EmailSenders {
  if (transport.kind === 'none') return { notifications: null, auth: null, account: null };
  if (transport.kind === 'smtp') {
    const sender = new SmtpEmailService(transport.config);
    return { notifications: sender, auth: sender, account: sender };
  }
  return {
    notifications: new ResendEmailService({
      apiKey: transport.apiKey,
      fromEmail: resend.fromNotifications,
      replyTo: resend.replyTo,
      listUnsubscribe: resend.listUnsubscribe,
    }),
    auth: new ResendEmailService({
      apiKey: transport.apiKey,
      fromEmail: resend.fromAuth,
      replyTo: resend.replyTo,
    }),
    // "Connect with STACK" and email transfer reuse the notifications-grade
    // sender: these are account-security emails, not marketing, and they must send.
    account: new ResendEmailService({
      apiKey: transport.apiKey,
      fromEmail: resend.fromNotifications,
      replyTo: resend.replyTo,
      listUnsubscribe: resend.listUnsubscribe,
    }),
  };
}
