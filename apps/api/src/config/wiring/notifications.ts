import { deployment, type Database } from '@stack/shared';
import {
  NotificationService,
  NotificationChannelRepository,
  NotificationDestinationRepository,
  type EmailSender,
  type KmsService,
  type NotificationSendMeter,
  type SmsTransport,
} from '@stack/vault';
import { env } from '../env.js';
import { createEmailSenders, resolveEmailTransport } from '../email-transport.js';
import type { ProviderConfigs } from './provider-config.js';

export interface Notifications {
  notification: NotificationService;
  notificationChannel: NotificationChannelRepository;
  notificationDestination: NotificationDestinationRepository;
  /** Auth-grade transactional delivery (sign-in links). Null only in local development. */
  authEmail: EmailSender | null;
  /** Sender for the "Connect with STACK" and email-change flows; null without a Resend key. */
  accountEmail: EmailSender | null;
}

/**
 * Operator notifications: channels, destinations, SMS and email delivery, and
 * the spend meter that caps every send which costs vendor money.
 */
export function createNotifications(deps: {
  db: Database;
  kms: KmsService;
  providers: Pick<ProviderConfigs, 'resendKey'>;
  /** How a text message is sent. Null: the SMS channel answers that delivery is unavailable. */
  sms: SmsTransport | null;
  /** Caps every send that costs vendor money. Null: sends are not metered (an install pays no vendor). */
  sendMeter: NotificationSendMeter | null;
}): Notifications {
  const { db, kms, providers, sms, sendMeter } = deps;
  const { resendKey } = providers;
  const notificationChannel = new NotificationChannelRepository(db);
  const notificationDestination = new NotificationDestinationRepository(db);
  const notification = new NotificationService(db, notificationChannel, sms);
  notification.setDestinationRepo(notificationDestination);
  notification.setSecretCrypto(kms);

  // Email: Resend (vault first, env var fallback) for STACK's own deployment;
  // a self-managed one may use SMTP or send none (see config/email-transport.ts).
  // Notifications-grade FROM (operator-facing security events + alerts), with
  // deliverability headers wired from env.
  const emailTransport = resolveEmailTransport({
    selfManaged: deployment().selfManaged,
    transport: process.env['STACK_EMAIL_TRANSPORT'],
    resendKey,
    smtpUrl: process.env['SMTP_URL'],
    smtpHost: process.env['SMTP_HOST'],
    smtpPort: process.env['SMTP_PORT'],
    smtpUser: process.env['SMTP_USER'],
    smtpPassword: process.env['SMTP_PASSWORD'],
    smtpSecure: process.env['SMTP_SECURE'],
    smtpAllowInsecure: process.env['SMTP_ALLOW_INSECURE'],
    emailFrom: process.env['EMAIL_FROM'],
    replyTo: env.RESEND_REPLY_TO,
  });
  const senders = createEmailSenders(emailTransport, {
    fromNotifications: env.RESEND_FROM_NOTIFICATIONS || env.RESEND_FROM_EMAIL,
    fromAuth: env.RESEND_FROM_AUTH,
    replyTo: env.RESEND_REPLY_TO,
    listUnsubscribe: env.RESEND_LIST_UNSUBSCRIBE,
  });
  if (senders.notifications) notification.setEmailService(senders.notifications);
  const authEmail = senders.auth;

  // Notification spend cap. Every send that costs vendor money — dispatched
  // events and verification codes alike — passes the gate inside
  // NotificationService.
  if (sendMeter) {
    notification.setSendMeter(sendMeter);
    if (sms && !env.isDev) {
      // Fail loudly rather than silently running an uncapped SMS lane in prod.
      console.log('[NOTIFICATION] Send meter wired — SMS and email are counted and capped.');
    }
  }

  // "Connect with STACK" and email transfer reuse the notifications-grade
  // sender: these are account-security emails, not marketing, and they must
  // send. Development keeps the explicit no-provider fallback (null).
  const accountEmail = senders.account;

  return { notification, notificationChannel, notificationDestination, authEmail, accountEmail };
}
