import {
  type Database,
  notificationChannelVerifications,
  operators,
  TENANT_PLACEHOLDER_EMAIL_DOMAIN,
  ids,
  assertPublicUrl,
  publicFetch,
  UnsafeUrlError,
  ServiceUnavailableError,
  notificationEmail,
  notificationVerificationEmail,
  deployment,
  generateWebhookSecret,
  webhookRotationLive,
  signStandardWebhook,
} from '@stack/shared';
import { and, eq, gt, lt, sql } from 'drizzle-orm';
import { randomBytes, randomInt, scryptSync, timingSafeEqual } from 'node:crypto';
import { reconnectMessage, safeErrorSummary } from '@stack/shared';
import type { NotificationChannelRepository } from '../repositories/notification-channel-repo.js';
import type { NotificationDestinationRepository } from '../repositories/notification-destination-repo.js';
import type { SmsTransport } from './sms-transport.js';
import type { EmailSender } from './email-sender.js';

export interface NotificationEvent {
  operatorId: string;
  eventType: string;
  severity: 'info' | 'warning' | 'critical';
  payload: Record<string, unknown>;
}

interface DispatchTarget {
  id: string;
  operator_id: string;
  secret_purpose: 'notification_destination_webhook_secret' | 'notification_channel_webhook_secret';
  channel_type: string;
  destination: string;
  webhook_secret_encrypted: string | null;
  /** The secret a rotation replaced; it signs beside the current one for 24 hours. */
  webhook_secret_previous_encrypted?: string | null;
  webhook_secret_rotated_at?: Date | null;
}

interface DestinationSecretRow {
  id: string;
  operator_id: string;
  channel_type: string;
  destination: string;
  webhook_secret_encrypted: string | null;
  webhook_secret_previous_encrypted: string | null;
  webhook_secret_rotated_at: Date | null;
}

function destinationTarget(dest: DestinationSecretRow): DispatchTarget {
  return {
    id: dest.id,
    operator_id: dest.operator_id,
    secret_purpose: 'notification_destination_webhook_secret',
    channel_type: dest.channel_type,
    destination: dest.destination,
    webhook_secret_encrypted: dest.webhook_secret_encrypted,
    webhook_secret_previous_encrypted: dest.webhook_secret_previous_encrypted,
    webhook_secret_rotated_at: dest.webhook_secret_rotated_at,
  };
}

export interface NotificationSecretCrypto {
  encryptDirect(
    plaintext: Buffer,
    opts: { operatorId: string; context: Record<string, string> },
  ): Promise<Buffer>;
  decryptDirect(
    ciphertext: Buffer,
    opts: { operatorId: string; expectedContext: Record<string, string> },
  ): Promise<Buffer>;
}

const SEVERITY_ORDER: Record<string, number> = { info: 0, warning: 1, critical: 2 };

/** The part of a stored rule that decides whether it can deliver. */
interface RuleRow {
  operator_id: string;
  active: boolean;
  verified: boolean;
  destination_ids: string[] | null;
  destination_id: string | null;
}

/** The delivery methods a rule names: its list, else its one legacy id, else none. Dispatch and `describeRule` both read it. */
function ruleDestinationIds(channel: Pick<RuleRow, 'destination_ids' | 'destination_id'>): string[] {
  return channel.destination_ids ?? (channel.destination_id ? [channel.destination_id] : []);
}

function hashVerificationCode(code: string): string {
  const salt = randomBytes(16);
  const digest = scryptSync(code, salt, 32);
  return `s1:${salt.toString('base64url')}:${digest.toString('base64url')}`;
}

function verificationCodeMatches(storedHash: string | null, code: string): boolean {
  if (!storedHash) return false;
  const [version, saltEncoded, digestEncoded] = storedHash.split(':');
  if (version !== 's1' || !saltEncoded || !digestEncoded) return false;
  try {
    const expected = Buffer.from(digestEncoded, 'base64url');
    const actual = scryptSync(code, Buffer.from(saltEncoded, 'base64url'), expected.length);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

/**
 * Counts and charges a single outbound notification.
 *
 * Implemented in the API layer (apps/api/src/config/services.ts) because it
 * needs Redis and the wallet; injected here so the vault package keeps no
 * opinion about where money lives. `allowed: false` means the send is dropped.
 */
export interface NotificationSendMeter {
  /**
   * Whether one send may go, counted and charged. `message` is the text a send of channel `sms` is about to send and
   * where it goes: a text is priced by its segments at its destination's price.
   */
  authorizeSend(
    operatorId: string,
    channelType: string,
    message?: { to: string; body: string },
  ): Promise<{ allowed: boolean; reason?: string }>;
}

export class NotificationService {
  private emailService: EmailSender | null = null;
  private destinationRepo: NotificationDestinationRepository | null = null;
  private sendMeter: NotificationSendMeter | null = null;
  private secretCrypto: NotificationSecretCrypto | null = null;
  /** Overridable only so tests can exercise the refusal path without DNS. */
  private urlGuard: typeof assertPublicUrl | null = null;

  constructor(
    private db: Database,
    private channelRepo: NotificationChannelRepository,
    private smsTransport: SmsTransport | null,
  ) {}

  setEmailService(emailService: EmailSender): void {
    this.emailService = emailService;
  }

  setDestinationRepo(repo: NotificationDestinationRepository): void {
    this.destinationRepo = repo;
  }

  setSendMeter(meter: NotificationSendMeter): void {
    this.sendMeter = meter;
  }

  /** Whether sends that cost vendor money are capped. A deployment that bills them refuses to boot without it. */
  hasSendMeter(): boolean {
    return this.sendMeter !== null;
  }

  setSecretCrypto(crypto: NotificationSecretCrypto): void {
    this.secretCrypto = crypto;
  }

  async createWebhookSecret(
    operatorId: string,
    resourceId: string,
    purpose: DispatchTarget['secret_purpose'],
  ): Promise<{ secret: string; encrypted: string }> {
    if (!this.secretCrypto) {
      throw new ServiceUnavailableError('Notification secret encryption is unavailable');
    }
    const secret = generateWebhookSecret();
    return { secret, encrypted: await this.encryptWebhookSecret(operatorId, resourceId, purpose, secret) };
  }

  /** Test seam for the webhook destination guard. Production uses the real one. */
  setUrlGuard(guard: typeof assertPublicUrl): void {
    this.urlGuard = guard;
  }

  /**
   * Count and charge one outbound send, or refuse it.
   *
   * Called from every path that hands a message to a vendor: the dispatcher,
   * and the two verification-code paths that do not go through it. Those were
   * not only uncounted — an unauthenticated stream of verification requests
   * could burn the text-message provider's balance, so the cap closes an abuse vector as well
   * as a billing gap.
   *
   * Fails OPEN when no meter is wired. Dev and test have no Redis or wallet,
   * and silently dropping every notification there would be worse than not
   * counting; the boot assertion in the API layer is what guarantees a meter
   * exists wherever a real vendor is configured.
   */
  private async authorizeSend(
    operatorId: string,
    channelType: string,
    message?: { to: string; body: string },
  ): Promise<boolean> {
    if (!this.sendMeter) return true;
    const verdict = await this.sendMeter.authorizeSend(operatorId, channelType, message);
    if (!verdict.allowed) {
      console.warn(
        '[NOTIFICATION] channel refused:', channelType, operatorId, verdict.reason ?? 'over allowance',
      );
    }
    return verdict.allowed;
  }

  private requireDeliveryProvider(channelType: string): void {
    if (channelType === 'sms' && !this.smsTransport) {
      throw new ServiceUnavailableError('Notification delivery is temporarily unavailable');
    }
    if (channelType === 'email' && !this.emailService) {
      throw new ServiceUnavailableError('Notification delivery is temporarily unavailable');
    }
  }

  /**
   * What a rule can actually do, and the one place that says so: the delivery methods it names that belong to its account
   * (`methods`, as stored, secrets and all: the caller redacts) and `delivers`, true only when the rule is active and
   * dispatch would send to at least one of them. It reads what `publishEvent` reads: a method must exist, be the account's
   * own and be verified; a rule that names none is judged by its own `verified` flag, as a rule stored with an inline
   * address always was. A rule shown to anyone as On must have `delivers` true.
   */
  async describeRule(channel: RuleRow): Promise<{ methods: NonNullable<Awaited<ReturnType<NotificationDestinationRepository['findById']>>>[]; delivers: boolean }> {
    const destIds = ruleDestinationIds(channel);
    const methods: NonNullable<Awaited<ReturnType<NotificationDestinationRepository['findById']>>>[] = [];
    if (this.destinationRepo) {
      for (const destId of destIds) {
        const dest = await this.destinationRepo.findById(destId);
        if (dest && dest.operator_id === channel.operator_id) methods.push(dest);
      }
    }
    const usesMethods = destIds.length > 0 && this.destinationRepo !== null;
    const reachable = usesMethods ? methods.some((dest) => dest.verified) : channel.verified;
    return { methods, delivers: channel.active && reachable };
  }

  async publishEvent(event: NotificationEvent): Promise<{ dispatched: number }> {
    const channels = await this.channelRepo.findByOperator(event.operatorId);
    let dispatched = 0;

    for (const channel of channels) {
      if (!channel.active) continue;
      if (!channel.events.includes(event.eventType)) continue;
      const channelSeverity = SEVERITY_ORDER[channel.min_severity] ?? 0;
      const eventSeverity = SEVERITY_ORDER[event.severity] ?? 0;
      if (eventSeverity < channelSeverity) continue;

      // Resolve destinations: prefer destination_ids array, fall back to single destination_id, then inline fields
      const destIds = ruleDestinationIds(channel);

      if (destIds.length > 0 && this.destinationRepo) {
        for (const destId of destIds) {
          const dest = await this.destinationRepo.findById(destId);
          if (!dest || !dest.verified || dest.operator_id !== event.operatorId) continue;
          try {
            if (await this.dispatchToTarget(destinationTarget(dest), event)) dispatched++;
          } catch (err) {
            console.error(
              '[NOTIFICATION] dispatch to destination failed:', destId, channel.id,
              safeErrorSummary(err),
            );
          }
        }
      } else if (channel.verified) {
        // Legacy: no destinations, use inline channel fields
        try {
          const sent = await this.dispatchToTarget(
            {
              id: channel.id,
              operator_id: channel.operator_id,
              secret_purpose: 'notification_channel_webhook_secret',
              channel_type: channel.channel_type,
              destination: channel.destination,
              webhook_secret_encrypted: channel.webhook_secret_encrypted,
            },
            event,
          );
          if (sent) dispatched++;
        } catch (err) {
          console.error('[NOTIFICATION] dispatch to channel failed:', channel.id, safeErrorSummary(err));
        }
      }
    }

    return { dispatched };
  }

  /**
   * Mail one event to the owner of the account, at the address the owner signs in with, for an event that no delivery
   * method of the account received. The recipient is read here from the account's own row and is never given by a
   * caller. It is the ordinary mail service (so a staging deployment's allow-list applies) and the ordinary send cap
   * and meter (`authorizeSend`, as any notification email). A white-label tenant's sign-in address is a placeholder
   * that reaches nobody, so nothing is sent to it. Answers whether a mail went; throws when the mail service fails.
   */
  async mailOwner(event: NotificationEvent): Promise<boolean> {
    if (!this.emailService) return false;
    const [owner] = await this.db
      .select({ email: operators.email })
      .from(operators)
      .where(eq(operators.id, event.operatorId))
      .limit(1);
    if (!owner || owner.email.toLowerCase().endsWith(TENANT_PLACEHOLDER_EMAIL_DOMAIN)) return false;
    const email = this.renderEmail(event);
    if (!(await this.authorizeSend(event.operatorId, 'email', { to: owner.email, body: email.text }))) return false;
    await this.emailService.sendEmail(owner.email, email.subject, email.text, email.html, { skipSignature: true });
    return true;
  }

  private renderEmail(event: NotificationEvent) {
    return notificationEmail({
      eventType: event.eventType,
      severity: event.severity,
      message: typeof event.payload.message === 'string' ? event.payload.message : undefined,
      summary: typeof event.payload.summary === 'string' ? event.payload.summary : undefined,
      payload: event.payload,
    });
  }

  /** Sends one event to one destination. Answers whether anything was sent: a send the meter refuses is not one. */
  private async dispatchToTarget(target: DispatchTarget, event: NotificationEvent): Promise<boolean> {
    this.requireDeliveryProvider(target.channel_type);
    const message = this.formatMessage(event);

    if (!(await this.authorizeSend(event.operatorId, target.channel_type, { to: target.destination, body: message }))) return false;

    switch (target.channel_type) {
      case 'sms':
        await this.smsTransport!.sendSms(target.destination, message);
        break;

      case 'email': {
        const email = this.renderEmail(event);
        await this.emailService!.sendEmail(
          target.destination,
          email.subject,
          email.text,
          email.html,
          { skipSignature: true },
        );
        break;
      }

      case 'webhook':
        await this.dispatchWebhook(
          target.destination,
          event,
          await this.resolveWebhookSecrets(target),
        );
        break;
    }
    return true;
  }

  // ─── Destination Verification ──────────────────────────────────────

  async sendDestinationVerificationCode(
    destinationId: string,
    operatorId: string,
  ): Promise<{ sent: boolean }> {
    if (!this.destinationRepo) throw new Error('Destination repo not configured');
    const dest = await this.destinationRepo.findById(destinationId);
    if (!dest || dest.operator_id !== operatorId) {
      throw new Error('Notification destination not found');
    }
    if (dest.verified) {
      return { sent: false };
    }
    this.requireDeliveryProvider(dest.channel_type);

    const code = String(randomInt(100000, 1000000));
    const codeHash = hashVerificationCode(code);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await this.db
      .insert(notificationChannelVerifications)
      .values({
        id: ids.verificationCode(),
        destination_id: destinationId,
        code_hash: codeHash,
        attempts: 0,
        expires_at: expiresAt,
        created_at: new Date(),
      })
      .onConflictDoUpdate({
        target: notificationChannelVerifications.destination_id,
        set: { code_hash: codeHash, attempts: 0, expires_at: expiresAt, created_at: new Date() },
      });

    const destinationCodeText = `Your STACK verification code is: ${code}`;
    if (!(await this.authorizeSend(operatorId, dest.channel_type, { to: dest.destination, body: destinationCodeText }))) {
      return { sent: false };
    }

    if (dest.channel_type === 'sms') {
      await this.smsTransport!.sendSms(dest.destination, destinationCodeText);
    } else if (dest.channel_type === 'email') {
      const email = notificationVerificationEmail({ code, kind: 'delivery method' });
      await this.emailService!.sendEmail(dest.destination, email.subject, email.text, email.html, {
        skipSignature: true,
      });
    } else if (dest.channel_type === 'webhook') {
      // Proof of control, same shape as the email and SMS codes: the code is
      // delivered TO the endpoint, and only someone who can read that
      // endpoint's traffic can echo it back. Nominating a URL is a claim;
      // this is what turns it into evidence.
      await this.deliverWebhookChallenge(
        dest.destination,
        await this.resolveWebhookSecrets(destinationTarget(dest)),
        code,
        expiresAt,
      );
    }

    return { sent: true };
  }

  /**
   * POST a verification challenge to a nominated webhook destination.
   *
   * Signed with the destination's own secret (Standard Webhooks) so the receiver can tell a STACK challenge from
   * an unrelated request. Throws on a refused or unreachable
   * URL: the operator asked us to prove their endpoint, and a silent failure
   * would leave them waiting for a code that was never sent.
   */
  private async deliverWebhookChallenge(
    url: string,
    secrets: readonly string[],
    code: string,
    expiresAt: Date,
  ): Promise<void> {
    const guard = this.urlGuard ?? assertPublicUrl;
    try {
      await guard(url, { allowedProtocols: ['https:'] });
    } catch (err) {
      const rejectionKind = err instanceof UnsafeUrlError ? 'unsafe_url' : 'invalid_url';
      // eslint-disable-next-line preserve-caught-error -- the guard error names the destination host; the refusal carries only its kind
      throw new Error(`Webhook destination refused: ${rejectionKind}`);
    }

    const id = `msg_${randomBytes(18).toString('base64url')}`;
    const body = JSON.stringify({
      id,
      event_type: 'stack.destination.verification',
      verification_code: code,
      expires_at: expiresAt.toISOString(),
      note: 'Submit this code to STACK to verify you control this endpoint.',
    });

    const headers = this.webhookHeaders(id, body, secrets);

    const response = await publicFetch(url, {
      method: 'POST',
      headers,
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) {
      throw new Error(
        `Webhook destination returned ${response.status} for the verification challenge`,
      );
    }
  }

  async verifyDestinationCode(
    destinationId: string,
    operatorId: string,
    code: string,
  ): Promise<{ verified: boolean; error?: string }> {
    if (!this.destinationRepo) return { verified: false, error: 'Destination repo not configured' };
    const dest = await this.destinationRepo.findById(destinationId);
    if (!dest || dest.operator_id !== operatorId) {
      return { verified: false, error: 'Destination not found' };
    }
    if (dest.verified) {
      return { verified: true };
    }

    const verification = await this.db.query.notificationChannelVerifications.findFirst({
      where: eq(notificationChannelVerifications.destination_id, destinationId),
    });

    if (!verification) {
      return { verified: false, error: 'No verification pending. Request a new code.' };
    }

    if (new Date() > verification.expires_at) {
      return { verified: false, error: 'Verification code expired. Request a new one.' };
    }

    if (verification.attempts >= 5) {
      return { verified: false, error: 'Too many attempts. Request a new code.' };
    }

    const [claimedAttempt] = await this.db
      .update(notificationChannelVerifications)
      .set({ attempts: sql`${notificationChannelVerifications.attempts} + 1` })
      .where(and(
        eq(notificationChannelVerifications.destination_id, destinationId),
        lt(notificationChannelVerifications.attempts, 5),
        gt(notificationChannelVerifications.expires_at, new Date()),
      ))
      .returning({ code_hash: notificationChannelVerifications.code_hash });

    if (!claimedAttempt) {
      return { verified: false, error: 'Too many attempts or expired code. Request a new one.' };
    }

    if (!verificationCodeMatches(claimedAttempt.code_hash, code)) {
      return { verified: false, error: 'Invalid code' };
    }

    await this.destinationRepo.update(destinationId, { verified: true });

    await this.db
      .delete(notificationChannelVerifications)
      .where(eq(notificationChannelVerifications.destination_id, destinationId));

    return { verified: true };
  }

  async testDestination(
    destinationId: string,
    operatorId: string,
  ): Promise<{ sent: boolean; error?: string }> {
    if (!this.destinationRepo) return { sent: false, error: 'Destination repo not configured' };
    const dest = await this.destinationRepo.findById(destinationId);
    if (!dest || dest.operator_id !== operatorId) {
      return { sent: false, error: 'Destination not found' };
    }
    if (!dest.verified) {
      return { sent: false, error: 'Destination not verified' };
    }

    const testEvent: NotificationEvent = {
      operatorId,
      eventType: 'test',
      severity: 'info',
      payload: { message: 'This is a test notification from STACK.' },
    };

    await this.dispatchToTarget(destinationTarget(dest), testEvent);
    return { sent: true };
  }

  // ─── Legacy Channel Verification (kept for backward compat) ────────

  async sendVerificationCode(channelId: string, operatorId: string): Promise<{ sent: boolean }> {
    const channel = await this.channelRepo.findById(channelId);
    if (!channel || channel.operator_id !== operatorId) {
      throw new Error('Notification channel not found');
    }
    if (channel.verified) {
      return { sent: false };
    }
    this.requireDeliveryProvider(channel.channel_type);

    const code = String(randomInt(100000, 1000000));
    const codeHash = hashVerificationCode(code);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await this.db
      .insert(notificationChannelVerifications)
      .values({
        id: ids.notificationChannel() + '_v',
        channel_id: channelId,
        code_hash: codeHash,
        attempts: 0,
        expires_at: expiresAt,
        created_at: new Date(),
      })
      .onConflictDoUpdate({
        target: notificationChannelVerifications.channel_id,
        set: { code_hash: codeHash, attempts: 0, expires_at: expiresAt, created_at: new Date() },
      });

    const channelCodeText = `Your STACK verification code is: ${code}`;
    if (!(await this.authorizeSend(operatorId, channel.channel_type, { to: channel.destination, body: channelCodeText }))) {
      return { sent: false };
    }

    if (channel.channel_type === 'sms') {
      await this.smsTransport!.sendSms(channel.destination, channelCodeText);
    } else if (channel.channel_type === 'email') {
      const email = notificationVerificationEmail({ code, kind: 'notification channel' });
      await this.emailService!.sendEmail(
        channel.destination,
        email.subject,
        email.text,
        email.html,
        { skipSignature: true },
      );
    }

    return { sent: true };
  }

  async verifyCode(
    channelId: string,
    operatorId: string,
    code: string,
  ): Promise<{ verified: boolean; error?: string }> {
    const channel = await this.channelRepo.findById(channelId);
    if (!channel || channel.operator_id !== operatorId) {
      return { verified: false, error: 'Channel not found' };
    }
    if (channel.verified) {
      return { verified: true };
    }

    const verification = await this.db.query.notificationChannelVerifications.findFirst({
      where: eq(notificationChannelVerifications.channel_id, channelId),
    });

    if (!verification) {
      return { verified: false, error: 'No verification pending. Request a new code.' };
    }

    if (new Date() > verification.expires_at) {
      return { verified: false, error: 'Verification code expired. Request a new one.' };
    }

    if (verification.attempts >= 5) {
      return { verified: false, error: 'Too many attempts. Request a new code.' };
    }

    const [claimedAttempt] = await this.db
      .update(notificationChannelVerifications)
      .set({ attempts: sql`${notificationChannelVerifications.attempts} + 1` })
      .where(and(
        eq(notificationChannelVerifications.channel_id, channelId),
        lt(notificationChannelVerifications.attempts, 5),
        gt(notificationChannelVerifications.expires_at, new Date()),
      ))
      .returning({ code_hash: notificationChannelVerifications.code_hash });

    if (!claimedAttempt) {
      return { verified: false, error: 'Too many attempts or expired code. Request a new one.' };
    }

    if (!verificationCodeMatches(claimedAttempt.code_hash, code)) {
      return { verified: false, error: 'Invalid code' };
    }

    await this.channelRepo.update(channelId, { verified: true });

    await this.db
      .delete(notificationChannelVerifications)
      .where(eq(notificationChannelVerifications.channel_id, channelId));

    return { verified: true };
  }

  async testChannel(
    channelId: string,
    operatorId: string,
  ): Promise<{ sent: boolean; error?: string }> {
    const channel = await this.channelRepo.findById(channelId);
    if (!channel || channel.operator_id !== operatorId) {
      return { sent: false, error: 'Channel not found' };
    }
    if (!channel.verified) {
      return { sent: false, error: 'Channel not verified' };
    }

    const testEvent: NotificationEvent = {
      operatorId,
      eventType: 'test',
      severity: 'info',
      payload: { message: 'This is a test notification from STACK.' },
    };

    await this.dispatchToTarget(
      {
        id: channel.id,
        operator_id: channel.operator_id,
        secret_purpose: 'notification_channel_webhook_secret',
        channel_type: channel.channel_type,
        destination: channel.destination,
        webhook_secret_encrypted: channel.webhook_secret_encrypted,
      },
      testEvent,
    );
    return { sent: true };
  }

  // ─── Helpers ────────────────────────────────────────────────────────

  private secretContext(
    operatorId: string,
    resourceId: string,
    purpose: DispatchTarget['secret_purpose'],
  ): Record<string, string> {
    return {
      operator_id: operatorId,
      notification_resource_id: resourceId,
      purpose,
    };
  }

  private async encryptWebhookSecret(
    operatorId: string,
    resourceId: string,
    purpose: DispatchTarget['secret_purpose'],
    secret: string,
  ): Promise<string> {
    if (!this.secretCrypto) {
      throw new ServiceUnavailableError('Notification secret encryption is unavailable');
    }
    const ciphertext = await this.secretCrypto.encryptDirect(Buffer.from(secret, 'utf8'), {
      operatorId,
      context: this.secretContext(operatorId, resourceId, purpose),
    });
    return ciphertext.toString('base64');
  }

  private async decryptWebhookSecret(target: DispatchTarget, encrypted: string): Promise<string> {
    if (!this.secretCrypto) {
      throw new ServiceUnavailableError('Notification secret decryption is unavailable');
    }
    const plaintext = await this.secretCrypto.decryptDirect(Buffer.from(encrypted, 'base64'), {
      operatorId: target.operator_id,
      expectedContext: this.secretContext(target.operator_id, target.id, target.secret_purpose),
    });
    return plaintext.toString('utf8');
  }

  /** The secrets live for a destination: the current one, and the previous for 24 hours after a rotation. */
  private async resolveWebhookSecrets(target: DispatchTarget): Promise<string[]> {
    if (!target.webhook_secret_encrypted) {
      throw new ServiceUnavailableError('Notification webhook signing secret is unavailable');
    }
    const current = await this.decryptWebhookSecret(target, target.webhook_secret_encrypted);
    if (!target.webhook_secret_previous_encrypted || !webhookRotationLive(target.webhook_secret_rotated_at)) {
      return [current];
    }
    return [current, await this.decryptWebhookSecret(target, target.webhook_secret_previous_encrypted)];
  }

  /**
   * The headers for one notification webhook: Standard Webhooks (`webhook-id`, `webhook-timestamp`,
   * `webhook-signature` over `id.timestamp.body`, one signature per live secret).
   */
  private webhookHeaders(id: string, body: string, secrets: readonly string[]): Record<string, string> {
    return {
      'Content-Type': 'application/json',
      ...signStandardWebhook({ id, body, secrets }),
    };
  }

  private formatMessage(event: NotificationEvent): string {
    if (event.eventType === 'security.credential_reconnect_required') {
      return `[STACK] Service reconnect required: ${reconnectMessage(event.payload.reason)} Reconnect: ${deployment().siteUrl}/services`;
    }
    const severity = event.severity.toUpperCase();
    const type = event.eventType.replace(/\./g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
    const details = event.payload.message || event.payload.agent_id || '';
    // a payload `summary` (governance approvals carry the
    // approve/reject URL in it) is appended so the human actually gets
    // the link in the email/SMS text. Events without a summary render
    // byte-identically to before - other consumers depend on the shape.
    const summary = typeof event.payload.summary === 'string' ? event.payload.summary : '';
    return `[STACK ${severity}] ${type}${details ? `: ${details}` : ''}${summary ? ` — ${summary}` : ''}`;
  }

  private async dispatchWebhook(
    url: string,
    event: NotificationEvent,
    secrets: readonly string[],
  ): Promise<void> {
    // The destination is operator-supplied, and STACK holds credentials and an
    // internal network. Guarding it only where it was stored is not enough: the
    // row outlives the check, the DNS answer can change after it, and this
    // service posts security events - the very content an attacker would want
    // redirected inward. So the guard runs here, at the moment of the call.
    //
    // https only. A destination that cannot take TLS is not a destination we
    // send incident detail to.
    //
    // publicFetch independently validates and pins the address used by the
    // socket and bounds the complete response, including a stalled body.
    const guard = this.urlGuard ?? assertPublicUrl;
    try {
      await guard(url, { allowedProtocols: ['https:'] });
    } catch (err) {
      const rejectionKind = err instanceof UnsafeUrlError ? 'unsafe_url' : 'invalid_url';
      // Loud, and never with the event payload attached - a refused webhook is
      // a configuration fault the operator has to see, not a silent drop.
      console.error(
        '[NOTIFICATION] webhook destination refused:', rejectionKind,
          'Event not delivered:', event.eventType, event.operatorId,
      );
      throw err;
    }

    // The message id: the same in the `webhook-id` header and the body, so a receiver that
    // has seen it can ignore it.
    const id = `msg_${randomBytes(18).toString('base64url')}`;
    const body = JSON.stringify({
      id,
      event_type: event.eventType,
      severity: event.severity,
      payload: event.payload,
      timestamp: new Date().toISOString(),
    });

    const headers = this.webhookHeaders(id, body, secrets);

    const response = await publicFetch(url, {
      method: 'POST',
      headers,
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) {
      throw new Error(`Webhook returned ${response.status}`);
    }
  }
}
