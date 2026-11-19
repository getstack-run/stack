import { createHash, randomBytes, scryptSync } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import {
  createDb,
  notificationChannelVerifications,
  notificationDestinations,
  operators,
} from '@stack/shared';
import { NotificationDestinationRepository } from '../repositories/notification-destination-repo.js';
import { NotificationService } from './notification-service.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;
const OPERATOR_ID = 'op_notification_attempt_race';
const DESTINATION_ID = 'ndst_notification_attempt_race';

function hashCode(code: string): string {
  const salt = randomBytes(16);
  const digest = scryptSync(code, salt, 32);
  return `s1:${salt.toString('base64url')}:${digest.toString('base64url')}`;
}

describeWithDb('notification verification attempt concurrency', () => {
  const db = createDb(DATABASE_URL!);
  const destinationRepo = new NotificationDestinationRepository(db);
  const service = new NotificationService(db, {} as never, null);
  service.setDestinationRepo(destinationRepo);

  beforeAll(async () => {
    await db.delete(notificationDestinations).where(eq(notificationDestinations.id, DESTINATION_ID));
    await db.delete(operators).where(eq(operators.id, OPERATOR_ID));
    await db.insert(operators).values({
      id: OPERATOR_ID,
      email: 'notification-attempt-race@example.invalid',
      api_key_hash: createHash('sha256').update('notification-attempt-race').digest('hex'),
      tier: 'free',
    });
    await db.insert(notificationDestinations).values({
      id: DESTINATION_ID,
      operator_id: OPERATOR_ID,
      channel_type: 'email',
      destination: 'notification-attempt-race@example.invalid',
      verified: false,
    });
    await db.insert(notificationChannelVerifications).values({
      id: 'ncv_notification_attempt_race',
      destination_id: DESTINATION_ID,
      code_hash: hashCode('123456'),
      attempts: 0,
      expires_at: new Date(Date.now() + 60_000),
    });
  });

  afterAll(async () => {
    await db.delete(notificationDestinations).where(eq(notificationDestinations.id, DESTINATION_ID));
    await db.delete(operators).where(eq(operators.id, OPERATOR_ID));
  });

  it('allows at most five guesses when attempts arrive together', async () => {
    const results = await Promise.all(
      Array.from({ length: 20 }, (_, index) => service.verifyDestinationCode(
        DESTINATION_ID,
        OPERATOR_ID,
        String(700000 + index),
      )),
    );

    expect(results.filter((result) => result.error === 'Invalid code')).toHaveLength(5);
    expect(results.filter((result) => result.error?.startsWith('Too many attempts'))).toHaveLength(15);

    const verification = await db.query.notificationChannelVerifications.findFirst({
      where: eq(notificationChannelVerifications.destination_id, DESTINATION_ID),
    });
    expect(verification?.attempts).toBe(5);
  });
});
