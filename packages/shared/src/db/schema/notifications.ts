// Notification destinations and channels.

import {
  pgTable,
  text,
  timestamp,
  integer,
  jsonb,
  boolean,
  index,
  uniqueIndex,
} from 'drizzle-orm/pg-core';
import { operators } from './operators.js';

// ─── Notification Destinations ────────────────────────────────────

export const notificationDestinations = pgTable(
  'notification_destinations',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    channel_type: text('channel_type').notNull(), // email | sms | webhook
    destination: text('destination').notNull(),
    verified: boolean('verified').notNull().default(false),
    // KMS envelope of the HMAC signing secret; the plaintext is never stored.
    webhook_secret_encrypted: text('webhook_secret_encrypted'),
    // The secret a rotation replaced: it keeps signing beside the new one for 24 hours.
    webhook_secret_previous_encrypted: text('webhook_secret_previous_encrypted'),
    webhook_secret_rotated_at: timestamp('webhook_secret_rotated_at', { withTimezone: true }),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('ndst_operator_idx').on(table.operator_id),
    uniqueIndex('ndst_operator_type_dest_idx').on(
      table.operator_id,
      table.channel_type,
      table.destination,
    ),
  ],
);

// ─── Notification Channels (rules) ──────────────────────────────────

export const notificationChannels = pgTable(
  'notification_channels',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    destination_id: text('destination_id').references(() => notificationDestinations.id, {
      onDelete: 'cascade',
    }),
    destination_ids: jsonb('destination_ids').$type<string[]>(),
    channel_type: text('channel_type').notNull(), // email | sms | webhook
    destination: text('destination').notNull(),
    events: text('events').array().notNull(),
    min_severity: text('min_severity').notNull().default('warning'), // info | warning | critical
    active: boolean('active').notNull().default(true),
    // KMS envelope of the HMAC signing secret; the plaintext is never stored.
    webhook_secret_encrypted: text('webhook_secret_encrypted'),
    verified: boolean('verified').notNull().default(false),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('nch_operator_idx').on(table.operator_id),
    index('nch_destination_idx').on(table.destination_id),
  ],
);

// ─── Notification Destination Verifications ──────────────────────────

export const notificationChannelVerifications = pgTable('notification_channel_verifications', {
  id: text('id').primaryKey(),
  channel_id: text('channel_id')
    .unique()
    .references(() => notificationChannels.id, { onDelete: 'cascade' }),
  destination_id: text('destination_id')
    .unique()
    .references(() => notificationDestinations.id, { onDelete: 'cascade' }),
  // Only a salted password-style hash of the challenge code is stored.
  code_hash: text('code_hash'),
  attempts: integer('attempts').notNull().default(0),
  expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
  created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});
