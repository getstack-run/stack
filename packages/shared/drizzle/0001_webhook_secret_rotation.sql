
ALTER TABLE notification_destinations ADD COLUMN IF NOT EXISTS webhook_secret_previous_encrypted text;
ALTER TABLE notification_destinations ADD COLUMN IF NOT EXISTS webhook_secret_rotated_at timestamptz;

ALTER TABLE inbound_webhooks ADD COLUMN IF NOT EXISTS webhook_secret_previous_encrypted text;
ALTER TABLE inbound_webhooks ADD COLUMN IF NOT EXISTS webhook_secret_rotated_at timestamptz;
