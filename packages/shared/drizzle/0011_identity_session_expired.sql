
ALTER TABLE identity_verification_sessions DROP CONSTRAINT IF EXISTS identity_verification_sessions_status_check;
ALTER TABLE identity_verification_sessions ADD CONSTRAINT identity_verification_sessions_status_check CHECK ("status" IN ('pending', 'completed', 'failed', 'expired'));

UPDATE identity_verification_sessions SET status = 'expired' WHERE status = 'pending' AND expires_at <= now();

CREATE INDEX IF NOT EXISTS ivsess_pending_expires_idx ON identity_verification_sessions (expires_at)
  WHERE status = 'pending';
