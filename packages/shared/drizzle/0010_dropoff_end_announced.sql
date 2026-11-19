
ALTER TABLE dropoffs ADD COLUMN IF NOT EXISTS end_announced_at timestamptz;

UPDATE dropoffs SET end_announced_at = now() WHERE status IN ('collected', 'expired') AND end_announced_at IS NULL;

CREATE INDEX IF NOT EXISTS dropoff_end_unannounced_idx ON dropoffs (deposited_at)
  WHERE status IN ('collected', 'expired') AND end_announced_at IS NULL AND deposited_at IS NOT NULL;
