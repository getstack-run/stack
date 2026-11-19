
ALTER TABLE control_sockets
  ADD COLUMN IF NOT EXISTS decision_on_unavailable text NOT NULL DEFAULT 'refuse'
  CHECK (decision_on_unavailable IN ('refuse', 'allow'));
