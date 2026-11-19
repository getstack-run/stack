
ALTER TABLE proxy_operations ADD COLUMN IF NOT EXISTS unresolved_at timestamptz;

CREATE INDEX IF NOT EXISTS proxy_operations_unresolved_due_idx ON proxy_operations (outcome_unknown_at)
  WHERE delivery_state = 'outcome_unknown' AND unresolved_at IS NULL;

CREATE INDEX IF NOT EXISTS ia_pending_expiry_idx ON intent_approvals (expires_at)
  WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS control_reviews_pending_expiry_idx ON control_reviews (expires_at)
  WHERE status = 'pending';
