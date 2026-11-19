
CREATE TABLE IF NOT EXISTS sso_verified_domains (
  id text PRIMARY KEY,
  operator_id text NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
  domain text NOT NULL,
  token text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  verified_at timestamptz,
  last_checked_at timestamptz,
  last_confirmed_at timestamptz,
  last_check text,
  missing_since timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT sso_domain_status_check CHECK (status IN ('pending', 'verified', 'lapsed'))
);

CREATE UNIQUE INDEX IF NOT EXISTS sso_domain_operator_domain_unique
  ON sso_verified_domains (operator_id, domain);

CREATE UNIQUE INDEX IF NOT EXISTS sso_domain_verified_unique
  ON sso_verified_domains (domain)
  WHERE status = 'verified';

CREATE INDEX IF NOT EXISTS sso_domain_recheck_idx
  ON sso_verified_domains (status, last_checked_at);
