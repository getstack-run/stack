
ALTER TABLE team_members ADD COLUMN IF NOT EXISTS sso_issuer text;
ALTER TABLE team_members ADD COLUMN IF NOT EXISTS sso_subject text;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'team_members_sso_binding_check') THEN
    ALTER TABLE team_members ADD CONSTRAINT team_members_sso_binding_check
      CHECK ((sso_issuer IS NULL) = (sso_subject IS NULL));
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS member_sso_subject_idx
  ON team_members (operator_id, sso_issuer, sso_subject)
  WHERE sso_subject IS NOT NULL;
