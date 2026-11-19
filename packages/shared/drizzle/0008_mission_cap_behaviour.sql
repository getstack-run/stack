
ALTER TABLE missions ADD COLUMN IF NOT EXISTS coverage_cap_period text NOT NULL DEFAULT 'mission';
ALTER TABLE missions ADD COLUMN IF NOT EXISTS cap_time_zone text NOT NULL DEFAULT 'UTC';
ALTER TABLE missions ADD COLUMN IF NOT EXISTS paused_at timestamptz;
ALTER TABLE missions ADD COLUMN IF NOT EXISTS paused_cap text;
ALTER TABLE missions ADD COLUMN IF NOT EXISTS paused_service text;
ALTER TABLE missions ADD COLUMN IF NOT EXISTS making_orders_up_to_cents bigint;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'missions_coverage_cap_period_check') THEN
    ALTER TABLE missions ADD CONSTRAINT missions_coverage_cap_period_check CHECK (coverage_cap_period IN ('mission', 'day'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'missions_making_allowance_check') THEN
    ALTER TABLE missions ADD CONSTRAINT missions_making_allowance_check CHECK (making_orders_up_to_cents IS NULL OR making_orders_up_to_cents >= 0);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'missions_paused_cap_check') THEN
    ALTER TABLE missions ADD CONSTRAINT missions_paused_cap_check CHECK (paused_cap IS NULL OR paused_cap IN ('coverage_cap_cents', 'max_dropoff_bytes', 'max_concurrent_intents', 'max_actions', 'max_duration_seconds', 'max_actions_per_service'));
  END IF;
END $$;

UPDATE missions
SET cap_behavior = (
  SELECT jsonb_object_agg(
    entry.key,
    CASE entry.value #>> '{}'
      WHEN 'auto_revoke' THEN 'end_mission'
      WHEN 'deny_and_flag' THEN 'refuse_action'
      ELSE entry.value #>> '{}'
    END
  )
  FROM jsonb_each(missions.cap_behavior) AS entry
)
WHERE cap_behavior <> '{}'::jsonb
  AND EXISTS (SELECT 1 FROM jsonb_each_text(missions.cap_behavior) AS old WHERE old.value IN ('auto_revoke', 'deny_and_flag'));

CREATE INDEX IF NOT EXISTS missions_paused_idx ON missions (operator_id, paused_at) WHERE paused_at IS NOT NULL;
