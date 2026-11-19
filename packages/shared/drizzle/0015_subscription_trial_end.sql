
ALTER TABLE operators ADD COLUMN IF NOT EXISTS platform_trial_ends_at timestamp with time zone;
--> statement-breakpoint
ALTER TABLE operators ADD COLUMN IF NOT EXISTS controls_trial_ends_at timestamp with time zone;
