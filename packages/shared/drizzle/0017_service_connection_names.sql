
ALTER TABLE service_connections ADD COLUMN IF NOT EXISTS name text NOT NULL DEFAULT 'default';
--> statement-breakpoint
DROP INDEX IF EXISTS "scon_active_shared_principal_idx";
--> statement-breakpoint
DROP INDEX IF EXISTS "scon_active_member_principal_idx";
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "scon_active_principal_name_idx"
  ON "service_connections" USING btree ("operator_id", "provider", (coalesce("member_id", '')), (lower("name")))
  WHERE "status" = 'active';
