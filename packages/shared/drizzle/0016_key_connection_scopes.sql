UPDATE "service_connections" AS c
SET "scopes" = '["*"]'::jsonb
FROM "services" AS s
WHERE s."id" = c."service_id"
  AND c."scopes" = '[]'::jsonb
  AND s."scopes_available" = '[]'::jsonb
  AND c."oauth_managed" = false
  AND c."status" <> 'revoked';
