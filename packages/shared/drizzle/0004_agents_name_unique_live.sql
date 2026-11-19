
DROP INDEX IF EXISTS agents_operator_name_idx;
CREATE UNIQUE INDEX IF NOT EXISTS agents_operator_name_idx ON agents (operator_id, name) WHERE status <> 'revoked';
