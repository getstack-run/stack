
ALTER TABLE dropoffs ADD COLUMN IF NOT EXISTS deposit_announced_at timestamptz;

CREATE TABLE IF NOT EXISTS dropoff_recipients (
  dropoff_id text NOT NULL REFERENCES dropoffs(id) ON DELETE CASCADE,
  agent_id text NOT NULL REFERENCES agents(id),
  operator_id text NOT NULL REFERENCES operators(id),
  position integer NOT NULL,
  collected_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (dropoff_id, agent_id),
  CONSTRAINT dropoff_recipients_position_check CHECK (position >= 0)
);

CREATE INDEX IF NOT EXISTS dropoff_recipients_agent_idx ON dropoff_recipients (agent_id, dropoff_id);
CREATE INDEX IF NOT EXISTS dropoff_recipients_operator_idx ON dropoff_recipients (operator_id);
CREATE UNIQUE INDEX IF NOT EXISTS dropoff_recipients_one_collector_idx ON dropoff_recipients (dropoff_id) WHERE collected_at IS NOT NULL;
