-- Gate policy revisions. The active row is what the gate enforces; every save
-- creates a new revision so a bad policy can be rolled back by activating an
-- older one. `body` is the same declarative shape policy.yaml uses, so a
-- revision can be exported back to YAML verbatim.
CREATE TABLE IF NOT EXISTS gate_policies (
  id          SERIAL PRIMARY KEY,
  revision    INTEGER     NOT NULL,
  name        TEXT        NOT NULL DEFAULT 'default',
  source      TEXT        NOT NULL DEFAULT 'ui',   -- ui | yaml
  body        JSONB       NOT NULL,
  note        TEXT,
  created_by  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  active      BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE UNIQUE INDEX IF NOT EXISTS gate_policies_revision_uniq ON gate_policies (revision);
-- At most one active revision at any time.
CREATE UNIQUE INDEX IF NOT EXISTS gate_policies_one_active ON gate_policies (active) WHERE active;
CREATE INDEX IF NOT EXISTS gate_policies_created_at ON gate_policies (created_at DESC);
