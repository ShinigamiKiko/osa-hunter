-- Audit log of every artifact the gate blocked, for reporting/dashboards.
CREATE TABLE IF NOT EXISTS gate_denials (
  id           BIGSERIAL PRIMARY KEY,
  denied_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  ecosystem    VARCHAR(32),
  package_name VARCHAR(255),
  version      VARCHAR(128),
  repository   VARCHAR(255),
  rules        VARCHAR(255),
  detail       TEXT,
  client_ip    VARCHAR(64)
);
CREATE INDEX IF NOT EXISTS idx_gate_denials_time ON gate_denials (denied_at DESC);
