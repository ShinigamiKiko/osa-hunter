-- Every artifact that passed through the gate (allowed or blocked), for the
-- Proxy activity view: what entered the system, from which client, verdict.
CREATE TABLE IF NOT EXISTS proxy_events (
  id           BIGSERIAL PRIMARY KEY,
  at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ecosystem    VARCHAR(48),
  package_name VARCHAR(255),
  version      VARCHAR(128),
  repository   VARCHAR(255),
  decision     VARCHAR(16),   -- allow | deny
  reasons      VARCHAR(255),
  client_ip    VARCHAR(64)
);
CREATE INDEX IF NOT EXISTS idx_proxy_events_at  ON proxy_events (at DESC);
CREATE INDEX IF NOT EXISTS idx_proxy_events_eco ON proxy_events (ecosystem, at DESC);
