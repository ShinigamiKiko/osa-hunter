-- Durable mapping for npm tarballs approved while serving package metadata.
CREATE TABLE IF NOT EXISTS proxy_artifacts (
  artifact_path VARCHAR(1024) PRIMARY KEY,
  ecosystem    VARCHAR(32) NOT NULL,
  package_name VARCHAR(255) NOT NULL,
  version      VARCHAR(128) NOT NULL,
  approved_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_proxy_artifacts_approved ON proxy_artifacts (approved_at);
