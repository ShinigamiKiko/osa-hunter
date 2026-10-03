ALTER TABLE cve_enrichment ADD COLUMN IF NOT EXISTS cvss_complete BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE cve_enrichment ADD COLUMN IF NOT EXISTS poc_complete BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE cve_enrichment ADD COLUMN IF NOT EXISTS cvss_updated_at TIMESTAMPTZ;
ALTER TABLE cve_enrichment ADD COLUMN IF NOT EXISTS poc_updated_at TIMESTAMPTZ;
-- Old scan results may contain incomplete pagination or underestimated severity.
DELETE FROM scan_cache WHERE type IN ('gate', 'lib', 'dep', 'composer', 'os');
