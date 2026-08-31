-- Per-CVE enrichment cache. Unlike a package's CVE *list* (which grows as new
-- CVEs are disclosed), the data ABOUT a given CVE - its CVSS and public PoCs -
-- is stable, so it can be cached long-term and reused across every package that
-- shares that CVE. OSV is still queried every scan for the current CVE list;
-- only this stable per-CVE data is served from here.
CREATE TABLE IF NOT EXISTS cve_enrichment (
  cve        VARCHAR(32) PRIMARY KEY,
  cvss       JSONB,
  poc        JSONB,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
