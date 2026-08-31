'use strict';

const { EPSS_URL, POC_BASE, OSV_URL, SEV_ORD } = require('./constants');
const { pLimit } = require('./primitives');
const { nvdCache, getCisaSet } = require('./cisaKev');
const { getPool } = require('../auth/db');

const NVD_API_KEY     = process.env.NVD_API_KEY || '';
const NVD_CONCURRENCY = NVD_API_KEY ? 10 : 3;
const NVD_TIMEOUT_MS  = NVD_API_KEY ? 8000 : 10000;
const CVE_CACHE_TTL_HOURS = parseInt(process.env.CVE_CACHE_TTL_HOURS || '24', 10) || 0;

if (NVD_API_KEY) {
  console.log('[NVD] API key detected — high-throughput mode (concurrency 10)');
} else {
  console.log('[NVD] No API key — conservative mode (concurrency 3). Set NVD_API_KEY for faster enrichment.');
}

const EPSS_ENABLED = process.env.OSA_EPSS_ENABLED !== 'false';

async function fetchEpss(cveIds) {
  if (!cveIds.length || !EPSS_ENABLED) return {};
  const results = {};
  for (let i = 0; i < cveIds.length; i += 30) {
    const chunk = cveIds.slice(i, i + 30);
    try {
      const r = await fetch(`${EPSS_URL}?cve=${chunk.join(',')}&limit=${chunk.length}`, { signal: AbortSignal.timeout(15000) });
      if (!r.ok) continue;
      const d = await r.json();
      for (const item of d.data || [])
        results[item.cve] = { epss: parseFloat(item.epss), percentile: parseFloat(item.percentile) };
    } catch {}
  }
  return results;
}

async function fetchCvss(cveIds) {
  if (!cveIds.length) return {};
  const result = {};
  await pLimit(cveIds, NVD_CONCURRENCY, async (cveId) => {
    if (nvdCache.has(cveId)) { result[cveId] = nvdCache.get(cveId); return; }
    try {
      const headers = { Accept: 'application/json' };
      if (NVD_API_KEY) headers['apiKey'] = NVD_API_KEY;
      const r = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`,
        { signal: AbortSignal.timeout(NVD_TIMEOUT_MS), headers }
      );
      if (r.status === 429) { result[cveId] = null; return; }
      if (!r.ok) { nvdCache.set(cveId, null); return; }
      const d = await r.json();
      const vuln = (d.vulnerabilities || [])[0]?.cve;
      if (!vuln) { nvdCache.set(cveId, null); return; }
      const metrics = vuln.metrics || {};
      const v3data  = (metrics.cvssMetricV31 || metrics.cvssMetricV30 || [])[0]?.cvssData;
      const v2data  = (metrics.cvssMetricV2  || [])[0]?.cvssData;
      const entry = {
        cvss3: v3data ? { score: v3data.baseScore, vector: v3data.vectorString, severity: v3data.baseSeverity, version: v3data.version } : null,
        cvss2: v2data ? { score: v2data.baseScore, vector: v2data.vectorString, severity: v2data.baseSeverity } : null,
        description: vuln.descriptions?.find(d => d.lang === 'en')?.value || null,
      };
      nvdCache.set(cveId, entry);
      result[cveId] = entry;
    } catch { nvdCache.set(cveId, null); }
  });
  for (const c of cveIds) if (!(c in result)) result[c] = nvdCache.get(c) ?? null;
  return result;
}

const POC_ENABLED = process.env.OSA_POC_ENABLED !== 'false';

async function fetchPocs(cveIds) {
  if (!cveIds.length || !POC_ENABLED) return {};
  const result = {};
  await pLimit(cveIds, 10, async (cveId) => {
    const m = cveId.match(/CVE-(\d{4})-/);
    if (!m) { result[cveId] = []; return; }
    try {
      const r = await fetch(`${POC_BASE}/${m[1]}/${cveId}.json`, {
        signal: AbortSignal.timeout(8000),
        headers: { 'Cache-Control': 'no-cache' },
      });
      if (r.status === 404) { result[cveId] = []; return; }
      const d = await r.json();
      result[cveId] = (Array.isArray(d) ? d : [])
        .map(p => ({ name: p.full_name || p.name, url: p.html_url, stars: p.stargazers_count || 0 }))
        .sort((a, b) => b.stars - a.stars)
        .slice(0, 5);
    } catch { result[cveId] = []; }
  });
  for (const c of cveIds) if (!result[c]) result[c] = [];
  return result;
}

const OSV_DESC_CACHE_MAX = 2000;
const _osvDescCache = new Map();
function _osvDescSet(cveId, value) {
  if (_osvDescCache.size >= OSV_DESC_CACHE_MAX)
    _osvDescCache.delete(_osvDescCache.keys().next().value);
  _osvDescCache.set(cveId, value);
}

async function fetchOsvDesc(cveId) {
  if (_osvDescCache.has(cveId)) return _osvDescCache.get(cveId);
  try {
    const r = await fetch(`${OSV_URL}/vulns/${encodeURIComponent(cveId)}`,
      { signal: AbortSignal.timeout(6000), headers: { Accept: 'application/json' } });
    if (!r.ok) { _osvDescSet(cveId, null); return null; }
    const d = await r.json();
    const desc = d.details || d.summary || null;
    _osvDescSet(cveId, desc);
    return desc;
  } catch { _osvDescSet(cveId, null); return null; }
}

async function osvQuery(pkgName, ecosystem, version) {
  try {
    const body = { package: { name: pkgName, ecosystem } };
    if (version) body.version = version;
    const r = await fetch(`${OSV_URL}/query`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body), signal: AbortSignal.timeout(12000),
    });
    if (!r.ok) {
      const e = new Error(`OSV returned HTTP ${r.status}`);
      e.status = 502;
      throw e;
    }
    const d = await r.json();
    return (d.vulns || []).map(v => ({
      ...v,
      _sev    : parseSev(v),
      _fix    : getFixed(v),
      _aliases: v.aliases || [],
      _refs   : (v.references || []).map(ref => ref.url),
    })).sort((a, b) => SEV_ORD.indexOf(a._sev) - SEV_ORD.indexOf(b._sev));
  } catch (e) {
    if (e.status) throw e;
    const upstream = new Error(`OSV query failed: ${e.message}`);
    upstream.status = 502;
    throw upstream;
  }
}

// Persistent per-CVE cache for the stable, slow-to-fetch fields (CVSS, PoC).
// Reads what's cached, fetches only the missing CVEs, writes them back. Falls
// back to a direct fetch if the DB is unavailable. EPSS and KEV are NOT cached
// here - EPSS shifts daily (kept live, one batched call) and KEV is a local set.
async function loadCveCache(cveIds) {
  if (!cveIds.length) return {};
  try {
    const query = CVE_CACHE_TTL_HOURS > 0
      ? `SELECT cve, cvss, poc FROM cve_enrichment WHERE cve = ANY($1)
         AND updated_at > NOW() - ($2 || ' hours')::interval`
      : `SELECT cve, cvss, poc FROM cve_enrichment WHERE cve = ANY($1)`;
    const params = CVE_CACHE_TTL_HOURS > 0 ? [cveIds, CVE_CACHE_TTL_HOURS] : [cveIds];
    const { rows } = await getPool().query(query, params);
    const out = {};
    for (const r of rows) out[r.cve] = { cvss: r.cvss, poc: r.poc };
    return out;
  } catch (e) { console.error('[cve-cache] read failed:', e.message); return {}; }
}

async function saveCveCache(entries) {
  const items = Object.entries(entries);
  if (!items.length) return;
  try {
    await pLimit(items, 20, async ([cve, v]) => {
      await getPool().query(
        `INSERT INTO cve_enrichment (cve, cvss, poc, updated_at)
         VALUES ($1, $2::jsonb, $3::jsonb, NOW())
         ON CONFLICT (cve) DO UPDATE SET cvss = EXCLUDED.cvss, poc = EXCLUDED.poc, updated_at = NOW()`,
        [cve, JSON.stringify(v.cvss ?? null), JSON.stringify(v.poc ?? [])]);
    });
  } catch (e) { console.error('[cve-cache] write failed:', e.message); }
}

// CVSS + PoC via the persistent cache; only misses hit NVD / PoC-in-GitHub.
async function cachedCvssPoc(cveIds) {
  const cache = await loadCveCache(cveIds);
  const missing = cveIds.filter(c => !(c in cache));
  const cvssMap = {}, pocMap = {};
  for (const c of cveIds) if (cache[c]) { cvssMap[c] = cache[c].cvss; pocMap[c] = cache[c].poc || []; }

  if (missing.length) {
    const [freshCvss, freshPoc] = await Promise.all([fetchCvss(missing), fetchPocs(missing)]);
    const toSave = {};
    for (const c of missing) {
      cvssMap[c] = freshCvss[c] ?? null;
      pocMap[c]  = freshPoc[c]  ?? [];
      toSave[c]  = { cvss: cvssMap[c], poc: pocMap[c] };
    }
    saveCveCache(toSave); // fire-and-forget
  }
  return { cvssMap, pocMap };
}

async function bulkEnrich(cveIds) {
  const [epssRes, kevRes, cvssPocRes] = await Promise.allSettled([
    fetchEpss(cveIds),
    (async () => { const s = await getCisaSet(); return cveIds.filter(c => s.has(c)); })(),
    cachedCvssPoc(cveIds),
  ]);
  const cvssPoc = cvssPocRes.status === 'fulfilled' ? cvssPocRes.value : { cvssMap: {}, pocMap: {} };
  return {
    epssMap: epssRes.status === 'fulfilled' ? epssRes.value : {},
    kevSet : new Set(kevRes.status === 'fulfilled' ? kevRes.value : []),
    cvssMap: cvssPoc.cvssMap,
    pocMap : cvssPoc.pocMap,
  };
}

function enrichVulns(vulns, { epssMap, kevSet, cvssMap, pocMap }) {
  return vulns.map(v => {
    // Pull an embedded CVE too - distro records use ids like "DEBIAN-CVE-2024-1"
    // with no plain-CVE alias, so a startsWith check would miss them.
    // Resolve every CVE this record covers. Distro advisories (RLSA/ALSA/RHSA)
    // carry no CVE alias but list them in `upstream`; one advisory can map to
    // many CVEs. Also mine aliases and the id itself (DEBIAN-CVE-… etc).
    const cves = [...new Set(
      [...(v._aliases || []), v.id, ...(v.upstream || [])]
        .flatMap(x => (typeof x === 'string' && x.match(/CVE-\d{4}-\d+/g)) || [])
    )];
    const cve = cves[0] || null;
    // Enrichment spans all covered CVEs, so KEV/EPSS fire even when the primary
    // isn't the exploited/worst one.
    const inKev = cves.some(c => kevSet.has(c));
    let epss = null;
    for (const c of cves) {
      const e = epssMap[c];
      if (e && (!epss || e.epss > epss.epss)) epss = e;
    }
    const cvss = cves.map(c => cvssMap[c]).find(Boolean) || null;
    const pocs = cves.flatMap(c => pocMap[c] || []);
    return {
      id       : v.id,
      summary  : v.summary   || null,
      details  : v.details   || null,
      published: v.published || null,
      modified : v.modified  || null,
      severity : v._sev,
      fix      : v._fix      || null,
      aliases  : v._aliases,
      refs     : v._refs,
      cve,
      cves,
      epss,
      cvss,
      inKev,
      pocs,
    };
  });
}

// Compute a CVSS v3.0/3.1 base score from a vector string. OSV puts the CVSS
// *vector* (e.g. "CVSS:3.1/AV:N/AC:L/...") in severity[].score, not a number,
// so parseFloat() returns NaN — without this every OSV finding fell back to
// UNKNOWN. Returns a number 0..10, or null when the vector can't be parsed.
function cvssV3BaseScore(vector) {
  if (typeof vector !== 'string' || !/^CVSS:3\.[01]\//.test(vector)) return null;
  const m = {};
  for (const part of vector.split('/')) {
    const [k, val] = part.split(':');
    if (k && val) m[k] = val;
  }
  const scopeChanged = m.S === 'C';
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const AC = { L: 0.77, H: 0.44 }[m.AC];
  const UI = { N: 0.85, R: 0.62 }[m.UI];
  const PR = (scopeChanged ? { N: 0.85, L: 0.68, H: 0.5 }
                           : { N: 0.85, L: 0.62, H: 0.27 })[m.PR];
  const imp = { H: 0.56, L: 0.22, N: 0 };
  const C = imp[m.C], I = imp[m.I], A = imp[m.A];
  if ([AV, AC, PR, UI, C, I, A].some(x => x === undefined)) return null;

  const iscBase = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = scopeChanged
    ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
    : 6.42 * iscBase;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * AV * AC * PR * UI;
  const raw = Math.min((scopeChanged ? 1.08 : 1) * (impact + exploitability), 10);
  // Official CVSS 3.1 roundup (ceil to 1 decimal with float tolerance).
  const int = Math.round(raw * 100000);
  return int % 10000 === 0 ? int / 100000 : (Math.floor(int / 10000) + 1) / 10;
}

function scoreToSev(sc) {
  if (sc >= 9) return 'CRITICAL';
  if (sc >= 7) return 'HIGH';
  if (sc >= 4) return 'MEDIUM';
  if (sc > 0)  return 'LOW';
  return null;
}

function parseSev(v) {
  for (const s of v.severity || []) {
    let sc = parseFloat(s.score);
    if (isNaN(sc)) sc = cvssV3BaseScore(s.score);
    const sev = (sc != null && !isNaN(sc)) ? scoreToSev(sc) : null;
    if (sev) return sev;
  }
  const db = ((v.database_specific || {}).severity || '').toUpperCase();
  return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(db) ? db : 'UNKNOWN';
}

function getFixed(v) {
  for (const a of v.affected || [])
    for (const r of a.ranges || [])
      for (const e of r.events || [])
        if (e.fixed) return e.fixed;
  return null;
}

function extractCVEs(vulns) {
  const s = new Set();
  for (const v of vulns) {
    for (const a of v.aliases || []) { const m = a && a.match(/CVE-\d{4}-\d+/); if (m) s.add(m[0]); }
    for (const u of v.upstream || []) { const m = u && u.match(/CVE-\d{4}-\d+/); if (m) s.add(m[0]); } // RLSA/ALSA/RHSA
    const im = v.id && v.id.match(/CVE-\d{4}-\d+/); if (im) s.add(im[0]);
  }
  return [...s];
}

function calcRisk(cvss, epss) {
  const cvssScore = cvss?.cvss3?.score ?? cvss?.cvss2?.score ?? 0;
  const epssScore = epss?.epss ?? 0;
  const raw = (cvssScore / 10) * 0.6 + epssScore * 0.4;
  const pct = Math.round(raw * 100);
  const label = pct >= 80 ? 'CRITICAL' : pct >= 50 ? 'HIGH' : pct >= 25 ? 'MEDIUM' : 'LOW';
  return { score: pct, label };
}

module.exports = {
  fetchEpss, fetchCvss, fetchPocs,
  fetchOsvDesc, osvQuery,
  bulkEnrich, enrichVulns,
  parseSev, getFixed, extractCVEs,
  calcRisk,
};
