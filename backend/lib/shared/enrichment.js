'use strict';

const { EPSS_URL, POC_BASE, OSV_URL, SEV_ORD } = require('./constants');
const { pLimit } = require('./primitives');
const { nvdCache, getCisaSet } = require('./cisaKev');
const { getPool } = require('../auth/db');
const { HTTP_CONCURRENCY, HTTP_TIMEOUT_MS } = require('../config');
const { observeExternalError } = require('../observability/metrics');
const { fromVector } = require('ae-cvss-calculator');
const semver = require('semver');

const NVD_API_KEY     = process.env.NVD_API_KEY || '';
const NVD_CONCURRENCY = NVD_API_KEY ? Math.min(HTTP_CONCURRENCY, 10) : Math.min(HTTP_CONCURRENCY, 3);
const NVD_TIMEOUT_MS  = HTTP_TIMEOUT_MS;
const CVE_CACHE_TTL_HOURS = parseInt(process.env.CVE_CACHE_TTL_HOURS || '24', 10) || 0;

if (NVD_API_KEY) {
  console.log('[NVD] API key detected — high-throughput mode (concurrency 10)');
} else {
  console.log('[NVD] No API key — conservative mode (concurrency 3). Set NVD_API_KEY for faster enrichment.');
}

const EPSS_ENABLED = process.env.OSA_EPSS_ENABLED !== 'false';

async function fetchEpss(cveIds, { strict = false } = {}) {
  if (!cveIds.length || !EPSS_ENABLED) return {};
  const results = {};
  for (let i = 0; i < cveIds.length; i += 30) {
    const chunk = cveIds.slice(i, i + 30);
    try {
      const r = await fetch(`${EPSS_URL}?cve=${chunk.join(',')}&limit=${chunk.length}`, { signal: AbortSignal.timeout(15000) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      if (!Array.isArray(d.data)) throw new Error('Invalid EPSS response');
      for (const item of d.data || []) {
        if (typeof item.cve !== 'string' || !Number.isFinite(Number(item.epss)) || Number(item.epss) < 0 || Number(item.epss) > 1) throw new Error('Invalid EPSS score');
        results[item.cve] = { epss: parseFloat(item.epss), percentile: parseFloat(item.percentile) };
      }
    } catch (error) { observeExternalError('epss'); if (strict) throw new Error(`EPSS unavailable: ${error.message}`); }
  }
  return results;
}

async function fetchCvss(cveIds, { strict = false } = {}) {
  if (!cveIds.length) return {};
  const result = {};
  const errors = [];
  await pLimit(cveIds, NVD_CONCURRENCY, async (cveId) => {
    if (nvdCache.has(cveId)) { result[cveId] = nvdCache.get(cveId); return; }
    try {
      const headers = { Accept: 'application/json' };
      if (NVD_API_KEY) headers['apiKey'] = NVD_API_KEY;
      const r = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`,
        { signal: AbortSignal.timeout(NVD_TIMEOUT_MS), headers }
      );
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      if (!Array.isArray(d.vulnerabilities)) throw new Error('Invalid NVD response');
      const vuln = (d.vulnerabilities || [])[0]?.cve;
      if (d.vulnerabilities.length && !vuln) throw new Error('Invalid NVD vulnerability record');
      if (!vuln) { nvdCache.set(cveId, null); result[cveId] = null; return; }
      const metrics = vuln.metrics || {};
      const highest = keys => keys.flatMap(key => metrics[key] || []).map(m => m.cvssData)
        .filter(m => Number.isFinite(m?.baseScore)).sort((a,b) => b.baseScore - a.baseScore)[0];
      const v4data = highest(['cvssMetricV40']);
      const v3data = highest(['cvssMetricV31', 'cvssMetricV30']);
      const v2data = highest(['cvssMetricV2']);
      const entry = {
        cvss4: v4data ? { score: v4data.baseScore, vector: v4data.vectorString, severity: v4data.baseSeverity, version: v4data.version } : null,
        cvss3: v3data ? { score: v3data.baseScore, vector: v3data.vectorString, severity: v3data.baseSeverity, version: v3data.version } : null,
        cvss2: v2data ? { score: v2data.baseScore, vector: v2data.vectorString, severity: v2data.baseSeverity } : null,
        description: vuln.descriptions?.find(d => d.lang === 'en')?.value || null,
      };
      nvdCache.set(cveId, entry);
      result[cveId] = entry;
    } catch (error) { observeExternalError('nvd'); errors.push(error); }
  });
  if (strict && errors.length) throw new Error(`NVD unavailable: ${errors[0].message}`);
  return result;
}

const POC_ENABLED = process.env.OSA_POC_ENABLED !== 'false';

async function fetchPocs(cveIds, { strict = false } = {}) {
  if (!cveIds.length || !POC_ENABLED) return {};
  const result = {};
  const errors = [];
  await pLimit(cveIds, 10, async (cveId) => {
    const m = cveId.match(/CVE-(\d{4})-/);
    if (!m) { result[cveId] = []; return; }
    try {
      const r = await fetch(`${POC_BASE}/${m[1]}/${cveId}.json`, {
        signal: AbortSignal.timeout(8000),
        headers: { 'Cache-Control': 'no-cache' },
      });
      if (r.status === 404) { result[cveId] = []; return; }
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      if (!Array.isArray(d)) throw new Error('Invalid PoC response');
      result[cveId] = (Array.isArray(d) ? d : [])
        .map(p => ({ name: p.full_name || p.name, url: p.html_url, stars: p.stargazers_count || 0 }))
        .sort((a, b) => b.stars - a.stars)
        .slice(0, 5);
    } catch (error) { observeExternalError('poc'); errors.push(error); }
  });
  if (strict && errors.length) throw new Error(`PoC feed unavailable: ${errors[0].message}`);
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
  } catch { observeExternalError('osv'); _osvDescSet(cveId, null); return null; }
}

async function osvQuery(pkgName, ecosystem, version) {
  try {
    const body = { package: { name: pkgName, ecosystem } };
    if (version) body.version = version;
    const seen = new Set(), records = new Map();
    const signal = AbortSignal.timeout(HTTP_TIMEOUT_MS);
    for (let page = 0; page < 100; page++) {
    const r = await fetch(`${OSV_URL}/query`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body), signal,
    });
    if (!r.ok) {
      const e = new Error(`OSV returned HTTP ${r.status}`);
      e.status = 502;
      throw e;
    }
    const d = await r.json();
    if (!d || typeof d !== 'object' || Array.isArray(d) || (d.vulns !== undefined && !Array.isArray(d.vulns))) throw new Error('Invalid OSV response');
    for (const v of d.vulns || []) {
      if (!v || typeof v.id !== 'string') throw new Error('Invalid OSV vulnerability record');
      records.set(v.id, v);
    }
    if (!d.next_page_token) return [...records.values()].map(v => ({
      ...v,
      _sev    : parseSev(v),
      _fix    : getFixed(v, { name: pkgName, ecosystem, version }),
      _aliases: v.aliases || [],
      _refs   : (v.references || []).map(ref => ref.url),
    })).sort((a, b) => SEV_ORD.indexOf(a._sev) - SEV_ORD.indexOf(b._sev));
    if (typeof d.next_page_token !== 'string' || seen.has(d.next_page_token)) throw new Error('Invalid OSV pagination token');
    seen.add(d.next_page_token);
    body.page_token = d.next_page_token;
    }
    throw new Error('OSV pagination limit exceeded');
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
    const { rows } = await getPool().query(`SELECT cve, cvss, poc, cvss_complete, poc_complete,
      cvss_updated_at, poc_updated_at FROM cve_enrichment WHERE cve = ANY($1)`, [cveIds]);
    const out = {};
    for (const r of rows) out[r.cve] = r;
    return out;
  } catch (e) { console.error('[cve-cache] read failed:', e.message); return {}; }
}

async function saveCveCache(entries) {
  const items = Object.entries(entries);
  if (!items.length) return;
  try {
    await pLimit(items, 20, async ([cve, v]) => {
      await getPool().query(
        `INSERT INTO cve_enrichment (cve, cvss, poc, cvss_complete, poc_complete, cvss_updated_at, poc_updated_at, updated_at)
         VALUES ($1, $2::jsonb, $3::jsonb, $4, $5, CASE WHEN $4 THEN NOW() END, CASE WHEN $5 THEN NOW() END, NOW())
         ON CONFLICT (cve) DO UPDATE SET
           cvss = CASE WHEN EXCLUDED.cvss_complete THEN EXCLUDED.cvss ELSE cve_enrichment.cvss END,
           poc = CASE WHEN EXCLUDED.poc_complete THEN EXCLUDED.poc ELSE cve_enrichment.poc END,
           cvss_complete = cve_enrichment.cvss_complete OR EXCLUDED.cvss_complete,
           poc_complete = cve_enrichment.poc_complete OR EXCLUDED.poc_complete,
           cvss_updated_at = CASE WHEN EXCLUDED.cvss_complete THEN EXCLUDED.cvss_updated_at ELSE cve_enrichment.cvss_updated_at END,
           poc_updated_at = CASE WHEN EXCLUDED.poc_complete THEN EXCLUDED.poc_updated_at ELSE cve_enrichment.poc_updated_at END,
           updated_at = NOW()`,
        [cve, JSON.stringify(v.cvss ?? null), JSON.stringify(v.poc ?? []), Object.hasOwn(v, 'cvss'), Object.hasOwn(v, 'poc')]);
    });
  } catch (e) { console.error('[cve-cache] write failed:', e.message); }
}

// CVSS + PoC via the persistent cache; only misses hit NVD / PoC-in-GitHub.
async function cachedCvssPoc(cveIds, { cvss = true, poc = true, strict = false } = {}) {
  const cache = await loadCveCache(cveIds);
  const cvssMap = {}, pocMap = {};
  const fresh = timestamp => timestamp && (CVE_CACHE_TTL_HOURS <= 0
    || Date.now() - new Date(timestamp).getTime() < CVE_CACHE_TTL_HOURS * 3600000);
  for (const c of cveIds) {
    if (cache[c]?.cvss_complete && fresh(cache[c].cvss_updated_at)) cvssMap[c] = cache[c].cvss;
    if (POC_ENABLED && cache[c]?.poc_complete && fresh(cache[c].poc_updated_at)) pocMap[c] = cache[c].poc || [];
  }
  const [freshCvss, freshPoc] = await Promise.all([
    cvss ? fetchCvss(cveIds.filter(c => !Object.hasOwn(cvssMap, c)), { strict }) : {},
    poc ? fetchPocs(cveIds.filter(c => !Object.hasOwn(pocMap, c)), { strict }) : {},
  ]);
  Object.assign(cvssMap, freshCvss); Object.assign(pocMap, freshPoc);
  const toSave = {};
  for (const c of cveIds) {
    const entry = {};
    if (Object.hasOwn(freshCvss, c)) entry.cvss = freshCvss[c];
    if (Object.hasOwn(freshPoc, c)) entry.poc = freshPoc[c];
    if (Object.keys(entry).length) toSave[c] = entry;
  }
  await saveCveCache(toSave);
  return { cvssMap, pocMap };
}

async function bulkEnrich(cveIds, { requiredFacts } = {}) {
  const strict = requiredFacts !== undefined;
  const needs = fact => !strict || requiredFacts.has(fact);
  const jobs = [
    needs('epssMax') ? fetchEpss(cveIds, { strict }) : {},
    (async () => { if (!cveIds.length || !needs('kev')) return []; const s = await getCisaSet({ strict }); return cveIds.filter(c => s.has(c)); })(),
    cachedCvssPoc(cveIds, { strict, cvss: needs('severity'), poc: needs('pocCount') }),
  ];
  if (strict) {
    const [epssMap, kev, maps] = await Promise.all(jobs);
    return { epssMap, kevSet: new Set(kev), ...maps };
  }
  const [epssRes, kevRes, cvssPocRes] = await Promise.allSettled([
    ...jobs,
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
    const candidates = cves.map(c => cvssMap[c]).filter(Boolean);
    const score = entry => Math.max(0, ...['cvss4', 'cvss3', 'cvss2'].map(key => entry?.[key]?.score).filter(Number.isFinite));
    const cvss = candidates.sort((a, b) => score(b) - score(a))[0] || null;
    const pocs = cves.flatMap(c => pocMap[c] || []);
    return {
      id       : v.id,
      summary  : v.summary   || null,
      details  : v.details   || null,
      published: v.published || null,
      modified : v.modified  || null,
      severity : worstSeverity([v._sev || parseSev(v), scoreToSev(score(cvss))]),
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

function vectorBaseScore(vector) {
  if (typeof vector !== 'string') return null;
  if (/^CVSS:3\.[01]\//.test(vector)) return cvssV3BaseScore(vector);
  const v4 = vector.startsWith('CVSS:4.0/');
  const v2 = vector.startsWith('CVSS:2.0/') || vector.startsWith('AV:');
  if (!v4 && !v2) return null;
  // The calculator accepts partial vectors with defaults; OSV severity needs
  // every base metric so an incomplete assessment cannot become score zero.
  const required = v4 ? { AV:'NALP', AC:'LH', AT:'NP', PR:'NLH', UI:'NPA',
    VC:'HLN', VI:'HLN', VA:'HLN', SC:'HLN', SI:'HLN', SA:'HLN' }
    : { AV:'NAL', AC:'LMH', Au:'MSN', C:'NPC', I:'NPC', A:'NPC' };
  const metrics = new Map();
  for (const item of vector.split('/').filter(s => !s.startsWith('CVSS:'))) {
    const [key,value,...rest] = item.split(':');
    if (!key || !value || rest.length || metrics.has(key)) return null;
    metrics.set(key,value);
  }
  for (const [key, values] of Object.entries(required)) {
    const value = metrics.get(key);
    if (!value || value.length !== 1 || !values.includes(value)) return null;
  }
  try {
    const scores = fromVector(vector)?.calculateScores();
    return v4 ? scores?.baseMetricsOnly : scores?.base;
  } catch { return null; }
}

function parseSev(v) {
  const severities = [];
  const sources = [v, v.database_specific, v.ecosystem_specific,
    ...(v.affected || []).flatMap(a => [a, a.database_specific, a.ecosystem_specific])];
  for (const source of sources.filter(Boolean)) {
    if (typeof source.severity === 'string') severities.push(source.severity.toUpperCase());
    for (const s of Array.isArray(source.severity) ? source.severity : []) {
      const value = s.score;
      const sc = typeof value === 'number' || (typeof value === 'string' && /^\d+(?:\.\d+)?$/.test(value))
        ? Number(value) : vectorBaseScore(value);
      if (Number.isFinite(sc) && sc >= 0 && sc <= 10) severities.push(scoreToSev(sc));
    }
  }
  return worstSeverity(severities);
}

function worstSeverity(values) { return SEV_ORD.find(sev => values.includes(sev)) || 'UNKNOWN'; }

// Dotted releases (PyPI 4.2.24, Maven 2.9.10.4, NuGet, RubyGems) order
// component by component. A pre-release (4.2a1, 2.0.0-rc1) sorts just below
// its release, which is enough for OSV bounds such as "introduced: 4.2a1".
// Other qualifiers (-r0, ~deb12, .post1) follow ecosystem rules: unordered.
const PRE_RELEASE = /^(?:[-.]?(?:a|b|c|rc|alpha|beta|pre|preview|dev|m)[-.]?\d*)$/i;
function numericVersion(value) {
  const m = /^v?(\d+(?:\.\d+)*)(.*)$/.exec(String(value ?? ''));
  if (!m || (m[2] && !PRE_RELEASE.test(m[2]))) return null;
  return { parts: m[1].split('.').map(Number), pre: Boolean(m[2]) };
}

function compareNumeric(a, b) {
  for (let i = 0; i < Math.max(a.parts.length, b.parts.length); i++) {
    const d = (a.parts[i] || 0) - (b.parts[i] || 0);
    if (d) return d;
  }
  return a.pre === b.pre ? 0 : a.pre ? -1 : 1;
}

const RANGE_ORDERS = {
  SEMVER:    { parse: v => semver.valid(v), compare: semver.compare },
  ECOSYSTEM: { parse: numericVersion, compare: compareNumeric },
};

function getFixed(v, { name, ecosystem, version } = {}) {
  const packageName = value => ecosystem === 'PyPI'
    ? value.toLowerCase().replace(/[-_.]+/g, '-')
    : ['npm', 'Packagist', 'NuGet'].includes(ecosystem) ? value.toLowerCase() : value;
  const matched = [];          // fixes of intervals that contain the scanned version
  const unordered = new Set(); // fixes of intervals that cannot be compared
  for (const affected of v.affected || []) {
    const pkg = affected.package;
    if (name && (!pkg?.name || packageName(pkg.name) !== packageName(name))) continue;
    if (ecosystem && pkg?.ecosystem && pkg.ecosystem !== ecosystem
        && !pkg.ecosystem.startsWith(ecosystem + ':')) continue;
    for (const range of affected.ranges || []) {
      const order = RANGE_ORDERS[range.type];
      if (!order) continue; // GIT ranges end in commit hashes
      let current = typeof version === 'string' ? order.parse(version) : null;
      // Two pre-releases of one release cannot be ordered by numbers alone.
      if (current?.pre) current = null;
      let introduced = null;
      for (const event of range.events || []) {
        if (event.introduced !== undefined) { introduced = event.introduced; continue; }
        const end = event.fixed ?? event.last_affected ?? event.limit;
        if (end === undefined) continue;
        const start = introduced === '0' ? 0 : introduced === null ? null : order.parse(introduced);
        const stop = order.parse(end);
        introduced = null;
        if (!current || start === null || !stop) {
          if (event.fixed) unordered.add(event.fixed);
          continue;
        }
        const inside = (start === 0 || order.compare(current, start) >= 0)
          && (event.last_affected !== undefined ? order.compare(current, stop) <= 0
                                                : order.compare(current, stop) < 0);
        if (inside && event.fixed) matched.push({ fix: event.fixed, stop, order });
      }
    }
  }
  if (matched.length) {
    // Overlapping intervals: only the highest fix leaves all of them.
    return matched.reduce((best, m) =>
      m.order === best.order && m.order.compare(m.stop, best.stop) > 0 ? m : best).fix;
  }
  // Without an ordering, only a unique fix is safe.
  return unordered.size === 1 ? [...unordered][0] : null;
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
  const cvssScore = cvss?.cvss4?.score ?? cvss?.cvss3?.score ?? cvss?.cvss2?.score ?? 0;
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
