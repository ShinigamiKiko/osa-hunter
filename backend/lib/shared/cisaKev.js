'use strict';

const { CISA_URL } = require('./constants');
const { TtlCache } = require('./primitives');
const { HTTP_TIMEOUT_MS } = require('../config');
const { observeExternalError } = require('../observability/metrics');

const KEV_ENABLED = process.env.OSA_KEV_ENABLED !== 'false';

let cisaCache = { set: null, ts: 0, error: null };
async function getCisaSet({ strict = false } = {}) {
  if (!KEV_ENABLED) return new Set();
  if (cisaCache.set && Date.now() - cisaCache.ts < 3_600_000) {
    if (strict && cisaCache.error) throw cisaCache.error;
    return cisaCache.set;
  }
  try {
    const r = await fetch(CISA_URL, { signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const d = await r.json();
    if (!Array.isArray(d.vulnerabilities)) throw new Error('Invalid CISA KEV response');
    if (d.vulnerabilities.some(v => !/^CVE-\d{4}-\d+$/.test(v?.cveID || ''))) throw new Error('Invalid CISA KEV entry');
    cisaCache.set = new Set((d.vulnerabilities || []).map(v => v.cveID));
    cisaCache.ts = Date.now();
    cisaCache.error = null;
    console.log('[CISA] KEV loaded:', cisaCache.set.size, 'entries');
  } catch (e) {
    observeExternalError('cisa');
    console.error('[CISA] Fetch failed:', e.message);
    if (!cisaCache.set) cisaCache.set = new Set();
    // Don't cache an empty/stale KEV set for a full hour on failure (that
    // silently reports known-exploited CVEs as not-in-KEV). Back off ~1 min
    // and retry instead.
    cisaCache.ts = Date.now() - 3_600_000 + 60_000;
    cisaCache.error = new Error(`CISA KEV unavailable: ${e.message}`);
    if (strict) throw cisaCache.error;
  }
  return cisaCache.set;
}

const nvdCache = new TtlCache(24 * 3_600_000);

module.exports = { getCisaSet, nvdCache };
