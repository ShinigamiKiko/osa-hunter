'use strict';

const { CISA_URL } = require('./constants');
const { TtlCache } = require('./primitives');

let cisaCache = { set: null, ts: 0 };
async function getCisaSet() {
  if (cisaCache.set && Date.now() - cisaCache.ts < 3_600_000) return cisaCache.set;
  try {
    const r = await fetch(CISA_URL, { signal: AbortSignal.timeout(15000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const d = await r.json();
    cisaCache.set = new Set((d.vulnerabilities || []).map(v => v.cveID));
    cisaCache.ts = Date.now();
    console.log('[CISA] KEV loaded:', cisaCache.set.size, 'entries');
  } catch (e) {
    console.error('[CISA] Fetch failed:', e.message);
    if (!cisaCache.set) cisaCache.set = new Set();
    // Don't cache an empty/stale KEV set for a full hour on failure (that
    // silently reports known-exploited CVEs as not-in-KEV). Back off ~1 min
    // and retry instead.
    cisaCache.ts = Date.now() - 3_600_000 + 60_000;
  }
  return cisaCache.set;
}

const nvdCache = new TtlCache(24 * 3_600_000);

module.exports = { getCisaSet, nvdCache };
