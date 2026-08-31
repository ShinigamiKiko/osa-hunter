'use strict';

const TOXIC_URL = 'https://raw.githubusercontent.com/toxic-repos/toxic-repos/main/data/json/toxic-repos.json';

const OK_TTL  = 3_600_000; // 1h on success
const NEG_TTL = 300_000;   // 5m after a failure - don't refetch on every scan

// Toxic feed can be disabled entirely (e.g. unreachable network): OSA_TOXIC_ENABLED=false
const TOXIC_ENABLED = process.env.OSA_TOXIC_ENABLED !== 'false';

let _toxicCache = { list: null, ts: 0, ttl: OK_TTL };

async function getToxicList() {
  if (!TOXIC_ENABLED) return [];
  if (_toxicCache.list && Date.now() - _toxicCache.ts < _toxicCache.ttl) return _toxicCache.list;
  try {
    const r = await fetch(TOXIC_URL, { signal: AbortSignal.timeout(15000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    // Guard the shape: a 200 with a non-array body (e.g. an error object) would
    // otherwise make checkToxic's list.filter throw and reject the whole scan.
    const list = Array.isArray(data) ? data : [];
    _toxicCache = { list, ts: Date.now(), ttl: OK_TTL };
    console.log('[TOXIC] Loaded', list.length, 'entries');
    return list;
  } catch (e) {
    console.error('[TOXIC] Load failed:', e.message, `- negative-caching for ${NEG_TTL / 1000}s`);
    // Negative-cache the failure so an unreachable feed doesn't cost a fetch
    // timeout on every single scan. Retries after NEG_TTL.
    _toxicCache = { list: _toxicCache.list || [], ts: Date.now(), ttl: NEG_TTL };
    return _toxicCache.list;
  }
}

async function checkToxic(pkgName) {
  const list = await getToxicList();
  const needle = String(pkgName || '').toLowerCase();
  const matches = list.filter(entry => {
    const n = (entry.name || '').toLowerCase();
    return n === needle || n.endsWith('/' + needle) || n === needle.replace(/^@[^/]+\//, '');
  });
  if (!matches.length) return { found: false };
  const m = matches[0];
  return {
    found: true,
    problem_type: m.problem_type,
    description: m.description,
    commit_link: m.commit_link,
    name: m.name,
  };
}

module.exports = { checkToxic };
