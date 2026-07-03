'use strict';

const TOXIC_URL = 'https://raw.githubusercontent.com/toxic-repos/toxic-repos/main/data/json/toxic-repos.json';

let _toxicCache = { list: null, ts: 0 };

async function getToxicList() {
  if (_toxicCache.list && Date.now() - _toxicCache.ts < 3_600_000) return _toxicCache.list;
  try {
    const r = await fetch(TOXIC_URL, { signal: AbortSignal.timeout(15000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    // Guard the shape: a 200 with a non-array body (e.g. an error object) would
    // otherwise make checkToxic's list.filter throw and reject the whole scan.
    const list = Array.isArray(data) ? data : [];
    _toxicCache = { list, ts: Date.now() };
    console.log('[TOXIC] Loaded', list.length, 'entries');
    return list;
  } catch (e) {
    console.error('[TOXIC] Load failed:', e.message);
    _toxicCache.ts = Date.now();
    return _toxicCache.list || [];
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
