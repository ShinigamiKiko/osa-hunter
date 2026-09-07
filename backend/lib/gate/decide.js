'use strict';

const { ScanError } = require('../auth/scanCache');
const {
  SEV_ORD, pLimit,
  checkToxic,
  osvQuery, bulkEnrich, enrichVulns, extractCVEs,
} = require('../shared');
const { DEFAULT_POLICY, evalRules } = require('./policy');

// deps.dev, reused for the optional transitive context (not for the verdict).
const DEPSDEV_URL   = 'https://api.deps.dev/v3alpha';
const OSV_TO_SYSTEM = { npm: 'NPM', Go: 'GO', PyPI: 'PYPI', 'crates.io': 'CARGO', Maven: 'MAVEN', NuGet: 'NUGET' };
const SYSTEM_TO_OSV = { NPM: 'npm', GO: 'Go', PYPI: 'PyPI', CARGO: 'crates.io', MAVEN: 'Maven', NUGET: 'NuGet' };
const MAX_TRANSITIVE = 150;

function osvEcosystem(ecosystem) {
  if (ecosystem.startsWith('Debian')) return 'Debian';
  if (ecosystem.startsWith('Ubuntu')) return 'Ubuntu';
  if (ecosystem.startsWith('Alpine')) return 'Alpine';
  if (ecosystem.startsWith('Rocky Linux')) return 'Rocky Linux';
  if (ecosystem.startsWith('AlmaLinux')) return 'AlmaLinux';
  // OSV has no CentOS ecosystem (HTTP 400). CentOS Stream is the RHEL upstream
  // and ships the same el<N> versions, so Red Hat advisories are the closest
  // match - and the richest (openssl@3.0.7-18.el9: 118 vulns vs 27 in Rocky).
  if (ecosystem.startsWith('CentOS')) return 'Red Hat';
  // OSV's name is exactly "Red Hat"; "Red Hat Enterprise Linux" returns 400.
  if (ecosystem.startsWith('Red Hat')) return 'Red Hat';
  if (ecosystem.startsWith('openSUSE')) return 'openSUSE';
  if (ecosystem.startsWith('SUSE')) return 'SUSE Linux Enterprise';
  return ecosystem;
}

function emptyCounts() {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
}

// Roll a scanned+enriched package up into the flat facts the policy reads.
function buildFacts({ ecosystem, name, version }, enriched, toxic) {
  const counts = emptyCounts();
  const cveSet = new Set(), ids = [];
  let kev = 0, epssMax = 0, pocCount = 0;
  for (const v of enriched) {
    if (v.severity in counts) counts[v.severity]++;
    if (v.inKev) kev++;
    if (v.epss && typeof v.epss.epss === 'number') epssMax = Math.max(epssMax, v.epss.epss);
    if (v.pocs && v.pocs.length) pocCount++;
    // v.cves covers every CVE the record maps to (an RLSA/ALSA/RHSA can be many).
    for (const c of (v.cves && v.cves.length ? v.cves : (v.cve ? [v.cve] : []))) cveSet.add(c);
    if (v.id) ids.push(v.id);
  }
  const cves = [...cveSet];
  return {
    ecosystem, name, version,
    total: enriched.length,
    counts,
    topSeverity: SEV_ORD.find(s => counts[s] > 0) || 'NONE',
    kev, epssMax, pocCount,
    cves,                 // CVE ids of this package's vulns - for `cves: CVE-…` rules
    cveCount: cves.length, // number of distinct CVEs - for `cveCount: "> 5"` rules
    ids,                  // all advisory ids (GHSA/GO-…/CVE) - for `ids: …` rules
    toxic: toxic || { found: false },
  };
}

// Turn matched rules into a final verdict. deny beats warn; nothing => default.
// A deny/allow list entry matches by name, name@version, or with the ecosystem
// prefix - and supports "*" globs. So all of these work:
//   left-pad                 (any ecosystem, all versions)
//   npm/left-pad             (npm, all versions)
//   npm/left-pad@1.3.0       (exact version)
//   npm/@evil/*              (a scope)
//   */event-stream           (that name in any ecosystem)
function _globToRe(s) {
  const esc = s.split('*').map(p => p.replace(/[.*+?^${}()|[\]\\]/g, m => '\\' + m)).join('.*');
  return new RegExp('^' + esc + '$');
}
function matchList(list, ecosystem, name, version) {
  const cands = [`${ecosystem}/${name}`, name];
  if (version) cands.push(`${ecosystem}/${name}@${version}`, `${name}@${version}`);
  for (const raw of list || []) {
    const entry = String(raw).trim();
    if (!entry) continue;
    if (entry.includes('*')) { const re = _globToRe(entry); if (cands.some(c => re.test(c))) return entry; }
    else if (cands.includes(entry)) return entry;
  }
  return null;
}

// A name rule may carry its own message, the way a scan rule carries `detail`.
// Without one, say what actually happened: matched by name.
function nameDetail(policy, kind, entry) {
  const custom = policy.nameReasons?.[kind]?.[entry];
  return custom || `${kind === 'deny' ? 'blocked' : 'allowed'} by name: ${entry}`;
}

function resolveDecision(policy, hits, { ecosystem, name, version }) {
  const denied = matchList(policy.deny, ecosystem, name, version);
  if (denied) return { decision: 'deny', reasons: [{ rule: 'denylist', detail: nameDetail(policy, 'deny', denied) }] };
  const allowed = matchList(policy.allow, ecosystem, name, version);
  if (allowed) return { decision: 'allow', reasons: [{ rule: 'allowlist', detail: nameDetail(policy, 'allow', allowed) }] };

  const denies = hits.filter(h => h.action === 'deny');
  const warns  = hits.filter(h => h.action === 'warn');
  if (denies.length) return { decision: 'deny', reasons: denies };
  if (warns.length)  return { decision: 'warn', reasons: warns };
  return { decision: policy.default || 'allow', reasons: [] };
}

async function depsDevGet(path) {
  const r = await fetch(`${DEPSDEV_URL}${path}`, {
    signal: AbortSignal.timeout(15000), headers: { Accept: 'application/json' },
  });
  if (!r.ok) throw new Error(`deps.dev HTTP ${r.status}`);
  return r.json();
}

// Cheap, informational-only view of the transitive tree: severity by OSV alone
// (no KEV/EPSS enrichment). Never influences the decision - it just tells the
// caller "this package also drags in X vulnerable transitive deps".
async function transitiveSummary(ecosystem, name, version) {
  const sys = OSV_TO_SYSTEM[ecosystem];
  if (!sys) return null; // ecosystem deps.dev can't resolve - skip quietly

  let resolved = version && sys === 'GO' && !version.startsWith('v') ? 'v' + version : version;
  const enc = encodeURIComponent(name);
  if (!resolved) {
    const data = await depsDevGet(`/systems/${sys.toLowerCase()}/packages/${enc}`);
    const av = data.versions || [];
    resolved = (av.find(v => v.isDefault) || av[av.length - 1])?.versionKey?.version;
  }
  if (!resolved) return null;

  const graph = await depsDevGet(`/systems/${sys.toLowerCase()}/packages/${enc}/versions/${encodeURIComponent(resolved)}:dependencies`);
  const nodes = (graph.nodes || []).filter((_, i) => i !== 0); // node 0 is the package itself
  const seen = new Map();
  for (const n of nodes) {
    const vk = n.versionKey || {};
    if (!vk.name || !vk.version) continue;
    const key = `${vk.system}:${vk.name}@${vk.version}`;
    if (!seen.has(key)) seen.set(key, { name: vk.name, system: vk.system || sys, version: vk.version, relation: n.relation || 'INDIRECT' });
  }
  const deps = [...seen.values()].slice(0, MAX_TRANSITIVE);

  const offenders = [];
  await pLimit(deps, 6, async (dep) => {
    const eco = SYSTEM_TO_OSV[dep.system] || ecosystem;
    const vulns = await osvQuery(dep.name, eco, dep.version).catch(() => []);
    if (vulns && vulns.length) {
      offenders.push({
        name: dep.name, version: dep.version, relation: dep.relation,
        topSeverity: vulns[0]._sev || 'UNKNOWN', vulnCount: vulns.length,
      });
    }
  });
  offenders.sort((a, b) => SEV_ORD.indexOf(a.topSeverity) - SEV_ORD.indexOf(b.topSeverity));

  return {
    totalDeps: deps.length,
    truncated: seen.size > MAX_TRANSITIVE,
    withVulns: offenders.length,
    worstSeverity: offenders[0]?.topSeverity || 'NONE',
    top: offenders.slice(0, 5),
  };
}

// Main entry point. Decides on the single package; transitive info is optional
// and purely advisory. Throws ScanError on upstream failures.
async function gateDecide({ name, ecosystem, version, includeDeps = false }, policy = DEFAULT_POLICY) {
  const pkg = name.trim();
  const eco = ecosystem.trim();
  const ver = (version || '').trim() || null;
  const key = `${eco}/${pkg}${ver ? '@' + ver : ''}`;

  // Hard name-based block/allow FIRST - before any network scan. This makes a
  // by-name block work for every ecosystem, even ones OSV doesn't cover (so a
  // denied package is a clean 403, never an OSV error), and costs no lookup.
  const denied = matchList(policy.deny, eco, pkg, ver);
  if (denied) {
    return {
      decision: 'deny',
      reasons: [{ rule: 'denylist', detail: nameDetail(policy, 'deny', denied) }],
      package: { ecosystem: eco, name: pkg, version: ver },
      findings: { total: 0, counts: emptyCounts(), topSeverity: 'NONE', kev: 0, epssMax: 0, pocCount: 0, cveCount: 0, toxic: { found: false } },
      transitive: null, policy: policy.version || 'default', scannedAt: new Date().toISOString(),
    };
  }
  const allowedByName = matchList(policy.allow, eco, pkg, ver);
  if (allowedByName) {
    return {
      decision: 'allow',
      reasons: [{ rule: 'allowlist', detail: nameDetail(policy, 'allow', allowedByName) }],
      package: { ecosystem: eco, name: pkg, version: ver },
      findings: { total: 0, counts: emptyCounts(), topSeverity: 'NONE', kev: 0, epssMax: 0, pocCount: 0, cveCount: 0, toxic: { found: false } },
      transitive: null, policy: policy.version || 'default', scannedAt: new Date().toISOString(),
    };
  }

  let vulns;
  try {
     vulns = await osvQuery(pkg, osvEcosystem(eco), ver);
    if (!vulns) throw new Error('OSV query returned null');
  } catch (e) {
    throw new ScanError(502, `OSV query failed: ${e.message}`);
  }

  const cveIds = extractCVEs(vulns);
  const [toxicRes, enrichRes] = await Promise.allSettled([checkToxic(pkg), bulkEnrich(cveIds)]);
  const toxic = toxicRes.status === 'fulfilled' ? toxicRes.value : { found: false };
  const maps  = enrichRes.status === 'fulfilled' ? enrichRes.value : { epssMap: {}, kevSet: new Set(), cvssMap: {}, pocMap: {} };

  const enriched = enrichVulns(vulns, maps);
  const facts = buildFacts({ ecosystem: eco, name: pkg, version: ver }, enriched, toxic);

  const hits = evalRules(policy, facts);
  const { decision, reasons } = resolveDecision(policy, hits, { ecosystem: eco, name: pkg, version: ver });

  let transitive = null;
  if (includeDeps) {
    try {
      transitive = await transitiveSummary(eco, pkg, ver);
    } catch (e) {
      transitive = { error: `transitive lookup unavailable: ${e.message}` };
    }
  }

  return {
    decision,                       // allow | warn | deny
    reasons,                        // [{ rule, detail }]
    package: { ecosystem: eco, name: pkg, version: ver },
    findings: {
      total: facts.total,
      counts: facts.counts,
      topSeverity: facts.topSeverity,
      kev: facts.kev,
      epssMax: facts.epssMax,
      pocCount: facts.pocCount,
      cveCount: facts.cveCount,   // policy can rule on it, so report it too
      toxic: facts.toxic,
    },
    transitive,                     // null unless includeDeps=true; advisory only
    policy: policy.version || 'default',
    scannedAt: new Date().toISOString(),
  };
}

module.exports = { gateDecide, buildFacts, resolveDecision, osvEcosystem };
