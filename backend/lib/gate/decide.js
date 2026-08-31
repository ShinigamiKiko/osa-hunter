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
  if (ecosystem.startsWith('CentOS')) return 'CentOS';
  if (ecosystem.startsWith('Red Hat')) return 'Red Hat Enterprise Linux';
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
function resolveDecision(policy, hits, key) {
  if (policy.deny.includes(key)) return { decision: 'deny', reasons: [{ rule: 'denylist', detail: 'on manual denylist' }] };
  if (policy.allow.includes(key)) return { decision: 'allow', reasons: [{ rule: 'allowlist', detail: 'on manual allowlist' }] };

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
  const { decision, reasons } = resolveDecision(policy, hits, key);

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
      toxic: facts.toxic,
    },
    transitive,                     // null unless includeDeps=true; advisory only
    policy: policy.version || 'default',
    scannedAt: new Date().toISOString(),
  };
}

module.exports = { gateDecide, buildFacts, resolveDecision };
