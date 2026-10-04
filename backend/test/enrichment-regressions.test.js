'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const nativeFetch = global.fetch;
const { execFileSync } = require('node:child_process');
for (const source of ['KEV', 'EPSS', 'POC', 'TOXIC']) process.env[`OSA_${source}_ENABLED`] = 'true';
let query = async () => ({ rows: [] });
const dbPath = require.resolve('../lib/auth/db');
require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: { getPool: () => ({ query: (...args) => query(...args) }) } };
const shared = require('../lib/shared');
const { osvQueryPackagist } = require('../lib/composer/osv');
const { compilePolicy, evalRules } = require('../lib/gate/policy');
const { normalizeBody, compileBody, fromYaml, toYaml } = require('../lib/gate/policyStore');
const { resolveDecision, gateDecide } = require('../lib/gate/decide');
const { cachedGate } = require('../lib/gate/service');
const json = value => new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } });
const pkg = { name: 'pkg', ecosystem: 'npm', version: '1.0' };
const advisory = id => ({ id, aliases: [id] });
test.afterEach(() => { global.fetch = nativeFetch; query = async () => ({ rows: [] }); });

test('both OSV clients include token-only pages and preserve query identity', async () => {
  for (const run of [() => shared.osvQuery('pkg','npm','1.0'), () => osvQueryPackagist('vendor/pkg','1.0')]) {
    const bodies = [];
    global.fetch = async (url, options) => {
      bodies.push(JSON.parse(options.body));
      return json(bodies.length === 1 ? { next_page_token: 'page2' } : bodies.length === 2
        ? { vulns: [{ id: 'GHSA-low', database_specific: { severity: 'LOW' } }], next_page_token: 'page3' }
        : { vulns: [{ id: 'GHSA-critical', database_specific: { severity: 'CRITICAL' } }] });
    };
    const vulns = await run(); assert.equal(vulns.length, 2); assert.equal(vulns[0]._sev, 'CRITICAL');
    assert.deepEqual(bodies[1].package, bodies[0].package); assert.equal(bodies[2].version, '1.0');
    assert.equal(bodies[1].page_token, 'page2');
  }
});

test('pagination loops, failed later pages and non-JSON responses never become clean scans', async () => {
  global.fetch = async () => json({ next_page_token: 'loop' });
  await assert.rejects(shared.osvQuery('pkg','npm','1'), /pagination/);
  let calls = 0;
  global.fetch = async () => ++calls === 1 ? json({ next_page_token: 'two' }) : new Response('', { status: 503 });
  await assert.rejects(osvQueryPackagist('vendor/pkg','1'), /503/);
  global.fetch = async () => new Response('<html>upstream error</html>', { headers: { 'content-type': 'text/html' } });
  await assert.rejects(osvQueryPackagist('vendor/pkg','1'), /OSV query failed/);
});

test('OSV severity uses the worst assessment across affected and ecosystem fields', () => {
  assert.equal(shared.parseSev({ severity: [{ score: '3.1' }, { score: '9.8' }] }), 'CRITICAL');
  assert.equal(shared.parseSev({ affected: [{ ecosystem_specific: { severity: 'HIGH' } }] }), 'HIGH');
  assert.equal(shared.parseSev({ database_specific: { severity: 'LOW' }, affected: [{ severity: [{ score: '9.0' }] }] }), 'CRITICAL');
  assert.equal(shared.parseSev({ severity: [{ score: 'CVSS:4.0/AV:N' }] }), 'UNKNOWN');
  assert.equal(shared.parseSev({ severity: [{ type: 'CVSS_V2', score: 'AV:N/AC:L/Au:N/C:C/I:C/A:C' }] }), 'CRITICAL');
});

test('complete CVSS v4 vectors without a CVE alias are blocked through the cached gate', async () => {
  const policy = compilePolicy({ rules: [{ id:'critical', action:'deny', when:{ 'counts.CRITICAL':'>= 1' } }] });
  const vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H';
  global.fetch = async url => String(url).includes('api.osv.dev') ? json({ vulns:[{ id:'GHSA-example',severity:[{ type:'CVSS_V4',score:vector }] }] }) : assert.fail('no CVE enrichment needed');
  let saved;
  query = async (sql,args) => { if (/INSERT INTO scan_cache/.test(sql)) saved=JSON.parse(args[1]); return {rows:[]}; };
  const result = await cachedGate({ ...pkg, policy });
  assert.equal(result.decision,'deny'); assert.equal(result.findings.counts.CRITICAL,1); assert.equal(saved.decision,'deny');
});

test('rules on any toxic field load and enforce the feed', async () => {
  const policy = compileBody(normalizeBody({ rules:[{ id:'malicious',action:'deny',when:{ 'toxic.problem_type':'malicious code' } }] }),1);
  let toxicRequests=0;
  global.fetch = async url => {
    if (String(url).includes('api.osv.dev')) return json({});
    toxicRequests++; return json([{ name:'pkg',problem_type:'malicious code', PURL: 'pkg:npm/pkg' }]);
  };
  assert.equal((await gateDecide(pkg,policy)).decision,'deny'); assert.equal(toxicRequests,1);
});

test('refreshing PoC cannot make an expired CVSS cache entry usable again', async () => {
  query = async sql => ({ rows:/FROM cve_enrichment/.test(sql) ? [{ cve:'CVE-2026-90007',cvss:null,poc:[],
    cvss_complete:true,poc_complete:true, updated_at:new Date(),
    cvss_updated_at:new Date(Date.now()-48*3600000),poc_updated_at:new Date(),
  }] : [] });
  global.fetch = async url => String(url).includes('api.osv.dev') ? json({ vulns:[advisory('CVE-2026-90007')] }) : new Response('',{status:503});
  const policy = compilePolicy({rules:[{id:'critical',action:'deny',when:{'counts.CRITICAL':'> 0'}}]});
  await assert.rejects(gateDecide(pkg,policy),/NVD unavailable/);
});

test('NVD v4 and the worst covered CVE upgrade gate facts and verdict severity', async () => {
  const ids = ['CVE-2026-90001','CVE-2026-90002'];
  global.fetch = async url => json({ vulnerabilities: [{ cve: { metrics: { cvssMetricV40: [
    { cvssData: { baseScore: String(url).includes(ids[1]) ? 9.8 : 4.0, baseSeverity: 'CRITICAL', version: '4.0' } },
  ] } } }] });
  const cvssMap = await shared.fetchCvss(ids, { strict: true });
  const enriched = shared.enrichVulns([{ id: 'OSV-advisory', _sev: 'LOW', _aliases: ids }], {
    cvssMap, epssMap: {}, kevSet: new Set(), pocMap: {},
  });
  assert.equal(enriched[0].severity, 'CRITICAL'); assert.equal(enriched[0].cvss.cvss4.score, 9.8);
  const policy = compilePolicy({ rules: [{ id: 'critical', action: 'deny', when: { 'counts.CRITICAL': '> 0' } }] });
  global.fetch = async url => String(url).includes('api.osv.dev') ? json({ vulns: [{ id: ids[1] }] }) : assert.fail('verified NVD cache should be used');
  assert.equal((await gateDecide(pkg, policy)).decision, 'deny');
});

test('KEV failure obeys on_gate_error and never enters verdict cache, including a retry', async () => {
  let inserts = 0, lookups = [];
  query = async sql => { if (/INSERT INTO scan_cache/.test(sql)) inserts++; return { rows: [] }; };
  const policy = compilePolicy({ defaults: { on_gate_error: 'deny' }, rules: [{ id: 'kev', action: 'deny', when: { all: [{ kev: true }] } }] });
  global.fetch = async url => {
    lookups.push(String(url));
    return String(url).includes('api.osv.dev') ? json({ vulns: [advisory('CVE-2026-90003')] }) : new Response('', { status: 503 });
  };
  for (let i = 0; i < 2; i++) {
    const result = await cachedGate({ ...pkg, policy });
    assert.equal(result.decision, 'deny'); assert.equal(result.reasons[0].rule, 'gate-error');
  }
  assert.equal(inserts, 0); assert.ok(!lookups.some(url => url.includes('nist.gov')));
  assert.equal((await cachedGate({ ...pkg, policy: { ...policy, onGateError: 'allow', version: 'allow-error' } })).decision, 'allow');
  assert.equal(inserts, 0);
});

test('required EPSS failures throw, while inactive sources and clean packages need no enrichment', async () => {
  const epssPolicy = compilePolicy({ rules: [{ id: 'hot', action: 'deny', when: { any: [{ epssMax: '> 0.5' }] } }] });
  let fail = true;
  global.fetch = async url => String(url).includes('api.osv.dev') ? json({ vulns: [advisory('CVE-2026-90004')] })
    : fail ? new Response('', { status: 500 }) : json({ data: [{ cve: 'CVE-2026-90004', epss: '0.9', percentile: '0.99' }] });
  await assert.rejects(gateDecide(pkg, epssPolicy), /EPSS unavailable/);
  fail = false; assert.equal((await gateDecide(pkg, epssPolicy)).decision, 'deny');
  const disabled = compileBody(normalizeBody({ rules: [{ id: 'kev', action: 'deny', enabled: false, when: { kev: true } }] }), 1);
  global.fetch = async url => String(url).includes('api.osv.dev') ? json({ vulns: [advisory('CVE-2026-90004')] }) : assert.fail('inactive rule fetched a source');
  assert.equal((await gateDecide(pkg, disabled)).decision, 'allow');
  global.fetch = async url => String(url).includes('api.osv.dev') ? json({}) : assert.fail('clean package fetched enrichment');
  assert.equal((await gateDecide(pkg, epssPolicy)).decision, 'allow');
});

test('old incomplete enrichment cache and failed NVD lookups cannot poison subsequent strict scans', async () => {
  const id = 'CVE-2026-90005', policy = compilePolicy({ rules: [{ id: 'critical', action: 'deny', when: { topSeverity: 'CRITICAL' } }] });
  query = async sql => ({ rows: /FROM cve_enrichment/.test(sql) ? [{ cve: id, cvss: null, poc: [], cvss_complete: false, poc_complete: false }] : [] });
  let fail = true, nvdCalls = 0;
  global.fetch = async url => {
    if (String(url).includes('api.osv.dev')) return json({ vulns: [advisory(id)] });
    nvdCalls++;
    return fail ? new Response('', { status: 429 }) : json({ vulnerabilities: [{ cve: { metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8 } }] } } }] });
  };
  await assert.rejects(gateDecide(pkg,policy), /NVD unavailable/);
  fail = false; assert.equal((await gateDecide(pkg,policy)).decision, 'deny'); assert.equal(nvdCalls, 2);
});

test('PoC errors and cached toxic-feed errors remain unavailable in strict mode', async () => {
  global.fetch = async () => new Response('', { status: 500 });
  assert.deepEqual(await shared.fetchPocs(['CVE-2026-90006']), {});
  await assert.rejects(shared.fetchPocs(['CVE-2026-90006'], { strict: true }), /PoC feed unavailable/);
  delete require.cache[require.resolve('../lib/shared/toxicRepos')];
  const { checkToxic } = require('../lib/shared/toxicRepos');
  await checkToxic('pkg');
  await assert.rejects(checkToxic('pkg', { strict: true }), /Toxic repository feed unavailable/);
  global.fetch = async () => new Response('', { status: 404 });
  assert.deepEqual(await shared.fetchPocs(['CVE-2026-90006'], { strict: true }), { 'CVE-2026-90006': [] });
});

test('native YAML booleans, scoped exception objects and allow-rule precedence survive round-trip', () => {
  const body = fromYaml('rules:\n  - id: kev\n    action: deny\n    when:\n      kev: true\nexceptions:\n  allow:\n    - ecosystem: npm\n      name: pkg\n      version: "1.0"\n      reason: reviewed\n');
  const policy = compileBody(fromYaml(toYaml(body)), 1);
  assert.equal(evalRules(policy, { kev: 2 }).length, 1); assert.equal(evalRules(policy, { kev: 0 }).length, 0);
  assert.deepEqual(policy.allow, ['npm/pkg@1.0']);
  assert.equal(resolveDecision(policy, [{ action: 'deny' }], { ...pkg, version: '2.0' }).decision, 'deny');
  assert.equal(resolveDecision(policy, [{ action: 'deny' }], { ...pkg, ecosystem: 'PyPI' }).decision, 'deny');
  const rulePolicy = { deny: [], allow: [], default: 'deny' };
  assert.equal(resolveDecision(rulePolicy, [{ action: 'allow' }], pkg).decision, 'allow');
  assert.equal(resolveDecision(rulePolicy, [{ action: 'allow' }, { action: 'warn' }], pkg).decision, 'warn');
  assert.equal(resolveDecision(rulePolicy, [{ action: 'allow' }, { action: 'deny' }], pkg).decision, 'deny');
});

test('explicitly disabled enrichment sources retain their configured behavior without network requests', () => {
  const env = { ...process.env, OSA_KEV_ENABLED:'false', OSA_EPSS_ENABLED:'false', OSA_POC_ENABLED:'false', OSA_TOXIC_ENABLED:'false' };
  execFileSync(process.execPath, ['-e', `const assert=require('node:assert/strict'); const shared=require('./lib/shared');
    global.fetch=()=>assert.fail('disabled source performed a network request');
    Promise.all([shared.fetchEpss(['CVE-2026-1'],{strict:true}),shared.fetchPocs(['CVE-2026-1'],{strict:true}),
      shared.getCisaSet({strict:true}),shared.checkToxic('pkg',{strict:true})]).then(([epss,poc,kev,toxic])=>{
      assert.deepEqual(epss,{});assert.deepEqual(poc,{});assert.equal(kev.size,0);assert.equal(toxic.found,false);
    }).catch(e=>{console.error(e);process.exitCode=1;});`], { cwd:require('node:path').join(__dirname,'..'),env,stdio:'pipe' });
});
