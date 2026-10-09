'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const reports = require('../lib/pdf');
function ui(stored = {}) {
  const nodes = {};
  const ctx = { console: { log() {}, warn() {} }, Date, Set, Map, Promise,
    localStorage: { getItem: key => JSON.stringify(stored[key] || []), setItem() {} },
    document: { addEventListener() {}, getElementById: id => nodes[id] ||= { innerHTML: '', style: {}, querySelector: () => null, querySelectorAll: () => [] } },
    navTo() {}, exportBtnHtml: () => '', renderStoredEnrichment() {}, updateDepBadge() {}, checkActivity() {},
    DEP_SYSTEMS: [{ id: 'NPM', label: 'npm', logo: '' }],
  };
  ctx.window = ctx; vm.createContext(ctx);
  vm.runInContext('let libScans=[], depScans=[], osScans=[]; let currentDepScan;', ctx);
  const load = file => vm.runInContext(fs.readFileSync(path.join(__dirname, '../../frontend/public/js', file), 'utf8'), ctx, { filename: file });
  for (const file of ['utils.js', 'ui-image-scan.js', 'ui-gh-scan.js', 'dependency-scan/30-scan.js',
    'dependency-scan/51-list.js', 'dependency-scan/52-detail.js', 'ui-scan-history.js']) load(file);
  return { ctx, nodes };
}
const trivy = { _cacheKey: 'img:registry.test:5000/app:1', _cachedAt: new Date().toISOString(),
  Results: [{ Type: 'debian', Vulnerabilities: [{ VulnerabilityID: 'CVE-2026-1', Severity: 'CRITICAL', PkgName: 'openssl' }] }] };
test('image history uses live-scan normalization and never labels a CRITICAL image clean', async () => {
  const { ctx, nodes } = ui();
  ctx.fetch = async () => ({ ok: true, json: async () => ({ entries: [trivy] }) });
  await ctx.navTo('img-list');
  const scan = vm.runInContext('imgScans[0]', ctx);
  assert.equal(scan.image, 'registry.test:5000/app'); assert.equal(scan.tag, '1');
  assert.equal(scan.counts.CRITICAL, 1); assert.equal(scan.vulns[0]._pkgType, 'debian');
  await ctx.renderImgList(); assert.ok(!nodes.imgListContent.innerHTML.includes('✓ clean'));
  assert.doesNotThrow(() => ctx.renderImgDetail(scan)); assert.match(nodes.imgDetailContent.innerHTML, /CRITICAL/);
});
test('older local image history is repaired before server history deduplication', () => {
  const { ctx } = ui({ es_img: [{ ...trivy, image: 'registry.test:5000/app', tag: '1' }] });
  assert.equal(vm.runInContext('imgScans[0].counts.CRITICAL', ctx), 1);
});
test('UNKNOWN findings are displayed as findings in image UI and PDF', () => {
  const { ctx, nodes } = ui();
  const scan = ctx.normalizeImageScan({ vulns: [{ VulnerabilityID: 'CVE-2026-1', Severity: 'UNKNOWN', PkgName: 'openssl' }] }, { image: 'fixture', tag: '1' });
  ctx.renderImgDetail(scan);
  assert.ok(!nodes.imgDetailContent.innerHTML.includes('✅ CLEAN'));
  assert.match(nodes.imgDetailContent.innerHTML, /UNKNOWN/);
  const html = reports.buildImgReportHtml(scan);
  assert.match(html, /rpt-sev UNKNOWN/); assert.ok(!html.includes('<b>✅</b> Clean'));
});
test('legacy SAST scans with unknown completeness require rescan in UI and PDF', async () => {
  const scan = { repo: 'example/repo', url: 'https://github.com/example/repo', findings: [], counts: {}, topSev: 'NONE' };
  const { ctx, nodes } = ui({ es_gh: [scan] });
  await ctx.renderGhList(); ctx.renderGhDetail(scan);
  assert.match(nodes.ghListContent.innerHTML, /RESCAN/);
  assert.ok(!nodes.ghListContent.innerHTML.includes('✓ clean'));
  assert.ok(!nodes.ghDetailContent.innerHTML.includes('looks clean'));
  assert.match(reports.buildSastReportHtml(scan), /rescan required/);
});
test('completed clean SAST scans still display clean, and UNKNOWN remains visible', () => {
  const { ctx, nodes } = ui();
  const clean = { repo: 'example/repo', complete: true, findings: [], counts: {} };
  ctx.renderGhDetail(clean); assert.match(nodes.ghDetailContent.innerHTML, /✅ CLEAN/);
  assert.match(reports.buildSastReportHtml(clean), /looks clean/);
  const unknown = { ...clean, counts: { UNKNOWN: 1 }, findings: [{ severity: 'UNKNOWN', cwe: [], path: 'index.js' }] };
  ctx.renderGhDetail(unknown); assert.ok(!nodes.ghDetailContent.innerHTML.includes('✅ CLEAN'));
  assert.match(reports.buildSastReportHtml(unknown), /rpt-sev UNKNOWN/);
});
test('legacy capped dependency scans require rescan, but complete 500-node results remain valid', async () => {
  const { ctx, nodes } = ui();
  const scan = { package: 'fixture', system: 'NPM', summary: { totalDeps: 500, vulnerabilityCount: 0 }, deps: [] };
  vm.runInContext('depScans = [];', ctx); ctx.legacy = scan; vm.runInContext('depScans.push(legacy)', ctx);
  await ctx.renderDepList(); ctx.renderDepDetail(scan);
  assert.match(nodes.depListContent.innerHTML, /RESCAN REQUIRED/);
  assert.match(nodes.depDetailContent.innerHTML, /Scan incomplete/);
  assert.match(reports.buildDepReportHtml(scan), /Scan incomplete/);
  const complete = { ...scan, complete: true }; ctx.renderDepDetail(complete);
  assert.ok(!nodes.depDetailContent.innerHTML.includes('Scan incomplete'));
});
