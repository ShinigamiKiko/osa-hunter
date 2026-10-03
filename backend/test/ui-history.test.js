'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

test('history retries after failure, accesses reassigned lexical arrays and normalizes Composer like live scans', async () => {
  const calls = {}, storage = {};
  const ctx = { console: { log() {}, warn() {} }, Date, Set, Promise,
    localStorage: { setItem: (key,value) => { storage[key] = value; } }, navTo() {},
    fetch: async url => {
      const type = url.split('=').pop(); calls[type] = (calls[type] || 0) + 1;
      if (calls[type] === 1) return { ok: false };
      const common = { _cacheKey: type + ':pkg:1', _cachedAt: new Date().toISOString(), package: 'pkg', system: 'COMPOSER' };
      return { ok: true, json: async () => ({ entries: type === 'composer' ? [{ ...common,
        deps: { root: { name: 'pkg', version: '1', vulns: [{ id: 'CVE-2026-1', severity: 'CRITICAL', fixed: '2' }],
          epss: { 'CVE-2026-1': { epss: 0.8 } }, kev: ['CVE-2026-1'], pocs: { 'CVE-2026-1': [{ url: 'https://example.test' }] } }, direct: [], transitive: [] },
        summary: { total: 1 },
      }] : [{ ...common, deps: [] }] }) };
    },
  };
  ctx.window = ctx; vm.createContext(ctx);
  vm.runInContext('let libScans=[], depScans=[], osScans=[], imgScans=[], ghScans=[];', ctx);
  for (const file of ['dependency-scan/30-scan.js','ui-scan-history.js']) vm.runInContext(fs.readFileSync(path.join(__dirname,'../../frontend/public/js',file),'utf8'),ctx);
  await ctx.navTo('dep-list'); assert.equal(vm.runInContext('depScans.length',ctx),0);
  vm.runInContext('depScans = [{id:"local",scannedAt:new Date().toISOString()}];', ctx);
  await ctx.navTo('dep-list');
  assert.equal(vm.runInContext('depScans.length',ctx),3);
  const composer = vm.runInContext('depScans.find(s=>s._cacheKey?.startsWith("composer:"))',ctx);
  assert.equal(composer.deps[0].vulns[0].inKev, true);
  assert.equal(composer.deps[0].vulns[0].epss.epss, 0.8);
  assert.equal(composer.deps[0].vulns[0].fix, '2');
  assert.equal(composer.summary.CRITICAL,1); assert.equal(composer.summary.withVulns,1);
  assert.ok(storage.es_dep);
  await ctx.navTo('dep-list'); assert.deepEqual(calls,{ dep:2, composer:2 });
});
