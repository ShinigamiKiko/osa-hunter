'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Scan history is shared between users, and /api/libscan accepts any
// ecosystem string, so every field that comes back from history is untrusted.
const XSS = '<img src=x onerror=alert(1)>';

function ui(entries) {
  const nodes = {};
  const ctx = { console: { log() {}, warn() {} }, Date, Set, Map, Promise,
    localStorage: { getItem: () => null, setItem() {} },
    document: { addEventListener() {}, getElementById: id => nodes[id] ||= { innerHTML: '', style: {}, querySelector: () => null, querySelectorAll: () => [] } },
    navTo() {}, exportBtnHtml: () => '', renderStoredEnrichment() {}, checkActivity() {}, _emptyRadar: () => '', _initEmptyRadar() {},
    fetch: async url => ({ ok: true, json: async () => ({ entries: entries[url.split('=').pop()] || [] }) }),
  };
  ctx.window = ctx; vm.createContext(ctx);
  vm.runInContext('let depScans=[], osScans=[], imgScans=[], ghScans=[];', ctx);
  for (const file of ['utils.js', 'ui-library-scan.js', 'ui-scan-history.js'])
    vm.runInContext(fs.readFileSync(path.join(__dirname, '../../frontend/public/js', file), 'utf8'), ctx, { filename: file });
  return { ctx, nodes };
}

test('a library scan with an HTML ecosystem from shared history renders as text', async () => {
  const { ctx, nodes } = ui({ lib: [{ _cacheKey: `lib:${XSS}:evil:latest`, _cachedAt: new Date().toISOString(),
    package: 'evil', ecosystem: XSS, version: null, toxic: { found: false }, topSeverity: 'NONE', vulns: [] }] });
  await ctx.navTo('lib-list');
  await ctx.renderLibList();
  const list = nodes.libListContent.innerHTML;
  assert.ok(list.includes('evil'), 'the entry is listed');
  assert.ok(!list.includes('<img'), 'no markup from the ecosystem field');
  assert.ok(list.includes('&lt;img'), 'the ecosystem is shown escaped');
  ctx.renderLibDetail(vm.runInContext('libScans[0]', ctx));
  assert.ok(!nodes.libDetailContent.innerHTML.includes('<img'));
});
