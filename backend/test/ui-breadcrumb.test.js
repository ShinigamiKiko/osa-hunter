'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

test('the OS scan breadcrumb names the scanned package', async () => {
  const nodes = {};
  const el = () => ({ innerHTML: '', style: {}, classList: { add() {}, remove() {}, toggle() {} },
    setAttribute() {}, removeAttribute() {}, querySelector: () => null, querySelectorAll: () => [] });
  const ctx = { console: { log() {}, warn() {} }, Date, Set, Map, Promise, setTimeout, setInterval() {},
    localStorage: { getItem: () => null, setItem() {} },
    fetch: async () => ({ ok: true, json: async () => ({}) }),
    document: { addEventListener() {}, getElementById: id => nodes[id] ||= el(), querySelectorAll: () => [] },
    renderOsDetail() {},
  };
  ctx.window = ctx; vm.createContext(ctx);
  for (const file of ['utils.js', 'ui-nav.js'])
    vm.runInContext(fs.readFileSync(path.join(__dirname, '../../frontend/public/js', file), 'utf8'), ctx, { filename: file });
  await ctx.navTo('os-detail', { scan: { pkg: 'openssl', pkgVer: '3.0.2', distro: 'ubuntu', vulns: [] } });
  const crumbs = Object.values(nodes).map(n => n.innerHTML).join('');
  assert.match(crumbs, /bc-current">openssl 3\.0\.2</);
  assert.doesNotMatch(crumbs, /undefined/);
});
