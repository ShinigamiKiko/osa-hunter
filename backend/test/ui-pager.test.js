'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const JS = file => fs.readFileSync(path.join(__dirname, '../../frontend/public/js', file), 'utf8');

function context(files, extra = {}) {
  const storage = {};
  const ctx = { console, Date, Set, Map, Promise,
    localStorage: { getItem: key => storage[key] ?? null, setItem: (key, value) => { storage[key] = String(value); } },
    document: { addEventListener() {}, getElementById: () => null, querySelector: () => null, querySelectorAll: () => [] },
    window: { addEventListener() {} }, CSS: { escape: s => s }, navTo() {}, setTimeout, ...extra };
  vm.createContext(ctx);
  for (const file of files) vm.runInContext(JS(file), ctx, { filename: file });
  return { ctx, storage, run: code => vm.runInContext(code, ctx) };
}

const rowsOf = html => (html.match(/data-pager-page="(\d+)"/g) || []).map(m => Number(m.match(/\d+/)[0]));

test('lists show 50, 100 or 150 rows and keep addressing the full list', () => {
  const { run, storage } = context(['utils.js']);
  run('var items = Array.from({ length: 160 }, (_, i) => "row" + i)');
  let page = run('paginate("lib-list", items, () => {})');
  assert.equal(page.rows.length, 50);
  assert.deepEqual([...page.rows[0]], ['row0', 0]);
  assert.match(page.html, /1–50 of 160/);
  assert.match(page.html, /<option value="50" selected>50<\/option><option value="100">100<\/option><option value="150">150<\/option>/);
  assert.deepEqual(rowsOf(page.html).filter((n, i, a) => a.indexOf(n) === i).sort((a, b) => a - b), [0, 1, 2, 3, 4]);

  run('pageState("lib-list").page = 4');
  page = run('paginate("lib-list", items, () => {})');
  assert.equal(page.rows.length, 10);
  assert.deepEqual([...page.rows[0]], ['row150', 150], 'row handlers get the absolute index');

  run('pageState("lib-list").size = 150; pageState("lib-list").page = 1');
  page = run('paginate("lib-list", items, () => {})');
  assert.equal(page.rows.length, 150);
  assert.equal(storage['osa.pageSize.lib-list'], undefined, 'only an explicit choice is remembered');
});

test('the pager hides when everything fits and the page resets for a new owner', () => {
  const { run } = context(['utils.js']);
  assert.equal(run('paginate("small", Array(50).fill(0), () => {}).html'), '');
  run('var long = Array(120).fill(0)');
  run('paginate("groups", long, () => {}, "scan-a"); pageState("groups").page = 3');
  assert.equal(run('paginate("groups", long, () => {}, "scan-a").rows[0][1]'), 100);
  assert.equal(run('paginate("groups", long, () => {}, "scan-b").rows[0][1]'), 0);
  run('pageState("groups").page = 9');
  assert.equal(run('paginate("groups", long, () => {}, "scan-b").rows[0][1]'), 100, 'an out-of-range page clamps to the last');
});

test('a saved page size is restored per list', () => {
  const { run } = context(['utils.js']);
  run('localStorage.setItem("osa.pageSize.proxy", "100"); localStorage.setItem("osa.pageSize.bad", "7")');
  assert.equal(run('pageState("proxy").size'), 100);
  assert.equal(run('pageState("bad").size'), 50);
});

test('a rule opened from Proxy activity lands on the page that holds it', () => {
  const { run } = context(['utils.js', 'ui-rules.js']);
  run(`
    _rulesFacts = [{ key: 'kev', label: 'In CISA KEV', type: 'boolean' }];
    _rulesState = { source: 'db', dirty: false, body: {
      defaults: { decision: 'allow', on_gate_error: 'deny' },
      rules: Array.from({ length: 120 }, (_, i) => ({ id: 'r' + i, action: 'deny', when: { kev: 'yes' } })),
      exceptions: { deny: [], allow: [] } } };`);
  const html = run('_rulesListHtml([], _rulesState.body.rules)');
  assert.equal((html.match(/class="rule-card/g) || []).length, 50);
  assert.match(html, /1–50 of 120/);
  run('rulesFocusOn("rule:r110")');
  const focused = run('_rulesListHtml([], _rulesState.body.rules)');
  assert.ok(focused.includes('data-key="rule:r110"'));
  assert.match(focused, /101–120 of 120/);
});

test('the Reason column names the rule: scan rule id or name-rule pattern', () => {
  const { run } = context(['utils.js', 'ui-proxy.js']);
  run(`_proxyRules = {
    rules: new Map([['critical', { action: 'deny', detail: 'critical vuln' }]]),
    names: new Map([['crossenv*', { action: 'deny', detail: 'typosquat of cross-env' }]]) };`);
  const cell = reasons => run(`_proxyReasonLinks(${JSON.stringify({ name: 'crossenv-x', reasons })})`);

  const byName = cell('denylist=' + encodeURIComponent('crossenv*'));
  assert.match(byName, />crossenv\*<\/a>/);
  assert.match(byName, /data-rule-target="name:crossenv\*"/);
  assert.match(byName, /title="typosquat of cross-env"/);

  const scanRule = cell('critical');
  assert.match(scanRule, />critical<\/a>/);
  assert.match(scanRule, /title="critical vuln"/);

  assert.match(cell('deleted-rule'), /class="reason-gone"[^>]*>deleted-rule</);
  assert.doesNotMatch(cell('scan data unavailable'), /<a /, 'system reasons are not rules');
  // Verdicts logged before patterns were stored fall back to the package name.
  assert.match(cell('denylist'), /data-rule-target="name:crossenv-x"[^>]*>crossenv-x \(by name\)</);
});
