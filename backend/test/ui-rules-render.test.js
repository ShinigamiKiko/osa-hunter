'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

// The Rules screen is plain browser JS with no build step, so its rendering is
// exercised here in a stub DOM. Two bugs have already shipped from this file
// (an empty dialog, a toggle wired to nothing); the parts that produce HTML are
// pure functions and there is no reason to leave them untested.
const SRC = path.join(__dirname, '../../frontend/public/js/ui-rules.js');

function load() {
  const ctx = {
    document: {
      getElementById: () => null, querySelector: () => null,
      querySelectorAll: () => [], addEventListener() {},
    },
    window: { addEventListener() {} },
    esc: s => String(s ?? '').replace(/[&<>"]/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])),
    console, setTimeout, CSS: { escape: s => s },
  };
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(SRC, 'utf8'), ctx);
  // let/const at the top of the script are not context properties, so state is
  // reached through expressions evaluated inside it.
  const run = code => vm.runInContext(code, ctx);
  run(`
    _rulesFacts = [
      { key: 'counts.CRITICAL', label: 'Critical vulnerabilities', type: 'number' },
      { key: 'kev', label: 'In CISA KEV', type: 'boolean' }];
    _rulesState = { source: 'yaml', dirty: false, body: {
      defaults: { decision: 'allow', on_gate_error: 'deny' },
      rules: [
        { id: 'critical', action: 'deny', when: { 'counts.CRITICAL': '>= 1' }, detail: 'critical vuln' },
        { id: 'actively-exploited', action: 'deny', when: { kev: 'yes' } }],
      exceptions: { deny: ['curl', { pattern: 'cowsay', reason: 'not approved' }], allow: [] } } };
    var _names = _nameEntries(_rulesState.body);
    var _rules = _rulesState.body.rules;`);
  return {
    run,
    html: q => run(`_rulesQuery = ${JSON.stringify(q ?? '')}; _rulesListHtml(_names, _rules)`),
  };
}

const count = (s, re) => (s.match(re) || []).length;

test('both kinds of rule render as cards in one list', () => {
  const { html } = load();
  const h = html();
  assert.equal(count(h, /class="rule-card/g), 4, '2 name rules + 2 scan rules');
  assert.equal(count(h, /data-fold="/g), 4, 'each one can be folded');
});

test('a card key is the target a Proxy verdict links to', () => {
  // ui-proxy builds "rule:<id>" and "name:<package>" from the reasons column;
  // if these drift, clicking a verdict silently lands nowhere.
  const { html } = load();
  const h = html();
  assert.ok(h.includes('data-key="rule:critical"'));
  assert.ok(h.includes('data-key="name:curl"'));
  assert.ok(h.includes('data-key="name:cowsay"'));
});

test('search filters by the name shown on the card', () => {
  const { html } = load();
  const scan = html('crit');
  assert.equal(count(scan, /class="rule-card/g), 1);
  assert.ok(scan.includes('data-key="rule:critical"'));

  const byName = html('cow');
  assert.ok(byName.includes('data-key="name:cowsay"'));
  assert.ok(!byName.includes('rule:critical'), 'non-matching rules are gone');
});

test('a search with no hits says so instead of looking empty', () => {
  const { html } = load();
  assert.match(html('zzz'), /Nothing matches/);
});

test('folding hides the body and keeps the name', () => {
  const { run, html } = load();
  run(`_rulesCollapsed.add('rule:critical')`);
  const h = html();
  assert.equal(count(h, /rule-card[^"]*folded/g), 1, 'only the folded one');
  const folded = h.split('data-key="rule:critical"')[1];
  assert.ok(folded.includes('value="critical"'), 'its name is still readable');
});
