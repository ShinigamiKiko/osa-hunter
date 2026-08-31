'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { compilePolicy, evalRules } = require('../lib/gate/policy');

// Test the policy ENGINE against a self-contained policy, independent of the
// shipped policy.yaml (which is user-editable config).
const policy = compilePolicy({
  version: 1,
  defaults: { decision: 'allow', on_gate_error: 'deny' },
  rules: [
    { id: 'toxic',        action: 'deny', when: { 'toxic.found': true } },
    { id: 'kev',          action: 'deny', when: { kev: 'yes' } },
    { id: 'critical',     action: 'deny', when: { 'counts.CRITICAL': '>= 1' } },
    { id: 'cve-2026',     action: 'deny', when: { cves: 'CVE-2026-*' } },
    { id: 'many-cves',    action: 'deny', when: { cveCount: '> 5' } },
    { id: 'high-hot',     action: 'deny', when: { all: [{ 'counts.HIGH': '>= 1' }, { epssMax: '>= 0.5' }] } },
  ],
});

function facts(overrides = {}) {
  return {
    toxic: { found: false },
    counts: { CRITICAL: 0, HIGH: 0 }, kev: 0, epssMax: 0, pocCount: 0,
    cves: [], cveCount: 0,
    ...overrides,
  };
}

const fired = (f) => evalRules(policy, f).map(h => h.rule);

test('toxic and critical are denied', () => {
  assert.ok(fired(facts({ toxic: { found: true } })).includes('toxic'));
  assert.ok(fired(facts({ counts: { CRITICAL: 1, HIGH: 0 } })).includes('critical'));
});

test('kev matches with yes/no boolean semantics', () => {
  assert.ok(fired(facts({ kev: 2 })).includes('kev'));
  assert.ok(!fired(facts({ kev: 0 })).includes('kev'));
});

test('cve glob and cve count operators work', () => {
  assert.ok(fired(facts({ cves: ['CVE-2026-25645'] })).includes('cve-2026'));
  assert.ok(!fired(facts({ cves: ['CVE-2021-1'] })).includes('cve-2026'));
  assert.ok(fired(facts({ cves: Array(6).fill('CVE-2020-1'), cveCount: 6 })).includes('many-cves'));
});

test('all: combines high severity with high epss', () => {
  assert.ok(fired(facts({ counts: { CRITICAL: 0, HIGH: 1 }, epssMax: 0.75 })).includes('high-hot'));
  assert.ok(!fired(facts({ counts: { CRITICAL: 0, HIGH: 1 }, epssMax: 0.1 })).includes('high-hot'));
});
