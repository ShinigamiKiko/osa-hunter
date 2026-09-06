'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveDecision, gateDecide } = require('../lib/gate/decide');

const policy = (deny = [], allow = []) => ({ deny, allow, rules: [], default: 'allow' });
const decide = (deny, pkg) => resolveDecision(policy(deny), [], pkg);

const lodash = { ecosystem: 'npm', name: 'lodash', version: '4.17.21' };

test('a bare name blocks the package in every ecosystem', () => {
  // Supplier-agnostic: operators should not need to know where a package
  // comes from to ban it.
  for (const ecosystem of ['npm', 'PyPI', 'Debian:12', 'Ubuntu:24.04', 'Alpine:v3.20', 'CentOS:9']) {
    const r = decide(['curl'], { ecosystem, name: 'curl', version: '1.0' });
    assert.equal(r.decision, 'deny', `curl should be denied in ${ecosystem}`);
    assert.equal(r.reasons[0].rule, 'denylist');
  }
});

test('entries may be scoped by ecosystem or pinned to a version', () => {
  assert.equal(decide(['npm/lodash'], lodash).decision, 'deny');
  assert.equal(decide(['npm/lodash@4.17.21'], lodash).decision, 'deny');
  // A different version, or the same name under another ecosystem, must pass.
  assert.equal(decide(['npm/lodash@4.17.20'], lodash).decision, 'allow');
  assert.equal(decide(['PyPI/lodash'], lodash).decision, 'allow');
});

test('globs match names, scopes and ecosystems', () => {
  assert.equal(decide(['lod*'], lodash).decision, 'deny');
  assert.equal(decide(['*/lodash'], lodash).decision, 'deny');
  assert.equal(decide(['npm/@evil/*'], { ecosystem: 'npm', name: '@evil/pkg', version: '1.0.0' }).decision, 'deny');
  assert.equal(decide(['npm/@evil/*'], lodash).decision, 'allow');
});

test('unlisted packages are not blocked', () => {
  assert.equal(decide(['left-pad', 'event-stream'], lodash).decision, 'allow');
  assert.equal(decide([], lodash).decision, 'allow');
});

test('allowlist short-circuits before rules', () => {
  const deny = [{ rule: 'critical', action: 'deny', detail: 'critical vuln' }];
  const blocked = resolveDecision(policy(), deny, lodash);
  assert.equal(blocked.decision, 'deny');

  const exempted = resolveDecision(policy([], ['npm/lodash']), deny, lodash);
  assert.equal(exempted.decision, 'allow');
  assert.equal(exempted.reasons[0].rule, 'allowlist');
});

test('denylist is a hard block decided before any scan', async () => {
  // No network or database is touched: a denied package must never depend on
  // OSV being reachable, or on the ecosystem existing in OSV at all.
  const verdict = await gateDecide(
    { name: 'curl', ecosystem: 'Ubuntu:26.04', version: '8.18.0-1ubuntu2.4' },
    { ...policy(['curl']), version: 'test' });

  assert.equal(verdict.decision, 'deny');
  assert.equal(verdict.reasons[0].rule, 'denylist');
  assert.match(verdict.reasons[0].detail, /blocked by name: curl/);
  assert.equal(verdict.findings.total, 0, 'no scan should have run');
});
