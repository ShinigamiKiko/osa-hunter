'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeBody, compileBody, toYaml, fromYaml } = require('../lib/gate/policyStore');
const { evalRules } = require('../lib/gate/policy');
const { resolveDecision } = require('../lib/gate/decide');

const base = {
  defaults: { decision: 'allow', on_gate_error: 'deny' },
  rules: [{ id: 'critical', action: 'deny', when: { 'counts.CRITICAL': '>= 1' }, detail: 'critical vuln' }],
  exceptions: { allow: [], deny: ['curl'] },
};

const facts = (over = {}) => ({
  ecosystem: 'npm', name: 'lodash', version: '1.0.0',
  total: 0, counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
  topSeverity: 'NONE', kev: 0, epssMax: 0, pocCount: 0, cveCount: 0,
  toxic: { found: false }, ...over,
});

test('a policy stored in the database enforces exactly like the YAML file', () => {
  // The UI writes JSON, the file writes YAML - both must compile to the same
  // decision, or the editor would quietly change behaviour.
  const compiled = compileBody(base, 7);
  const hit = evalRules(compiled, facts({ counts: { CRITICAL: 2, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 } }));
  assert.equal(resolveDecision(compiled, hit, { ecosystem: 'npm', name: 'x', version: '1' }).decision, 'deny');
  assert.equal(resolveDecision(compiled, [], { ecosystem: 'npm', name: 'x', version: '1' }).decision, 'allow');
  assert.equal(resolveDecision(compiled, [], { ecosystem: 'Ubuntu:26.04', name: 'curl', version: '8' }).decision, 'deny');
});

test('the version counter feeds the policy version, so a save busts the cache', () => {
  // cachedGate keys verdicts by policy.version; if two saves shared one,
  // a saved policy would keep serving the previous verdicts.
  assert.equal(compileBody(base, 7).version, 'db:7');
  assert.notEqual(compileBody(base, 7).version, compileBody(base, 8).version);
});

test('a disabled rule is kept in the body but never compiled', () => {
  const body = normalizeBody({ ...base, rules: [{ ...base.rules[0], enabled: false }] });
  assert.equal(body.rules[0].enabled, false, 'the UI still needs to show it');
  assert.equal(compileBody(body, 1).rules.length, 0, 'but it must not fire');
});

test('a disabled name rule is kept in the body but stops blocking', () => {
  // Switching curl off in the UI must actually let curl through, while the
  // entry stays visible so it can be switched back on.
  const body = normalizeBody({
    ...base,
    exceptions: { allow: [], deny: [{ pattern: 'curl', enabled: false }, 'cowsay'] },
  });
  assert.deepEqual(body.exceptions.deny, [{ pattern: 'curl', enabled: false }, 'cowsay']);

  const compiled = compileBody(body, 1);
  const pkg = n => ({ ecosystem: 'Ubuntu:26.04', name: n, version: '1' });
  assert.equal(resolveDecision(compiled, [], pkg('curl')).decision, 'allow');
  assert.equal(resolveDecision(compiled, [], pkg('cowsay')).decision, 'deny');
});

test('an enabled name rule stays a plain string, so exported YAML is unchanged', () => {
  const body = normalizeBody({ ...base, exceptions: { allow: [], deny: [{ pattern: 'curl', enabled: true }] } });
  assert.deepEqual(body.exceptions.deny, ['curl']);
});

test('a name rule can carry its own message, like a scan rule does', () => {
  // This text is what the blocked developer actually reads, so it has to reach
  // the verdict - not just sit in the policy.
  const body = normalizeBody({
    ...base,
    exceptions: { allow: [], deny: [{ pattern: 'curl', reason: 'use the platform HTTP client' }, 'cowsay'] },
  });
  const compiled = compileBody(body, 1);
  const detail = n => resolveDecision(compiled, [], { ecosystem: 'Ubuntu:26.04', name: n, version: '1' }).reasons[0].detail;
  assert.equal(detail('curl'), 'use the platform HTTP client');
  assert.equal(detail('cowsay'), 'blocked by name: cowsay', 'no message means the default one');
});

test('a disabled name rule cannot leak its message into a verdict', () => {
  const compiled = compileBody(normalizeBody({
    ...base,
    exceptions: { allow: [], deny: [{ pattern: 'curl', reason: 'banned internally', enabled: false }] },
  }), 1);
  const r = resolveDecision(compiled, [], { ecosystem: 'npm', name: 'curl', version: '1' });
  assert.equal(r.decision, 'allow');
});

test('invalid policies are rejected before they can be stored', () => {
  const bad = [
    [{ ...base, rules: [{ action: 'deny', when: {} }] }, /id/i],
    [{ ...base, rules: [{ id: 'x', action: 'nuke', when: {} }] }, /action/i],
    [{ ...base, rules: [{ id: 'x', action: 'deny' }] }, /when/i],
    [{ ...base, rules: [base.rules[0], base.rules[0]] }, /duplicate/i],
    [{ ...base, defaults: { decision: 'maybe' } }, /decision/i],
    [{ ...base, defaults: { decision: 'allow', on_gate_error: 'warn' } }, /on_gate_error/i],
    ['not an object', /object/i],
  ];
  for (const [input, expected] of bad) {
    assert.throws(() => normalizeBody(input), expected, `should reject: ${JSON.stringify(input)}`);
  }
});

test('YAML export and import round-trip without changing the policy', () => {
  // Export must stay pasteable into policy.yaml, and re-importing it must not
  // drift - otherwise git and the database slowly disagree.
  const once = normalizeBody(base);
  const twice = fromYaml(toYaml(once));
  assert.deepEqual(twice, once);
});

test('name lists survive normalisation with globs and scoping intact', () => {
  const body = normalizeBody({
    ...base,
    exceptions: { deny: [' npm/left-pad@1.3.0 ', 'crossenv*', ''], allow: ['npm/lodash'] },
  });
  assert.deepEqual(body.exceptions.deny, ['npm/left-pad@1.3.0', 'crossenv*']);
  const compiled = compileBody(body, 1);
  assert.equal(resolveDecision(compiled, [], { ecosystem: 'npm', name: 'crossenv-evil', version: '1' }).decision, 'deny');
  assert.equal(resolveDecision(compiled, [], { ecosystem: 'npm', name: 'left-pad', version: '1.3.0' }).decision, 'deny');
  assert.equal(resolveDecision(compiled, [], { ecosystem: 'npm', name: 'left-pad', version: '1.2.0' }).decision, 'allow');
});

test('a policy is data, not code: rules cannot smuggle executable input', () => {
  // Rules are interpreted by policy.js; nothing is eval'd. A JS-looking value
  // must be treated as a literal and simply not match.
  const compiled = compileBody(normalizeBody({
    ...base,
    rules: [{ id: 'x', action: 'deny', when: { name: 'process.exit(1)' } }],
  }), 1);
  assert.deepEqual(evalRules(compiled, facts()), []);
});
