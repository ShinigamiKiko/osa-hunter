'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { getFixed, osvQuery } = require('../lib/shared');
const nativeFetch = global.fetch;
test.afterEach(() => { global.fetch = nativeFetch; });
const range = (introduced, fixed) => ({ type: 'SEMVER', events: [{ introduced }, { fixed }] });
const affected = (name, ranges, ecosystem = 'npm') => ({ package: { name, ecosystem }, ranges });

test('OSV fixes follow the requested Express branch through the query client', async () => {
  const record = { id: 'GHSA-qw6h-vgh9-j6wx', affected: [
    affected('express', [range('0', '4.20.0')]),
    affected('express', [range('5.0.0-alpha.1', '5.0.0')]),
  ] };
  global.fetch = async () => new Response(JSON.stringify({ vulns: [record] }));
  assert.equal((await osvQuery('express', 'npm', '5.0.0-beta.3'))[0]._fix, '5.0.0');
  assert.equal((await osvQuery('express', 'npm', '4.19.0'))[0]._fix, '4.20.0');
});

test('fix selection ignores other packages, ecosystems and Git commit hashes', () => {
  const record = { affected: [
    affected('different', [range('0', '1.2.0')]),
    affected('target', [range('0', '1.3.0')], 'PyPI'),
    affected('target', [{ type: 'GIT', events: [{ introduced: '0' }, { fixed: 'abcdef' }] }, range('0', '9.9.0')]),
  ] };
  assert.equal(getFixed(record, { name: 'target', ecosystem: 'npm', version: '9.8.0' }), '9.9.0');
});

test('multiple intervals, prereleases and v-prefixed versions choose their own fix', () => {
  const record = { affected: [affected('pkg', [{ type: 'SEMVER', events: [
    { introduced: '0' }, { fixed: '1.2.0' }, { introduced: '2.0.0-beta.1' }, { fixed: '2.0.0' },
  ] }])] };
  assert.equal(getFixed(record, { name: 'pkg', ecosystem: 'npm', version: 'v1.1.0' }), '1.2.0');
  assert.equal(getFixed(record, { name: 'pkg', ecosystem: 'npm', version: '2.0.0-beta.2' }), '2.0.0');
  assert.equal(getFixed(record, { name: 'pkg', ecosystem: 'npm', version: '1.5.0' }), null);
  assert.equal(getFixed(record, { name: 'pkg', ecosystem: 'npm', version: '2.0.0' }), null);
});

test('an ambiguous fix is omitted rather than chosen from an unrelated branch', () => {
  const record = { affected: [affected('pkg', [range('0', '1.2.0'), range('2.0.0', '2.1.0')])] };
  assert.equal(getFixed(record, { name: 'pkg', ecosystem: 'npm' }), null);
  assert.equal(getFixed(record, { name: 'pkg', ecosystem: 'npm', version: 'not-semver' }), null);
  assert.equal(getFixed({ affected: [affected('pkg', [range('0', '1.2.0')])] }), '1.2.0');
});

test('native package normalization and unique ecosystem fixes remain supported', () => {
  const record = { affected: [affected('Some_Pkg', [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.2' }] }], 'PyPI')] };
  assert.equal(getFixed(record, { name: 'some-pkg', ecosystem: 'PyPI', version: '1.1' }), '1.2');
});

test('ecosystem ranges order dotted releases and pre-release bounds per branch', () => {
  const eco = (introduced, fixed) => ({ type: 'ECOSYSTEM', events: [{ introduced }, { fixed }] });
  // Django-style advisory: one interval per supported branch, bounds at a1.
  const django = { affected: [
    affected('django', [eco('6.0a1', '6.0.2')], 'PyPI'),
    affected('django', [eco('5.2a1', '5.2.11')], 'PyPI'),
    affected('django', [eco('4.2a1', '4.2.28')], 'PyPI'),
  ] };
  assert.equal(getFixed(django, { name: 'django', ecosystem: 'PyPI', version: '4.2.0' }), '4.2.28');
  assert.equal(getFixed(django, { name: 'django', ecosystem: 'PyPI', version: '5.2' }), '5.2.11');
  assert.equal(getFixed(django, { name: 'django', ecosystem: 'PyPI', version: '5.1.3' }), null);
  // Maven four-part versions compare numerically, not as text.
  const jackson = { affected: [affected('jd', [eco('2.9.0', '2.9.10.4'), eco('2.10.0', '2.10.3')], 'Maven')] };
  assert.equal(getFixed(jackson, { name: 'jd', ecosystem: 'Maven', version: '2.9.8' }), '2.9.10.4');
  assert.equal(getFixed(jackson, { name: 'jd', ecosystem: 'Maven', version: '2.10.1' }), '2.10.3');
});

test('overlapping intervals take the fix that leaves all of them; qualifiers stay unordered', () => {
  const eco = (introduced, fixed) => ({ type: 'ECOSYSTEM', events: [{ introduced }, { fixed }] });
  const overlap = { affected: [affected('pkg', [eco('0', '1.5'), eco('1.0', '2.0')], 'PyPI')] };
  assert.equal(getFixed(overlap, { name: 'pkg', ecosystem: 'PyPI', version: '1.2' }), '2.0');
  const debian = { affected: [affected('openssl', [eco('0', '3.0.11-1~deb12u2'), eco('0', '1.1.1w-0+deb11u1')], 'Debian')] };
  assert.equal(getFixed(debian, { name: 'openssl', ecosystem: 'Debian', version: '3.0.9-1' }), null);
  const single = { affected: [affected('openssl', [eco('0', '3.0.11-1~deb12u2')], 'Debian')] };
  assert.equal(getFixed(single, { name: 'openssl', ecosystem: 'Debian', version: '3.0.9-1' }), '3.0.11-1~deb12u2');
});
