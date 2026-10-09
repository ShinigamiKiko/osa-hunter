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
