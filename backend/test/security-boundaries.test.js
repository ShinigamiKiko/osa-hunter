'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const { performance } = require('node:perf_hooks');

process.env.OSA_NEXUS_REPOSITORIES = JSON.stringify({ npm: 'npm', go: 'Go', gems: 'RubyGems', cargo: 'crates.io' });
const dbPath = require.resolve('../lib/auth/db');
require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true,
  exports: { getPool: () => ({ query: async () => ({ rows: [] }) }) } };
const { compilePolicy } = require('../lib/gate/policy');
const { resolveDecision } = require('../lib/gate/decide');
const policy = compilePolicy({ exceptions: { deny: [
  'npm/lodash@4.17.20', 'Go/github.com/Azure/go-autorest@v1.0.0-RC1',
  'RubyGems/nokogiri@1.18.2', 'RubyGems/foo@2', 'RubyGems/foo-2@1.0',
] } });
let checked = [];
const servicePath = require.resolve('../lib/gate/service');
require.cache[servicePath] = { id: servicePath, filename: servicePath, loaded: true,
  exports: { cachedGate: async artifact => { checked.push(artifact); return resolveDecision(policy, [], artifact); } } };
const { router, parseArtifact } = require('../lib/routes/gate-proxy.route');
const nativeFetch = global.fetch;
const platforms = ['java', 'x86_64-linux-gnu', 'aarch64-linux-musl', 'arm64-darwin-23',
  'x86_64-darwin-23.0', 'x64-mingw-ucrt', 'x86-mswin32_60', 'armv7-linux',
  'universal-java-1.8', 'x86_64-cygwin', 'powerpc-aix-7', 'wasm32-wasi'];
let gemIndex = { nokogiri: '---\n1.18.2 \n' + platforms.map(p => '1.18.2-' + p + ' \n').join('') };
global.fetch = async url => {
  const marker = String(url).indexOf('/info/');
  if (String(url).endsWith('/gems/ffi-1.0.0.gem')) return new Response('gem');
  if (marker < 0) throw new Error('unexpected upstream request');
  const name = decodeURIComponent(String(url).slice(marker + 6));
  return gemIndex[name] === undefined ? new Response('', { status: 404 }) : new Response(gemIndex[name]);
};
test.after(() => { global.fetch = nativeFetch; });


async function rawRequest(path) {
  const app = express(); app.use('/api/gate', router);
  app.use((error, req, res, next) => res.status(error.status || 500).json({ error: error.message }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  try {
    return await new Promise((resolve, reject) => {
      const req = http.get({ hostname: '127.0.0.1', port: server.address().port, path }, res => {
        res.resume(); res.on('end', () => resolve(res.statusCode));
      });
      req.on('error', reject);
    });
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}

test('gateway rejects normalization aliases before evaluation or forwarding', async () => {
  checked = [];
  for (const prefix of ['%2e', '.', '%2E%2e', '%252e', '%2e%2f', '%5c', '%00', '%0a', '%zz']) {
    assert.equal(await rawRequest(`/api/gate/npm/${prefix}/lodash/-/lodash-4.17.20.tgz`), 400, prefix);
  }
  assert.deepEqual(checked, []);
  assert.equal(await rawRequest('/api/gate/npm/lodash/-/lodash-4.17.20.tgz'), 403);
  assert.deepEqual(checked, [{ ecosystem: 'npm', name: 'lodash', version: '4.17.20' }]);
  assert.deepEqual(parseArtifact('npm', '@scope%2fname/-/name-1.2.3.tgz'),
    { ecosystem: 'npm', name: '@scope/name', version: '1.2.3' });
});

test('Go proxy escapes are decoded before exact policy matching', async () => {
  assert.equal(await rawRequest('/api/gate/go/github.com/!azure/go-autorest/@v/v1.0.0-!r!c1.zip'), 403);
  assert.deepEqual(parseArtifact('go', 'example.org/!user/mod/@v/v2.0.0+incompatible.mod'),
    { ecosystem: 'Go', name: 'example.org/User/mod', version: 'v2.0.0+incompatible' });
  for (const value of ['!Azure', '!!azure', '!azure!', 'Azure']) {
    assert.equal(parseArtifact('go', `github.com/${value}/mod/@v/v1.0.0.zip`), null);
  }
});

test('Ruby platform packages use the canonical version for exact denies', async () => {
  for (const platform of platforms) {
    assert.deepEqual(parseArtifact('gems', `gems/nokogiri-1.18.2-${platform}.gem`),
      { ecosystem: 'RubyGems', name: 'nokogiri', version: '1.18.2' }, platform);
    assert.equal(await rawRequest(`/api/gate/gems/gems/nokogiri-1.18.2-${platform}.gem`), 403);
  }
  assert.deepEqual(parseArtifact('gems', 'gems/foo-2-1.0.pre.rc1.gem'),
    { ecosystem: 'RubyGems', name: 'foo-2', version: '1.0.pre.rc1' });
  for (const file of ['foo-1.0-custom.gem', 'foo-1.0-custom-23.gem']) {
    assert.equal(parseArtifact('gems', 'gems/' + file), null);
    assert.equal(await rawRequest('/api/gate/gems/gems/' + file), 403);
  }
});

test('RubyGems metadata resolves numeric name/platform ambiguity and fails closed on conflicts', async () => {
  const original = gemIndex;
  try {
    gemIndex = { foo: '---\n2-1.0 \n' };
    assert.equal(await rawRequest('/api/gate/gems/gems/foo-2-1.0.gem'), 403);
    assert.deepEqual(checked.at(-1), { ecosystem: 'RubyGems', name: 'foo', version: '2' });
    gemIndex = { 'foo-2': '---\n1.0 \n' };
    assert.equal(await rawRequest('/api/gate/gems/gems/foo-2-1.0.gem'), 403);
    assert.deepEqual(checked.at(-1), { ecosystem: 'RubyGems', name: 'foo-2', version: '1.0' });
    const count = checked.length;
    gemIndex.foo = '---\n2-1.0 \n';
    assert.equal(await rawRequest('/api/gate/gems/gems/foo-2-1.0.gem'), 403);
    assert.equal(checked.length, count, 'ambiguous metadata cannot reach policy evaluation');
  } finally { gemIndex = original; }
});

test('a metadata-confirmed allowed gem still downloads normally', async () => {
  const original = gemIndex;
  try {
    gemIndex = { ffi: '---\n1.0.0 \n' };
    assert.equal(await rawRequest('/api/gate/gems/gems/ffi-1.0.0.gem'), 200);
    assert.deepEqual(checked.at(-1), { ecosystem: 'RubyGems', name: 'ffi', version: '1.0.0' });
  } finally { gemIndex = original; }
});

test('RubyGems metadata failures and oversized responses never allow a guessed identity', async () => {
  const original = global.fetch;
  const count = checked.length;
  try {
    for (const response of [new Response('', { status: 503 }), new Response('x'.repeat(1024 * 1024 + 1))]) {
      global.fetch = async () => response;
      assert.equal(await rawRequest('/api/gate/gems/gems/foo-1.0.gem'), 502);
    }
    assert.equal(checked.length, count);
  } finally { global.fetch = original; }
});

test('Cargo downloads use the same decoded identity that the gate evaluated', async () => {
  const originalFetch = global.fetch;
  const downloaded = [];
  global.fetch = async url => { downloaded.push(String(url)); return new Response('crate'); };
  try {
    assert.equal(await rawRequest('/api/gate/cargo/c0wsay/0%2e1%2e0/download'), 200);
    assert.deepEqual(checked.at(-1), { ecosystem: 'crates.io', name: 'c0wsay', version: '0.1.0' });
    assert.equal(downloaded.length, 1);
    assert.ok(downloaded[0].endsWith('/c0wsay/c0wsay-0.1.0.crate'));
  } finally { global.fetch = originalFetch; }
});

test('Composer rejects long malformed names in bounded time', () => {
  const { isComposerPackageName } = require('../lib/composer/names');
  const start = performance.now();
  for (const input of ['a'.repeat(100000) + '!', 'vendor/' + 'a'.repeat(100000) + '!']) {
    assert.equal(isComposerPackageName(input), false);
  }
  assert.ok(performance.now() - start < 1000);
  for (const name of ['symfony/console', 'Acme/vendor--package', ' vendor.name/package_name ']) {
    assert.equal(isComposerPackageName(name), true, name);
  }
  assert.equal(isComposerPackageName('vendor---name/package'), false);
});

test('policy aliases are bounded before compilation and serialization, including disabled rules', () => {
  const { fromYaml, normalizeBody, compileBody, toYaml } = require('../lib/gate/policyStore');
  let yaml = 'a0: &a0 {kev: yes}\n';
  for (let i = 1; i <= 20; i++) yaml += `a${i}: &a${i} {all: [*a${i - 1}, *a${i - 1}]}\n`;
  for (const disabled of ['', '    enabled: false\n']) {
    const start = performance.now();
    assert.throws(() => fromYaml(yaml + `rules:\n  - id: bomb\n    action: deny\n${disabled}    when: *a20\n`), /limit/);
    assert.ok(performance.now() - start < 1000);
  }
  let condition = { kev: 'yes' };
  for (let i = 0; i < 20; i++) condition = { any: [condition, condition] };
  const body = { rules: [{ id: 'bomb', action: 'deny', enabled: false, when: condition }] };
  for (const fn of [normalizeBody, compilePolicy, compileBody, toYaml]) assert.throws(() => fn(body), /limit/);
  const cycle = {}; cycle.all = [cycle];
  assert.throws(() => normalizeBody({ rules: [{ id: 'cycle', action: 'deny', when: cycle }] }), /cyclic/);
  const valid = fromYaml('rules:\n  - id: small\n    action: deny\n    when: {all: [&one {kev: yes}, *one]}\n');
  assert.equal(compileBody(valid, 1).rules[0].when({ kev: 1 }), true);
  assert.deepEqual(fromYaml(toYaml(valid)), valid);
});
