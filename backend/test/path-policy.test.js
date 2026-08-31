'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { ARTIFACT_EXT, metadataAllowed } = require('../lib/gate/proxy/path-policy');
const { allowedDownloadUrl } = require('../lib/gate/proxy/composer');

test('allows package archives but not script-like files', () => {
  assert.ok(ARTIFACT_EXT.test('main/x86_64/libfoo-1.0-r0.apk'));
  assert.ok(ARTIFACT_EXT.test('requests-2.31.0-py3-none-any.whl'));
  assert.equal(ARTIFACT_EXT.test('install.sh'), false);
  assert.equal(ARTIFACT_EXT.test('package.js'), false);
  assert.equal(ARTIFACT_EXT.test('README'), false);
});

test('Debian metadata does not become an arbitrary file proxy', () => {
  assert.ok(metadataAllowed('Debian:12', 'dists/bookworm/Release'));
  assert.ok(metadataAllowed('Debian:12', 'dists/bookworm/main/binary-amd64/Packages.xz'));
  assert.ok(metadataAllowed('Ubuntu:22.04', 'dists/jammy/main/binary-amd64/by-hash/SHA256/abcdef0123456789'));
  assert.ok(metadataAllowed('Debian:12', 'dists/bookworm/Contents-amd64.gz'));
  assert.equal(metadataAllowed('Debian:12', 'dists/bookworm/install.sh'), false);
  assert.equal(metadataAllowed('Debian:12', 'dists/bookworm/main/binary-amd64/script.py'), false);
});

test('Maven and NuGet metadata are restricted to package structures', () => {
  assert.ok(metadataAllowed('Maven', 'org/acme/tool/1.2.3/tool-1.2.3.jar.sha1'));
  assert.ok(metadataAllowed('Maven', 'org/acme/tool/maven-metadata.xml'));
  assert.equal(metadataAllowed('Maven', 'scripts/install.sh.asc'), false);
  assert.ok(metadataAllowed('NuGet', 'newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nuspec'));
  assert.equal(metadataAllowed('NuGet', 'scripts/install.sh.nuspec'), false);
});

test('Composer dist URLs require trusted HTTPS hosts', () => {
  const cfg = { upstream: 'https://repo.packagist.org' };
  assert.equal(allowedDownloadUrl('https://api.github.com/repos/a/b/zipball/v1', cfg), true);
  assert.equal(allowedDownloadUrl('http://github.com/a/b.zip', cfg), false);
  assert.equal(allowedDownloadUrl('https://localhost/internal.zip', cfg), false);
  assert.equal(allowedDownloadUrl('https://example.com/file.zip', cfg), false);
});
