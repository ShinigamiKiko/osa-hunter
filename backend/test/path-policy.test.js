'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { metadataAllowed, ARTIFACT_EXT } = require('../lib/gate/proxy/path-policy');

// The gate's open endpoint proxies ONLY known package/metadata paths. Each case
// below is a path a real client actually requests (allowed) or an attempt to
// reach something else through the gate (rejected).
function check(ecosystem, cases) {
  for (const [path, expected] of cases) {
    assert.equal(metadataAllowed(ecosystem, path), expected,
      `${ecosystem} ${path} should be ${expected ? 'allowed' : 'rejected'}`);
  }
}

test('apt metadata: every index family apt fetches is allowed', () => {
  // Regression: cnf/dep11/i18n were missing, so `apt update` aborted the whole
  // index build on a 404 and no package was installable.
  check('Ubuntu:24.04', [
    ['dists/noble/InRelease', true],
    ['dists/noble/Release', true],
    ['dists/noble/Release.gpg', true],
    ['dists/noble/main/binary-amd64/Packages', true],
    ['dists/noble/main/binary-amd64/Packages.xz', true],
    ['dists/noble/main/binary-amd64/by-hash/SHA256/deadbeef', true],
    ['dists/noble/main/cnf/Commands-amd64', true],
    ['dists/noble/main/cnf/Commands-amd64.xz', true],
    ['dists/noble/main/cnf/by-hash/SHA256/abc123', true],
    ['dists/noble/main/dep11/Components-amd64.yml.gz', true],
    ['dists/noble/main/dep11/icons-64x64.tar.gz', true],
    ['dists/noble/main/i18n/Translation-en.xz', true],
  ]);
  check('Debian:12', [['dists/bookworm/InRelease', true]]);
});

test('apt metadata: anything outside the index families is rejected', () => {
  check('Ubuntu:24.04', [
    ['dists/noble/../../etc/passwd', false],
    ['dists/noble/main/evil.sh', false],
    ['dists/noble/main/cnf/../../../secret', false],
    ['etc/passwd', false],
    ['pool/main/c/curl/curl_8.5.0_amd64.deb', false], // an artifact, not metadata
  ]);
});

test('rpm repodata: every compression dnf uses is allowed', () => {
  // Regression: only gz/xz/bz2 were allowed, so CentOS Stream 9 (which ships
  // zstd) failed `dnf makecache` and nothing could be installed.
  check('CentOS:9', [
    ['repodata/repomd.xml', true],
    ['repodata/repomd.xml.asc', true],
    ['repodata/abc-comps-BaseOS.x86_64.xml.zst', true],
    ['repodata/abc-primary.xml.gz', true],
    ['repodata/abc-primary.xml.zck', true],
    ['repodata/abc-primary.sqlite.bz2', true],
    ['repodata/abc-modules.yaml.gz', true],
  ]);
  check('Rocky Linux:9', [['repodata/repomd.xml', true]]);
});

test('rpm repodata: nesting, traversal and stray files are rejected', () => {
  check('CentOS:9', [
    ['repodata/../../etc/passwd', false],
    ['repodata/evil.sh', false],
    ['repodata/sub/dir/primary.xml', false],
    ['Packages/c/curl-7.76.1-31.el9.x86_64.rpm', false], // artifact, not metadata
  ]);
});

test('alpine: only APKINDEX is metadata', () => {
  check('Alpine:v3.20', [
    ['main/x86_64/APKINDEX.tar.gz', true],
    ['main/x86_64/curl-8.7.1-r0.apk', false],
    ['main/x86_64/../../etc/passwd', false],
  ]);
});

test('unknown ecosystem allows nothing', () => {
  assert.equal(metadataAllowed('Nope', 'dists/noble/InRelease'), false);
});

test('ARTIFACT_EXT covers every packaged format the gate must evaluate', () => {
  for (const f of ['a.tgz', 'a.whl', 'a.tar.gz', 'a.jar', 'a.deb', 'a.apk', 'a.rpm',
                   'a.nupkg', 'a.crate', 'a.gem', 'a.zip']) {
    assert.ok(ARTIFACT_EXT.test(f), `${f} should be recognised as an artifact`);
  }
  assert.ok(!ARTIFACT_EXT.test('Packages.xz'), 'index files are not artifacts');
});
