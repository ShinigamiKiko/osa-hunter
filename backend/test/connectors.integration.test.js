'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const enabled = process.env.OSA_LIVE_CONNECTORS === 'true';
const base = (process.env.OSA_GATE_URL || 'http://localhost:3001/api/gate').replace(/\/$/, '');
const timeoutMs = Number(process.env.OSA_CONNECTOR_TIMEOUT_MS || 30000);

const cases = [
  { name: 'npm metadata', method: 'GET', path: 'npm-proxy/lodash' },
  { name: 'npm archive', method: 'HEAD', path: 'npm-proxy/lodash/-/lodash-4.17.21.tgz' },
  { name: 'PyPI metadata', method: 'GET', path: 'pypi-proxy/simple/requests/' },
  { name: 'PyPI archive', method: 'HEAD', path: 'pypi-proxy/packages/requests-2.31.0-py3-none-any.whl' },
  { name: 'Go metadata', method: 'GET', path: 'go-proxy/github.com/stretchr/testify/@v/list' },
  { name: 'Go archive', method: 'HEAD', path: 'go-proxy/github.com/stretchr/testify/@v/v1.8.4.zip' },
  { name: 'Composer metadata', method: 'GET', path: 'composer/packages.json' },
  { name: 'Maven metadata', method: 'GET', path: 'maven-public/org/apache/commons/commons-lang3/maven-metadata.xml' },
  { name: 'Maven archive', method: 'HEAD', path: 'maven-public/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar' },
  { name: 'NuGet metadata', method: 'GET', path: 'nuget-proxy/newtonsoft.json/index.json' },
  { name: 'NuGet archive', method: 'HEAD', path: 'nuget-proxy/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg' },
  { name: 'Cargo sparse config', method: 'GET', path: 'cargo-proxy/config.json' },
  { name: 'Cargo archive', method: 'HEAD', path: 'cargo-proxy/api/v1/crates/serde/1.0.0/download' },
  { name: 'RubyGems metadata', method: 'HEAD', path: 'rubygems-proxy/versions' },
  { name: 'RubyGems archive', method: 'HEAD', path: 'rubygems-proxy/gems/rake-13.2.1.gem' },
  { name: 'Alpine metadata', method: 'HEAD', path: 'alpine-v320/main/x86_64/APKINDEX.tar.gz' },
  { name: 'Alpine archive', method: 'HEAD', path: 'alpine-v320/main/x86_64/busybox-1.36.1-r31.apk' },
  { name: 'Debian metadata', method: 'GET', path: 'debian-bookworm/dists/bookworm/InRelease' },
  { name: 'Debian archive', method: 'HEAD', path: 'debian-bookworm/pool/main/c/curl/curl_7.88.1-10+deb12u8_amd64.deb' },
  { name: 'Ubuntu 22.04 metadata', method: 'GET', path: 'ubuntu-2204/dists/jammy/InRelease' },
  { name: 'Ubuntu 24.04 metadata', method: 'GET', path: 'ubuntu-2404/dists/noble/InRelease' },
  { name: 'Ubuntu 24.04 archive', method: 'HEAD', path: 'ubuntu-2404/pool/main/c/curl/curl_8.5.0-2ubuntu10.6_amd64.deb' },
  { name: 'CentOS Stream metadata', method: 'HEAD', path: 'centos-stream9-baseos/repodata/repomd.xml' },
  { name: 'CentOS Stream archive', method: 'HEAD', path: 'centos-stream9-baseos/Packages/c/curl-8.0.1-12.el9.x86_64.rpm' },
  { name: 'RHEL metadata without configured subscription mirror', method: 'HEAD', path: 'rhel9-baseos/repodata/repomd.xml', expectedStatus: 404 },
  { name: 'Rocky metadata', method: 'HEAD', path: 'rocky9-baseos/repodata/repomd.xml', expectedStatus: 502 },
  { name: 'Rocky archive', method: 'HEAD', path: 'rocky9-baseos/Packages/c/curl-8.0.1-12.el9_5.x86_64.rpm', expectedStatus: 403 },
];

async function request(item) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(`${base}/${item.path}`, {
      method: item.method,
      redirect: 'follow',
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

for (const item of cases) {
  test(item.name, { skip: !enabled }, async () => {
    const response = await request(item);
    if (item.expectedStatus) {
      assert.equal(response.status, item.expectedStatus, `${item.name}: unexpected connector status`);
      return;
    }
    assert.notEqual(response.status, 404, `${item.name}: connector path returned 404`);
    assert.ok(response.status < 500, `${item.name}: upstream/proxy failure HTTP ${response.status}`);
    if (item.method === 'GET') {
      const body = await response.text();
      assert.ok(body.length > 0, `${item.name}: empty metadata response`);
    }
  });
}
