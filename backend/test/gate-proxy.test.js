'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { PassThrough } = require('node:stream');

process.env.OSA_NEXUS_REPOSITORIES = JSON.stringify({
  npm: 'npm', pypi: 'PyPI', go: 'Go', composer: 'Packagist',
  maven: 'Maven', nuget: 'NuGet', cargo: 'crates.io', gems: 'RubyGems',
  apk: 'Alpine:v3.20', deb: 'Debian:12', ubuntu: 'Ubuntu:22.04', ubuntu24: 'Ubuntu:24.04',
  centos: 'CentOS:9', rhel: 'Red Hat:9', rpm: 'Rocky Linux:9',
});
const { parseArtifact } = require('../lib/routes/gate-proxy.route');
const cargo = require('../lib/gate/proxy/cargo');

test('parses scoped npm artifacts', () => {
  assert.deepEqual(parseArtifact('npm', '@scope/pkg/-/pkg-1.2.3.tgz'), {
    ecosystem: 'npm', name: '@scope/pkg', version: '1.2.3',
  });
});

test('parses PyPI wheels and Go module zips', () => {
  assert.deepEqual(parseArtifact('pypi', 'packages/requests-2.31.0-py3-none-any.whl'), {
    ecosystem: 'PyPI', name: 'requests', version: '2.31.0',
  });
  assert.deepEqual(parseArtifact('go', 'github.com/acme/tool/@v/v1.4.0.zip'), {
    ecosystem: 'Go', name: 'github.com/acme/tool', version: 'v1.4.0',
  });
});

test('parses Composer, Maven, NuGet, Cargo and RubyGems artifacts', () => {
  // Composer downloads go through a gate-generated dist path (see composer.js).
  assert.deepEqual(parseArtifact('composer', 'dist/vendor/package/1.2.3.zip'), {
    ecosystem: 'Packagist', name: 'vendor/package', version: '1.2.3',
  });
  assert.deepEqual(parseArtifact('maven', 'org/acme/tool/1.2.3/tool-1.2.3.jar'), {
    ecosystem: 'Maven', name: 'org.acme:tool', version: '1.2.3',
  });
  assert.deepEqual(parseArtifact('nuget', 'newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg'), {
    ecosystem: 'NuGet', name: 'newtonsoft.json', version: '13.0.3',
  });
  assert.deepEqual(parseArtifact('cargo', 'serde/1.0.0/download'), {
    ecosystem: 'crates.io', name: 'serde', version: '1.0.0',
  });
  assert.deepEqual(parseArtifact('gems', 'rails-7.1.0.gem'), {
    ecosystem: 'RubyGems', name: 'rails', version: '7.1.0',
  });
});

test('parses Alpine, Debian and RPM artifacts', () => {
  assert.deepEqual(parseArtifact('apk', 'main/x86_64/libfoo-1.2.3-r0.apk'), {
    ecosystem: 'Alpine:v3.20', name: 'libfoo', version: '1.2.3-r0',
  });
  assert.deepEqual(parseArtifact('deb', 'pool/main/n/nginx/nginx_1.18.0-6_amd64.deb'), {
    ecosystem: 'Debian:12', name: 'nginx', version: '1.18.0-6',
  });
  assert.deepEqual(parseArtifact('ubuntu', 'pool/main/n/nginx/nginx_1.18.0-6_amd64.deb'), {
    ecosystem: 'Ubuntu:22.04', name: 'nginx', version: '1.18.0-6',
  });
  assert.deepEqual(parseArtifact('ubuntu24', 'pool/main/c/curl/curl_8.5.0-2ubuntu10.6_amd64.deb'), {
    ecosystem: 'Ubuntu:24.04', name: 'curl', version: '8.5.0-2ubuntu10.6',
  });
  assert.deepEqual(parseArtifact('centos', 'Packages/c/curl-8.0.1-12.el9.x86_64.rpm'), {
    ecosystem: 'CentOS:9', name: 'curl', version: '8.0.1-12.el9',
  });
  assert.deepEqual(parseArtifact('rhel', 'Packages/c/curl-8.0.1-12.el9.x86_64.rpm'), {
    ecosystem: 'Red Hat:9', name: 'curl', version: '8.0.1-12.el9',
  });
  assert.deepEqual(parseArtifact('rpm', 'Packages/o/openssl-3.0.7-18.el9_2.x86_64.rpm'), {
    ecosystem: 'Rocky Linux:9', name: 'openssl', version: '3.0.7-18.el9_2',
  });
});

test('Cargo download adapter maps registry requests to static crate archives', async () => {
  const server = http.createServer((req, res) => {
    assert.equal(req.url, '/serde/serde-1.0.0.crate');
    res.end('crate-bytes');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const output = new PassThrough();
  const chunks = [];
  output.on('data', chunk => chunks.push(chunk));
  const response = output;
  response.status = code => { response.code = code; };
  response.setHeader = () => {};
  try {
    await cargo.download(
      { method: 'GET' }, response,
      { upstream: `http://127.0.0.1:${port}`, downloadUpstream: `http://127.0.0.1:${port}` },
      'cargo', 'api/v1/crates/serde/1.0.0/download'
    );
    await new Promise(resolve => output.on('end', resolve));
    assert.equal(response.code, 200);
    assert.equal(Buffer.concat(chunks).toString(), 'crate-bytes');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('Cargo sparse config redirects downloads back through OSA', async () => {
  const server = http.createServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ dl: 'https://static.crates.io/crates', api: 'https://crates.io' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const body = {};
  const response = {
    status: code => { response.code = code; },
    setHeader: () => {},
    json: value => Object.assign(body, value),
    end: () => {},
  };
  try {
    await cargo.serveIndex(
      { protocol: 'http', get: () => 'localhost:3001', baseUrl: '/api/gate' },
      response,
      { upstream: `http://127.0.0.1:${port}`, direct: true },
      'cargo', 'config.json'
    );
    assert.equal(body.dl, 'http://localhost:3001/api/gate/cargo/download');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
