'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

// parseArtifact resolves against this map, so it must be set before requiring.
process.env.OSA_NEXUS_REPOSITORIES = JSON.stringify({
  npm: 'npm',
  pypi: 'PyPI',
  go: 'Go',
  maven: 'Maven',
  nuget: 'NuGet',
  cargo: 'crates.io',
  gems: 'RubyGems',
  composer: 'Packagist',
  deb: { ecosystem: 'Debian:12' },
  ubuntu: { ecosystem: 'Ubuntu:24.04' },
  alpine: { ecosystem: 'Alpine:v3.20' },
  centos: { ecosystem: 'CentOS:9' },
});

const { parseArtifact } = require('../lib/routes/gate-proxy.route');
const { osvEcosystem } = require('../lib/gate/decide');

// A wrong name or version means the gate scans the wrong package - so every
// ecosystem's real-world path layout is pinned here.
test('package names and versions are parsed per ecosystem', () => {
  const cases = [
    ['npm',      '@scope/pkg/-/pkg-1.2.3.tgz',                       { ecosystem: 'npm', name: '@scope/pkg', version: '1.2.3' }],
    ['npm',      'lodash/-/lodash-4.17.21.tgz',                       { ecosystem: 'npm', name: 'lodash', version: '4.17.21' }],
    ['pypi',     'packages/requests/2.31.0/requests-2.31.0-py3-none-any.whl',
                                                                      { ecosystem: 'PyPI', name: 'requests', version: '2.31.0' }],
    ['go',       'github.com/acme/tool/@v/v1.4.0.zip',                { ecosystem: 'Go', name: 'github.com/acme/tool', version: 'v1.4.0' }],
    ['nuget',    'newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg',
                                                                      { ecosystem: 'NuGet', name: 'newtonsoft.json', version: '13.0.3' }],
    ['cargo',    'serde/1.0.100/download',                            { ecosystem: 'crates.io', name: 'serde', version: '1.0.100' }],
    ['gems',     'gems/rails-7.1.0.gem',                              { ecosystem: 'RubyGems', name: 'rails', version: '7.1.0' }],
    ['composer', 'dist/monolog/monolog/3.10.0.zip',                   { ecosystem: 'Packagist', name: 'monolog/monolog', version: '3.10.0' }],
    // OS packages: name may contain '-', the version is the trailing field(s).
    ['deb',      'pool/main/c/curl/curl_7.88.1-10+deb12u15_amd64.deb', { ecosystem: 'Debian:12', name: 'curl', version: '7.88.1-10+deb12u15' }],
    ['alpine',   'main/x86_64/curl-8.7.1-r0.apk',                     { ecosystem: 'Alpine:v3.20', name: 'curl', version: '8.7.1-r0' }],
    ['centos',   'Packages/p/perl-Pod-Simple-3.42-4.el9.noarch.rpm',  { ecosystem: 'CentOS:9', name: 'perl-Pod-Simple', version: '3.42-4.el9' }],
  ];
  for (const [repo, path, expected] of cases) {
    assert.deepEqual(parseArtifact(repo, path), expected, `${repo}: ${path}`);
  }
});

test('maven coordinates use group.with.dots:artifact', () => {
  // Regression: the group was joined with ':' ("org:apache:...:log4j-core"),
  // which OSV never matches - so vulnerable jars (log4j) sailed through.
  assert.deepEqual(
    parseArtifact('maven', 'org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar'),
    { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1' });
});

test('unparseable and unknown-repo paths yield no artifact', () => {
  assert.equal(parseArtifact('npm', 'not/a/tarball.txt'), null);
  assert.equal(parseArtifact('deb', 'pool/main/c/curl/curl.deb'), null); // no version field
  assert.equal(parseArtifact('does-not-exist', 'lodash/-/lodash-4.17.21.tgz'), null);
});

test('ecosystems map to names OSV actually accepts', () => {
  // Regression: 'CentOS' and 'Red Hat Enterprise Linux' both return HTTP 400
  // from OSV, which made the gate fail closed and block every package.
  assert.equal(osvEcosystem('CentOS:9'), 'Red Hat');
  assert.equal(osvEcosystem('Red Hat:9'), 'Red Hat');
  assert.equal(osvEcosystem('Debian:12'), 'Debian');
  assert.equal(osvEcosystem('Ubuntu:24.04'), 'Ubuntu');
  assert.equal(osvEcosystem('Alpine:v3.20'), 'Alpine');
  assert.equal(osvEcosystem('Rocky Linux:9'), 'Rocky Linux');
  assert.equal(osvEcosystem('AlmaLinux:9'), 'AlmaLinux');
  assert.equal(osvEcosystem('npm'), 'npm'); // language ecosystems pass through
});
