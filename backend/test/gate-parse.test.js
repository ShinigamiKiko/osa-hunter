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

test('a fail-closed block is told apart from a policy block', () => {
  // on_gate_error: deny blocks the package when OSV is unreachable. That must
  // not be reported as "forbidden by policy": the package was never judged.
  const { isGateError } = require('../lib/routes/gate-proxy.route');
  assert.equal(isGateError([{ rule: 'gate-error', detail: 'OSV query failed' }]), true);
  assert.equal(isGateError([{ rule: 'critical', detail: '1 critical vuln' }]), false);
  assert.equal(isGateError([{ rule: 'denylist', detail: 'blocked by name: curl' }]), false);
  // A real policy hit alongside an error is still a policy decision.
  assert.equal(isGateError([{ rule: 'gate-error' }, { rule: 'critical' }]), false);
  assert.equal(isGateError([]), false);
});

test('rule text written by a person cannot break the HTTP response', () => {
  // Regression: a reason with an em dash made res.setHeader throw
  // ERR_INVALID_CHAR, and the whole request came back as 502 Bad Gateway.
  const { headerSafe } = require('../lib/routes/gate-proxy.route');
  assert.equal(headerSafe('not approved — ask #appsec'), 'not approved ask #appsec');
  assert.equal(headerSafe('запрещено политикой'), '');
  assert.equal(headerSafe('line\nbreak\tand  spaces'), 'line break and spaces');
  assert.equal(headerSafe('x'.repeat(500)).length, 200);
  assert.equal(headerSafe(null), '');
  for (const c of headerSafe('plain ascii stays')) {
    assert.ok(c.charCodeAt(0) >= 0x20 && c.charCodeAt(0) <= 0x7e);
  }
});

test('an IPv4 client is recorded as IPv4, not as its IPv6-mapped spelling', () => {
  // Node hands back ::ffff:91.122.9.47 on a dual-stack socket. Same address,
  // but nobody greps their logs for that form.
  const { clientIp } = require('../lib/routes/gate-proxy.route');
  assert.equal(clientIp({ ip: '::ffff:91.122.9.47' }), '91.122.9.47');
  assert.equal(clientIp({ ip: '::FFFF:10.0.0.1' }), '10.0.0.1');
  // Real IPv6 and plain IPv4 are left exactly as they are.
  assert.equal(clientIp({ ip: '2001:db8::1' }), '2001:db8::1');
  assert.equal(clientIp({ ip: '::1' }), '::1');
  assert.equal(clientIp({ ip: '172.18.0.1' }), '172.18.0.1');
  assert.equal(clientIp({}), null);
});
