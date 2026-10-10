'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const zlib = require('node:zlib');
const nativeFetch = global.fetch;
let verdict = 'deny', evaluated = [], mappings = new Map();
process.env.OSA_NEXUS_REPOSITORIES = JSON.stringify({
  py: { ecosystem: 'PyPI', upstream: 'https://pypi.org', direct: true },
  php: { ecosystem: 'Packagist', upstream: 'https://repo.packagist.org', direct: true },
});
const dbPath = require.resolve('../lib/auth/db');
require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: { getPool: () => ({ query: async (sql, args) => {
  if (/INSERT INTO proxy_artifacts/.test(sql)) {
    mappings.set(args[0], { url: args[3], name: args[1], version: args[2] });
  }
  return { rows: /SELECT url FROM proxy_artifacts/.test(sql) && mappings.has(args[0]) ? [mappings.get(args[0])] : [] };
} }) } };
const servicePath = require.resolve('../lib/gate/service');
require.cache[servicePath] = { id: servicePath, filename: servicePath, loaded: true, exports: {
  cachedGate: async pkg => { evaluated.push(pkg); return { decision: verdict, reasons: [{ rule: 'critical', detail: 'critical vulnerability' }] }; },
} };
const gate = require('../lib/routes/gate-proxy.route').router;
const common = require('../lib/gate/proxy/common');
const pypi = require('../lib/gate/proxy/pypi');
const composer = require('../lib/gate/proxy/composer');
const cargo = require('../lib/gate/proxy/cargo');
const nuget = require('../lib/gate/proxy/nuget');
const cfg = { upstream: 'https://registry.test', direct: true };
const pyCfg = { upstream: 'https://pypi.org', direct: true };
const phpCfg = { upstream: 'https://repo.packagist.org', direct: true };
test.afterEach(() => { global.fetch = nativeFetch; });
test.beforeEach(() => { mappings = new Map(); evaluated = []; verdict = 'deny'; });

async function withApp(app, fn) {
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  try { await fn(`http://127.0.0.1:${server.address().port}`); }
  finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}
function mockMetadata(doc, type = 'application/json') {
  return new Response(typeof doc === 'string' ? doc : JSON.stringify(doc), { headers: { 'content-type': type } });
}
function fakeRes() { return { status() { return this; }, setHeader() {}, type() { return this; },
  end() {}, send(value) { this.body = value; }, json(value) { this.body = value; } }; }
const req = { protocol: 'http', baseUrl: '/api/gate', headers: {}, get: () => 'osa.test', method: 'GET' };

test('every download adapter safely terminates a failed upstream stream and serves the next request', async () => {
  for (const [label, handler] of [
    ['common', (r,s) => common.proxyResponse(r,s,'/file',cfg)],
    ['cargo', (r,s) => cargo.download(r,s,cfg,'crates','pkg/1.0/download')],
    ['nuget', (r,s) => nuget.download(r,s,cfg,'nuget','pkg.1.0.nupkg')],
    ['composer', (r,s) => composer.download(r,s,phpCfg,'php','dist/vendor/pkg/1.zip')],
  ]) {
    mappings.set('Packagist:php/dist/vendor/pkg/1.zip', { url: 'https://api.github.com/repos/vendor/pkg/zipball/1' });
    let fail = true;
    global.fetch = async () => fail ? new Response(new ReadableStream({ start(controller) {
      controller.enqueue(new Uint8Array([1,2,3])); setTimeout(() => controller.error(new Error('upstream disconnected')), 15);
    } })) : new Response('valid artifact');
    const app = express(); app.get('/artifact', handler);
    await withApp(app, async base => {
      await assert.rejects(async () => (await nativeFetch(base + '/artifact')).arrayBuffer(), undefined, label);
      fail = false;
      assert.equal(await (await nativeFetch(base + '/artifact')).text(), 'valid artifact', label);
    });
  }
});

test('decompressed GET streams discard compressed lengths, while HEAD preserves wire metadata', async () => {
  const body = 'package-data-'.repeat(1000), compressed = zlib.gzipSync(body);
  const upstream = express(); upstream.get('/file', (req, res) => res.set({ 'Content-Encoding': 'gzip', 'Content-Length': String(compressed.length) }).end(compressed));
  await withApp(upstream, async source => {
    const proxy = express(); proxy.get('/file', (req, res) => common.proxyResponse(req,res,'/file',{ upstream: source }));
    await withApp(proxy, async base => {
      const response = await nativeFetch(base + '/file');
      assert.equal(await response.text(), body); assert.equal(response.headers.get('content-encoding'), null);
      assert.equal(response.headers.get('content-length'), null);
      const head = await nativeFetch(base + '/file', { method: 'HEAD' });
      assert.equal(head.headers.get('content-length'), String(compressed.length)); assert.equal(head.headers.get('content-encoding'), 'gzip');
    });
  });
});

test('PyPI HTML and JSON indices preserve media types and gate file URLs, hashes, local versions and metadata sidecars', async () => {
  for (const format of ['html', 'json']) {
    verdict = 'deny';
    let downloads = 0;
    const file = 'https://files.pythonhosted.org/packages/demo_pkg-1!2.0.post1+cpu-py3-none-any.whl?token=a#sha256=abcd';
    global.fetch = async (url, options) => {
      if (String(url).startsWith('http://127.0.0.1:')) return nativeFetch(url, options);
      if (String(url).includes('/simple/')) return format === 'html'
        ? mockMetadata(`<a href="${file}">file</a>`, 'text/html')
        : mockMetadata({ name: 'demo-pkg', files: [{ filename: file.split('/').pop(), url: file }] }, 'application/vnd.pypi.simple.v1+json');
      downloads++; return new Response('downloaded');
    };
    const app = express(); app.use('/api/gate', gate);
    await withApp(app, async base => {
      const response = await nativeFetch(base + '/api/gate/py/simple/demo-pkg/');
      assert.equal(response.headers.get('content-type').split(';')[0],
        format === 'html' ? 'text/html' : 'application/vnd.pypi.simple.v1+json');
      const url = format === 'html' ? (await response.text()).match(/href="([^"]+)"/)[1] : (await response.json()).files[0].url;
      assert.ok(url.startsWith(base + '/api/gate/py/files/')); assert.ok(url.endsWith('#sha256=abcd'));
      assert.equal((await nativeFetch(url)).status, 403); assert.equal(downloads, 0);
      assert.deepEqual(evaluated[0], { ecosystem: 'PyPI', name: 'demo-pkg', version: '1!2.0.post1+cpu' });
      verdict = 'allow'; assert.equal(await (await nativeFetch(url)).text(), 'downloaded');
      const sidecar = url.split('#')[0] + '.metadata';
      assert.equal(await (await nativeFetch(sidecar)).text(), 'downloaded');
      assert.equal(evaluated.at(-1).version, '1!2.0.post1+cpu');
    });
  }
});

test('PyPI relative project links and file queries survive rewriting; downloads reject foreign redirects', async () => {
  global.fetch = async () => mockMetadata('<a href=../../packages/demo-1.0.tar.gz?x=1&amp;y=2#sha256=x>file</a>', 'text/html');
  const res = fakeRes(); await pypi.serveIndex(req,res,pyCfg,'py','simple/demo/');
  assert.match(res.body, /\/api\/gate\/py\/files\/demo\/1.0\//);
  assert.match([...mappings.values()][0].url, /\?x=1&y=2$/);
  global.fetch = async () => mockMetadata('<a href="./demo/">project</a>', 'text/html');
  const root = fakeRes(); await pypi.serveIndex(req,root,pyCfg,'py','simple/');
  assert.match(root.body, /http:\/\/osa.test\/api\/gate\/py\/simple\/demo\//);
  let calls = 0;
  global.fetch = async () => { calls++; return new Response(null, { status: 302, headers: { location: 'http://127.0.0.1/secret' } }); };
  await assert.rejects(pypi.fetchDownload('https://files.pythonhosted.org/pkg', pyCfg, 'GET'), /not trusted/);
  assert.equal(calls, 1);
});

test('Composer expands minified inherited fields, removes source fallbacks and isolates repository mappings', async () => {
  const doc = { minified: 'composer/2.0', packages: { 'vendor/pkg': [
    { version: '2.0', source: { url: 'https://github.com/vendor/pkg.git' }, dist: { url: 'https://api.github.com/repos/vendor/pkg/tarball/abc', type: 'tar', reference: 'abc', mirrors: [{ url: 'https://github.com/vendor/pkg' }] } },
    { version: '1.0' }, { version: 'dev-main', dist: '__unset' },
    { version: '0.9', dist: { url: 'https://evil.test/file.zip', type: 'zip' } },
  ] } };
  global.fetch = async () => mockMetadata(doc);
  const res = fakeRes(); await composer.serveIndex(req,res,phpCfg,'php','p2/vendor/pkg.json');
  assert.equal(res.body.minified, undefined);
  assert.equal(res.body.packages['vendor/pkg'].length, 2);
  for (const version of res.body.packages['vendor/pkg']) {
    assert.equal(version.source, undefined); assert.equal(version.dist.type, 'tar');
    assert.equal(version.dist.mirrors, undefined);
    assert.equal(version.dist.reference, 'abc'); assert.match(version.dist.url, /\/api\/gate\/php\/dist\/vendor\/pkg\//);
  }
  assert.notEqual(res.body.packages['vendor/pkg'][0].dist.url, res.body.packages['vendor/pkg'][1].dist.url);
  assert.ok(mappings.has('Packagist:php/dist/vendor/pkg/2.0.zip'));
  const other = fakeRes(); await composer.download(req,other,phpCfg,'other','dist/vendor/pkg/2.0.zip');
  assert.equal(other.body.error, 'composer dist not resolved (fetch package metadata first)');
});
