'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs');
const nativeFetch = global.fetch;
let graphSize = 0, scanned = [], saved = [], semgrepOutput, semgrepError, created = [];
const dbPath = require.resolve('../lib/auth/db');
require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: { getPool: () => ({
  query: async (sql, args) => { if (sql.includes('INSERT INTO scan_cache')) saved.push(JSON.parse(args[2])); return { rows: [] }; },
}) } };
const sharedPath = require.resolve('../lib/shared');
const shared = require(sharedPath);
require.cache[sharedPath].exports = { ...shared,
  osvQuery: async name => { scanned.push(name); return []; },
  checkToxic: async () => ({ found: false }),
  bulkEnrich: async () => ({ epssMap: {}, kevSet: new Set(), cvssMap: {}, pocMap: {} }),
};
const cp = require('node:child_process'), nativeExec = cp.execFile;
cp.execFile = (command, args, options, callback) => {
  if (command === 'git') { fs.mkdirSync(args.at(-1), { recursive: true }); created.push(args.at(-1)); return callback(null, '', ''); }
  if (command === 'du') return callback(null, '1\tfixture', '');
  if (command === 'semgrep') {
    const file = args[args.indexOf('--output') + 1];
    fs.writeFileSync(file, JSON.stringify(semgrepOutput)); created.push(file);
    return callback(semgrepError, '', semgrepError ? 'scan failed' : '');
  }
  throw new Error('unexpected executable: ' + command);
};
const depsRoute = require('../lib/routes/dependency-scan.route');
const ghRoute = require('../lib/routes/ghscan.route');
test.after(() => { cp.execFile = nativeExec; });
test.beforeEach(() => {
  graphSize = 0; scanned = []; saved = []; created = []; semgrepOutput = { results: [], errors: [] }; semgrepError = null;
  global.fetch = async (url, options) => {
    const value = String(url);
    if (value.startsWith('http://127.0.0.1:')) return nativeFetch(url, options);
    if (value.startsWith('https://api.github.com/')) return { status: 200 };
    if (!value.startsWith('https://api.deps.dev/')) assert.fail('unexpected external request');
    const doc = value.endsWith(':dependencies') ? { nodes: [
      { versionKey: { name: 'root', version: '1.0.0', system: 'NPM' } },
      ...Array.from({ length: graphSize }, (_, i) => ({ versionKey: { name: `dep${i}`, version: '1.0.0', system: 'NPM' } })),
    ] } : value.includes('/versions/') ? {} : { versions: [{ isDefault: true, versionKey: { version: '1.0.0' } }] };
    return { ok: true, json: async () => doc };
  };
});
test.afterEach(() => {
  global.fetch = nativeFetch;
  for (const file of created) { assert.equal(fs.existsSync(file), false, 'scan workspaces and output must be cleaned'); }
});
async function request(route, endpoint, body) {
  const app = express(); app.use(express.json()); app.use('/api', route);
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/${endpoint}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}
test('a graph over 500 dependencies fails explicitly without scanning or caching a subset', async () => {
  graphSize = 501;
  const response = await request(depsRoute, 'depscan', { name: 'root', system: 'NPM' });
  assert.equal(response.status, 413); assert.match(response.body.error, /501.*500.*not completed/);
  assert.deepEqual(scanned, []); assert.deepEqual(saved, []);
});
test('a graph at the supported boundary scans every dependency and is complete', async () => {
  graphSize = 500;
  const response = await request(depsRoute, 'depscan', { name: 'root', system: 'NPM' });
  assert.equal(response.status, 200); assert.equal(response.body.complete, true);
  assert.equal(response.body.summary.totalDeps, 500); assert.equal(scanned.length, 501); assert.equal(saved.length, 1);
});
test('a Semgrep failure cannot become a cached clean result even with valid JSON output', async () => {
  semgrepError = Object.assign(new Error('semgrep failed'), { code: 2 });
  const response = await request(ghRoute, 'ghscan', { url: 'https://github.com/example/failure' });
  assert.equal(response.status, 502); assert.match(response.body.error, /Semgrep failed/); assert.deepEqual(saved, []);
});
test('Semgrep analysis errors keep the findings, mark the scan incomplete and skip the cache', async () => {
  semgrepOutput = { results: [{ check_id: 'rules.eval', path: 'app.js', start: { line: 1 }, end: { line: 1 },
    extra: { severity: 'ERROR', message: 'eval', lines: 'eval(x)' } }],
  errors: [
    { level: 'warn', type: ['PartialParsing', []], path: 'vendor/min.js', message: 'Syntax error at line 1' },
    { level: 'warn', type: 'Timeout', path: 'big.js', message: 'Timeout when running rules.eval' },
  ] };
  const response = await request(ghRoute, 'ghscan', { url: 'https://github.com/example/timeout' });
  assert.equal(response.status, 200);
  assert.equal(response.body.complete, false); assert.equal(response.body.errors, 2);
  assert.equal(response.body.findings.length, 1); assert.equal(response.body.counts.HIGH, 1);
  assert.deepEqual(response.body.errorSamples.map(e => [e.type, e.path]), [['PartialParsing', 'vendor/min.js'], ['Timeout', 'big.js']]);
  assert.deepEqual(saved, []);
});

test('malformed Semgrep output is a failed scan', async () => {
  semgrepOutput = {};
  const invalid = await request(ghRoute, 'ghscan', { url: 'https://github.com/example/invalid' });
  assert.equal(invalid.status, 502); assert.match(invalid.body.error, /Invalid Semgrep/);
});
test('a successful empty Semgrep scan remains a complete, cacheable clean result', async () => {
  const response = await request(ghRoute, 'ghscan', { url: 'https://github.com/example/clean' });
  assert.equal(response.status, 200); assert.equal(response.body.complete, true);
  assert.equal(response.body.topSev, 'NONE'); assert.equal(saved.length, 1);
});
