'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
let query;
const dbPath = require.resolve('../lib/auth/db');
require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true,
  exports: { getPool: () => ({ query: (...args) => query(...args) }) } };
const sharedPath = require.resolve('../lib/shared');
const shared = require(sharedPath);
require.cache[sharedPath].exports = { ...shared,
  osvQuery: async () => [], checkToxic: async () => ({ found: false }),
  bulkEnrich: async () => ({ epssMap: {}, kevSet: new Set(), cvssMap: {}, pocMap: {} }),
};
const body = { defaults: { decision: 'allow', on_gate_error: 'deny' }, rules: [],
  exceptions: { deny: ['npm/blocked'], allow: [] } };
const row = () => ({ id: 1, version: 15, source: 'ui', body: structuredClone(body), updated_by: 'admin' });
function fresh() {
  for (const name of ['../lib/gate/policyStore', '../lib/gate/service']) delete require.cache[require.resolve(name)];
  return { ...require('../lib/gate/policyStore'), ...require('../lib/gate/service') };
}
const input = { ecosystem: 'npm', name: 'blocked', version: '1.0.0' };

test('bootstrap aborts a failed policy read without writing or changing rules', async () => {
  const stored = row(), before = structuredClone(stored), calls = [];
  query = async sql => { calls.push(sql); throw new Error('database unavailable'); };
  await assert.rejects(fresh().bootstrapPolicy(), /database unavailable/);
  assert.equal(calls.length, 1);
  assert.match(calls[0], /^SELECT/);
  assert.deepEqual(stored, before);
});

test('bootstrap preserves an existing row and creates a fresh policy only once', async () => {
  let stored = row(), inserts = 0;
  query = async (sql, args) => {
    if (sql.startsWith('SELECT')) return { rows: stored ? [stored] : [] };
    assert.match(sql, /ON CONFLICT \(id\) DO NOTHING/);
    inserts++;
    stored = { id: 1, version: 1, source: args[0], body: JSON.parse(args[1]) };
    return { rows: [stored] };
  };
  const store = fresh();
  assert.equal((await store.bootstrapPolicy()).version, 15);
  assert.equal(inserts, 0);
  stored = null;
  assert.equal((await store.bootstrapPolicy()).version, 1);
  assert.equal(inserts, 1);
  await store.bootstrapPolicy();
  assert.equal(inserts, 1);
});

test('bootstrap never overwrites a policy saved after its empty read', async () => {
  const winner = row(); let reads = 0;
  query = async sql => {
    if (sql.startsWith('SELECT')) return { rows: ++reads === 1 ? [] : [winner] };
    assert.match(sql, /DO NOTHING/);
    assert.ok(!sql.includes('DO UPDATE'));
    return { rows: [] };
  };
  const actual = await fresh().bootstrapPolicy();
  assert.deepEqual(actual, winner);
  assert.equal(reads, 2, 'reread the committed winner in a separate statement');
});

test('cold policy failures deny before reading cached verdicts or running scans', async () => {
  const calls = [];
  query = async sql => {
    calls.push(sql);
    if (sql.includes('gate_policy')) throw new Error('policy read failed');
    assert.fail('an unknown policy must not reach verdict cache or scanning');
  };
  const result = await fresh().cachedGate(input);
  assert.equal(result.decision, 'deny');
  assert.equal(result.reasons[0].rule, 'gate-error');
  assert.equal(result.policy, 'unavailable');
  assert.equal(calls.length, 1);
});

test('missing or invalid policy rows cannot authorize a download', async () => {
  query = async sql => ({ rows: sql.includes('gate_policy') ? [] : assert.fail('cache accessed') });
  assert.equal((await fresh().cachedGate(input)).reasons[0].rule, 'gate-error');
  query = async sql => ({ rows: sql.includes('gate_policy')
    ? [{ ...row(), body: { rules: [{ id: 'bad', action: 'invalid' }] } }]
    : assert.fail('cache accessed') });
  assert.equal((await fresh().cachedGate(input)).decision, 'deny');
});

test('recovery enforces the saved policy and normal verdict caching still works', async () => {
  let unavailable = true, cached, inserts = 0;
  query = async (sql, args) => {
    if (sql.includes('FROM gate_policy')) {
      if (unavailable) throw new Error('temporary outage');
      return { rows: [row()] };
    }
    if (sql.startsWith('SELECT payload')) return { rows: cached ? [{ payload: cached }] : [] };
    if (sql.includes('INSERT INTO scan_cache')) { cached = JSON.parse(args[1]); inserts++; }
    return { rows: [] };
  };
  const store = fresh();
  assert.equal((await store.cachedGate(input)).reasons[0].rule, 'gate-error');
  unavailable = false;
  assert.equal((await store.cachedGate(input)).reasons[0].rule, 'denylist');
  assert.equal((await store.cachedGate(input))._cached, true);
  assert.equal(inserts, 1);
});

test('a failed reload preserves the last known policy, and saves invalidate it', async () => {
  let unavailable = false, stored = row();
  query = async (sql, args) => {
    if (sql.startsWith('INSERT INTO gate_policy')) {
      stored = { ...stored, version: 16, body: JSON.parse(args[1]) };
      return { rows: [stored] };
    }
    if (unavailable) throw new Error('database unavailable');
    return { rows: [stored] };
  };
  const store = fresh(), originalNow = Date.now;
  const known = await store.getActivePolicy();
  try {
    const future = Date.now() + 20000; Date.now = () => future; unavailable = true;
    assert.equal(await store.getActivePolicy(), known);
  } finally { Date.now = originalNow; }
  unavailable = false;
  await store.savePolicy({ ...body, exceptions: { deny: [], allow: [] } });
  assert.equal((await store.getActivePolicy()).version, 'db:16');
});
