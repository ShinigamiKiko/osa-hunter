'use strict';

const fs = require('fs');
const yaml = require('js-yaml');
const { getPool } = require('../auth/db');
const { compilePolicy, POLICY_FILE } = require('./policy');

// The gate reads its policy from the database: one row per revision, exactly
// one active. `body` keeps the declarative YAML shape, so a revision compiles
// with the same compilePolicy() the file loader uses - the UI, the file and the
// enforcement path can never drift into different dialects.
//
// A policy is data, never code: rules are {id, action, when: {fact: expr}} and
// are interpreted by policy.js. Nothing here evaluates user input.

const CACHE_MS = 10000; // re-read the active revision at most this often
let _cache = null;      // { at, revision, compiled }

// Used only when there is no policy.yaml to import on a fresh database.
const STARTER_BODY = {
  defaults: { decision: 'allow', on_gate_error: 'deny' },
  rules: [
    { id: 'toxic-repository', action: 'deny', when: { 'toxic.found': 'yes' },
      detail: 'package is listed as a toxic repository' },
    { id: 'actively-exploited', action: 'deny', when: { kev: 'yes' },
      detail: 'package contains a vulnerability listed in CISA KEV' },
    { id: 'critical', action: 'deny', when: { 'counts.CRITICAL': '>= 1' },
      detail: 'package contains a critical vulnerability' },
  ],
  exceptions: { allow: [], deny: [] },
};

// Validate and strip a policy body down to the fields we persist. Throws on
// anything compilePolicy rejects, so an invalid policy can never be stored -
// and therefore never becomes the active one.
function normalizeBody(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('Policy must be an object');
  }
  const body = {
    defaults: {
      decision: input.defaults?.decision || 'allow',
      on_gate_error: input.defaults?.on_gate_error || 'deny',
    },
    rules: (input.rules || []).map(r => ({
      id: String(r.id || '').trim(),
      action: r.action,
      when: r.when,
      ...(r.detail ? { detail: String(r.detail) } : {}),
      ...(r.enabled === false ? { enabled: false } : {}),
    })),
    exceptions: {
      allow: (input.exceptions?.allow || []).map(String).map(s => s.trim()).filter(Boolean),
      deny: (input.exceptions?.deny || []).map(String).map(s => s.trim()).filter(Boolean),
    },
  };
  if (!['allow', 'warn', 'deny'].includes(body.defaults.decision)) {
    throw new Error('defaults.decision must be allow, warn or deny');
  }
  if (!['allow', 'deny'].includes(body.defaults.on_gate_error)) {
    throw new Error('defaults.on_gate_error must be allow or deny');
  }
  const seen = new Set();
  for (const rule of body.rules) {
    if (!rule.id) throw new Error('Every rule needs an id');
    if (seen.has(rule.id)) throw new Error(`Duplicate rule id: ${rule.id}`);
    seen.add(rule.id);
    if (!rule.when || typeof rule.when !== 'object') {
      throw new Error(`Rule ${rule.id}: "when" must be a condition object`);
    }
  }
  // The real check: if it does not compile, it does not get stored.
  compilePolicy({ ...body, rules: body.rules.filter(r => r.enabled !== false), version: 0 });
  return body;
}

// Disabled rules stay in the body (so the UI can show them) but never compile.
function compileBody(body, revision) {
  return compilePolicy({
    ...body,
    rules: (body.rules || []).filter(r => r.enabled !== false),
    version: `db:${revision}`,
  });
}

async function listRevisions(limit = 50) {
  const { rows } = await getPool().query(
    `SELECT id, revision, name, source, note, created_by, created_at, active,
            jsonb_array_length(COALESCE(body->'rules', '[]'::jsonb)) AS rule_count
       FROM gate_policies ORDER BY revision DESC LIMIT $1`, [limit]);
  return rows;
}

async function getRevision(revision) {
  const { rows } = await getPool().query(
    'SELECT * FROM gate_policies WHERE revision = $1', [revision]);
  return rows[0] || null;
}

async function getActiveRow() {
  const { rows } = await getPool().query(
    'SELECT * FROM gate_policies WHERE active LIMIT 1');
  return rows[0] || null;
}

// Store a new revision. Activating it is the caller's choice, so a policy can
// be prepared and simulated before it starts blocking anyone.
async function createRevision(body, { user, note, source = 'ui', activate = false } = {}) {
  const clean = normalizeBody(body);
  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [{ next }] } = await client.query(
      'SELECT COALESCE(MAX(revision), 0) + 1 AS next FROM gate_policies');
    if (activate) await client.query('UPDATE gate_policies SET active = FALSE WHERE active');
    const { rows } = await client.query(
      `INSERT INTO gate_policies (revision, source, body, note, created_by, active)
       VALUES ($1, $2, $3::jsonb, $4, $5, $6) RETURNING *`,
      [next, source, JSON.stringify({ ...clean, version: next }), note || null, user || null, !!activate]);
    await client.query('COMMIT');
    if (activate) _cache = null;
    return rows[0];
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

async function activateRevision(revision) {
  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rowCount } = await client.query(
      'SELECT 1 FROM gate_policies WHERE revision = $1', [revision]);
    if (!rowCount) throw new Error(`Revision ${revision} not found`);
    await client.query('UPDATE gate_policies SET active = FALSE WHERE active');
    await client.query('UPDATE gate_policies SET active = TRUE WHERE revision = $1', [revision]);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
  _cache = null;
  return getRevision(revision);
}

// Seed the database from policy.yaml on first boot, so an existing file-based
// setup keeps working and its rules show up in the UI unchanged.
async function bootstrapPolicy() {
  const active = await getActiveRow().catch(() => null);
  if (active) return active;

  let body = STARTER_BODY, source = 'builtin', note = 'built-in starter policy';
  if (fs.existsSync(POLICY_FILE)) {
    try {
      body = yaml.load(fs.readFileSync(POLICY_FILE, 'utf8'));
      source = 'yaml';
      note = `imported from ${POLICY_FILE}`;
    } catch (e) {
      throw new Error(`policy.yaml is present but unreadable: ${e.message}`);
    }
  }
  return createRevision(body, { source, note, activate: true, user: 'system' });
}

// What the gate enforces. Falls back to the last good compile if the database
// blips, so a transient outage does not silently change the policy.
async function getActivePolicy() {
  if (_cache && Date.now() - _cache.at < CACHE_MS) return _cache.compiled;
  try {
    const row = await getActiveRow();
    if (!row) throw new Error('no active policy revision');
    const compiled = compileBody(row.body, row.revision);
    _cache = { at: Date.now(), revision: row.revision, compiled };
    return compiled;
  } catch (e) {
    if (_cache) {
      console.error('[policy] using cached revision, reload failed:', e.message);
      _cache.at = Date.now();
      return _cache.compiled;
    }
    throw e;
  }
}

function toYaml(body) {
  return yaml.dump(body, { lineWidth: 100, noRefs: true });
}

function fromYaml(text) {
  const parsed = yaml.load(text);
  return normalizeBody(parsed);
}

module.exports = {
  bootstrapPolicy, getActivePolicy, listRevisions, getRevision, getActiveRow,
  createRevision, activateRevision, normalizeBody, compileBody, toYaml, fromYaml,
  STARTER_BODY,
};
