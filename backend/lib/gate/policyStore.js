'use strict';

const fs = require('fs');
const yaml = require('js-yaml');
const { getPool } = require('../auth/db');
const { compilePolicy, POLICY_FILE } = require('./policy');

// The gate reads its policy from a single database row. `body` keeps the
// declarative YAML shape, so it compiles with the same compilePolicy() the file
// loader uses - the UI, the file and the enforcement path can never drift into
// different dialects.
//
// A policy is data, never code: rules are {id, action, when: {fact: expr}} and
// are interpreted by policy.js. Nothing here evaluates user input.

const CACHE_MS = 10000; // re-read the stored policy at most this often
let _cache = null;      // { at, version, compiled }

// Used only when there is no policy.yaml to import into a fresh database.
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
// and therefore never becomes the enforced one.
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
function compileBody(body, version) {
  return compilePolicy({
    ...body,
    rules: (body.rules || []).filter(r => r.enabled !== false),
    version: `db:${version}`,
  });
}

async function getPolicyRow() {
  const { rows } = await getPool().query('SELECT * FROM gate_policy WHERE id = 1');
  return rows[0] || null;
}

// Replace the policy. The version counter bumps so every cached verdict made
// under the previous policy is invalidated.
async function savePolicy(body, { user, source = 'ui' } = {}) {
  const clean = normalizeBody(body);
  const { rows } = await getPool().query(
    `INSERT INTO gate_policy (id, version, source, body, updated_by, updated_at)
     VALUES (1, 1, $1, $2::jsonb, $3, NOW())
     ON CONFLICT (id) DO UPDATE SET
       version = gate_policy.version + 1,
       source = EXCLUDED.source,
       body = EXCLUDED.body,
       updated_by = EXCLUDED.updated_by,
       updated_at = NOW()
     RETURNING *`,
    [source, JSON.stringify(clean), user || null]);
  _cache = null;
  return rows[0];
}

// Seed the database from policy.yaml on first boot, so an existing file-based
// setup keeps working and its rules show up in the UI unchanged.
async function bootstrapPolicy() {
  const existing = await getPolicyRow().catch(() => null);
  if (existing) return existing;

  let body = STARTER_BODY, source = 'builtin';
  if (fs.existsSync(POLICY_FILE)) {
    try {
      body = yaml.load(fs.readFileSync(POLICY_FILE, 'utf8'));
      source = 'yaml';
    } catch (e) {
      throw new Error(`policy.yaml is present but unreadable: ${e.message}`);
    }
  }
  return savePolicy(body, { source, user: 'system' });
}

// What the gate enforces. Falls back to the last good compile if the database
// blips, so a transient outage does not silently change the policy.
async function getActivePolicy() {
  if (_cache && Date.now() - _cache.at < CACHE_MS) return _cache.compiled;
  try {
    const row = await getPolicyRow();
    if (!row) throw new Error('no policy stored');
    const compiled = compileBody(row.body, row.version);
    _cache = { at: Date.now(), version: row.version, compiled };
    return compiled;
  } catch (e) {
    if (_cache) {
      console.error('[policy] using cached policy, reload failed:', e.message);
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
  return normalizeBody(yaml.load(text));
}

module.exports = {
  bootstrapPolicy, getActivePolicy, getPolicyRow, savePolicy,
  normalizeBody, compileBody, toYaml, fromYaml, STARTER_BODY,
};
