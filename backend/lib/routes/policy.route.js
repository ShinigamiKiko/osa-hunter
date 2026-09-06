'use strict';

const express = require('express');
const router = express.Router();
const { getPool } = require('../auth/db');
const { apiLimiter, rateLimit } = require('../shared');
const { evalRules } = require('../gate/policy');
const { resolveDecision } = require('../gate/decide');
const {
  listRevisions, getRevision, getActiveRow, createRevision, activateRevision,
  compileBody, toYaml, fromYaml, normalizeBody,
} = require('../gate/policyStore');

// Policy administration. Mounted behind requireAuth in server.js - only
// /api/gate is public, and it accepts package paths, never policy input.

const FACTS = [
  { key: 'counts.CRITICAL', label: 'Critical vulnerabilities', type: 'number' },
  { key: 'counts.HIGH', label: 'High vulnerabilities', type: 'number' },
  { key: 'counts.MEDIUM', label: 'Medium vulnerabilities', type: 'number' },
  { key: 'counts.LOW', label: 'Low vulnerabilities', type: 'number' },
  { key: 'total', label: 'Total vulnerabilities', type: 'number' },
  { key: 'cveCount', label: 'Distinct CVEs', type: 'number' },
  { key: 'kev', label: 'In CISA KEV (actively exploited)', type: 'boolean' },
  { key: 'epssMax', label: 'Highest EPSS score (0-1)', type: 'number' },
  { key: 'pocCount', label: 'CVEs with a public PoC', type: 'number' },
  { key: 'toxic.found', label: 'Listed as a toxic repository', type: 'boolean' },
  { key: 'topSeverity', label: 'Highest severity', type: 'enum',
    values: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'NONE'] },
  { key: 'cves', label: 'Carries a specific CVE', type: 'pattern', example: 'CVE-2026-*' },
  { key: 'ids', label: 'Carries a specific advisory id', type: 'pattern', example: 'GHSA-*' },
  { key: 'ecosystem', label: 'Ecosystem', type: 'pattern', example: 'npm' },
  { key: 'name', label: 'Package name', type: 'pattern', example: 'left-*' },
];

// Facts that only exist during a live scan, so a replay cannot evaluate them.
const NOT_REPLAYABLE = new Set(['cves', 'ids']);

function actor(req) {
  return req.session?.user?.username || req.session?.user?.email || 'unknown';
}

function usedFacts(condition, out = new Set()) {
  if (!condition || typeof condition !== 'object') return out;
  for (const [key, value] of Object.entries(condition)) {
    if ((key === 'all' || key === 'any') && Array.isArray(value)) value.forEach(c => usedFacts(c, out));
    else out.add(key);
  }
  return out;
}

router.get('/policy/facts', (req, res) => res.json({ facts: FACTS }));

// Validate a candidate policy (YAML or object) and hand back the normalised
// body, without storing anything. Lets the editor load YAML without shipping a
// parser to the browser, and without creating junk revisions.
router.post('/policy/normalize', rateLimit(apiLimiter), (req, res) => {
  try {
    const { body, yaml: yamlText } = req.body || {};
    res.json({ body: yamlText ? fromYaml(String(yamlText)) : normalizeBody(body) });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

router.get('/policy/revisions', async (req, res) => {
  try {
    res.json({ revisions: await listRevisions() });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/policy/active', async (req, res) => {
  try {
    const row = await getActiveRow();
    if (!row) return res.status(404).json({ error: 'No active policy revision' });
    res.json(row);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/policy/revisions/:revision', async (req, res) => {
  try {
    const row = await getRevision(parseInt(req.params.revision, 10));
    if (!row) return res.status(404).json({ error: 'Revision not found' });
    res.json(row);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Export any revision back to YAML - the same file format policy.yaml uses.
router.get('/policy/revisions/:revision/yaml', async (req, res) => {
  try {
    const row = await getRevision(parseInt(req.params.revision, 10));
    if (!row) return res.status(404).json({ error: 'Revision not found' });
    res.type('text/yaml').send(toYaml(row.body));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Save a new revision. `activate: true` makes it the enforced policy at once;
// leaving it false lets you simulate first.
router.post('/policy/revisions', rateLimit(apiLimiter), async (req, res) => {
  try {
    const { body, yaml: yamlText, note, activate } = req.body || {};
    const source = yamlText ? 'yaml' : 'ui';
    const parsed = yamlText ? fromYaml(String(yamlText)) : body;
    const row = await createRevision(parsed, { user: actor(req), note, source, activate: !!activate });
    res.status(201).json(row);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

router.post('/policy/revisions/:revision/activate', rateLimit(apiLimiter), async (req, res) => {
  try {
    res.json(await activateRevision(parseInt(req.params.revision, 10)));
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Dry run: re-decide every package the gate has already seen, using a candidate
// policy, and diff against what is enforced today. Reads cached facts only - no
// network, no scans - so it is safe to run on a live install.
router.post('/policy/simulate', rateLimit(apiLimiter), async (req, res) => {
  try {
    const { body, yaml: yamlText, revision, limit } = req.body || {};
    let candidateBody;
    if (yamlText) candidateBody = fromYaml(String(yamlText));
    else if (body) candidateBody = body;
    else if (revision != null) candidateBody = (await getRevision(parseInt(revision, 10)))?.body;
    if (!candidateBody) return res.status(400).json({ error: 'Nothing to simulate' });

    const candidate = compileBody(candidateBody, 'sim');
    const cap = Math.min(parseInt(limit, 10) || 2000, 5000);
    const { rows } = await getPool().query(
      `SELECT payload FROM scan_cache WHERE type = 'gate' ORDER BY scanned_at DESC LIMIT $1`, [cap]);

    const changes = [];
    const counts = { allow: 0, warn: 0, deny: 0 };
    for (const { payload } of rows) {
      const pkg = payload?.package;
      const f = payload?.findings;
      if (!pkg?.name || !f) continue;
      const facts = {
        ecosystem: pkg.ecosystem, name: pkg.name, version: pkg.version,
        total: f.total || 0, counts: f.counts || {}, topSeverity: f.topSeverity || 'NONE',
        kev: f.kev || 0, epssMax: f.epssMax || 0, pocCount: f.pocCount || 0,
        cveCount: f.cveCount || 0, toxic: f.toxic || { found: false },
      };
      const next = resolveDecision(candidate, evalRules(candidate, facts), pkg);
      counts[next.decision] = (counts[next.decision] || 0) + 1;
      const before = payload.decision;
      if (next.decision !== before) {
        changes.push({
          ecosystem: pkg.ecosystem, name: pkg.name, version: pkg.version,
          from: before, to: next.decision,
          reason: (next.reasons || []).map(r => `${r.rule}: ${r.detail}`).join('; ') || '—',
        });
      }
    }

    // Be explicit about what a replay cannot answer, rather than quietly
    // reporting a clean run.
    const skipped = [];
    for (const rule of candidateBody.rules || []) {
      const facts = [...usedFacts(rule.when)].filter(k => NOT_REPLAYABLE.has(k));
      if (facts.length) skipped.push({ rule: rule.id, facts });
    }

    res.json({
      evaluated: rows.length,
      counts,
      newlyBlocked: changes.filter(c => c.to === 'deny').length,
      newlyAllowed: changes.filter(c => c.from === 'deny').length,
      changes: changes.slice(0, 500),
      truncated: changes.length > 500,
      notSimulated: skipped,
    });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

module.exports = router;
