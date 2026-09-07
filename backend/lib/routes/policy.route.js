'use strict';

const express = require('express');
const router = express.Router();
const { apiLimiter, rateLimit } = require('../shared');
const { getPolicyRow, savePolicy, toYaml, fromYaml, normalizeBody } = require('../gate/policyStore');

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

function actor(req) {
  return req.session?.user?.username || req.session?.user?.email || 'unknown';
}

router.get('/policy/facts', (req, res) => res.json({ facts: FACTS }));

router.get('/policy', async (req, res) => {
  try {
    const row = await getPolicyRow();
    if (!row) return res.status(404).json({ error: 'No policy stored' });
    res.json(row);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Export the policy in the same file format policy.yaml uses.
router.get('/policy/yaml', async (req, res) => {
  try {
    const row = await getPolicyRow();
    if (!row) return res.status(404).json({ error: 'No policy stored' });
    res.type('text/yaml').send(toYaml(row.body));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Validate a candidate policy (YAML or object) and hand back the normalised
// body without storing it. Lets the editor load YAML without shipping a parser
// to the browser.
router.post('/policy/normalize', rateLimit(apiLimiter), (req, res) => {
  try {
    const { body, yaml: yamlText } = req.body || {};
    res.json({ body: yamlText ? fromYaml(String(yamlText)) : normalizeBody(body) });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Replace the policy. It takes effect immediately, and the bumped version
// invalidates every verdict cached under the previous policy.
router.put('/policy', rateLimit(apiLimiter), async (req, res) => {
  try {
    const { body, yaml: yamlText } = req.body || {};
    const source = yamlText ? 'yaml' : 'ui';
    const parsed = yamlText ? fromYaml(String(yamlText)) : body;
    res.json(await savePolicy(parsed, { user: actor(req), source }));
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

module.exports = router;
