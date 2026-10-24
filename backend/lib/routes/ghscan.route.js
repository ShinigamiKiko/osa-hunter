'use strict';
const { withCache, ScanError } = require('../auth/scanCache');

const express      = require('express');
const router = require('../utils/router')();
const { runBoundedProcess } = require('../utils/runBoundedProcess');
const fs           = require('fs');
const path         = require('path');
const os           = require('os');
const { Semaphore } = require('../shared/primitives');
const { GHSCAN_CONCURRENCY, GHSCAN_QUEUE_SIZE } = require('../config');
const { downloadRepository } = require('../utils/githubArchive');
const scanSlots = new Semaphore(GHSCAN_CONCURRENCY, GHSCAN_QUEUE_SIZE);
const { semgrepSnippet } = require('../utils/semgrepSnippet');
const { scanLimiter, rateLimit, checkToxic, SEV_ORD } = require('../shared');

const GH_RE = /^https:\/\/github\.com\/([a-zA-Z0-9._-]+)\/([a-zA-Z0-9._-]+?)(\.git)?$/;

function validGhUrl(url) {
  return typeof url === 'string' && GH_RE.test(url.trim()) && url.length < 200;
}
function parseRepoName(url) {
  const m = url.match(GH_RE);
  return m ? `${m[1]}/${m[2]}` : url;
}
function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
}
function ruleShortName(ruleId) {
  const parts = (ruleId || '').split('.');
  const skip = new Set(['security','audit','correctness','performance','best-practice','lang','rules']);
  const last = [...parts].reverse().find(p => p && !skip.has(p)) || parts[parts.length - 1] || ruleId;
  return last.replace(/[-_]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function langFromPath(filePath) {
  const ext = (filePath || '').split('.').pop().toLowerCase();
  const map = {
    js:'JavaScript', ts:'TypeScript', jsx:'JavaScript', tsx:'TypeScript',
    py:'Python', rb:'Ruby', php:'PHP', java:'Java', go:'Go',
    cs:'C#', cpp:'C++', c:'C', rs:'Rust', kt:'Kotlin',
    swift:'Swift', scala:'Scala', sh:'Shell', bash:'Shell',
    yaml:'YAML', yml:'YAML', json:'JSON', xml:'XML', html:'HTML',
    tf:'Terraform', dockerfile:'Dockerfile',
  };
  return map[ext] || ext.toUpperCase() || 'Unknown';
}

function normSev(s) {
  const up = (s||'').toUpperCase();
  if (up === 'ERROR')   return 'HIGH';
  if (up === 'WARNING') return 'MEDIUM';
  if (up === 'INFO')    return 'LOW';
  return SEV_ORD.includes(up) ? up : 'UNKNOWN';
}

router.post('/ghscan', rateLimit(scanLimiter), async (req, res) => {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const { url, desc } = req.body || {};

  if (!url) return res.status(400).json({ error: 'url is required' });
  if (!validGhUrl(url)) return res.status(400).json({ error: 'Only public GitHub URLs supported' });

  const repo     = parseRepoName(url.trim());
  const _cacheKey = `sast:${repo}`;

  return withCache(_cacheKey, 'sast', res, async () => {
  const release = await scanSlots.acquire();
  if (!release) throw new ScanError(503, 'GitHub scan queue is full');
  let workspace;
  try {
  workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'ghscan-'));
  const tmpDir = path.join(workspace, 'source');
  console.log(`[GHScan] ${repo} → ${tmpDir} (ip: ${ip})`);

  try {
    await downloadRepository(repo, workspace);
  } catch (e) {
    throw new ScanError(e.status || 502, `Repository download failed: ${e.message}`);
  }
  console.log(`[GHScan] ${repo} — starting semgrep p/security-audit`);
  let semgrepOutput;
  let semgrepErr = '';
  try {
    const { stdout, stderr } = await runBoundedProcess('semgrep', [
      '--config', 'p/security-audit',
      '--metrics=off',
      '--json',
      '--no-error',
      '--no-git-ignore',
      '--jobs', '1',
      '--timeout', '60',
      '--max-memory', '1000',
      tmpDir,
    ], {
      timeout: 300_000,
      maxBuffer: 50 * 1024 * 1024,
      env: {
        ...process.env,
        SEMGREP_SEND_METRICS: 'off',
        NO_COLOR: '1',
      },
    });
    semgrepOutput = stdout;
    semgrepErr = stderr || '';
    console.log(`[GHScan] ${repo} — semgrep done`);
    if (semgrepErr) console.log(`[GHScan] semgrep stderr: ${semgrepErr.slice(0, 300)}`);
  } catch (e) {
    semgrepErr = e.stderr || '';
    console.log(`[GHScan] semgrep exit: code=${e.code} signal=${e.signal} killed=${e.killed}`);
    console.log(`[GHScan] semgrep stderr: ${semgrepErr.slice(0, 500)}`);
    cleanup(tmpDir);
    throw new ScanError(e.status || 502, 'Semgrep failed: ' + (semgrepErr.slice(0,200) || e.message));
  }

  let parsed;
  try {
    const raw = semgrepOutput;
    parsed = JSON.parse(raw);
    console.log(`[GHScan] ${repo} — JSON received, ${raw.length} bytes`);
  } catch (e) {
    console.error('[GHScan] JSON parse failed:', e.message);
    cleanup(tmpDir);
    throw new ScanError(500, 'Failed to read Semgrep JSON output: ' + e.message);
  }

  if (!Array.isArray(parsed?.results) || (parsed.errors !== undefined && !Array.isArray(parsed.errors))) {
    cleanup(tmpDir);
    throw new ScanError(502, 'Invalid Semgrep output; scan was not completed');
  }
  // A run that exits cleanly can still skip files it failed to parse or timed
  // out on. Real repositories almost always have a few, so the findings are
  // returned, marked incomplete (and never cached) rather than discarded.
  const scanErrors = (parsed.errors || []).map(e => ({
    type:    String(Array.isArray(e?.type) ? e.type[0] : e?.type || 'Error').slice(0, 80),
    level:   String(e?.level || 'error').slice(0, 20),
    path:    typeof e?.path === 'string' && e.path.startsWith(tmpDir) ? e.path.slice(tmpDir.length + 1) : (e?.path || null),
    message: String(e?.message || '').split(tmpDir + path.sep).join('').split(tmpDir).join('').slice(0, 300),
  }));
  if (scanErrors.length) console.warn(`[GHScan] ${repo} — ${scanErrors.length} Semgrep analysis error(s); scan incomplete`);

  const rawFindings = parsed.results || [];
  let findings;
  try { findings = rawFindings.map(f => {
    const rawPath = f.path || '';
    const relPath = rawPath.startsWith(tmpDir)
      ? rawPath.slice(tmpDir.length + 1)
      : rawPath;

    const ruleId  = f.check_id || '';
    const meta    = f.extra?.metadata || {};
    const normArr = v => Array.isArray(v) ? v : (v ? [v] : []);

    const startLine = f.start?.line || 1;
    const endLine   = f.end?.line   || startLine;

    const codeSnippet = semgrepSnippet(tmpDir, f);

    return {
      ruleId,
      ruleShortName: ruleShortName(ruleId),
      path:          relPath,
      language:      meta.language || meta.languages?.[0] || langFromPath(relPath),
      line:          startLine,
      col:           f.start?.col || null,
      lineEnd:       endLine,
      colEnd:        f.end?.col   || null,
      snippetStart:  startLine,
      severity:      normSev(f.extra?.severity || f.severity),
      message:       f.extra?.message || '',
      codeSnippet,
      fix:           f.extra?.fix || null,
      category:      meta.category    || '',
      likelihood:    meta.likelihood  || '',
      impact:        meta.impact      || '',
      confidence:    meta.confidence  || '',
      cwe:           normArr(meta.cwe),
      owasp:         normArr(meta.owasp),
      references:    normArr(meta.references),
      technology:    normArr(meta.technology),
    };
  }); } finally {
    cleanup(tmpDir);
    console.log(`[GHScan] ${repo} — temp repo cleaned`);
  }

  findings.sort((a,b) => SEV_ORD.indexOf(a.severity) - SEV_ORD.indexOf(b.severity));

  const counts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, UNKNOWN:0 };
  findings.forEach(f => { if (f.severity in counts) counts[f.severity]++; });
  const topSev = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].find(s => counts[s]) || 'NONE';

  console.log(`[GHScan] ${repo} — ${findings.length} findings (${topSev})`);

  const toxic = await checkToxic(repo, { repository: url }).catch(() => ({ found: false }));
  console.log(`[GHScan] ${repo} — toxic: ${toxic.found}`);

  return { repo, url, desc: desc||'', findings, counts, topSev, toxic,
    complete: scanErrors.length === 0, errors: scanErrors.length, errorSamples: scanErrors.slice(0, 20),
    scannedAt: new Date().toISOString() };
  } finally {
    if (workspace) cleanup(workspace);
    release();
  }
  });
});

module.exports = router;
