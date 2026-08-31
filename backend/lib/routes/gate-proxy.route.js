'use strict';

const express = require('express');
const router = express.Router();
const { getPool } = require('../auth/db');
const { cachedGate } = require('../gate/service');
const { fwd, proxyResponse } = require('../gate/proxy/common');
const { ARTIFACT_EXT, metadataAllowed } = require('../gate/proxy/path-policy');
const { gatewayLimiter, rateLimit } = require('../shared');

const ADAPTERS = [
  require('../gate/proxy/npm'),
  require('../gate/proxy/pypi'),
  require('../gate/proxy/apk'),
  require('../gate/proxy/rpm'),
  require('../gate/proxy/debian'),
  require('../gate/proxy/go'),
  require('../gate/proxy/maven'),
  require('../gate/proxy/nuget'),
  require('../gate/proxy/cargo'),
  require('../gate/proxy/rubygems'),
  require('../gate/proxy/composer'),
];
const adapterFor = ecosystem => ADAPTERS.find(a => a.handles(ecosystem)) || null;

const DEFAULT_UPSTREAM = (process.env.NEXUS_UPSTREAM || 'http://nexus:8081').replace(/\/$/, '');
const DEFAULT_AUTH = process.env.NEXUS_AUTH || null;
const STRICT = process.env.OSA_NEXUS_STRICT !== 'false';
const REPOSITORIES = loadRepositories();
const MAX_ACTIVE = Math.max(parseInt(process.env.GATE_MAX_ACTIVE || '16', 10), 1);
let activeRequests = 0;

router.use(rateLimit(gatewayLimiter), (req, res, next) => {
  if (activeRequests >= MAX_ACTIVE) return res.status(429).json({ error: 'Gateway busy; retry later' });
  activeRequests++;
  let released = false;
  const release = () => {
    if (!released) { released = true; activeRequests--; }
  };
  res.once('finish', release);
  res.once('close', release);
  next();
});

function loadRepositories() {
  let value;
  try {
    value = JSON.parse(process.env.OSA_NEXUS_REPOSITORIES || '{}');
  } catch {
    throw new Error('OSA_NEXUS_REPOSITORIES must be valid JSON');
  }
  const out = {};
  for (const [repo, cfg] of Object.entries(value)) {
    if (typeof cfg === 'string') {
      out[repo] = { ecosystem: cfg, upstream: DEFAULT_UPSTREAM, auth: DEFAULT_AUTH, direct: false };
    } else if (cfg && typeof cfg === 'object' && cfg.ecosystem) {
      out[repo] = {
        ecosystem: String(cfg.ecosystem),
        upstream: (cfg.upstream || DEFAULT_UPSTREAM).replace(/\/$/, ''),
        auth: cfg.auth || DEFAULT_AUTH,
        downloadUpstream: cfg.downloadUpstream ? String(cfg.downloadUpstream).replace(/\/$/, '') : null,
        downloadAuth: cfg.downloadAuth || null,
        direct: cfg.direct === true,
      };
    } else {
      throw new Error(`OSA_NEXUS_REPOSITORIES["${repo}"] must be an ecosystem string or { ecosystem, upstream?, auth? }`);
    }
  }
  return out;
}

function parseArtifact(repository, artifactPath) {
  const repoCfg = REPOSITORIES[repository];
  if (!repoCfg) return null;
  const adapter = adapterFor(repoCfg.ecosystem);
  if (!adapter) return null;
  const path = decodeURIComponent(artifactPath).replace(/^\/+/, '');
  const r = adapter.parse(path);
  return r ? { ecosystem: repoCfg.ecosystem, ...r } : null;
}

function reasonPhrase(reasons) {
  const parts = (reasons || []).map(r => {
    const cve = (r.detail || '').match(/CVE-\d{4}-\d+/);
    return cve ? `${r.rule}: ${cve[0]}` : r.rule;
  });
  return `Blocked by OSA gate (${parts.join(', ') || 'policy'})`.replace(/[^\x20-\x7E]/g, '').slice(0, 150);
}

function recordEvent(req, { decision, ecosystem, name, version, repository, reasons }) {
  const ip = req.ip || null;
  getPool().query(
    `INSERT INTO proxy_events (ecosystem, package_name, version, repository, decision, reasons, client_ip)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [ecosystem || null, name || null, version || null, repository || null, decision, reasons || null, ip]
  ).catch(e => console.error('[gate] event log failed:', e.message));
  if (decision === 'deny') {
    getPool().query(
      `INSERT INTO gate_denials (ecosystem, package_name, version, repository, rules, detail, client_ip)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [ecosystem || null, name || null, version || null, repository || null, reasons || null, reasons || null, ip]
    ).catch(() => {});
  }
}

router.all('/*', async (req, res) => {
  // The open endpoint is read-only: only fetching packages/metadata.
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return res.status(405).json({ error: 'method not allowed' });
  }
  const pathOnly = req.originalUrl.split('?')[0].replace(/^\/api\/gate/, '') || '/';
  let decodedPath = pathOnly;
  try { decodedPath = decodeURIComponent(pathOnly); } catch { /* keep raw */ }
  if (/\.\.(\/|\\|$)/.test(decodedPath) || /[\x00-\x1f\x7f]/.test(pathOnly)
      || decodedPath.includes('\\') || decodedPath.includes('://')) {
    return res.status(400).json({ error: 'invalid path' });
  }
  const parts = pathOnly.replace(/^\/+/, '').split('/');
  if (!parts[0]) return res.status(400).json({ error: 'Expected /api/gate/<repo>/...' });

  try {
    const repository = decodeURIComponent(parts[0]);
    const repoCfg = REPOSITORIES[repository];
    if (!repoCfg) return res.status(404).json({ error: `unknown repo "${repository}"` });
    const adapter = adapterFor(repoCfg.ecosystem);
    if (!adapter) return res.status(400).json({ error: `unsupported ecosystem "${repoCfg.ecosystem}"` });
    const artifactPath = parts.slice(1).join('/');
    const query = req.originalUrl.includes('?') ? `?${req.originalUrl.split('?')[1]}` : '';
    const artifact = parseArtifact(repository, artifactPath);

    if (!artifact && req.method === 'GET' && adapter.serveIndex) {
      if (await adapter.serveIndex(req, res, repoCfg, repository, artifactPath)) return;
    }

    const isIndex = adapter.passIndex ? adapter.passIndex(artifactPath) : false;
    if (!artifact && !isIndex && STRICT && ARTIFACT_EXT.test(artifactPath)) {
      console.warn(`[gate] DENY ${repository}/${artifactPath} -> unparseable-artifact`);
      res.setHeader('X-OSA-Deny-Reason', 'artifact path could not be evaluated');
      res.statusMessage = 'Blocked by OSA gate (unparseable-artifact)';
      recordEvent(req, { decision: 'deny', ecosystem: repoCfg.ecosystem, repository, reasons: 'unparseable-artifact' });
      return res.status(403).json({ error: 'Artifact path could not be evaluated by OSA gate' });
    }

    if (artifact) {
      const verdict = await cachedGate(artifact);
      if (verdict.decision === 'deny') {
        const why = (verdict.reasons || []).map(r => `${r.rule}: ${r.detail}`).join('; ') || 'policy';
        const rules = (verdict.reasons || []).map(r => r.rule).join(',') || 'policy';
        console.warn(`[gate] DENY ${artifact.ecosystem} ${artifact.name}@${artifact.version} -> ${why}`);
        res.setHeader('X-OSA-Deny-Reason', why);
        res.statusMessage = reasonPhrase(verdict.reasons);
        recordEvent(req, { decision: 'deny', ecosystem: artifact.ecosystem, name: artifact.name, version: artifact.version, repository, reasons: rules });
        return res.status(403).json({ error: 'Artifact blocked by OSA gate', reasons: verdict.reasons });
      }
      recordEvent(req, { decision: 'allow', ecosystem: artifact.ecosystem, name: artifact.name, version: artifact.version, repository });
      if (adapter.download) return await adapter.download(req, res, repoCfg, repository, artifactPath);
      return await proxyResponse(req, res, fwd(repoCfg, repository, artifactPath).path + query, repoCfg);
    }

    if (isIndex || metadataAllowed(repoCfg.ecosystem, artifactPath)) {
      return await proxyResponse(req, res, fwd(repoCfg, repository, artifactPath).path + query, repoCfg);
    }
    return res.status(404).json({ error: 'not a package or recognized metadata path' });
  } catch (error) {
    return res.status(error.status || 502).json({ error: error.message || 'gate proxy failed' });
  }
});

module.exports = { router, parseArtifact, metadataAllowed };
