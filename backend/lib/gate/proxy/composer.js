'use strict';

const { getPool } = require('../../auth/db');
const { osaBase, fwd, streamResponse } = require('./common');

function handles(ecosystem) { return ecosystem === 'Packagist'; }

function allowedDownloadUrl(value, repoCfg) {
  let url;
  try { url = new URL(value); } catch { return false; }
  if (url.username || url.password) return false;
  if (url.origin === new URL(repoCfg.upstream).origin) return true;
  if (url.protocol !== 'https:') return false;

  const configured = (process.env.OSA_COMPOSER_DOWNLOAD_HOSTS || '')
    .split(',').map(host => host.trim().toLowerCase()).filter(Boolean);
  const upstreamHost = new URL(repoCfg.upstream).hostname.toLowerCase();
  const allowed = new Set(configured.length ? configured : [
    upstreamHost, 'github.com', 'api.github.com', 'codeload.github.com',
    'gitlab.com', 'bitbucket.org',
  ]);
  const host = url.hostname.toLowerCase();
  if (!allowed.has(host)) return false;
  if (host === 'localhost' || host.endsWith('.localhost')
      || /^(127\.|10\.|192\.168\.|169\.254\.)/.test(host)
      || /^(172\.(?:1[6-9]|2\d|3[0-1])\.)/.test(host)
      || host === '::1') return false;
  return true;
}

async function fetchDownload(url, repoCfg, method = 'GET') {
  if (!allowedDownloadUrl(url, repoCfg)) throw new Error('Composer download URL is not trusted');
  let current = url;
  for (let redirects = 0; redirects <= 3; redirects++) {
    const response = await fetch(current, {
      headers: { 'User-Agent': 'osa-gate', Accept: 'application/zip, application/octet-stream' },
      redirect: 'manual', signal: AbortSignal.timeout(60000),
      method,
    });
    if (response.status < 300 || response.status >= 400) return response;
    const location = response.headers.get('location');
    await response.body?.cancel();
    if (!location) throw new Error('Composer download redirect has no location');
    current = new URL(location, current).toString();
    if (!allowedDownloadUrl(current, repoCfg)) throw new Error('Composer download redirect is not trusted');
  }
  throw new Error('Composer download redirect limit exceeded');
}

// We generate this download path inside the p2 metadata we serve:
//   dist/<vendor>/<pkg>/<version>.zip
function parse(path) {
  const m = path.match(/^dist\/([^/]+\/[^/]+)\/(.+)\.zip$/);
  return m ? { name: m[1], version: decodeURIComponent(m[2]) } : null;
}

// Remember the real (github) dist URL for a gated download path.
async function remember(repository, artifactPath, name, version, url) {
  await getPool().query(
    `INSERT INTO proxy_artifacts (artifact_path, ecosystem, package_name, version, url)
     VALUES ($1,'Packagist',$2,$3,$4)
     ON CONFLICT (artifact_path) DO UPDATE SET package_name=EXCLUDED.package_name,
       version=EXCLUDED.version, url=EXCLUDED.url, approved_at=NOW()`,
    [`Packagist:${repository}/${artifactPath}`, name, version, url]
  );
}

function expandVersions(versions) {
  let previous = {};
  return versions.map(version => {
    const current = { ...previous };
    for (const [key, value] of Object.entries(version)) {
      if (value === '__unset') delete current[key]; else current[key] = value;
    }
    previous = current;
    return structuredClone(current);
  });
}

// Serve the two metadata layers. packages.json: strip mirrors + pin a relative
// metadata-url so composer stays on the gate. p2/<vendor>/<pkg>.json: rewrite
// every version's dist.url to a gated path and remember the real URL.
async function serveIndex(req, res, repoCfg, repository, artifactPath) {
  const isRoot = artifactPath === 'packages.json' || artifactPath === '';
  const isP2 = /^p2\/.+\.json$/.test(artifactPath);
  if (!isRoot && !isP2) return false;

  const f = fwd(repoCfg, repository, artifactPath || 'packages.json');
  const headers = { Accept: 'application/json' };
  if (repoCfg.auth) headers.Authorization = repoCfg.auth;
  const upstream = await fetch(`${repoCfg.upstream}${f.path}`, { headers, signal: AbortSignal.timeout(30000) });
  if (!upstream.ok) { res.status(upstream.status).end(); return true; }
  const doc = await upstream.json();
  const base = `${osaBase(req)}/${repository}`;

  if (isRoot) {
    // Minimal v2 root: per-package metadata only, via an ABSOLUTE url on the
    // gate (a leading-slash metadata-url would resolve against the host root and
    // drop /api/gate/<repo>). Dropping every packagist-absolute endpoint means
    // composer has no channel to packagist that bypasses the gate.
    res.json({ packages: {}, 'metadata-url': `${base}/p2/%package%.json` });
    return true;
  }

  delete doc['security-advisories']; // OSA is the gate; drop composer's embedded audit
  const minified = doc.minified === 'composer/2.0';
  if (doc.minified && !minified) throw new Error('Unsupported Composer metadata minification');
  delete doc.minified;
  const pkgs = doc.packages || {};
  for (const [name, versions] of Object.entries(pkgs)) {
    if (!Array.isArray(versions)) continue;
    const usable = [];
    for (const v of (minified ? expandVersions(versions) : versions)) {
      if (v && v.dist && v.dist.url && v.version && allowedDownloadUrl(v.dist.url, repoCfg)) {
        const synth = `dist/${name}/${encodeURIComponent(v.version)}.zip`;
        await remember(repository, synth, name, v.version, v.dist.url);
        v.dist.url = `${base}/${synth}`;
        delete v.dist.mirrors;
        delete v.source;
        usable.push(v);
      }
    }
    pkgs[name] = usable;
  }
  res.json(doc);
  return true;
}

// Stream a remembered dist through the gate (real url stored during p2 serve).
async function download(req, res, repoCfg, repository, artifactPath) {
  const key = artifactPath.replace(/^\/+/, '');
  const { rows } = await getPool().query('SELECT url FROM proxy_artifacts WHERE artifact_path=$1', [`Packagist:${repository}/${key}`]);
  const url = rows[0] && rows[0].url;
  if (!url) return res.status(404).json({ error: 'composer dist not resolved (fetch package metadata first)' });
  if (!allowedDownloadUrl(url, repoCfg)) {
    console.warn(`[composer] blocked untrusted dist URL for ${key}`);
    return res.status(502).json({ error: 'Composer dist URL is not trusted' });
  }
  const upstream = await fetchDownload(url, repoCfg, req.method);
  return streamResponse(req, res, upstream);
}

module.exports = { handles, parse, serveIndex, download, allowedDownloadUrl, fetchDownload, expandVersions };
