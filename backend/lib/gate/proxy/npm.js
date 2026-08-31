'use strict';

const { osaBase, fwd } = require('./common');

function handles(ecosystem) { return ecosystem === 'npm'; }

function parse(path) {
  const m = path.match(/^(.+?)\/-\/([^/]+)\.tgz$/);
  if (!m) return null;
  const name = m[1];
  const leaf = name.split('/').pop();
  const version = m[2].startsWith(`${leaf}-`) ? m[2].slice(leaf.length + 1) : null;
  return version ? { name, version } : null;
}

async function serveIndex(req, res, repoCfg, repository, artifactPath) {
  if (!/^(?:@[^/]+\/[^/]+|[^/]+)$/.test(artifactPath) || artifactPath.endsWith('.tgz')) return false;
  const f = fwd(repoCfg, repository, artifactPath);
  const headers = { Accept: 'application/json' };
  if (repoCfg.auth) headers.Authorization = repoCfg.auth;
  const upstream = await fetch(`${repoCfg.upstream}${f.path}`, { headers, signal: AbortSignal.timeout(30000) });
  if (!upstream.ok) { res.status(upstream.status).end(); return true; }

  const doc = await upstream.json();
  const target = `${osaBase(req)}/${repository}`;
  const rewrite = u => (typeof u === 'string' && u.startsWith(f.srcPrefix)) ? target + u.slice(f.srcPrefix.length) : u;
  if (doc.versions) {
    for (const v of Object.values(doc.versions)) {
      if (v?.dist?.tarball) v.dist.tarball = rewrite(v.dist.tarball);
    }
  }
  res.json(doc);
  return true;
}

module.exports = { handles, parse, serveIndex };
