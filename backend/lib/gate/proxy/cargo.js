'use strict';

const { Readable } = require('stream');
const { osaBase, fwd } = require('./common');

function handles(ecosystem) { return ecosystem === 'crates.io'; }

function parse(path) {
  const file = path.split('/').pop();
  const m = file.match(/^(.+)-([0-9][^/]*)\.crate$/i);
  if (m) return { name: m[1], version: m[2] };
  const d = path.match(/^(?:api\/v1\/crates\/)?([^/]+)\/([^/]+)\/download$/i);
  return d ? { name: d[1], version: d[2] } : null;
}

async function serveIndex(req, res, repoCfg, repository, artifactPath) {
  if (artifactPath !== 'config.json') return false;
  const f = fwd(repoCfg, repository, artifactPath);
  const headers = { Accept: 'application/json' };
  if (repoCfg.auth) headers.Authorization = repoCfg.auth;
  const upstream = await fetch(`${repoCfg.upstream}${f.path}`, {
    headers, signal: AbortSignal.timeout(30000),
  });
  if (!upstream.ok) { res.status(upstream.status).end(); return true; }
  const config = await upstream.json();
  config.dl = `${osaBase(req)}/${repository}/download`;
  res.json(config);
  return true;
}

async function download(req, res, repoCfg, _repository, artifactPath) {
  const artifact = parse(artifactPath);
  if (!artifact) return res.status(404).json({ error: 'invalid Cargo artifact path' });
  const base = repoCfg.downloadUpstream || repoCfg.upstream;
  const url = `${base}/${encodeURIComponent(artifact.name)}/${encodeURIComponent(artifact.name)}-${encodeURIComponent(artifact.version)}.crate`;
  const headers = { Accept: 'application/octet-stream' };
  const auth = repoCfg.downloadAuth || repoCfg.auth;
  if (auth) headers.Authorization = auth;
  const upstream = await fetch(url, { method: req.method, headers, signal: AbortSignal.timeout(60000) });
  res.status(upstream.status);
  upstream.headers.forEach((value, key) => {
    if (!['content-encoding', 'transfer-encoding', 'connection'].includes(key)) res.setHeader(key, value);
  });
  if (req.method === 'HEAD' || !upstream.body) return res.end();
  return Readable.fromWeb(upstream.body).pipe(res);
}

module.exports = { handles, parse, serveIndex, download };
