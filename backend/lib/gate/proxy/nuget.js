'use strict';

const { Readable } = require('stream');
const { osaBase, fwd } = require('./common');

function handles(ecosystem) { return ecosystem === 'NuGet'; }

function parse(path) {
  const m = path.match(/^([^/]+)\/([^/]+)\/\1\.\2\.nupkg$/i)
    || path.match(/^([^/]+)\.([0-9][^/]*)\.nupkg$/i);
  return m ? { name: m[1], version: m[2] } : null;
}

async function serveIndex(req, res, repoCfg, repository, artifactPath) {
  const isServiceIndex = artifactPath === 'index.json';
  const isPackageIndex = /^[^/]+\/index\.json$/i.test(artifactPath);
  if (!isServiceIndex && !isPackageIndex) return false;
  const base = isPackageIndex ? (repoCfg.downloadUpstream || repoCfg.upstream) : repoCfg.upstream;
  const f = isPackageIndex
    ? { path: `/${artifactPath}` }
    : fwd(repoCfg, repository, artifactPath);
  const headers = { Accept: 'application/json' };
  if (repoCfg.auth) headers.Authorization = repoCfg.auth;
  const upstream = await fetch(`${base}${f.path}`, {
    headers, signal: AbortSignal.timeout(30000),
  });
  if (!upstream.ok) { res.status(upstream.status).end(); return true; }
  const doc = await upstream.json();
  if (isServiceIndex) {
    const target = `${osaBase(req)}/${repository}/`;
    const sources = [`${repoCfg.upstream}/`, `${repoCfg.downloadUpstream || ''}/`].filter(Boolean);
    for (const resource of doc.resources || []) {
      if (typeof resource?.['@id'] !== 'string') continue;
      const source = sources.find(value => resource['@id'].startsWith(value));
      if (source) resource['@id'] = target + resource['@id'].slice(source.length);
    }
  }
  res.json(doc);
  return true;
}

async function download(req, res, repoCfg, _repository, artifactPath) {
  const base = repoCfg.downloadUpstream || repoCfg.upstream;
  const headers = { Accept: 'application/octet-stream' };
  const auth = repoCfg.downloadAuth || repoCfg.auth;
  if (auth) headers.Authorization = auth;
  const upstream = await fetch(`${base}/${artifactPath}`, {
    method: req.method, headers, signal: AbortSignal.timeout(60000),
  });
  res.status(upstream.status);
  upstream.headers.forEach((value, key) => {
    if (!['content-encoding', 'transfer-encoding', 'connection'].includes(key)) res.setHeader(key, value);
  });
  if (req.method === 'HEAD' || !upstream.body) return res.end();
  return Readable.fromWeb(upstream.body).pipe(res);
}

module.exports = { handles, parse, serveIndex, download };
