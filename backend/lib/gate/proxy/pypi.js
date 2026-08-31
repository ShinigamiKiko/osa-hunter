'use strict';

const { osaBase, fwd } = require('./common');

function handles(ecosystem) { return ecosystem === 'PyPI'; }

function parse(path) {
  const file = path.split('/').pop();
  const m = file.match(/^(.+?)-(\d+(?:\.\d+)+(?:[a-z]+\d*)?)(?:-[^-]+)*\.(?:whl|tar\.gz|zip)$/i);
  return m ? { name: m[1].replace(/_/g, '-'), version: m[2] } : null;
}

async function serveIndex(req, res, repoCfg, repository, artifactPath) {
  if (!/^simple(?:\/[^/]+)?\/?$/i.test(artifactPath)) return false;
  const f = fwd(repoCfg, repository, artifactPath);
  const headers = { Accept: req.headers.accept || '*/*' };
  if (repoCfg.auth) headers.Authorization = repoCfg.auth;
  const upstream = await fetch(`${repoCfg.upstream}${f.path}`, { headers, signal: AbortSignal.timeout(30000) });
  if (!upstream.ok) { res.status(upstream.status).end(); return true; }

  const target = `${osaBase(req)}/${repository}`;
  const body = (await upstream.text()).split(f.srcPrefix).join(target);
  res.status(upstream.status);
  const contentType = upstream.headers.get('content-type');
  if (contentType) res.setHeader('content-type', contentType);
  res.send(body);
  return true;
}

module.exports = { handles, parse, serveIndex };
