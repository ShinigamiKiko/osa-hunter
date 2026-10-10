'use strict';

const { createHash } = require('node:crypto');
const { getPool } = require('../../auth/db');
const { osaBase, fwd, proxyResponse, streamResponse } = require('./common');
const { esc } = require('../../pdf/style');

function handles(ecosystem) { return ecosystem === 'PyPI'; }
const canonical = name => name.toLowerCase().replace(/[-_.]+/g, '-');

function parse(path) {
  const mapped = path.match(/^files\/([^/]+)\/([^/]+)\/[a-f0-9]{64}\/[^/]+$/);
  if (mapped) return { name: mapped[1], version: mapped[2] };
  const file = path.split('/').pop().replace(/\.metadata$/, '');
  const m = file.endsWith('.whl') ? file.match(/^([^-]+)-([^-]+)-.+\.whl$/i)
    : file.match(/^(.+?)-([0-9][a-z0-9.!+_-]*)\.(?:tar\.gz|zip|tar\.bz2|tgz)$/i);
  return m ? { name: canonical(m[1]), version: m[2] } : null;
}

function allowedUrl(value, repoCfg) {
  const url = new URL(value);
  return !url.username && !url.password && (url.origin === new URL(repoCfg.upstream).origin
    || url.origin === 'https://files.pythonhosted.org');
}

async function fetchDownload(value, repoCfg, method) {
  let url = value;
  for (let redirects = 0; redirects <= 3; redirects++) {
    if (!allowedUrl(url, repoCfg)) throw new Error('PyPI download URL is not trusted');
    const headers = { Accept: '*/*' };
    if (new URL(url).origin === new URL(repoCfg.upstream).origin && repoCfg.auth) headers.Authorization = repoCfg.auth;
    const response = await fetch(url, { method, headers, redirect: 'manual', signal: AbortSignal.timeout(60000) });
    if (response.status < 300 || response.status >= 400) return response;
    const location = response.headers.get('location');
    await response.body?.cancel();
    if (!location) throw new Error('PyPI download redirect has no location');
    url = new URL(location, url).toString();
  }
  throw new Error('PyPI download redirect limit exceeded');
}

async function serveIndex(req, res, repoCfg, repository, artifactPath) {
  if (!/^simple(?:\/[^/]+)?\/?$/i.test(artifactPath)) return false;
  const f = fwd(repoCfg, repository, artifactPath);
  const originUrl = `${repoCfg.upstream}${f.path}`;
  const headers = { Accept: req.headers.accept || '*/*' };
  if (repoCfg.auth) headers.Authorization = repoCfg.auth;
  const upstream = await fetch(originUrl, { headers, signal: AbortSignal.timeout(30000) });
  if (!upstream.ok) { res.status(upstream.status).end(); return true; }
  const target = `${osaBase(req)}/${repository}`;
  async function rewrite(raw) {
    const url = new URL(raw, originUrl);
    if (!allowedUrl(url.href, repoCfg)) throw new Error('PyPI index contains an untrusted URL');
    const identity = parse(decodeURIComponent(url.pathname));
    if (identity) {
      const hash = url.hash;
      url.hash = '';
      const token = createHash('sha256').update(url.href).digest('hex');
      const filename = url.pathname.split('/').pop();
      const synth = `files/${encodeURIComponent(identity.name)}/${encodeURIComponent(identity.version)}/${token}/${filename}`;
      await getPool().query(`INSERT INTO proxy_artifacts (artifact_path, ecosystem, package_name, version, url)
        VALUES ($1,'PyPI',$2,$3,$4) ON CONFLICT (artifact_path) DO UPDATE SET
        package_name=EXCLUDED.package_name, version=EXCLUDED.version, url=EXCLUDED.url, approved_at=NOW()`,
      [`PyPI:${repository}/${synth}`, identity.name, identity.version, url.href]);
      return `${target}/${synth}${hash}`;
    }
    const prefix = new URL(f.srcPrefix).pathname.replace(/\/$/, '') + '/simple/';
    if (url.origin !== new URL(repoCfg.upstream).origin || !url.pathname.startsWith(prefix)) {
      throw new Error('PyPI index artifact identity could not be evaluated');
    }
    return target + url.href.slice(f.srcPrefix.length);
  }
  const contentType = upstream.headers.get('content-type') || 'text/html';
  if (contentType.includes('json')) {
    const doc = await upstream.json();
    for (const file of doc.files || []) file.url = await rewrite(file.url);
    res.type(contentType).json(doc);
  } else {
    const html = await upstream.text();
    const matches = [...html.matchAll(/\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`]+))/gi)];
    let body = '', cursor = 0;
    for (const match of matches) {
      body += html.slice(cursor, match.index);
      const raw = (match[1] ?? match[2] ?? match[3]).replace(/&amp;/g, '&').replace(/&#(?:x([a-f0-9]+)|(\d+));/gi,
        (_, hex, dec) => String.fromCodePoint(parseInt(hex || dec, hex ? 16 : 10)));
      body += `href="${esc(await rewrite(raw))}"`;
      cursor = match.index + match[0].length;
    }
    body += html.slice(cursor);
    res.type(contentType).send(body);
  }
  return true;
}

async function download(req, res, repoCfg, repository, artifactPath) {
  if (!artifactPath.startsWith('files/')) return proxyResponse(req, res, fwd(repoCfg, repository, artifactPath).path, repoCfg);
  const sidecar = artifactPath.endsWith('.metadata');
  const key = sidecar ? artifactPath.slice(0, -9) : artifactPath;
  const { rows } = await getPool().query("SELECT url FROM proxy_artifacts WHERE artifact_path=$1 AND ecosystem='PyPI'", [`PyPI:${repository}/${key}`]);
  if (!rows[0]?.url) return res.status(404).json({ error: 'PyPI file not resolved (fetch package metadata first)' });
  const url = new URL(rows[0].url);
  if (sidecar) url.pathname += '.metadata';
  return streamResponse(req, res, await fetchDownload(url.href, repoCfg, req.method));
}

module.exports = { handles, parse, serveIndex, download, allowedUrl, fetchDownload };
