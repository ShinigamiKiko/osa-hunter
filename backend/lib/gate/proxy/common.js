'use strict';

const { Readable } = require('stream');

const MAX_PROXY_BYTES = Math.max(parseInt(process.env.GATE_MAX_RESPONSE_BYTES || String(512 * 1024 * 1024), 10), 1);

function osaBase(req) {
  return `${req.protocol}://${req.get('host')}${req.baseUrl}`;
}

function fwd(repoCfg, repository, artifactPath) {
  const prefix = repoCfg.direct ? '' : `/repository/${repository}`;
  return { path: `${prefix}/${artifactPath}`, srcPrefix: `${repoCfg.upstream}${prefix}` };
}

async function proxyResponse(req, res, forwardPath, repoCfg) {
  const headers = { Accept: req.headers.accept || '*/*' };
  if (repoCfg?.auth) headers.Authorization = repoCfg.auth;
  const upstream = await fetch(`${repoCfg.upstream}${forwardPath}`, {
    method: req.method, headers, signal: AbortSignal.timeout(60000),
  });
  const length = Number(upstream.headers.get('content-length'));
  if (Number.isFinite(length) && length > MAX_PROXY_BYTES) {
    await upstream.body?.cancel();
    return res.status(413).json({ error: 'Upstream artifact exceeds gateway response limit' });
  }
  res.status(upstream.status);
  upstream.headers.forEach((value, key) => {
    if (!['content-encoding', 'transfer-encoding', 'connection'].includes(key)) res.setHeader(key, value);
  });
  if (req.method === 'HEAD' || !upstream.body) return res.end();
  return Readable.fromWeb(upstream.body).pipe(res);
}

module.exports = { osaBase, fwd, proxyResponse };
