'use strict';

const { Readable, Transform } = require('stream');
const { pipeline } = require('stream/promises');

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
  return streamResponse(req, res, upstream);
}

async function streamResponse(req, res, upstream) {
  const length = Number(upstream.headers.get('content-length'));
  if (Number.isFinite(length) && length > MAX_PROXY_BYTES) {
    await upstream.body?.cancel();
    return res.status(413).json({ error: 'Upstream artifact exceeds gateway response limit' });
  }
  res.status(upstream.status);
  upstream.headers.forEach((value, key) => {
    const decoded = req.method !== 'HEAD' && upstream.headers.get('content-encoding')
      && upstream.headers.get('content-encoding') !== 'identity';
    if (!['transfer-encoding', 'connection'].includes(key)
        && !(decoded && ['content-encoding', 'content-length'].includes(key))) res.setHeader(key, value);
  });
  if (req.method === 'HEAD' || !upstream.body) { await upstream.body?.cancel(); return res.end(); }
  let bytes = 0;
  const limit = new Transform({ transform(chunk, encoding, done) {
    bytes += chunk.length;
    done(bytes > MAX_PROXY_BYTES ? new Error('Upstream artifact exceeds gateway response limit') : null, chunk);
  } });
  try { await pipeline(Readable.fromWeb(upstream.body), limit, res); }
  catch (error) {
    // pipeline cancels the source and destroys the response on failure. Never
    // send JSON after a partial artifact, or let a stream error escape globally.
    console.warn('[gate/stream]', error.message);
    if (!res.destroyed) res.destroy(error);
  }
}

module.exports = { osaBase, fwd, proxyResponse, streamResponse };
