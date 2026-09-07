'use strict';

// express.json() rejects a malformed or oversized body by throwing, and without
// this the generic error handler turns that into "500 Internal server error"
// with a stack trace in the log - as if the server had broken, when in fact the
// client sent something it should be told about.
//
// Mount immediately after the express.json() middlewares.
function jsonBodyErrors(err, req, res, next) {
  if (!err || res.headersSent) return next(err);

  // body-parser tags what went wrong; SyntaxError covers older versions.
  const type = err.type;
  if (type === 'entity.parse.failed' || (err instanceof SyntaxError && 'body' in err)) {
    return res.status(400).json({ error: 'Request body is not valid JSON' });
  }
  if (type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body too large' });
  }
  if (type === 'encoding.unsupported') {
    return res.status(415).json({ error: 'Unsupported content encoding' });
  }
  return next(err);
}

module.exports = { jsonBodyErrors };
