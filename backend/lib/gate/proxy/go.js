'use strict';

function handles(ecosystem) { return ecosystem === 'Go'; }

function parse(path) {
  const m = path.match(/^(.+?)\/@v\/(v[^/]+)\.(zip|mod|info)$/);
  if (!m || m.slice(1, 3).some(value => /!(?![a-z])|[A-Z]/.test(value))) return null;
  const unescape = value => value.replace(/!([a-z])/g, (_, c) => c.toUpperCase());
  return { name: unescape(m[1]), version: unescape(m[2]) };
}

module.exports = { handles, parse };
