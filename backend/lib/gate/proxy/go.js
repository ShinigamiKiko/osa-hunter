'use strict';

function handles(ecosystem) { return ecosystem === 'Go'; }

function parse(path) {
  const m = path.match(/^(.+?)\/@v\/(v[^/]+)\.(zip|mod|info)$/);
  return m ? { name: m[1], version: m[2] } : null;
}

module.exports = { handles, parse };
