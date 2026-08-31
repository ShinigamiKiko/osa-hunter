'use strict';

function handles(ecosystem) { return ecosystem === 'NuGet'; }

function parse(path) {
  const m = path.match(/^([^/]+)\/([^/]+)\/\1\.\2\.nupkg$/i)
    || path.match(/^([^/]+)\.([0-9][^/]*)\.nupkg$/i);
  return m ? { name: m[1], version: m[2] } : null;
}

module.exports = { handles, parse };
