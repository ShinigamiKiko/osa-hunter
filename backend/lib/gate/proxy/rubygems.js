'use strict';

function handles(ecosystem) { return ecosystem === 'RubyGems'; }

function parse(path) {
  const file = path.split('/').pop();
  const m = file.match(/^(.+)-([0-9][^/]*)\.gem$/i);
  return m ? { name: m[1], version: m[2] } : null;
}

module.exports = { handles, parse };
