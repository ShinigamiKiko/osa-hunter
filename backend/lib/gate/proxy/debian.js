'use strict';

function handles(ecosystem) {
  return ecosystem.startsWith('Debian') || ecosystem.startsWith('Ubuntu');
}

function parse(path) {
  const file = path.split('/').pop();
  const m = file.match(/^([^_]+)_([^_]+)_[^_]+\.deb$/);
  return m ? { name: m[1], version: decodeURIComponent(m[2]) } : null;
}

module.exports = { handles, parse };
