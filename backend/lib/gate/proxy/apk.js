'use strict';

function handles(ecosystem) { return ecosystem.startsWith('Alpine'); }

function parse(path) {
  const file = path.split('/').pop();
  const m = file.match(/^(.+)-([^-]+-r\d+)\.apk$/);
  return m ? { name: m[1], version: m[2] } : null;
}

function passIndex(path) {
  return /APKINDEX\.tar\.gz$/i.test(path);
}

module.exports = { handles, parse, passIndex };
