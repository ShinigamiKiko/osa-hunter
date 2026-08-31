'use strict';

function handles(ecosystem) {
  return /^(Rocky Linux|AlmaLinux|Red Hat|CentOS|openSUSE|SUSE)\b/.test(ecosystem);
}

function parse(path) {
  const file = path.split('/').pop();
  const m = file.match(/^(.+)-([^-]+)-([^-]+)\.([^.]+)\.rpm$/);
  return m ? { name: m[1], version: `${m[2]}-${m[3]}` } : null;
}

module.exports = { handles, parse };
