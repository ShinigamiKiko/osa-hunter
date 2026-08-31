'use strict';

function handles(ecosystem) { return ecosystem === 'Maven'; }

function parse(path) {
  const m = path.match(/^(.+?)\/([^/]+)\/([^/]+)\/\2-\3(?:-[^/]+)?\.(?:jar|pom|module)$/i);
  return m ? { name: `${m[1].replace(/\//g, '.')}:${m[2]}`, version: m[3] } : null;
}

module.exports = { handles, parse };
