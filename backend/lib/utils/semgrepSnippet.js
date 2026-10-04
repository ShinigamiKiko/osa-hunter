'use strict';
const fs = require('node:fs');
const path = require('node:path');

function semgrepSnippet(root, finding) {
  const supplied = typeof finding.extra?.lines === 'string' ? finding.extra.lines.trimEnd() : '';
  if (supplied && !/^requires login\b/i.test(supplied.trim())) return supplied;
  const start = finding.start?.line, end = finding.end?.line ?? start;
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end < start || typeof finding.path !== 'string') return '';
  try {
    const realRoot = fs.realpathSync(root);
    const file = fs.realpathSync(path.resolve(root, finding.path));
    if (!file.startsWith(realRoot + path.sep)) return '';
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > 2 * 1024 * 1024) return '';
    return fs.readFileSync(file, 'utf8').split(/\r?\n/)
      .slice(start - 1, Math.min(end, start + 199)).join('\n').slice(0, 65536).trimEnd();
  } catch { return ''; }
}

module.exports = { semgrepSnippet };
