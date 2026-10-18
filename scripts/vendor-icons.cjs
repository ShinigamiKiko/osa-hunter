'use strict';

// Run with extracted lucide-static and simple-icons package directories.
const fs = require('node:fs');
const path = require('node:path');
const [lucideDir, brandsDir] = process.argv.slice(2);
if (!lucideDir || !brandsDir) throw new Error('Usage: node scripts/vendor-icons.cjs <lucide-static> <simple-icons>');
const root = path.join(__dirname, '..');
const lucide = [
  'activity', 'arrow-down', 'arrow-left', 'arrow-right', 'arrow-up', 'bug', 'check',
  'chevron-down', 'chevron-right', 'circle-help', 'copy', 'download',
  'external-link', 'file-search', 'flame', 'key-round', 'loader-circle', 'log-out',
  'package', 'play', 'refresh-cw', 'shield-check', 'skull', 'star', 'triangle-alert',
  'users', 'x', 'zap',
];
const brands = [
  'alpinelinux', 'apachemaven', 'composer', 'debian', 'docker', 'go', 'npm', 'nuget',
  'opensuse', 'packagist', 'pypi', 'redhat', 'rubygems', 'rust', 'ubuntu',
];
function readIcons(dir, names) {
  return Object.fromEntries(names.map(name => {
    const svg = fs.readFileSync(path.join(dir, 'icons', name + '.svg'), 'utf8');
    const body = svg.replace(/^[\s\S]*?<svg\b[^>]*>/, '').replace(/<\/svg>\s*$/, '')
      .replace(/<title>[\s\S]*?<\/title>/g, '').trim();
    if (/<(?:script|image|use|foreignObject)\b|\bon\w+=|\b(?:href|style)=/i.test(body)) {
      throw new Error('Unexpected SVG content in ' + name);
    }
    return [name, body];
  }));
}
const data = { lucide: readIcons(lucideDir, lucide), brands: readIcons(brandsDir, brands) };
const script = "// Selected upstream SVG paths. Refresh with scripts/vendor-icons.cjs.\n" +
  "(function(root){\n  const icons = " + JSON.stringify(data, null, 2) +
  ";\n  if (typeof module === 'object' && module.exports) module.exports = icons;\n  else root.OSA_ICONS = icons;\n})(globalThis);\n";
fs.writeFileSync(path.join(root, 'frontend/public/js/icons.js'), script);
const dest = path.join(root, 'frontend/public/assets/icons');
fs.mkdirSync(dest, { recursive: true });
fs.copyFileSync(path.join(lucideDir, 'LICENSE'), path.join(dest, 'Lucide-LICENSE.txt'));
fs.copyFileSync(path.join(brandsDir, 'LICENSE.md'), path.join(dest, 'Simple-Icons-LICENSE.txt'));
fs.copyFileSync(path.join(brandsDir, 'DISCLAIMER.md'), path.join(dest, 'Simple-Icons-DISCLAIMER.md'));
console.log('Vendored ' + lucide.length + ' Lucide icons and ' + brands.length + ' brand logos.');
