(function (root) {
  'use strict';

  const aliases = {
    npm: 'npm', pypi: 'pypi', python: 'pypi', go: 'go',
    cargo: 'rust', crates: 'rust', 'crates.io': 'rust', rust: 'rust',
    maven: 'apachemaven', ruby: 'rubygems', rubygems: 'rubygems',
    nuget: 'nuget', php: 'packagist', packagist: 'packagist', composer: 'composer',
    rhel: 'redhat', alpine: 'alpinelinux', suse: 'opensuse', sles: 'opensuse',
  };

  function classNames(extra) {
    return String(extra || '').split(/\s+/).filter(s => /^[a-z][a-z0-9-]*$/i.test(s)).join(' ');
  }

  function icon(name, extra = '') {
    const body = Object.hasOwn(root.OSA_ICONS.lucide, name)
      ? root.OSA_ICONS.lucide[name] : root.OSA_ICONS.lucide['circle-help'];
    return '<svg class="icon ' + classNames(extra) + '" viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' + body + '</svg>';
  }

  function brandIcon(name, extra = '') {
    const key = String(name || '').toLowerCase();
    const slug = Object.hasOwn(aliases, key) ? aliases[key] : key;
    if (!Object.hasOwn(root.OSA_ICONS.brands, slug)) return icon('package', extra);
    return '<svg class="icon brand-icon ' + classNames(extra) + '" viewBox="0 0 24 24" width="24" height="24" fill="currentColor" aria-hidden="true" focusable="false">' + root.OSA_ICONS.brands[slug] + '</svg>';
  }

  if (typeof module === 'object' && module.exports) {
    module.exports = { icon, brandIcon };
  } else {
    root.icon = icon;
    root.brandIcon = brandIcon;
    document.addEventListener('DOMContentLoaded', () => {
      document.querySelectorAll('[data-icon], [data-brand]').forEach(el => {
        el.innerHTML = el.dataset.brand ? brandIcon(el.dataset.brand) : icon(el.dataset.icon);
      });
    }, { once: true });
  }
})(typeof module === 'object' && module.exports
  ? { OSA_ICONS: require('./icons.js') } : globalThis);
