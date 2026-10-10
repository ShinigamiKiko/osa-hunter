'use strict';

const dns = require('node:dns').promises;
const compileTrust = require('express/lib/utils').compileTrust;

function configureTrustedProxy(app, { addresses = process.env.TRUSTED_PROXIES || '',
  hosts = process.env.TRUSTED_PROXY_HOSTS || '', lookup = dns.lookup } = {}) {
  const fixed = compileTrust(addresses.split(',').map(s => s.trim()).filter(Boolean));
  const names = hosts.split(',').map(s => s.trim()).filter(Boolean);
  let resolved = new Set(), expires = 0, pending;
  const normalize = ip => ip.replace(/^::ffff:/, '');
  app.set('trust proxy', (ip, hop) => hop === 0 && typeof ip === 'string'
    && (fixed(ip) || resolved.has(normalize(ip))));
  return async function refreshProxyAddresses(req, res, next) {
    if (names.length && Date.now() >= expires) {
      if (!pending) pending = Promise.all(names.map(async host => {
        try { return (await lookup(host, { all: true })).map(row => normalize(row.address)); }
        catch { return []; }
      })).then(rows => { resolved = new Set(rows.flat()); expires = Date.now() + 30000; })
        .finally(() => { pending = null; });
      await pending;
    }
    next();
  };
}

module.exports = { configureTrustedProxy };
