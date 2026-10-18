'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const express = require('express');
const { version } = require('../package.json');

test('/api/health reports the OSA Hunter version from package.json', async () => {
  const app = express();
  app.use('/api', require('../lib/routes/health.route'));
  const server = app.listen(0);
  await new Promise(resolve => server.once('listening', resolve));
  try {
    const r = await fetch(`http://127.0.0.1:${server.address().port}/api/health`);
    assert.equal((await r.json()).appVersion, version);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('the UI shows the version that /api/health reports', async () => {
  const el = () => ({ hidden: true, textContent: '', className: '', innerHTML: '', style: {},
    classList: { add() {}, remove() {}, toggle() {} }, setAttribute() {}, querySelectorAll: () => [] });
  const labels = [el(), el()];
  const ctx = { console, Promise, setInterval() {},
    fetch: async () => ({ ok: true, headers: { get: () => 'application/json' }, json: async () => ({ trivy: true, appVersion: '1.0.0' }) }),
    document: { addEventListener() {}, getElementById: () => el(),
      querySelectorAll: selector => selector === '.app-version' ? labels : [] },
  };
  ctx.window = ctx; vm.createContext(ctx);
  for (const file of ['icons.js', 'icon-renderer.js', 'utils.js', 'ui-nav.js'])
    vm.runInContext(fs.readFileSync(path.join(__dirname, '../../frontend/public/js', file), 'utf8'), ctx, { filename: file });
  await new Promise(resolve => setImmediate(resolve));
  for (const label of labels) {
    assert.equal(label.textContent, 'OSA Hunter 1.0.0');
    assert.equal(label.hidden, false);
  }
});
