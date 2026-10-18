'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');

// The ecosystem ends up in the shared scan history, so only OSV-style names
// ("npm", "crates.io", "Debian:12", "Rocky Linux") are accepted.
test('libscan rejects an ecosystem that is not an ecosystem name', async () => {
  const app = express();
  app.use(express.json());
  app.use('/api', require('../lib/routes/library-scan.route'));
  const server = app.listen(0);
  await new Promise(resolve => server.once('listening', resolve));
  try {
    const r = await fetch(`http://127.0.0.1:${server.address().port}/api/libscan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'evil', ecosystem: '<img src=x onerror=alert(1)>' }),
    });
    assert.equal(r.status, 400);
    assert.match((await r.json()).error, /ecosystem/);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
