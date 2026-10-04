'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const childProcess = require('node:child_process');
const calls = [];
childProcess.execFile = (command, args, options, callback) => {
  calls.push({ command, args }); callback(null, '{"Results":[]}', '');
};
const sharedPath = require.resolve('../lib/shared');
require.cache[sharedPath] = { id: sharedPath, filename: sharedPath, loaded: true,
  exports: { trivyLimiter: { check: () => true } } };
const cachePath = require.resolve('../lib/auth/scanCache');
require.cache[cachePath] = { id: cachePath, filename: cachePath, loaded: true,
  exports: { withCache: async (key, type, res, fn) => res.json(await fn()) } };
const router = require('../lib/routes/trivy.route');

test('Trivy rejects unapproved references before subprocess execution and accepts normal/custom registries', async () => {
  const app = express(); app.use(express.json()); app.use(router);
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const scan = (image, tag) => fetch(`http://127.0.0.1:${server.address().port}/trivy/scan`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ image, tag }),
  });
  const before = process.env.TRIVY_ALLOWED_REGISTRIES;
  try {
    delete process.env.TRIVY_ALLOWED_REGISTRIES;
    for (const [image, tag] of [
      ['127.0.0.1:5000/private', 'latest'], ['internal-host:5000/img', 'latest'],
      ['localhost/private', 'latest'], ['docker.io.evil.test/img', 'latest'],
      ['user@docker.io/img', 'latest'], ['docker.io//img', 'latest'],
      ['docker.io/img', '../evil'], ['nginx', 'host:5000/img'],
      ['nginx:latest', 'latest'], ['docker.io/../img', 'latest'],
    ]) assert.equal((await scan(image, tag)).status, 400, `${image}:${tag}`);
    assert.equal(calls.length, 0);
    for (const image of ['nginx', 'library/nginx', 'ghcr.io/owner/image', 'DOCKER.IO/library/nginx', 'index.docker.io/library/nginx']) {
      assert.equal((await scan(image, '1.27-alpine')).status, 200, image);
      assert.equal(calls.at(-1).args.at(-1), `${image}:1.27-alpine`);
    }
    process.env.TRIVY_ALLOWED_REGISTRIES = 'registry.example.test:5000';
    assert.equal((await scan('registry.example.test:5000/team/img', 'latest')).status, 200);
    assert.equal((await scan('registry.example.test:5001/team/img', 'latest')).status, 400);
    assert.equal((await scan('nginx', 'latest')).status, 400);
    process.env.TRIVY_ALLOWED_REGISTRIES = '';
    assert.equal((await scan('nginx', 'latest')).status, 400);
  } finally {
    if (before === undefined) delete process.env.TRIVY_ALLOWED_REGISTRIES; else process.env.TRIVY_ALLOWED_REGISTRIES = before;
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  }
});
