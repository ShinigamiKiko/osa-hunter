'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const originalFetch = global.fetch;
process.env.OSA_TOXIC_ENABLED = 'true';
const feed = [
  { name: 'fork-owner/popular', commit_link: 'https://github.com/fork-owner/popular/commit/abc', problem_type: 'malware' },
  { name: 'bombardier', commit_link: 'https://github.com/almerico/bombardier', problem_type: 'ddos' },
  { name: 'node-ipc', commit_link: 'https://github.com/RIAEvangelist/node-ipc/issues/233', problem_type: 'malware' },
  { name: 'facebook/react-create-app', commit_link: 'https://github.com/facebook/create-react-app/commit/abc', 'PURL-link': 'https://www.npmjs.com/package/create-react-app' },
  { name: 'vendor/pkg', commit_link: 'https://github.com/other/pkg' },
  { name: 'future', PURL: 'pkg:npm/%40toxic/one@1.2.3' },
  { name: 'makenotion/notion-sdk-js', commit_link: 'https://www.notion.so/help/restrictions' },
  { name: 'bufbuild/buf', commit_link: 'https://buf.build/' },
  { name: 'other-host/only', commit_link: 'https://gitlab.com/other-host/only' },
];
let requests;
global.fetch = async url => {
  requests.push(url);
  if (url.includes('toxic-repos.json')) return { ok: true, json: async () => feed };
  if (url.includes('unavailable')) return { ok: false, status: 503 };
  const npm = {
    popular: 'git+https://github.com/original-owner/popular.git',
    '@safe/popular': 'https://github.com/original-owner/popular',
    bombardier: 'https://github.com/codesenberg/bombardier',
    'node-ipc': 'git@github.com:RIAEvangelist/node-ipc.git',
    '@scope/node-ipc': 'https://github.com/another/node-ipc',
    '@notionhq/client': 'git+https://github.com/makenotion/notion-sdk-js.git',
  };
  if (url.startsWith('https://registry.npmjs.org/')) {
    const name = decodeURIComponent(url.split('/')[3]);
    return { ok: true, json: async () => ({ repository: { url: npm[name] } }) };
  }
  if (url.startsWith('https://packagist.org/')) return { ok: true, json: async () => ({ package: { repository: 'https://github.com/vendor/pkg' } }) };
  if (url.startsWith('https://pypi.org/')) return { ok: true, json: async () => ({ info: { project_urls: { Source: 'https://github.com/fork-owner/popular' } } }) };
  assert.fail(`unexpected lookup ${url}`);
};
test.beforeEach(() => { requests = []; });
test.after(() => { global.fetch = originalFetch; });
const { checkToxic } = require('../lib/shared/toxicRepos');

test('a fork or colliding bare name does not make an unrelated package toxic', async () => {
  for (const name of ['popular', '@safe/popular', 'bombardier', '@scope/node-ipc'])
    assert.equal((await checkToxic(name, { ecosystem: 'npm' })).found, false, name);
  assert.equal((await checkToxic('vendor/pkg', { ecosystem: 'Packagist' })).found, false);
});
test('real repository identity, explicit package links and PURLs still detect listed packages', async () => {
  assert.equal((await checkToxic('node-ipc', { ecosystem: 'npm' })).problem_type, 'malware');
  assert.equal((await checkToxic('create-react-app', { ecosystem: 'npm' })).found, true);
  assert.equal((await checkToxic('@toxic/one', { ecosystem: 'npm' })).found, true);
  assert.equal((await checkToxic('popular', { ecosystem: 'PyPI' })).found, true);
  assert.equal((await checkToxic('fork-owner/popular', { repository: 'https://github.com/FORK-OWNER/popular.git' })).found, true);
  assert.equal((await checkToxic('popular', { repository: 'https://github.com/original-owner/popular' })).found, false);
});
test('repository lookup failures remain unavailable to strict gate rules even when cached', async () => {
  await assert.rejects(checkToxic('unavailable', { ecosystem: 'npm', strict: true }), /lookup unavailable/);
  await assert.rejects(checkToxic('unavailable', { ecosystem: 'npm', strict: true }), /lookup unavailable/);
  assert.equal(requests.filter(url => url.includes('/unavailable/')).length, 1);
});
test('qualified feed repository names with advisory links still match the exact GitHub source', async () => {
  assert.equal((await checkToxic('@notionhq/client', { ecosystem: 'npm' })).found, true);
  assert.equal((await checkToxic('github.com/bufbuild/buf', { ecosystem: 'Go' })).found, true);
  assert.equal((await checkToxic('makenotion/notion-sdk-js', { repository: 'https://github.com/makenotion/notion-sdk-js' })).found, true);
  for (const repository of ['https://github.com/fork/notion-sdk-js', 'https://gitlab.com/makenotion/notion-sdk-js', 'https://github.com/other-host/only'])
    assert.equal((await checkToxic('pkg', { repository })).found, false, repository);
});
test('large dependency batches bound metadata concurrency and share duplicate lookups', async () => {
  let active = 0, peak = 0, calls = 0;
  global.fetch = async () => {
    calls++; active++; peak = Math.max(peak, active);
    await new Promise(resolve => setTimeout(resolve, 10));
    active--;
    return { ok: true, json: async () => ({}) };
  };
  try {
    await Promise.all(Array.from({ length: 18 }, (_, i) => checkToxic(`batch-${i % 12}`, { ecosystem: 'npm' })));
    assert.equal(calls, 12); assert.ok(peak <= 6); assert.equal(active, 0);
  } finally { global.fetch = originalFetch; }
});
