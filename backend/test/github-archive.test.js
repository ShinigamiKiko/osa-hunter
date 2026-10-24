'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { gzipSync } = require('node:zlib');
const { Header } = require('tar');
const { createHash } = require('node:crypto');
const { extractArchive } = require('../lib/utils/githubArchive');

function archive(entries) {
  const blocks = [];
  for (const item of entries) {
    const data = Buffer.from(item.data || '');
    const header = new Header({ path: item.path, type: item.type || 'File',
      size: data.length, mode: 0o644, linkpath: item.linkpath });
    header.encode(); blocks.push(header.block, data, Buffer.alloc((512 - data.length % 512) % 512));
  }
  return gzipSync(Buffer.concat([...blocks, Buffer.alloc(1024)]));
}

async function workspace(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'osa-archive-test-'));
  try { await fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

test('a legitimate source archive extracts nested files and removes its staged copy', async () => {
  await workspace(async dir => {
    const body = new Response(archive([{ path: 'repo-HEAD/src/app.js', data: 'console.log(1);' }])).body;
    const source = await extractArchive(body, dir);
    assert.equal(fs.readFileSync(path.join(source, 'src/app.js'), 'utf8'), 'console.log(1);');
    assert.equal(fs.existsSync(path.join(dir, 'source.tar')), false);
  });
});

test('gzip expansion is capped while writing, before extraction', async () => {
  await workspace(async dir => {
    const body = new Response(archive([{ path: 'repo/bomb', data: 'a'.repeat(200000) }])).body;
    await assert.rejects(extractArchive(body, dir, { maxBytes: 8192 }), e => e.status === 413);
    assert.ok(fs.statSync(path.join(dir, 'source.tar')).size <= 8192);
    assert.equal(fs.existsSync(path.join(dir, 'source')), false);
  });
});

test('empty files and implicit directories consume the shared disk and entry budgets', async () => {
  for (const [entries, options] of [
    [Array.from({ length: 10 }, (_, i) => ({ path: `repo/file${i}` })), { maxBytes: 16000 }],
    [[{ path: 'repo/a/b/c/file' }], { maxEntries: 3 }],
    [[{ path: 'repo/a/b/c/file' }], { maxBytes: 15000 }],
  ]) await workspace(async dir => {
    await assert.rejects(extractArchive(new Response(archive(entries)).body, dir, options), e => e.status === 413);
    assert.equal(fs.existsSync(path.join(dir, 'source')), false);
  });
});

test('traversal, mixed archive roots, links and special files are rejected before extraction', async () => {
  for (const entries of [
    [{ path: 'repo/../outside' }], [{ path: '/absolute/file' }], [{ path: 'repo/back\\slash' }],
    [{ path: 'repo/link', type: 'SymbolicLink', linkpath: '/etc/passwd' }],
    [{ path: 'repo/link', type: 'Link', linkpath: 'repo/target' }],
    [{ path: 'repo/fifo', type: 'FIFO' }], [{ path: 'repo/a' }, { path: 'other/b' }],
  ]) await workspace(async dir => {
    await assert.rejects(extractArchive(new Response(archive(entries)).body, dir), /Unsupported/);
    assert.equal(fs.existsSync(path.join(dir, 'source')), false);
  });
});

test('a malformed compressed archive cannot become a successful source tree', async () => {
  await workspace(async dir => {
    await assert.rejects(extractArchive(new Response(Buffer.from('invalid')).body, dir));
    assert.equal(fs.existsSync(path.join(dir, 'source')), false);
  });
});

function expectedFile(data) {
  const bytes = Buffer.from(data);
  return { size: bytes.length, sha: createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex') };
}

test('tracked files must all be present with unchanged Git blob hashes', async () => {
  const files = [{ path: 'repo/visible.js', data: 'safe' }];
  for (const expectedFiles of [
    new Map([['visible.js', expectedFile('safe')], ['hidden.js', expectedFile('eval(x)')]]),
    new Map([['visible.js', expectedFile('evil')]]),
  ]) await workspace(async dir => {
    await assert.rejects(extractArchive(new Response(archive(files)).body, dir, { expectedFiles }),
      /omits tracked files|content differs/);
  });
  await workspace(async dir => {
    const source = await extractArchive(new Response(archive(files)).body, dir,
      { expectedFiles: new Map([['visible.js', expectedFile('safe')]]) });
    assert.equal(fs.readFileSync(path.join(source, 'visible.js'), 'utf8'), 'safe');
  });
});

test('GitHub downloader verifies its bounded tree manifest and rejects truncated or unsupported trees', async () => {
  const { downloadRepository } = require('../lib/utils/githubArchive');
  const originalFetch = global.fetch;
  const entry = { path: 'README', mode: '100644', type: 'blob', ...expectedFile('hello') };
  let document = { truncated: false, tree: [entry] }, downloads;
  global.fetch = async url => {
    if (String(url).startsWith('https://api.github.com/')) return new Response(JSON.stringify(document));
    assert.match(String(url), /^https:\/\/codeload\.github\.com\/example\/repo\/tar.gz\/HEAD$/);
    downloads++; return new Response(archive([{ path: 'repo-HEAD/README', data: 'hello' }]));
  };
  try {
    await workspace(async dir => {
      downloads = 0; const source = await downloadRepository('example/repo', dir);
      assert.equal(fs.readFileSync(path.join(source, 'README'), 'utf8'), 'hello'); assert.equal(downloads, 1);
    });
    for (const bad of [ { truncated: true, tree: [] },
      { truncated: false, tree: [{ ...entry, mode: '120000' }] },
      { truncated: false, tree: [{ ...entry, path: '../outside' }] },
    ]) await workspace(async dir => {
      document = bad; downloads = 0;
      await assert.rejects(downloadRepository('example/repo', dir), e => [413, 422].includes(e.status));
      assert.equal(downloads, 0);
    });
  } finally { global.fetch = originalFetch; }
});
