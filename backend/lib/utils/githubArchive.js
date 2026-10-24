'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { Readable, Transform, Writable } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const { createGunzip } = require('node:zlib');
const tar = require('tar');
const { createHash } = require('node:crypto');
const { ScanError } = require('../auth/scanCache');

const MAX_BYTES = 700 * 1024 * 1024;
const MAX_ENTRIES = 20000;

function byteLimit(maxBytes) {
  let bytes = 0;
  return new Transform({ transform(chunk, encoding, callback) {
    bytes += chunk.length;
    if (bytes > maxBytes) return callback(new ScanError(413, 'Repository exceeds the scan workspace limit'));
    callback(null, chunk);
  } });
}

// Stage a bounded uncompressed archive, validate every entry, then extract.
// The archive and extracted allocation share one budget, including empty files
// and directory blocks. No Git checkout or remote-supplied link is followed.
async function extractArchive(body, workspace, { maxBytes = MAX_BYTES, maxEntries = MAX_ENTRIES,
  signal = AbortSignal.timeout(120000), expectedFiles } = {}) {
  const archive = path.join(workspace, 'source.tar');
  const source = path.join(workspace, 'source');
  await pipeline(Readable.fromWeb(body), byteLimit(maxBytes), createGunzip(), byteLimit(maxBytes),
    fs.createWriteStream(archive, { flags: 'wx', mode: 0o600 }), { signal });
  let allocated = Math.ceil(fs.statSync(archive).size / 4096) * 4096 + 8192;
  let count = 0, invalid = null, root = null;
  const directories = new Set();
  const seenFiles = new Set();
  await tar.t({ file: archive, strict: true, maxMetaEntrySize: 16384,
    filter(name, entry) {
      if (invalid) return false;
      const parts = name.replace(/\/$/, '').split('/');
      if (name.length > 1024 || parts.length > 32 || parts.some(p => !p || p === '.' || p === '..')
          || /[\x00-\x1f\x7f\\:]/.test(name) || (root && parts[0] !== root)
          || !['File', 'Directory'].includes(entry.type)
          || !Number.isSafeInteger(entry.size) || entry.size < 0) {
        invalid = new ScanError(422, 'Unsupported repository archive entry');
        return false;
      }
      root = parts[0];
      // Files may imply parent directories that have no explicit tar header.
      for (let i = 1; i < parts.length - (entry.type === 'Directory' ? 0 : 1); i++) {
        const directory = parts.slice(1, i + 1).join('/');
        if (!directories.has(directory)) {
          directories.add(directory); allocated += 4096; count++;
        }
      }
      if (entry.type === 'File') {
        const relative = parts.slice(1).join('/');
        const expected = expectedFiles?.get(relative);
        if (seenFiles.has(relative) || (expectedFiles && (!expected || expected.size !== entry.size))) {
          invalid = new ScanError(422, 'Repository archive differs from the Git tree');
          return false;
        }
        seenFiles.add(relative);
        allocated += Math.max(4096, Math.ceil(entry.size / 4096) * 4096); count++;
      }
      if (count > maxEntries || allocated > maxBytes) {
        invalid = new ScanError(413, 'Repository exceeds the scan workspace limit');
      }
      return false;
    },
  });
  if (invalid) throw invalid;
  if (!root) throw new ScanError(422, 'Repository archive contains no files');
  if (expectedFiles && seenFiles.size !== expectedFiles.size) {
    throw new ScanError(422, 'Repository archive omits tracked files; scan was not completed');
  }
  fs.mkdirSync(source, { mode: 0o700 });
  await tar.x({ file: archive, cwd: source, strip: 1, strict: true,
    maxMetaEntrySize: 16384, noChmod: true, noMtime: true });
  fs.unlinkSync(archive);
  // Archives can honor export-ignore/export-subst or include expanded LFS data.
  // Only report a complete scan when every tracked blob is present unchanged.
  for (const [name, expected] of expectedFiles || []) {
    const hash = createHash('sha1').update(`blob ${expected.size}\0`);
    for await (const chunk of fs.createReadStream(path.join(source, name))) hash.update(chunk);
    if (hash.digest('hex') !== expected.sha) {
      throw new ScanError(422, 'Repository archive content differs from the Git tree; retry the scan');
    }
  }
  return source;
}

async function downloadRepository(repo, workspace) {
  const signal = AbortSignal.timeout(120000);
  const treeResponse = await fetch(`https://api.github.com/repos/${repo}/git/trees/HEAD?recursive=1`, {
    redirect: 'error', signal, headers: { 'User-Agent': 'OSAHunter/1.0' },
  });
  if (!treeResponse.ok || !treeResponse.body) {
    await treeResponse.body?.cancel();
    throw new ScanError(treeResponse.status === 404 ? 404 : 502, 'GitHub repository lookup failed');
  }
  const chunks = [];
  await pipeline(Readable.fromWeb(treeResponse.body), byteLimit(10 * 1024 * 1024),
    new Writable({ write(chunk, encoding, callback) { chunks.push(chunk); callback(); } }), { signal });
  const tree = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!Array.isArray(tree.tree) || tree.truncated !== false || tree.tree.length > MAX_ENTRIES) {
    throw new ScanError(413, 'Repository Git tree exceeds the scan limit');
  }
  const expectedFiles = new Map();
  for (const entry of tree.tree) {
    if (entry.type === 'tree') continue;
    if (entry.type !== 'blob' || !['100644', '100755'].includes(entry.mode)
        || typeof entry.path !== 'string' || entry.path.split('/').some(p => !p || p === '.' || p === '..')
        || /[\x00-\x1f\x7f\\:]/.test(entry.path) || !/^[a-f0-9]{40}$/.test(entry.sha)
        || !Number.isSafeInteger(entry.size) || entry.size < 0 || expectedFiles.has(entry.path)) {
      throw new ScanError(422, 'Unsupported Git tree entry');
    }
    expectedFiles.set(entry.path, { size: entry.size, sha: entry.sha });
  }
  const response = await fetch(`https://codeload.github.com/${repo}/tar.gz/HEAD`, {
    redirect: 'error', signal, headers: { 'User-Agent': 'OSAHunter/1.0' },
  });
  if (!response.ok || !response.body) {
    await response.body?.cancel();
    throw new ScanError(response.status === 404 ? 404 : 502, 'Could not download public GitHub repository');
  }
  return extractArchive(response.body, workspace, { signal, expectedFiles });
}

module.exports = { downloadRepository, extractArchive };
