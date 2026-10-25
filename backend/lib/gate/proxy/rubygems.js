'use strict';

const { Readable } = require('node:stream');
const { fwd } = require('./common');

function handles(ecosystem) { return ecosystem === 'RubyGems'; }

// Gem::Version normalizes prerelease hyphens to .pre.; filename hyphens
// after the version therefore belong to the platform, not to the version.
const CPU = '[A-Za-z][A-Za-z0-9_]*';
const OS_VERSION = '(?:-[0-9]+(?:\\.[0-9]+)*)?';
const OS = [
  `(?:aix|darwin|freebsd|openbsd|solaris|java|dalvik|dotnet|netbsd)${OS_VERSION}`,
  'linux(?:-[A-Za-z0-9_]+)?',
  'mingw(?:32|64)?(?:-[A-Za-z0-9_]+)?',
  'mswin(?:32|64)(?:[_-][0-9]+)?',
  'cygwin|macruby|netbsdelf|wasi',
].join('|');
const PLATFORM = new RegExp(`-(?:java|ruby|${CPU}-(?:${OS}))$`);

function parse(path) {
  const file = path.split('/').pop();
  if (!file.endsWith('.gem')) return null;
  const stem = file.slice(0, -4).replace(PLATFORM, '');
  const m = stem.match(/^([A-Za-z0-9_.-]+)-([0-9]+(?:\.[0-9A-Za-z]+)*)$/);
  // Unknown custom platforms ending in a number are indistinguishable from
  // another gem name. Reject that ambiguity instead of evaluating a false name.
  if (!m || /-[0-9][0-9A-Za-z.]*-/.test(m[1])) return null;
  return { name: m[1], version: m[2] };
}

// Filenames alone cannot disambiguate numeric gem-name components from
// arbitrary custom platforms. Bind the requested filename to the registry's
// compact index before using its name/version as a security identity.
async function resolveArtifact(repoCfg, repository, artifactPath) {
  if (!artifactPath.endsWith('.gem')) return null;
  const file = artifactPath.split('/').pop();
  if (!/^[A-Za-z0-9_.-]+\.gem$/.test(file)) return null;
  const names = [];
  for (let i = 1; i < file.length - 4; i++) {
    if (file[i] === '-' && /[0-9]/.test(file[i + 1])) names.push(file.slice(0, i));
  }
  if (!names.length) return null;
  if (names.length > 8) throw Object.assign(new Error('Ambiguous RubyGems filename'), { status: 403 });
  const lookups = await Promise.allSettled(names.map(async name => {
    const headers = { Accept: 'text/plain' };
    if (repoCfg.auth) headers.Authorization = repoCfg.auth;
    const response = await fetch(`${repoCfg.upstream}${fwd(repoCfg, repository, `info/${encodeURIComponent(name)}`).path}`,
      { headers, redirect: 'error', signal: AbortSignal.timeout(8000) });
    if (response.status === 404) { await response.body?.cancel(); return []; }
    if (!response.ok || !response.body) {
      await response.body?.cancel(); throw new Error('RubyGems compact index unavailable');
    }
    let bytes = 0;
    const chunks = [];
    for await (const chunk of Readable.fromWeb(response.body)) {
      bytes += chunk.length;
      if (bytes > 1024 * 1024) throw new Error('RubyGems compact index exceeds the metadata limit');
      chunks.push(chunk);
    }
    for (const line of Buffer.concat(chunks).toString('utf8').split('\n')) {
      const token = line.trim().split(/\s/, 1)[0];
      if (`${name}-${token}.gem` !== file) continue;
      const version = token.split('-', 1)[0];
      if (/^[0-9]+(?:\.[0-9A-Za-z]+)*$/.test(version)) return [{ name, version }];
    }
    return [];
  }));
  const failure = lookups.find(result => result.status === 'rejected');
  if (failure) throw Object.assign(new Error('Could not verify RubyGems artifact: ' + failure.reason.message), { status: 502 });
  const matches = new Map(lookups.flatMap(result => result.value).map(value => [value.name + '@' + value.version, value]));
  if (matches.size !== 1) throw Object.assign(new Error('RubyGems filename is missing or ambiguous in the registry index'), { status: 403 });
  return [...matches.values()][0];
}

module.exports = { handles, parse, resolveArtifact };
