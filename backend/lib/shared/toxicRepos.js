'use strict';

const TOXIC_URL = 'https://raw.githubusercontent.com/toxic-repos/toxic-repos/main/data/json/toxic-repos.json';
const { Semaphore } = require('./primitives');
const repositoryLookups = new Semaphore(6, 2000);

const OK_TTL  = 3_600_000; // 1h on success
const NEG_TTL = 300_000;   // 5m after a failure - don't refetch on every scan

// Toxic feed can be disabled entirely (e.g. unreachable network): OSA_TOXIC_ENABLED=false
const TOXIC_ENABLED = process.env.OSA_TOXIC_ENABLED !== 'false';

let _toxicCache = { list: null, ts: 0, ttl: OK_TTL };

async function getToxicList({ strict = false } = {}) {
  if (!TOXIC_ENABLED) return [];
  if (_toxicCache.list && Date.now() - _toxicCache.ts < _toxicCache.ttl) {
    if (strict && _toxicCache.error) throw _toxicCache.error;
    return _toxicCache.list;
  }
  try {
    const r = await fetch(TOXIC_URL, { signal: AbortSignal.timeout(15000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    // Guard the shape: a 200 with a non-array body (e.g. an error object) would
    // otherwise make checkToxic's list.filter throw and reject the whole scan.
    if (!Array.isArray(data)) throw new Error('Invalid toxic repository feed');
    if (data.some(entry => typeof entry?.name !== 'string' || !entry.name.trim())) throw new Error('Invalid toxic repository entry');
    const list = data;
    _toxicCache = { list, ts: Date.now(), ttl: OK_TTL };
    console.log('[TOXIC] Loaded', list.length, 'entries');
    return list;
  } catch (e) {
    console.error('[TOXIC] Load failed:', e.message, `- negative-caching for ${NEG_TTL / 1000}s`);
    // Negative-cache the failure so an unreachable feed doesn't cost a fetch
    // timeout on every single scan. Retries after NEG_TTL.
    _toxicCache = { list: _toxicCache.list || [], ts: Date.now(), ttl: NEG_TTL,
      error: new Error(`Toxic repository feed unavailable: ${e.message}`) };
    if (strict) throw _toxicCache.error;
    return _toxicCache.list;
  }
}

const repositoryCache = new Map();
const ecosystemTypes = { npm: 'npm', PyPI: 'pypi', Packagist: 'composer',
  'crates.io': 'cargo', NuGet: 'nuget', RubyGems: 'gem', Go: 'golang', Maven: 'maven' };

function packageKey(type, name) {
  const normalized = type === 'pypi' ? name.toLowerCase().replace(/[-_.]+/g, '-')
    : ['npm', 'composer', 'nuget'].includes(type) ? name.toLowerCase() : name;
  return `${type}:${normalized}`;
}

function packageIdentity(value) {
  if (typeof value !== 'string') return null;
  try {
    if (value.startsWith('pkg:')) {
      const [type, ...parts] = value.slice(4).split(/[?#]/)[0].split('/');
      const name = parts.join('/').replace(/@[^/]*$/, '');
      return name ? packageKey(type, decodeURIComponent(name)) : null;
    }
    const url = new URL(value);
    const types = { 'www.npmjs.com': ['npm', '/package/'], 'npmjs.com': ['npm', '/package/'],
      'packagist.org': ['composer', '/packages/'], 'pypi.org': ['pypi', '/project/'],
      'www.nuget.org': ['nuget', '/packages/'], 'crates.io': ['cargo', '/crates/'],
      'rubygems.org': ['gem', '/gems/'] };
    const spec = types[url.hostname];
    if (!spec || !url.pathname.startsWith(spec[1])) return null;
    const rest = decodeURIComponent(url.pathname.slice(spec[1].length)).replace(/\/$/, '');
    const name = spec[0] === 'composer' ? rest.split('/').slice(0, 2).join('/')
      : spec[0] === 'npm' && rest.startsWith('@') ? rest.split('/').slice(0, 2).join('/') : rest.split('/')[0];
    return name ? packageKey(spec[0], name) : null;
  } catch { return null; }
}

// Repository identity includes the host and owner. A fork with the same basename
// is not evidence about a package published from a different repository.
function repositoryIdentity(value) {
  if (typeof value !== 'string') return null;
  try {
    const raw = value.replace(/^git\+/, '').replace(/^git@([^:]+):/, 'https://$1/');
    const url = new URL(raw);
    if (!['github.com', 'gitlab.com', 'bitbucket.org'].includes(url.hostname)) return null;
    const parts = url.pathname.split('/').filter(Boolean);
    if (parts.length < 2) return null;
    // GitLab subgroups precede /-/commit, /-/tree etc.
    const repoParts = url.hostname === 'gitlab.com' ? parts.slice(0, parts.indexOf('-') < 0 ? parts.length : parts.indexOf('-')) : parts.slice(0, 2);
    return `${url.hostname}/${repoParts.join('/').replace(/\.git$/i, '')}`.toLowerCase();
  } catch { return null; }
}

function feedRepositoryIdentity(entry) {
  const explicit = repositoryIdentity(entry.commit_link) || repositoryIdentity(entry.name);
  if (explicit) return explicit;
  // The feed also uses exact GitHub owner/repo names with links to advisory
  // pages (e.g. bufbuild/buf). Only this qualified shape implies GitHub;
  // package URLs and explicit repositories on other hosts keep their identity.
  if (!packageIdentity(entry.commit_link) && /^[a-z0-9_.-]+\/[a-z0-9_.-]+$/i.test(entry.name))
    return repositoryIdentity(`https://github.com/${entry.name}`);
  return null;
}

async function packageRepository(name, ecosystem, version) {
  const key = JSON.stringify([ecosystem, name, version || 'latest']);
  const cached = repositoryCache.get(key);
  if (cached && Date.now() < cached.expires) return cached.result;
  if (repositoryCache.size >= 2000) repositoryCache.delete(repositoryCache.keys().next().value);
  const result = (async () => {
    let url, select;
    const enc = encodeURIComponent(name);
    if (ecosystem === 'Go') return { repo: repositoryIdentity(`https://${name}`) };
    if (ecosystem === 'npm') {
      url = `https://registry.npmjs.org/${enc}/${encodeURIComponent(version || 'latest')}`;
      select = data => [typeof data.repository === 'string' ? data.repository : data.repository?.url];
    } else if (ecosystem === 'PyPI') {
      url = `https://pypi.org/pypi/${enc}${version ? '/' + encodeURIComponent(version) : ''}/json`;
      select = data => [...Object.entries(data.info?.project_urls || {})
        .filter(([label]) => /^(source(?: code)?|repository|code|github)$/i.test(label))
        .map(([, value]) => value), data.info?.home_page];
    } else if (ecosystem === 'Packagist') {
      url = `https://packagist.org/packages/${name.split('/').map(encodeURIComponent).join('/')}.json`;
      select = data => [data.package?.versions?.[version]?.source?.url, data.package?.repository];
    } else if (ecosystem === 'crates.io') {
      url = `https://crates.io/api/v1/crates/${enc}`;
      select = data => [data.crate?.repository];
    } else if (ecosystem === 'RubyGems') {
      url = `https://rubygems.org/api/v1/gems/${enc}.json`;
      select = data => [data.source_code_uri];
    } else return { repo: null };
    const release = await repositoryLookups.acquire();
    if (!release) return { error: new Error('Package repository lookup queue is full') };
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(15000),
        headers: { 'User-Agent': 'OSAHunter/1.0', Accept: 'application/json' } });
      if (response.status === 404) return { repo: null };
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const candidates = select(await response.json());
      return { repo: candidates.map(repositoryIdentity).find(Boolean) || null };
    } catch (error) { return { error: new Error(`Package repository lookup unavailable: ${error.message}`) }; }
    finally { release(); }
  })();
  repositoryCache.set(key, { expires: Date.now() + OK_TTL, result });
  const outcome = await result;
  if (outcome.error) repositoryCache.set(key, { expires: Date.now() + NEG_TTL, result });
  return outcome;
}

async function checkToxic(pkgName, options = {}) {
  const list = await getToxicList(options);
  if (!list.length) return { found: false };
  const { ecosystem, version, repository, strict = false } = options;
  const type = ecosystemTypes[ecosystem];
  const key = type ? packageKey(type, String(pkgName || '').trim()) : null;
  let m = key && list.find(entry => [entry.PURL, entry['PURL-link'], entry.commit_link].some(value => packageIdentity(value) === key));
  if (!m) {
    const source = repository ? { repo: repositoryIdentity(repository) }
      : await packageRepository(String(pkgName || '').trim(), ecosystem, version);
    if (strict && source.error) throw source.error;
    if (source.repo) m = list.find(entry => feedRepositoryIdentity(entry) === source.repo);
  }
  if (!m) return { found: false };
  return {
    found: true,
    problem_type: m.problem_type,
    description: m.description,
    commit_link: m.commit_link,
    name: m.name,
  };
}

module.exports = { checkToxic };
