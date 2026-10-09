'use strict';

const { getPool } = require('../auth/db');
const { gateDecide } = require('./decide');
const { getActivePolicy } = require('./policyStore');
const { singleFlight } = require('../shared/primitives');
const { observeCache, observeExternalError } = require('../observability/metrics');

// Verdict cache TTL (hours). Default 6h so new CVEs on an already-scanned
// version surface on the next scan; 0 = forever. Same knob as scanCache.
const _ttlRaw = process.env.SCAN_CACHE_TTL_HOURS;
const DEFAULT_TTL_HOURS = (_ttlRaw === undefined || _ttlRaw === '') ? 6 : (parseInt(_ttlRaw, 10) || 0);

async function cachedGate(input) {
  const name = input.name.trim();
  const ecosystem = input.ecosystem.trim();
  let policy = input.policy;
  if (!policy) {
    try { policy = await getActivePolicy(); }
    catch (err) {
      observeExternalError('postgres');
      console.error('[gate] policy unavailable:', err.message);
      // Without a known policy even its error mode is unknown. Deny before
      // consulting verdict caches; the proxy translates gate-error to 503.
      return {
        decision: 'deny',
        reasons: [{ rule: 'gate-error', detail: `Gate policy unavailable: ${err.message}` }],
        package: { ecosystem, name, version: input.version || null },
        policy: 'unavailable',
        scannedAt: new Date().toISOString(),
      };
    }
  }
  // Part of the cache key: activating a revision invalidates every verdict.
  const version = policy.version || '1';
  const requestedVersion = (input.version || '').trim() || 'latest';
  const key = `gate:v2:${version}:${ecosystem}:${name}:${requestedVersion}:${input.includeDeps ? 'deps' : 'root'}`;
  const pool = getPool();

  const ttl = input.ttlHours ?? DEFAULT_TTL_HOURS;
  try {
    const cached = ttl > 0
      ? await pool.query(
          `SELECT payload FROM scan_cache
           WHERE cache_key = $1 AND scanned_at > NOW() - ($2 || ' hours')::interval LIMIT 1`,
          [key, ttl])
      : await pool.query(
          `SELECT payload FROM scan_cache WHERE cache_key = $1 LIMIT 1`,
          [key]);
    if (cached.rows.length) {
      observeCache('gate', 'hit');
      return { ...cached.rows[0].payload, _cached: true };
    }
    observeCache('gate', 'miss');
  } catch (error) {
    observeExternalError('postgres');
    console.error('[gate] cache read failed:', error.message);
  }

  return singleFlight(`gate:${key}`, async () => {
   let result;
   try {
    result = await gateDecide({ ...input, name, ecosystem, version: input.version }, policy);
  } catch (error) {
    // A registry must not turn an upstream outage into an implicit allow.
    return {
      decision: policy.onGateError || 'deny',
      reasons: [{ rule: 'gate-error', detail: error.message || 'Gate unavailable' }],
      package: { ecosystem, name, version: input.version || null },
      policy: version,
      scannedAt: new Date().toISOString(),
    };
    }
   try {
    await pool.query(
      `INSERT INTO scan_cache (cache_key, type, payload, scanned_at)
       VALUES ($1, 'gate', $2::jsonb, NOW())
       ON CONFLICT (cache_key) DO UPDATE SET payload = EXCLUDED.payload, scanned_at = NOW()`,
      [key, JSON.stringify(result)]
    );
  } catch (error) {
    observeExternalError('postgres');
    console.error('[gate] cache write failed:', error.message);
  }
   return result;
  });
}

module.exports = { cachedGate };
