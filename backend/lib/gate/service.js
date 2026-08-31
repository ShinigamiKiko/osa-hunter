'use strict';

const { getPool } = require('../auth/db');
const { gateDecide } = require('./decide');
const { DEFAULT_POLICY } = require('./policy');

// Verdict cache TTL (hours). Default 6h so new CVEs on an already-scanned
// version surface on the next scan; 0 = forever. Same knob as scanCache.
const _ttlRaw = process.env.SCAN_CACHE_TTL_HOURS;
const DEFAULT_TTL_HOURS = (_ttlRaw === undefined || _ttlRaw === '') ? 6 : (parseInt(_ttlRaw, 10) || 0);

async function cachedGate(input) {
  const policy = input.policy || DEFAULT_POLICY;
  const version = policy.version || '1';
  const name = input.name.trim();
  const ecosystem = input.ecosystem.trim();
  const requestedVersion = (input.version || '').trim() || 'latest';
  const key = `gate:${version}:${ecosystem}:${name}:${requestedVersion}:${input.includeDeps ? 'deps' : 'root'}`;
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
    if (cached.rows.length) return { ...cached.rows[0].payload, _cached: true };
  } catch (error) {
    console.error('[gate] cache read failed:', error.message);
  }

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
    console.error('[gate] cache write failed:', error.message);
  }
  return result;
}

module.exports = { cachedGate };
