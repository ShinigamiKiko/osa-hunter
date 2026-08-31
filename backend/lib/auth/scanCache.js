'use strict';

const { getPool } = require('./db');
// Verdict cache lifetime in hours. Default 6h: short enough that newly-disclosed
// CVEs for an already-scanned version are picked up on the next scan, long enough
// that repeated installs in a session are instant. The slow part (per-CVE
// CVSS/PoC) is cached separately and permanently, so re-scans stay fast.
// Set to 0 to keep verdicts forever (clear manually via DELETE /api/cache).
const _ttlRaw = process.env.SCAN_CACHE_TTL_HOURS;
const TTL_HOURS = (_ttlRaw === undefined || _ttlRaw === '') ? 6 : (parseInt(_ttlRaw, 10) || 0);

class ScanError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function withCache(key, type, res, scanFn) {
  const pool = getPool();

  try {
    const { rows } = TTL_HOURS > 0
      ? await pool.query(
          `SELECT payload, scanned_at FROM scan_cache
           WHERE cache_key = $1 AND scanned_at > NOW() - ($2 || ' hours')::interval LIMIT 1`,
          [key, TTL_HOURS])
      : await pool.query(
          `SELECT payload, scanned_at FROM scan_cache WHERE cache_key = $1 LIMIT 1`,
          [key]);
    if (rows.length) {
      const age = Math.round((Date.now() - new Date(rows[0].scanned_at)) / 60000);
      console.log(`[cache] HIT  ${key}  (${age}m old)`);
      return res.json({ ...rows[0].payload, _cached: true, _cachedAt: rows[0].scanned_at });
    }
    console.log(`[cache] MISS ${key}`);
  } catch (e) {
    console.error(`[cache] READ ERROR for key "${key}":`, e.message);
  }

  let result;
  try {
    result = await scanFn();
  } catch (e) {
    const status = e.status ?? e.statusCode ?? 500;
    const payload = { error: e.message || 'Scan failed' };
    if (e.details) payload.details = e.details;
    return res.status(status).json(payload);
  }

  if (result != null && typeof result === 'object' && typeof result.socket !== 'undefined') {
    console.error(`[cache] scanFn returned res/ServerResponse for key "${key}" — fix error paths to throw ScanError`);
    return;
  }

  let serialized;
  try {
    serialized = JSON.stringify(result);
  } catch (e) {
    console.error(`[cache] SERIALIZE ERROR for key "${key}":`, e.message);
    return res.json(result);
  }

  try {
    await pool.query(
      `INSERT INTO scan_cache (cache_key, type, payload, scanned_at)
       VALUES ($1, $2, $3::jsonb, NOW())
       ON CONFLICT (cache_key)
       DO UPDATE SET payload = EXCLUDED.payload, scanned_at = NOW()`,
      [key, type, serialized]
    );
    console.log(`[cache] SAVE ${key}`);
  } catch (e) {
    console.error(`[cache] WRITE ERROR for key "${key}":`, e.message);
  }

  return res.json(result);
}

async function purgeExpired() {
  if (TTL_HOURS <= 0) return; // forever-cache mode: nothing auto-expires
  try {
    const { rowCount } = await getPool().query(
      `DELETE FROM scan_cache WHERE scanned_at < NOW() - ($1 || ' hours')::interval`,
      [TTL_HOURS]
    );
    if (rowCount) console.log(`[cache] purged ${rowCount} expired entries`);
  } catch (e) {
    if (!e.message.includes('does not exist')) {
      console.error('[cache] purge error:', e.message);
    }
  }
}

module.exports = { withCache, purgeExpired, ScanError };
