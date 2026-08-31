'use strict';

const { getPool } = require('../auth/db');

// Proxy history retention in days (default 30). Rows older than this in the
// proxy tables are pruned on a schedule; 0 disables auto-pruning.
const RETENTION_DAYS = (() => {
  const raw = process.env.PROXY_RETENTION_DAYS;
  return raw === undefined || raw === '' ? 30 : (parseInt(raw, 10) || 0);
})();

const PROXY_TABLES = ['proxy_events', 'gate_denials', 'proxy_artifacts'];
const AGE_COLUMN = { proxy_events: 'at', gate_denials: 'denied_at', proxy_artifacts: 'approved_at' };

// Delete proxy rows older than RETENTION_DAYS. No-op when retention is 0.
async function purgeProxyData() {
  if (RETENTION_DAYS <= 0) return;
  const pool = getPool();
  for (const table of PROXY_TABLES) {
    try {
      const { rowCount } = await pool.query(
        `DELETE FROM ${table} WHERE ${AGE_COLUMN[table]} < NOW() - ($1 || ' days')::interval`,
        [RETENTION_DAYS]
      );
      if (rowCount) console.log(`[retention] ${table}: pruned ${rowCount} rows older than ${RETENTION_DAYS}d`);
    } catch (e) {
      if (!e.message.includes('does not exist')) console.error(`[retention] ${table} purge error:`, e.message);
    }
  }
}

// Manual clear of all proxy history (used by DELETE /api/cache?type=proxy).
async function clearProxyData() {
  const pool = getPool();
  const deleted = {};
  for (const table of PROXY_TABLES) {
    try {
      const { rowCount } = await pool.query(`DELETE FROM ${table}`);
      deleted[table] = rowCount;
    } catch (e) {
      if (!e.message.includes('does not exist')) throw e;
    }
  }
  return deleted;
}

module.exports = { purgeProxyData, clearProxyData, RETENTION_DAYS, PROXY_TABLES };
