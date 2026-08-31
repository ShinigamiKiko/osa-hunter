'use strict';
const express = require('express');
const router  = express.Router();
const { getPool } = require('../auth/db');
const { requireAdmin } = require('../auth/middleware');
const { clearProxyData } = require('../gate/retention');

// GET /api/cache/stats - how much is cached (total + by type).
router.get('/cache/stats', requireAdmin, async (req, res) => {
  try {
    const { rows } = await getPool().query(
      `SELECT type, COUNT(*)::int AS count,
              MIN(scanned_at) AS oldest, MAX(scanned_at) AS newest
       FROM scan_cache GROUP BY type ORDER BY count DESC`
    );
    res.json({ total: rows.reduce((a, r) => a + r.count, 0), byType: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/cache[?type=gate|lib|dep|...] - clear cache now (no TTL wait).
router.delete('/cache', requireAdmin, async (req, res) => {
  const { type } = req.query;
  const pool = getPool();
  try {
    // Proxy history (events + denials + artifact map) - its own tables.
    if (type === 'proxy') {
      const deleted = await clearProxyData();
      console.log('[cache] cleared proxy history', JSON.stringify(deleted));
      return res.json({ ok: true, type: 'proxy', deleted });
    }
    let result;
    if (type && type !== 'all') {
      result = await pool.query('DELETE FROM scan_cache WHERE type = $1', [type]);
    } else {
      result = await pool.query('DELETE FROM scan_cache');
      if (!type || type === 'all') await clearProxyData(); // "all" wipes proxy history too
    }
    console.log(`[cache] cleared ${result.rowCount} entries (type=${type||'all'})`);
    res.json({ ok: true, deleted: result.rowCount, type: type || 'all' });
  } catch (e) {
    console.error('[cache] clear error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
