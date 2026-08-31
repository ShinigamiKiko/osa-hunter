'use strict';

// Proxy activity API for the UI. What packages entered the system through the
// gate, filterable by ecosystem/decision, with the client IP that pulled them.
const express = require('express');
const router = express.Router();
const { getPool } = require('../auth/db');
const { requireAdmin } = require('../auth/middleware');

// GET /api/proxy/events?ecosystem=&decision=&q=&page=  (50 per page)
const PAGE_SIZE = 50;
router.get('/proxy/events', requireAdmin, async (req, res) => {
  const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
  const where = [];
  const args = [];
  if (req.query.ecosystem) { args.push(req.query.ecosystem); where.push(`ecosystem = $${args.length}`); }
  if (req.query.decision)  { args.push(req.query.decision);  where.push(`decision = $${args.length}`); }
  if (req.query.q)         { args.push(`%${req.query.q}%`);  where.push(`package_name ILIKE $${args.length}`); }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  try {
    const countRes = await getPool().query(`SELECT COUNT(*)::int AS n FROM proxy_events ${clause}`, args);
    const total = countRes.rows[0].n;
    const pages = Math.max(Math.ceil(total / PAGE_SIZE), 1);
    const cur = Math.min(page, pages);
    const { rows } = await getPool().query(
      `SELECT id, at, ecosystem, package_name AS name, version, repository, decision, reasons, client_ip
       FROM proxy_events ${clause} ORDER BY at DESC LIMIT ${PAGE_SIZE} OFFSET $${args.length + 1}`,
      [...args, (cur - 1) * PAGE_SIZE]
    );
    res.json({ total, page: cur, pages, pageSize: PAGE_SIZE, events: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/proxy/summary - counts per ecosystem (+ deny counts) for the tabs.
router.get('/proxy/summary', requireAdmin, async (req, res) => {
  try {
    const { rows } = await getPool().query(
      `SELECT ecosystem,
              COUNT(*)::int AS total,
              COUNT(*) FILTER (WHERE decision='deny')::int AS denied,
              MAX(at) AS last_at
       FROM proxy_events GROUP BY ecosystem ORDER BY total DESC`
    );
    const totals = await getPool().query(
      `SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE decision='deny')::int AS denied FROM proxy_events`
    );
    res.json({ overall: totals.rows[0] || { total: 0, denied: 0 }, byEcosystem: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
