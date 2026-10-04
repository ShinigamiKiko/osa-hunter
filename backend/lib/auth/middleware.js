'use strict';

const crypto = require('crypto');
const { getPool } = require('./db');

function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

async function requireAuth(req, res, next) {
  // This middleware is mounted via app.use('/api', requireAuth), so req.path is
  // already stripped of the '/api' prefix (e.g. '/health', '/auth/login').
  const open = [
    '/auth/login',
    '/auth/status',
    '/auth/logout',
    '/health',
    '/ready',
  ];
  if (open.includes(req.path)) return next();

  if (req.session?.user) {
    try {
      const { rows } = await getPool().query(
        'SELECT id, username, role, session_version FROM users WHERE id = $1', [req.session.user.id]);
      const user = rows[0];
      if (user && user.session_version === req.session.user.sessionVersion) {
        req.user = { id: user.id, username: user.username, role: user.role };
        req.session.user = { ...req.user, sessionVersion: user.session_version };
        return next();
      }
      delete req.session.user;
    } catch (error) {
      console.error('[auth/session]', error.message);
      return res.status(503).json({ error: 'Authentication temporarily unavailable' });
    }
  }

  const apiKey = req.headers['x-api-key'];
  if (typeof apiKey === 'string' && apiKey.startsWith('osa_')) {
    try {
      const hash = hashKey(apiKey);
      const { rows } = await getPool().query(
        `SELECT k.id, u.id as user_id, u.username, u.role
         FROM api_keys k JOIN users u ON u.id = k.user_id
         WHERE k.key_hash = $1`,
        [hash]
      );
      if (rows.length) {
        req.session = req.session || {};
        req.apiKeyUser = rows[0];
        req.user = { id: rows[0].user_id, username: rows[0].username, role: rows[0].role };
        getPool().query('UPDATE api_keys SET last_used = NOW() WHERE id = $1', [rows[0].id])
          .catch(e => console.error('[auth/api-key] last_used update failed:', e.message));
        return next();
      }
    } catch (e) {
      console.error('[auth/api-key]', e.message);
    }
  }

  // API authentication must return 401 even for browser navigation headers.
  // nginx auth_request rejects redirects and turns them into HTTP 500.
  return res.status(401).json({ error: 'Unauthorized' });
}

function requireAdmin(req, res, next) {
  const role = req.user?.role || req.session?.user?.role;
  if (role === 'admin') return next();
  return res.status(403).json({ error: 'Forbidden — admin only' });
}

module.exports = { requireAuth, requireAdmin };
