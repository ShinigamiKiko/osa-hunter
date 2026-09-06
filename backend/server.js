'use strict';
const express   = require('express');
const cors      = require('cors');
const path      = require('path');
const crypto    = require('crypto');
const session   = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const { closePool, getPool, runMigrations, seedAdmin } = require('./lib/auth/db');
const { purgeExpired }        = require('./lib/auth/scanCache');
const { purgeProxyData }      = require('./lib/gate/retention');
const { requireAuth }         = require('./lib/auth/middleware');
const { installConsoleLogger, logError, logRequest, write } = require('./lib/observability/logger');
const { metricsHandler, requestMetrics } = require('./lib/observability/metrics');
installConsoleLogger();
const authRoutes              = require('./lib/auth/routes');
const apiKeyRoutes            = require('./lib/auth/api-key-routes');
const scanHistoryRoutes       = require('./lib/routes/scan-history.route');
const { router: gateProxyRoutes } = require('./lib/routes/gate-proxy.route');
const { bootstrapPolicy }     = require('./lib/gate/policyStore');

const sessionSecret = process.env.SESSION_SECRET || (() => {
  const generated = crypto.randomBytes(32).toString('hex');
  console.warn('[boot] SESSION_SECRET not set — generated a random one.');
  console.warn('[boot] All sessions will be lost on restart. Set SESSION_SECRET in .env to avoid this.');
  return generated;
})();

const cookieSecure = process.env.SESSION_COOKIE_SECURE === 'true'
  || (process.env.NODE_ENV === 'production' && process.env.HTTPS === 'true');
const cookieName = cookieSecure ? '__Host-osa.sid' : 'osa.sid';

const app = express();
let httpServer;
let metricsServer;
let shuttingDown = false;
let cleanupIntervals = [];

process.on('uncaughtException', (err) => {
  logError('uncaught_exception', err);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  logError('unhandled_rejection', reason instanceof Error ? reason : new Error(String(reason)));
});

app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  res.setHeader('X-Request-Id', req.requestId);
  next();
});
app.use(requestMetrics);
app.use((req, res, next) => {
  const startedAt = Date.now();
  res.once('finish', () => logRequest(req, res.statusCode, Date.now() - startedAt));
  res.once('close', () => {
    if (!res.writableEnded) logRequest(req, res.statusCode, Date.now() - startedAt);
  });
  next();
});

app.set('trust proxy', 1);

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data:",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      ...(cookieSecure ? ['upgrade-insecure-requests'] : []),
    ].join('; ')
  );
  next();
});

const corsOrigin = process.env.CORS_ORIGIN;
app.use(cors(
  corsOrigin
    ? { origin: corsOrigin, credentials: true }
    : { origin: false }
));

app.use('/api/export/pdf', express.json({ limit: '10mb' }));
app.use(express.json({ limit: '64kb' }));

app.use(express.static(path.join(__dirname, '../frontend/public')));

const PORT = process.env.PORT || 3001;
const METRICS_PORT = parseInt(process.env.METRICS_PORT || '9100', 10);

runMigrations()
  .then(async () => {
    await seedAdmin();

    // Seed gate_policies from policy.yaml on a fresh database, then serve the
    // active revision from there. Fail loudly: a gate with no policy is worse
    // than a gate that refuses to start.
    const seededPolicy = await bootstrapPolicy();
    write('info', 'policy_ready', { revision: seededPolicy.revision, source: seededPolicy.source });

    app.use(session({
      name: cookieName,
      store: new pgSession({
        pool: getPool(),
        tableName: 'session',
        createTableIfMissing: false,
      }),
      secret: sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: cookieSecure,
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      },
    }));

    app.use((req, res, next) => {
      if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();

      const supplied = req.get('origin') || req.get('referer');
      // Non-browser API clients do not send Origin/Referer. SameSite cookies
      // protect browser requests, while this rejects cross-origin browser calls.
      if (!supplied) return next();

      let origin;
      try { origin = new URL(supplied).origin; } catch {
        return res.status(403).json({ error: 'Invalid request origin' });
      }

      const expected = `${req.protocol}://${req.get('host')}`;
      const configured = (process.env.CORS_ORIGIN || '')
        .split(',').map(value => value.trim()).filter(Boolean);
      if (origin !== expected && !configured.includes(origin)) {
        return res.status(403).json({ error: 'Cross-origin request blocked' });
      }
      next();
    });

    app.use('/api/gate', gateProxyRoutes);

    app.use('/api', authRoutes);

    app.use('/api', requireAuth);

    app.use('/api', apiKeyRoutes);
    app.use('/api', scanHistoryRoutes);

    app.get('/', (req, res, next) => {
      if (!req.session?.user) return res.redirect('/login.html');
      next();
    });

    const routes = [
      ['health',    './lib/routes/health.route'],
      ['trivy',     './lib/routes/trivy.route'],
      ['libscan',   './lib/routes/library-scan.route'],
      ['proxy',     './lib/routes/proxy.route'],
      ['depscan',   './lib/routes/dependency-scan.route'],
      ['composer',  './lib/routes/composer-scan.route'],
      ['activity',  './lib/routes/activity.route'],
      ['export',    './lib/routes/export.route'],
      ['grype',     './lib/routes/grype.route'],
      ['ghscan',    './lib/routes/ghscan.route'],
      ['cache',     './lib/routes/cache.route'],
      ['policy',    './lib/routes/policy.route'],
    ];

    for (const [name, modPath] of routes) {
      try {
        app.use('/api', require(modPath));
         write('info', 'route_loaded', { route: name });
      } catch (e) {
        logError('route_load_failed', e, { route: name });
        process.exit(1);
      }
    }

    app.use((err, req, res, _next) => {
      logError('unhandled_error', err, { requestId: req.requestId, method: req.method, path: req.originalUrl });
      if (!res.headersSent) res.status(500).json({ error: 'Internal server error' });
    });

    cleanupIntervals.push(setInterval(purgeExpired, 6 * 60 * 60 * 1000));
    purgeExpired();
    cleanupIntervals.push(setInterval(purgeProxyData, 6 * 60 * 60 * 1000));
    purgeProxyData();

     httpServer = app.listen(PORT, () => {
       write('info', 'server_started', { port: PORT, environment: process.env.NODE_ENV || 'development' });
       const metricsApp = express();
       metricsApp.get('/metrics', metricsHandler);
       metricsServer = metricsApp.listen(METRICS_PORT, '0.0.0.0', () => {
         write('info', 'metrics_server_started', { port: METRICS_PORT, host: '0.0.0.0' });
       });
     });
  })
  .catch(err => {
    logError('migration_failed', err);
    process.exit(1);
});

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  write('info', 'shutdown_started', { signal });
  cleanupIntervals.forEach(clearInterval);
  await Promise.all([
    httpServer ? new Promise(resolve => httpServer.close(resolve)) : Promise.resolve(),
    metricsServer ? new Promise(resolve => metricsServer.close(resolve)) : Promise.resolve(),
  ]);
  await closePool();
  write('info', 'shutdown_complete');
  process.exit(0);
}

process.once('SIGTERM', () => shutdown('SIGTERM'));
process.once('SIGINT', () => shutdown('SIGINT'));
