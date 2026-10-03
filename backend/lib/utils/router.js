'use strict';

// Express 4 does not forward rejected handler promises to its error handler.
module.exports = function createRouter() {
  const router = require('express').Router();
  for (const method of ['get', 'post', 'put', 'patch', 'delete', 'all']) {
    const register = router[method].bind(router);
    router[method] = (path, ...handlers) => register(path, ...handlers.flat(Infinity).map(handler =>
      function asyncHandler(req, res, next) {
        try { Promise.resolve(handler(req, res, next)).catch(next); } catch (error) { next(error); }
      }));
  }
  router.use((req, res, next) => {
    const fields = ['name', 'version', 'ecosystem', 'system', 'distro', 'distroVersion',
      'image', 'tag', 'url', 'desc', 'username', 'password', 'role', 'currentPassword', 'newPassword'];
    if (req.body !== undefined && (req.body === null || typeof req.body !== 'object' || Array.isArray(req.body))) {
      return res.status(400).json({ error: 'Request body must be an object' });
    }
    for (const field of fields) {
      if (req.body && Object.hasOwn(req.body, field) && typeof req.body[field] !== 'string') {
        return res.status(400).json({ error: `${field} must be a string` });
      }
    }
    next();
  });
  return router;
};
