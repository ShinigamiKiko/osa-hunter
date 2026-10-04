'use strict';
const express   = require('express');
const router = require('../utils/router')();
const { execFile } = require('child_process');
const { trivyLimiter } = require('../shared');
const { imageReference } = require('../utils/imageReference');
const { Semaphore } = require('../shared/primitives');
const { withCache } = require('../auth/scanCache');
const { TRIVY_CONCURRENCY, TRIVY_QUEUE_SIZE } = require('../config');

const trivySemaphore = new Semaphore(
  TRIVY_CONCURRENCY,
  TRIVY_QUEUE_SIZE
);

router.post('/trivy/scan', async (req, res) => {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  if (!trivyLimiter.check(ip))
    return res.status(429).json({ error: 'Too many scan requests. Please wait before retrying.' });

  const { image, tag } = req.body || {};
  if (!image) return res.status(400).json({ error: 'image is required' });
  let fullImage;
  try { fullImage = imageReference(image, tag); }
  catch (error) { return res.status(400).json({ error: error.message }); }
  const _cacheKey = `img:${fullImage}`;

  const release = await trivySemaphore.acquire();
  if (!release) return res.status(503).json({ error: 'Trivy scan queue is full' });

  try {
   return await withCache(_cacheKey, 'img', res, () => new Promise((resolve, reject) => {
    console.log(`[Trivy] Scanning: ${fullImage} (ip: ${ip})`);
    execFile('trivy', ['image', '--format', 'json', '--quiet', '--timeout', '10m', '--', fullImage],
      { timeout: 600_000, maxBuffer: 50 * 1024 * 1024 },
      (err, stdout, stderr) => {
        const trimmedOut = (stdout || '').trim();
        const trivyErr   = (stderr  || '').trim() || err?.message;
        if (err && !trimmedOut) return reject(new Error(trivyErr));
        try { resolve(JSON.parse(trimmedOut || stdout)); }
        catch (e) { reject(new Error(trivyErr || 'Failed to parse Trivy output')); }
      });
   })).catch(e => {
    console.error('[Trivy] Error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
   });
  } finally {
    release();
  }
});

module.exports = router;
