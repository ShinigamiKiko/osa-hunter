'use strict';

const { IMAGE_RE } = require('./constants');

function validateImage(image) {
  // Reject a leading '-' so the value can never be parsed by trivy as a CLI
  // flag (argument injection), even though it is passed via execFile (no shell).
  return typeof image === 'string'
    && image.length > 0
    && image.length < 512
    && !image.startsWith('-')
    && IMAGE_RE.test(image);
}

module.exports = { validateImage };
