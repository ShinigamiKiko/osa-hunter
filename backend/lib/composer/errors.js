'use strict';

class HttpError extends Error {
  constructor(statusCode, msg, details) {
    super(msg);
    this.statusCode = statusCode;
    this.status = statusCode;
    this.details = details;
  }
}

function classifyComposerError(pkg, constraint, errMsg) {
  const msg = String(errMsg || '');

  if (/could not find (a matching|any) package|no matching package found|package .* not found/i.test(msg)) {
    return new HttpError(404, `Package ${pkg} was not found on Packagist, or the version is not available.`);
  }

  if (/affected by security advisories|block-insecure|security advisories/i.test(msg)) {
    return new HttpError(
      409,
      `Composer refused to resolve ${pkg}@${constraint} because of security advisories (Packagist audit).`,
      { kind: 'security_advisories' }
    );
  }

  if (/requires php|requires ext-|composer-runtime-api|php extension/i.test(msg)) {
    return new HttpError(
      409,
      `Could not resolve ${pkg}@${constraint}: its platform requirements (PHP version or ext-*) are not met.`,
      { kind: 'platform_requirements' }
    );
  }

  if (/Your requirements could not be resolved|conflict|cannot be resolved to an installable set/i.test(msg)) {
    return new HttpError(
      409,
      `Could not resolve the dependencies of ${pkg}@${constraint}: their version constraints conflict.`,
      { kind: 'dependency_conflict' }
    );
  }

  if (/Could not parse version constraint|Invalid version string/i.test(msg)) {
    return new HttpError(
      400,
      `Invalid version constraint for ${pkg}: "${constraint}". Use, for example, "3.0.0", "^3.0", "~3.0", "*" or "dev-main".`,
      { kind: 'bad_constraint' }
    );
  }

  return new HttpError(502, `Composer scan failed for ${pkg}@${constraint}.`);
}

module.exports = { HttpError, classifyComposerError };
