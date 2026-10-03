'use strict';

const { osvQuery, extractCVEs } = require('../shared');

const OSV_ECOSYSTEM = 'Packagist';

async function osvQueryPackagist(name, version) {
  return osvQuery(name, OSV_ECOSYSTEM, version);
}
function mapVulnForApi(x) {
  return {
    id: x.id,
    summary: x.summary || x.details || '',
    severity: x._sev,
    aliases: x._aliases,
    fixed: x._fix,
    refs: x._refs,
  };
}

function extractCvesFromOsv(vulns) {
  return extractCVEs(vulns);
}

module.exports = { osvQueryPackagist, mapVulnForApi, extractCvesFromOsv };
