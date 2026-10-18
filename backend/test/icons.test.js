'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { icon, brandIcon } = require('../../frontend/public/js/icon-renderer');
const reports = require('../lib/pdf');

const EMOJI = /[\p{Extended_Pictographic}]/u;

test('icon names and extra classes never turn into SVG markup or attributes', () => {
  const payload = '"><image href="https://example.invalid" onload="alert(1)">';
  const svg = icon(payload, payload);
  assert.match(svg, /aria-hidden="true"/);
  assert.doesNotMatch(svg, /<image|onload|https:/);
  assert.equal(brandIcon(payload), icon('package'));
  assert.equal(brandIcon('__proto__'), icon('package'));
});

test('brand logos are found by ecosystem, system and distro ids', () => {
  assert.equal(brandIcon('NPM'), brandIcon('npm'));
  assert.equal(brandIcon('CARGO'), brandIcon('rust'));
  assert.equal(brandIcon('crates'), brandIcon('rust'));
  assert.equal(brandIcon('rhel'), brandIcon('redhat'));
  assert.notEqual(brandIcon('debian'), icon('package'));
});

test('a scan button shows a spinner and a busy state while it runs', () => {
  const button = { attrs: {}, setAttribute(k, v) { this.attrs[k] = v; } };
  const ctx = { console, document: { addEventListener() {}, getElementById: () => button } };
  vm.createContext(ctx);
  for (const file of ['icons.js', 'icon-renderer.js', 'utils.js'])
    vm.runInContext(fs.readFileSync(path.join(__dirname, '../../frontend/public/js', file), 'utf8'), ctx, { filename: file });
  vm.runInContext("setBtn('scan', true)", ctx);
  assert.equal(button.disabled, true);
  assert.equal(button.attrs['aria-busy'], 'true');
  assert.match(button.innerHTML, /class="icon spin"[^]*Scanning…/);
  vm.runInContext("setBtn('scan', false, 'Scan Image')", ctx);
  assert.equal(button.attrs['aria-busy'], 'false');
  assert.match(button.innerHTML, /<\/svg> Scan Image$/);
});

test('reports draw icons as inline SVG and name weakness groups in text', () => {
  const image = reports.buildImgReportHtml({ image: 'nginx', vulns: [] });
  assert.match(image, /<svg/);
  assert.doesNotMatch(image, EMOJI);
  const sast = reports.buildSastReportHtml({ repo: 'example/repo', complete: true, counts: { HIGH: 1 },
    findings: [{ ruleId: 'sql-injection', cwe: ['CWE-89'], severity: 'HIGH', path: 'db.js' }] });
  assert.match(sast, /SQL Injection/);
  assert.doesNotMatch(sast, EMOJI);
});
