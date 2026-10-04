'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { semgrepSnippet } = require('../lib/utils/semgrepSnippet');

test('anonymous Semgrep placeholders/missing snippets recover the indicated source lines', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'osa-snippet-test-'));
  try {
    const file = path.join(root, 'sample.js');
    fs.writeFileSync(file, 'function run(input) {\r\n  return eval(input);\r\n}\r\n');
    for (const supplied of ['requires login', '', undefined]) {
      assert.equal(semgrepSnippet(root, { path: file, start: { line: 2 }, end: { line: 2 }, extra: { lines: supplied } }), '  return eval(input);');
    }
    assert.equal(semgrepSnippet(root, { extra: { lines: 'already supplied code\n' } }), 'already supplied code');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('source fallback refuses traversal, symlinks outside the clone and invalid ranges', () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'osa-snippet-test-'));
  const root = path.join(parent, 'clone'); fs.mkdirSync(root);
  fs.writeFileSync(path.join(parent, 'private.js'), 'secret');
  fs.writeFileSync(path.join(root, 'sample.js'), 'safe');
  const escapes = ['../private.js', path.join(parent, 'private.js')];
  // Windows refuses symlinks without Developer Mode or admin rights.
  try { fs.symlinkSync(path.join(parent, 'private.js'), path.join(root, 'link.js')); escapes.push('link.js'); }
  catch (error) { if (error.code !== 'EPERM') throw error; }
  const finding = file => ({ path: file, start: { line: 1 }, end: { line: 1 }, extra: { lines: 'requires login' } });
  try {
    for (const file of escapes)
      assert.equal(semgrepSnippet(root, finding(file)), '');
    for (const line of [0, -1, 1.5, '1']) assert.equal(semgrepSnippet(root, { ...finding('sample.js'), start: { line } }), '');
    assert.equal(semgrepSnippet(root, finding('sample.js')), 'safe');
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
});
