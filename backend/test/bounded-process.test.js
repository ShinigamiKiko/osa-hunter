'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { runBoundedProcess } = require('../lib/utils/runBoundedProcess');

test('bounded process preserves normal successful output and errors', async () => {
  const result = await runBoundedProcess(process.execPath, ['-e', 'console.log("ok")'],
    { timeout: 5000, maxBuffer: 4096 });
  assert.equal(result.stdout.trim(), 'ok');
  await assert.rejects(runBoundedProcess(process.execPath, ['-e', 'process.exit(2)'],
    { timeout: 5000, maxBuffer: 4096 }), e => e.code === 2);
});

test('output limits stop a process without waiting for the execution timeout', async () => {
  await assert.rejects(runBoundedProcess(process.execPath, ['-e',
    'setInterval(() => process.stdout.write("a".repeat(65536)), 1)'],
  { timeout: 5000, maxBuffer: 1024 }), /limit|maxBuffer/);
});

test('timeouts terminate the whole Linux process group before releasing the scan',
  { skip: process.platform !== 'linux' }, async () => {
    const script = `const {spawn}=require('node:child_process');
      const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});
      console.log(child.pid); setInterval(()=>{},1000);`;
    let childPid;
    await assert.rejects(runBoundedProcess(process.execPath, ['-e', script],
      { timeout: 1000, maxBuffer: 4096 }), e => {
      childPid = Number(e.stdout.trim()); return /timed out/.test(e.message);
    });
    assert.ok(childPid > 0);
    // A killed orphan may briefly remain as a zombie until init reaps it.
    try { assert.match(fs.readFileSync(`/proc/${childPid}/stat`, 'utf8'), /\) [ZX] /); }
    catch (e) { if (e.code !== 'ENOENT') throw e; }
  });
