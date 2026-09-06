'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Semaphore, singleFlight } = require('../lib/shared/primitives');

test('singleFlight runs one producer for concurrent callers', async () => {
  let calls = 0;
  const producer = () => singleFlight('test-key', async () => {
    calls++;
    await new Promise(resolve => setTimeout(resolve, 10));
    return 42;
  });
  assert.deepEqual(await Promise.all([producer(), producer(), producer()]), [42, 42, 42]);
  assert.equal(calls, 1);
});

test('semaphore bounds active work and rejects a full queue', async () => {
  const semaphore = new Semaphore(1, 1);
  const first = await semaphore.acquire();
  const queued = semaphore.acquire();
  const rejected = await semaphore.acquire();
  assert.equal(rejected, null);
  first();
  const release = await queued;
  assert.equal(typeof release, 'function');
  release();
});
