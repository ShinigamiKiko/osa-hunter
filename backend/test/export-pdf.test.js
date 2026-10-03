'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { sendPdf } = require('../lib/routes/export.route');
const { secureReportPage } = require('../lib/routes/export.route');
const reports = require('../lib/pdf');

// Regression: puppeteer 23+ returns a Uint8Array from page.pdf(). res.send()
// JSON-serialises anything that is not a Buffer or string, so the download was
// a file full of {"0":37,"1":80,...} that no reader could open.
function withServer(bytes, fn) {
  return async () => {
    const app = express();
    app.get('/pdf', (req, res) => sendPdf(res, bytes, 'report.pdf'));
    const server = app.listen(0);
    await new Promise(resolve => server.once('listening', resolve));
    try {
      const r = await fetch(`http://127.0.0.1:${server.address().port}/pdf`);
      await fn(r, Buffer.from(await r.arrayBuffer()));
    } finally {
      await new Promise(resolve => server.close(resolve));
    }
  };
}

// "%PDF-1.4" followed by a byte that is not valid UTF-8 on its own.
const PDF_BYTES = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34, 0x0a, 0xff, 0xfe]);

test('a Uint8Array from puppeteer is sent as PDF bytes, not as JSON',
  withServer(PDF_BYTES, async (r, body) => {
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-type'), /application\/pdf/);
    assert.equal(body.subarray(0, 4).toString('latin1'), '%PDF');
    assert.deepEqual([...body], [...PDF_BYTES], 'every byte survives the trip');
    assert.equal(r.headers.get('content-length'), String(PDF_BYTES.length));
  }));

test('a Buffer is passed through unchanged',
  withServer(Buffer.from(PDF_BYTES), async (r, body) => {
    assert.deepEqual([...body], [...PDF_BYTES]);
  }));

test('the download is offered as a file, with the name the route chose',
  withServer(PDF_BYTES, async (r) => {
    assert.equal(r.headers.get('content-disposition'), 'attachment; filename="report.pdf"');
  }));

test('client report data cannot introduce HTML through text, attributes or numeric fields', () => {
  const attack = '"><script>fetch("http://127.0.0.1/secret")</script><img src=x onerror=alert(1)>';
  const vuln = { id: 'CVE-' + attack, severity: attack, Severity: attack, summary: attack,
    pocs: { length: attack }, cvss: { cvss3: { score: attack } } };
  const scan = { package: attack, distro: attack, distroVersion: attack,
    counts: { CRITICAL: attack }, summary: { CRITICAL: attack },
    toxic: { found:true, problem_type:attack }, vulns:[vuln],
    deps:[{ name:attack, vulns:[vuln] }], findings:[{ severity:attack, message:attack, cwe:[] }] };
  for (const build of Object.values(reports)) {
    const html = build(scan);
    assert.ok(!html.includes('<script>'), build.name); assert.ok(!html.includes('<img src=x'), build.name);
    assert.ok(!html.includes('class="sev ' + attack), build.name);
    assert.match(html, /script-src 'none'/); assert.match(html, /default-src 'none'/);
  }
});

test('report pages disable scripts and abort network/file requests before rendering', async () => {
  const calls = []; let intercept;
  const page = { setJavaScriptEnabled: async value => calls.push(['javascript',value]),
    setRequestInterception: async value => calls.push(['interception',value]),
    on: (event,handler) => { assert.equal(event,'request'); intercept = handler; } };
  await secureReportPage(page); assert.deepEqual(calls,[['javascript',false],['interception',true]]);
  for (const url of ['http://127.0.0.1/secret','https://example.test/','file:///etc/passwd','data:text/html,attack']) {
    let aborted = false; intercept({ url:()=>url, abort:()=>{ aborted=true; }, continue:()=>assert.fail('unsafe resource allowed') });
    assert.equal(aborted,true,url);
  }
  let continued = false; intercept({ url:()=> 'data:image/png;base64,aGVsbG8=', continue:()=>{ continued=true; }, abort:()=>assert.fail('local logo blocked') });
  assert.equal(continued,true);
});
