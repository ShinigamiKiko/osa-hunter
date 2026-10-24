'use strict';

const { spawn } = require('node:child_process');

function runBoundedProcess(cmd, args, opts) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: opts.cwd, env: opts.env,
      detached: process.platform !== 'win32', windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'] });
    let failure, outBytes = 0, errBytes = 0;
    const stdout = [], stderr = [];
    const killGroup = () => {
      try {
        if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch { child.kill('SIGKILL'); }
    };
    const stop = error => { failure ||= error; killGroup(); };
    const timer = setTimeout(() => stop(new Error('Scan process execution timed out')), opts.timeout);
    child.stdout.on('data', chunk => {
      outBytes += chunk.length;
      if (outBytes > opts.maxBuffer) return stop(Object.assign(new Error('Process output exceeds the scan limit'), { status: 413 }));
      stdout.push(chunk);
    });
    child.stderr.on('data', chunk => {
      errBytes += chunk.length;
      if (errBytes > 1024 * 1024) return stop(Object.assign(new Error('Process diagnostic output exceeds the scan limit'), { status: 413 }));
      stderr.push(chunk);
    });
    child.on('error', error => { failure ||= error; });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      killGroup();
      const result = { stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') };
      if (failure || code !== 0) return reject(Object.assign(failure || new Error(`Scan process exited (${code ?? signal})`),
        result, { code, signal }));
      resolve(result);
    });
  });
}

module.exports = { runBoundedProcess };
