'use strict';

const { execFile } = require('child_process');

function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, {
      ...opts,
      shell: false,
      maxBuffer: opts.maxBuffer ?? 50 * 1024 * 1024,
    }, (error, stdout = '', stderr = '') => {
      if (!error) return resolve({ out: stdout, err: stderr });
      const code = error.code ?? 'unknown';
      const msg = `${cmd} ${args.join(' ')} exited ${code}: ${stderr || stdout}`;
      const e = new Error(msg);
      e.exitCode = error.code;
      e.stdout = stdout;
      e.stderr = stderr;
      reject(e);
    });
  });
}

module.exports = { run };
