#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { randomBytes } = require('node:crypto');

const args = process.argv.slice(2);
let output = path.resolve(__dirname, '../.env'), development = false;
for (let index = 0; index < args.length; index++) {
  if (args[index] === '--development') development = true;
  else if (args[index] === '--output' && args[index + 1]) output = path.resolve(args[++index]);
  else { console.error('Usage: node scripts/init-env.cjs [--development] [--output path]'); process.exit(1); }
}

try {
  let text = fs.readFileSync(path.resolve(__dirname, '../.env.example'), 'utf8');
  const values = { NODE_ENV: development ? 'development' : 'production',
    SESSION_SECRET: randomBytes(32).toString('hex'), PGPASSWORD: randomBytes(24).toString('hex'),
    ADMIN_PASSWORD: randomBytes(24).toString('hex'),
    SESSION_COOKIE_SECURE: development ? 'false' : 'true', HTTPS: development ? 'false' : 'true' };
  for (const [name, value] of Object.entries(values)) {
    text = text.replace(new RegExp(`^${name}=.*$`, 'm'), `${name}=${value}`);
  }
  fs.writeFileSync(output, text, { flag: 'wx', mode: 0o600 });
  console.log(`Created ${output}. Credentials are stored in that file and are not printed.`);
  console.log(development ? 'Start locally with docker compose up --build.'
    : 'Start behind your HTTPS proxy with docker compose -f docker-compose.yml -f docker-compose.production.yml up --build -d.');
} catch (error) {
  console.error(error.code === 'EEXIST' ? `Preserved existing ${output}; no credentials were changed.` : error.message);
  process.exitCode = 1;
}
