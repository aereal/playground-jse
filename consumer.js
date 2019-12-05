#!/usr/bin/env node

const jwt = require('jsonwebtoken');
const fs = require('fs');

const bufSize = 4096;
const buf = Buffer.alloc(bufSize);
let token = '';
while (true) {
  const hasRead = fs.readSync(0, buf, 0, bufSize);
  if (hasRead <= 0) break;
  token += buf.slice(0, hasRead).toString('utf8');
}

const publicKey = fs.readFileSync('./keys/rsa.public.pem', 'utf8');
const decoded = jwt.verify(token.trim(), publicKey, { algorithms: ['RSA-OAEP'] });
process.stdout.write(JSON.stringify(decoded) + "\n")
