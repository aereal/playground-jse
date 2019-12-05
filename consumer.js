#!/usr/bin/env node

const { JWE, JWK } = require('jose');
const fs = require('fs');

const bufSize = 4096;
const buf = Buffer.alloc(bufSize);
let token = '';
while (true) {
  const hasRead = fs.readSync(0, buf, 0, bufSize);
  if (hasRead <= 0) break;
  token += buf.slice(0, hasRead).toString('utf8');
}

const privateKey = JWK.asKey(fs.readFileSync('./keys/rsa.private.pem', 'utf8'));
const decrypted = JWE.decrypt(token.trim(), privateKey, { algorithms: ['RSA-OAEP'], complete: true });
const decoded = typeof decrypted === 'object' ? JSON.stringify(decrypted) : decrypted.toString();
process.stdout.write(decoded + "\n")
