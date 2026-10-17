/*!
 * kidlat - security
 * Copyright(c) 2026 JoshLei
 * MIT Licensed
 */

// HTTPS target for testssl.sh: node tls/server.mjs [port] [--ca-out file]
// Serves a fresh root → intermediate → leaf chain for 127.0.0.1; --ca-out writes the root so the scanner can trust it.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Kidlat } from 'kidlat';
import { makeChain } from '../lib/tls-chain.mjs';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kidlat-testssl-'));
const pki = makeChain(dir, 397);
const caOut = process.argv.indexOf('--ca-out');
if (caOut !== -1) fs.writeFileSync(process.argv[caOut + 1], pki.root);
const app = new Kidlat({ https: { cert: pki.chain, key: pki.key } });
app.get('/', () => 'tls ok');
const port = app.listen(Number(process.argv[2] || 8443), '127.0.0.1');
console.log(`ready ${port}`);
process.on('SIGTERM', async () => { await app.close(); fs.rmSync(dir, { recursive: true, force: true }); process.exit(0); });
