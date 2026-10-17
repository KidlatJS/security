/*!
 * kidlat - security
 * Copyright(c) 2026 JoshLei
 * MIT Licensed
 */

// Test PKI: a root -> intermediate -> leaf chain for 127.0.0.1, made with the openssl CLI.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export function makeChain(dir, days = 2) {
    const run = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' });
    fs.writeFileSync(path.join(dir, 'ca.ext'), 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
    fs.writeFileSync(path.join(dir, 'leaf.ext'), 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n');
    run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'root.key', '-out', 'root.pem', '-days', String(days), '-subj', '/CN=Kidlat Test Root', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
    run('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'int.key', '-out', 'int.csr', '-subj', '/CN=Kidlat Test Intermediate');
    run('x509', '-req', '-in', 'int.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-out', 'int.pem', '-days', String(days), '-extfile', 'ca.ext');
    run('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=127.0.0.1');
    run('x509', '-req', '-in', 'leaf.csr', '-CA', 'int.pem', '-CAkey', 'int.key', '-CAcreateserial', '-out', 'leaf.pem', '-days', String(days), '-extfile', 'leaf.ext');
    const read = (f) => fs.readFileSync(path.join(dir, f), 'utf8');
    return { root: read('root.pem'), chain: read('leaf.pem') + read('int.pem'), key: read('leaf.key') };
}
