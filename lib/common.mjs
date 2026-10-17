/*!
 * kidlat - security
 * Copyright(c) 2026 JoshLei
 * MIT Licensed
 */

import { fork } from 'node:child_process';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

export function startServer(env = {}) {
    const child = fork(new URL('./server.mjs', import.meta.url), { env: { ...process.env, ...env }, stdio: 'inherit' });
    return new Promise((resolve, reject) => {
        child.once('message', ({ port }) => resolve({ child, port }));
        child.once('exit', (code) => reject(new Error(`server exited early (${code})`)));
    });
}

export function alive(child) {
    return child.exitCode === null && child.signalCode === null;
}

// Sends raw bytes, collects everything until the server closes or goes quiet
export function raw(port, data, { idle = 500 } = {}) {
    return new Promise((resolve) => {
        const sock = net.connect(port, '127.0.0.1');
        const chunks = [];
        let timer;
        const done = (closed) => { clearTimeout(timer); sock.destroy(); resolve({ text: Buffer.concat(chunks).toString('latin1'), closed }); };
        const arm = () => { clearTimeout(timer); timer = setTimeout(() => done(false), idle); };
        sock.on('connect', () => { sock.write(data); arm(); });
        sock.on('data', (c) => { chunks.push(c); arm(); });
        sock.on('end', () => done(true));
        sock.on('error', () => done(true));
    });
}

export function statuses(text) {
    return [...text.matchAll(/HTTP\/1\.[01] (\d{3}) /g)].map((m) => Number(m[1]));
}

export function environment() {
    return {
        kidlat: require('kidlat/package.json').version,
        node: process.version,
        os: `${os.type()} ${os.release()} ${os.arch()}`,
        cpu: os.cpus()[0]?.model,
        date: new Date().toISOString(),
    };
}

// Every suite writes results/<name>.json and exits 1 on failure
export function report(name, data) {
    const out = { suite: name, environment: environment(), ...data };
    fs.mkdirSync(new URL('../results/', import.meta.url), { recursive: true });
    fs.writeFileSync(new URL(`../results/${name}.json`, import.meta.url), JSON.stringify(out, null, 2) + '\n');
    console.log(`${name}: ${out.passed ? 'PASS' : 'FAIL'}`);
    process.exitCode = out.passed ? 0 : 1;
}
