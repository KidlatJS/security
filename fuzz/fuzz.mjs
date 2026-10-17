/*!
 * kidlat - security
 * Copyright(c) 2026 JoshLei
 * MIT Licensed
 */

// Black-box mutation fuzzer for the HTTP/1.1 parser over raw TCP.
// Runs for FUZZ_MINUTES. Reproduce a run with the same FUZZ_SEED and FUZZ_ITERATIONS from its results.
import fs from 'node:fs';
import { startServer, raw, alive, report } from '../lib/common.mjs';

const seed = Number(process.env.FUZZ_SEED ?? Date.now() % 2 ** 31);
const minutes = Number(process.env.FUZZ_MINUTES ?? 120);
const iterations = Number(process.env.FUZZ_ITERATIONS ?? Infinity);
const concurrency = 32;
const regressionsDir = new URL('./regressions/', import.meta.url);

// mulberry32
let s = seed;
const rand = () => { s = (s + 0x6d2b79f5) | 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 2 ** 32; };
const pick = (a) => a[Math.floor(rand() * a.length)];

const seeds = [
    'GET / HTTP/1.1\r\nHost: x\r\n\r\n',
    'GET /users/42?a=1&b=%20 HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n',
    'POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello',
    'POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\nTrailer: v\r\n\r\n',
    'GET / HTTP/1.0\r\n\r\n',
];
const tokens = ['\r\n', '\n', '\r', ':', ' ', '\t', '\0', '\x7f', '\xff', ';', ',', '%', '%00', '0', '-1', 'chunked', 'Content-Length: ', 'Transfer-Encoding: ', '9'.repeat(30), 'A'.repeat(9000), '\r\n\r\n'];

function mutate(input) {
    let b = Buffer.from(input, 'latin1');
    for (let n = 1 + Math.floor(rand() * 8); n > 0; n--) {
        const i = Math.floor(rand() * (b.length + 1));
        switch (Math.floor(rand() * 5)) {
            case 0: if (b.length) b[i % b.length] ^= 1 << Math.floor(rand() * 8); break;
            case 1: b = Buffer.concat([b.subarray(0, i), Buffer.from([Math.floor(rand() * 256)]), b.subarray(i)]); break;
            case 2: b = Buffer.concat([b.subarray(0, i), b.subarray(i + 1 + Math.floor(rand() * 8))]); break;
            case 3: b = Buffer.concat([b.subarray(0, i), Buffer.from(pick(tokens), 'latin1'), b.subarray(i)]); break;
            case 4: b = Buffer.concat([b, Buffer.from(pick(seeds), 'latin1')]); break;
        }
    }
    return b;
}

const { child, port } = await startServer();
const failures = [];
let failCount = 0;
const fail = (f) => { failCount++; if (failures.length < 20) failures.push(f); };
const statusCounts = {};

async function check(input, label) {
    const { text } = await raw(port, input, { idle: 50 });
    if (!alive(child)) return fail({ label, reason: 'server crashed', input: input.toString('base64') });
    if (text && !text.startsWith('HTTP/1.1 ')) fail({ label, reason: 'malformed response', input: input.toString('base64') });
    const code = text.slice(9, 12) || 'none';
    statusCounts[code] = (statusCounts[code] ?? 0) + 1;
}

// Saved crashers are replayed first so fixed bugs stay fixed.
const regressions = fs.readdirSync(regressionsDir).filter((f) => f.endsWith('.bin'));
for (const f of regressions) await check(fs.readFileSync(new URL(f, regressionsDir)), `regression ${f}`);

const start = Date.now();
let next = 0;
const deadline = start + minutes * 60000;
await Promise.all(Array.from({ length: concurrency }, async () => {
    while (alive(child) && next < iterations && Date.now() < deadline) await check(mutate(pick(seeds)), `case ${next++}`);
}));
const seconds = (Date.now() - start) / 1000;

const control = await raw(port, 'GET / HTTP/1.1\r\nHost: x\r\n\r\n');
const survived = alive(child) && control.text.startsWith('HTTP/1.1 200');
for (const f of failures) fs.writeFileSync(new URL(`crash-${seed}-${f.label.replace(/\D/g, '')}.bin`, regressionsDir), Buffer.from(f.input, 'base64'));
child.kill();

report('fuzz', {
    passed: survived && failCount === 0,
    summary: { seed, minutes, iterations: next, regressions: regressions.length, seconds, casesPerSecond: Math.round(next / seconds), failures: failCount, serverSurvived: survived },
    statusCounts,
    failures,
});
