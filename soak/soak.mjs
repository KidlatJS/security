/*!
 * kidlat - security
 * Copyright(c) 2026 JoshLei
 * MIT Licensed
 */

// Sustained keep-alive load. Pass = zero errors and heap/RSS growth within limits after warmup.
import http from 'node:http';
import { startServer, alive, report } from '../lib/common.mjs';

const seconds = Number(process.env.SOAK_SECONDS ?? 3600);
const connections = Number(process.env.SOAK_CONNECTIONS ?? 50);
const maxGrowthMB = 64;

const { child, port } = await startServer();
const agent = new http.Agent({ keepAlive: true, maxSockets: connections });
const body = JSON.stringify({ data: 'x'.repeat(1024) });
const paths = ['/', '/users/123', '/missing'];

function request(i) {
    const post = i % 4 === 3;
    return new Promise((resolve) => {
        const req = http.request({ port, agent, method: post ? 'POST' : 'GET', path: post ? '/echo' : paths[i % 3], headers: post ? { 'content-type': 'application/json', 'content-length': body.length } : {} }, (res) => {
            res.resume();
            res.on('end', () => resolve(res.statusCode));
        });
        req.on('error', () => resolve('error'));
        req.end(post ? body : undefined);
    });
}

const mem = () => new Promise((resolve) => http.get({ port, path: '/__mem' }, (res) => {
    let d = '';
    res.on('data', (c) => (d += c)).on('end', () => resolve(JSON.parse(d)));
}).on('error', () => resolve(null)));

const counts = {};
const samples = [];
let total = 0;
const end = Date.now() + seconds * 1000;
const sampler = setInterval(async () => { const m = await mem(); if (m) samples.push({ t: samples.length * 5, rssMB: +(m.rss / 2 ** 20).toFixed(1), heapMB: +(m.heapUsed / 2 ** 20).toFixed(1) }); }, 5000);

await Promise.all(Array.from({ length: connections }, async () => {
    while (Date.now() < end && alive(child)) {
        const code = await request(total++);
        counts[code] = (counts[code] ?? 0) + 1;
    }
}));
clearInterval(sampler);

// Ignore the first 20% as warmup
const steady = samples.slice(Math.floor(samples.length / 5));
const growth = (k) => (steady.length > 1 ? +(steady.at(-1)[k] - steady[0][k]).toFixed(1) : 0);
const unexpected = Object.entries(counts).filter(([c]) => !['200', '404'].includes(c)).reduce((n, [, v]) => n + v, 0);
const survived = alive(child);
child.kill();
agent.destroy();

report('soak', {
    passed: survived && unexpected === 0 && growth('heapMB') < maxGrowthMB && growth('rssMB') < maxGrowthMB,
    summary: { seconds, connections, requests: total, requestsPerSecond: Math.round(total / seconds), errors: unexpected, rssGrowthMB: growth('rssMB'), heapGrowthMB: growth('heapMB'), peakRssMB: Math.max(0, ...samples.map((s) => s.rssMB)), serverSurvived: survived },
    statusCounts: counts,
    samples,
});
