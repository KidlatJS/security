/*!
 * kidlat - security
 * Copyright(c) 2026 JoshLei
 * MIT Licensed
 */

// Each probe hides "GET /smuggled" behind a framing trick, then a victim request follows on a fresh connection.
// Pass = Kidlat never executes /smuggled and the victim gets its own response.
//   node request-smuggling/probes.mjs          direct to Kidlat
//   node request-smuggling/probes.mjs --via 127.0.0.1:8080 --app-port 3001  through a proxy
import fs from 'node:fs';
import net from 'node:net';
import { Kidlat } from 'kidlat';
import { report } from '../lib/common.mjs';

const opt = (name, fallback) => {
    const i = process.argv.indexOf(`--${name}`);
    return i === -1 ? fallback : process.argv[i + 1];
};
const via = opt('via', null);

// In-process app so every request Kidlat actually executes is recorded
const seen = [];
const app = new Kidlat({ bodyLimit: 1 << 20 });
app.all('/*', async (req) => {
    seen.push(`${req.method} ${req.path}`);
    if (req.method === 'POST') await req.buffer().catch(() => {});
    return `path=${req.path}`;
});
const appPort = app.listen(Number(opt('app-port', 0)), '127.0.0.1');
const [host, port] = via ? [via.split(':')[0], Number(via.split(':')[1])] : ['127.0.0.1', appPort];

const SMUGGLED = 'GET /smuggled HTTP/1.1\r\nHost: a\r\n\r\n';
const P = 'POST /probe HTTP/1.1\r\nHost: a\r\n';
const hex = (n) => n.toString(16);
const clte = (te) => { const body = `0\r\n\r\n${SMUGGLED}`; return `${P}Content-Length: ${body.length}\r\n${te}\r\n\r\n${body}`; };
const tecl = (te) => `${P}Content-Length: 4\r\n${te}\r\n\r\n${hex(SMUGGLED.length)}\r\n${SMUGGLED}\r\n0\r\n\r\n`;

const TE_VARIANTS = [
    'Transfer-Encoding: chunked',
    'Transfer-Encoding: xchunked',
    'Transfer-Encoding : chunked',
    'Transfer-Encoding:\tchunked',
    'Transfer-Encoding: chunked\r\nTransfer-Encoding: x',
    'Transfer-Encoding: x\r\nTransfer-Encoding: chunked',
    'Transfer-Encoding: chunked, identity',
    'Transfer-Encoding: identity, chunked',
    'Transfer-Encoding:\r\n chunked',
    'Transfer-Encoding: CHUNKED',
    'Transfer-Encoding: "chunked"',
    'X: x\nTransfer-Encoding: chunked',
    ' Transfer-Encoding: chunked',
];

const probes = [];
for (const te of TE_VARIANTS) {
    probes.push([`CL.TE ${JSON.stringify(te)}`, clte(te)]);
    probes.push([`TE.CL ${JSON.stringify(te)}`, tecl(te)]);
}
const n = SMUGGLED.length;
probes.push(
    ['CL.CL conflicting', `${P}Content-Length: 0\r\nContent-Length: ${n}\r\n\r\n${SMUGGLED}`],
    ['CL "+N"', `${P}Content-Length: +${n}\r\n\r\n${SMUGGLED}`],
    ['CL "N, N"', `${P}Content-Length: ${n}, ${n}\r\n\r\n${SMUGGLED}`],
    ['CL hex', `${P}Content-Length: 0x${hex(n)}\r\n\r\n${SMUGGLED}`],
    ['CL space before colon', `${P}Content-Length : ${n}\r\n\r\n${SMUGGLED}`],
    ['bare LF line endings', `POST /probe HTTP/1.1\nHost: a\nContent-Length: ${n}\n\n${SMUGGLED}`],
    ['bare CR in header', `${P}X: a\rContent-Length: ${n}\r\n\r\n${SMUGGLED}`],
    ['NUL in header value', `${P}X: a\0b\r\nContent-Length: 0\r\n\r\n${SMUGGLED}`],
    ['HTTP/1.0 + chunked', `POST /probe HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n${hex(n)}\r\n${SMUGGLED}\r\n0\r\n\r\n`],
    ['chunk size overflow', `${P}Transfer-Encoding: chunked\r\n\r\n1${'0'.repeat(16)}\r\n${SMUGGLED}\r\n0\r\n\r\n`],
    ['chunk size trailing junk', `${P}Transfer-Encoding: chunked\r\n\r\n${hex(n)} x\r\n${SMUGGLED}\r\n0\r\n\r\n`],
    ['chunk ext with bare LF', `${P}Transfer-Encoding: chunked\r\n\r\n0;x\n${SMUGGLED}\r\n0\r\n\r\n`],
    ['chunk data without CRLF', `${P}Transfer-Encoding: chunked\r\n\r\n2\r\nab${SMUGGLED}0\r\n\r\n`],
);

function exchange(payload, waitMs = 1500) {
    return new Promise((resolve) => {
        let out = '';
        const s = net.connect(port, host, () => s.write(payload));
        const t = setTimeout(() => { s.destroy(); resolve(out); }, waitMs);
        s.on('data', (d) => { out += d; });
        s.on('error', () => {});
        s.on('close', () => { clearTimeout(t); resolve(out); });
    });
}

const results = [];
for (const [name, payload] of probes) {
    const before = seen.length;
    const front = await exchange(payload);
    // Through a proxy the victim may reuse a poisoned upstream connection
    const victim = await exchange('GET /victim HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n');
    const executed = seen.slice(before);
    const smuggled = executed.some((p) => p.includes('smuggled'));
    const victimOk = victim.startsWith('HTTP/1.1 200') && victim.includes('path=/victim');
    results.push({
        name,
        firstResponse: front.split('\r\n')[0] || '(no response)',
        executed,
        got: smuggled ? 'smuggled request executed' : victimOk ? 'safe' : 'victim got wrong response',
        passed: !smuggled && victimOk,
    });
}
await app.close();

const passed = results.filter((r) => r.passed).length;
const esc = (v) => String(v).replace(/\|/g, '\|');
const table = `### Request smuggling (${via ? `through ${via}` : 'direct'})\n\n| Probe | First response | Executed | |\n|---|---|---|---|\n` +
    results.map((r) => `| ${esc(r.name)} | ${esc(r.firstResponse)} | ${r.executed.join(', ') || '–'} | ${r.passed ? '✅' : `❌ ${r.got}`} |`).join('\n') +
    `\n\n${passed}/${results.length} probes safe.\n`;
if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, table + '\n');

report(via ? 'request-smuggling-nginx' : 'request-smuggling', {
    passed: passed === results.length,
    summary: { mode: via ? `via ${via}` : 'direct', probes: results.length, passed },
    results,
});
