/*!
 * kidlat - security
 * Copyright(c) 2026 JoshLei
 * MIT Licensed
 */

import fs from 'node:fs';

const root = new URL('../', import.meta.url);
const load = (name) => { try { return JSON.parse(fs.readFileSync(new URL(`results/${name}.json`, root))); } catch { return null; } };
const suites = { fuzz: 'Fuzzing', 'request-smuggling': 'Smuggling (direct)', 'request-smuggling-nginx': 'Smuggling (via nginx)', soak: 'Soak', tls: 'TLS (testssl.sh)' };
const data = Object.fromEntries(Object.keys(suites).map((k) => [k, load(k)]));

const esc = (v) => String(v).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
const num = (n) => Number(n).toLocaleString('en');
const verdict = (r) => (r.passed ? '✅ pass' : '❌ fail');
const table = (head, rows) => [`| ${head.join(' | ')} |`, `|${head.map(() => '---').join('|')}|`, ...rows.map((r) => `| ${r.map(esc).join(' | ')} |`)];
const runUrl = process.env.GITHUB_RUN_ID ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}` : null;

function header(r) {
    const e = r.environment;
    return [
        `**${verdict(r)}** · ${e.date.replace('T', ' ').slice(0, 16)} UTC${runUrl ? ` · [workflow run](${runUrl})` : ''}`,
        '',
        ...table(['Kidlat', 'Node', 'OS', 'CPU'], [[e.kidlat, e.node, e.os, e.cpu ?? '']]),
        '',
    ];
}

function writeBlock(file, lines) {
    const url = new URL(file, root);
    const text = fs.readFileSync(url, 'utf8');
    fs.writeFileSync(url, text.replace(/<!-- results:start -->[\s\S]*<!-- results:end -->/, `<!-- results:start -->\n${lines.join('\n')}\n<!-- results:end -->`));
}

const counts = (c) => table(['Status', 'Count'], Object.entries(c).sort((a, b) => b[1] - a[1]).map(([k, v]) => [k, num(v)]));

const summary = [];
const env = Object.values(data).find(Boolean)?.environment;
if (env) summary.push(`Last run: **${env.date.slice(0, 10)}** · Kidlat **${env.kidlat}** · Node ${env.node} · ${env.os}${runUrl ? ` · [workflow run](${runUrl})` : ''}`, '');
summary.push('| Suite | Result | Key numbers |', '|---|---|---|');
for (const [name, title] of Object.entries(suites)) {
    const r = data[name];
    if (!r) { summary.push(`| ${title} | not run | |`); continue; }
    const s = r.summary;
    const numbers = {
        fuzz: () => `${s.minutes} min, ${num(s.iterations)} cases (seed \`${s.seed}\`), ${s.failures} failures`,
        'request-smuggling': () => `${s.passed}/${s.probes} probes safe`,
        'request-smuggling-nginx': () => `${s.passed}/${s.probes} probes safe`,
        soak: () => `${s.seconds / 60} min, ${num(s.requests)} req (${num(s.requestsPerSecond)}/s), ${s.errors} errors, RSS +${s.rssGrowthMB} MB`,
        tls: () => `grade ${s.grade} (min ${s.minGrade}), ${s.highOrCritical} HIGH/CRITICAL, ${s.medium} MEDIUM`,
    }[name]();
    const dir = name.startsWith('request-smuggling') ? 'request-smuggling' : name;
    summary.push(`| [${title}](${dir}/README.md#latest-run) | ${verdict(r)} | ${numbers} |`);
}
const failed = Object.values(data).filter(Boolean).flatMap((r) => (r.results ?? r.failures ?? []).filter((x) => x.passed === false || x.reason).map((x) => `${r.suite}: ${x.name ?? x.label} → ${JSON.stringify(x.got ?? x.reason)}`));
if (failed.length) summary.push('', '**Failing checks**', '', ...failed.map((f) => `- ${f}`));
writeBlock('README.md', summary);

// Fuzzing
const notRun = ['Not run yet.'];
const fz = data.fuzz;
const fuzzLog = !fz ? notRun : [
    ...header(fz),
    ...table(['Seed', 'Minutes', 'Cases', 'Cases/s', 'Regressions replayed', 'Failures', 'Server survived'],
        [[`\`${fz.summary.seed}\``, fz.summary.minutes, num(fz.summary.iterations), num(fz.summary.casesPerSecond), fz.summary.regressions, fz.summary.failures, fz.summary.serverSurvived ? 'yes' : 'no']]),
    '',
    `Reproduce: \`FUZZ_SEED=${fz.summary.seed} FUZZ_ITERATIONS=${fz.summary.iterations} npm run fuzz\``,
    '',
    '**Responses by status**',
    '',
    ...counts(fz.statusCounts),
    '',
    ...(fz.failures.length ? ['**Failures**', '', ...table(['Case', 'Reason', 'Input (base64)'], fz.failures.map((f) => [f.label, f.reason, `\`${f.input.slice(0, 80)}${f.input.length > 80 ? '…' : ''}\``]))] : ['No failures.']),
    '',
    `Raw data: [results/fuzz.json](../results/fuzz.json)`,
];

// Request smuggling: direct and via nginx
const smuggling = [];
for (const name of ['request-smuggling', 'request-smuggling-nginx']) {
    const r = data[name];
    smuggling.push(`### ${suites[name]}`, '');
    if (!r) { smuggling.push('Not run yet.', ''); continue; }
    smuggling.push(...header(r), `${r.summary.passed}/${r.summary.probes} probes safe (${r.summary.mode}).`, '',
        ...table(['Probe', 'First response', 'Requests Kidlat executed', 'Result'],
            r.results.map((p) => [`\`${p.name}\``, p.firstResponse, p.executed.join(', ') || '–', p.passed ? '✅ safe' : `❌ ${p.got}`])),
        '', `Raw data: [results/${name}.json](../results/${name}.json)`, '');
}
writeBlock('request-smuggling/README.md', smuggling);

// Soak
const sk = data.soak;
const step = sk ? Math.max(1, Math.ceil(sk.samples.length / 60)) : 1;
const soakLog = !sk ? notRun : [
    ...header(sk),
    ...table(['Duration', 'Connections', 'Requests', 'Req/s', 'Errors', 'RSS growth', 'Heap growth', 'Peak RSS'],
        [[`${sk.summary.seconds / 60} min`, sk.summary.connections, num(sk.summary.requests), num(sk.summary.requestsPerSecond), sk.summary.errors, `${sk.summary.rssGrowthMB} MB`, `${sk.summary.heapGrowthMB} MB`, `${sk.summary.peakRssMB} MB`]]),
    '',
    '**Responses by status**',
    '',
    ...counts(sk.statusCounts),
    '',
    '<details><summary>Memory samples</summary>',
    '',
    ...table(['Time (s)', 'RSS (MB)', 'Heap (MB)'], sk.samples.filter((_, i) => i % step === 0 || i === sk.samples.length - 1).map((m) => [m.t, m.rssMB, m.heapMB])),
    '',
    '</details>',
    '',
    `Raw data: [results/soak.json](../results/soak.json)`,
];

// TLS
const tl = data.tls;
const tlsLog = !tl ? notRun : [
    ...header(tl),
    ...table(['Scanner', 'Grade', 'Minimum', 'HIGH/CRITICAL', 'MEDIUM'], [[tl.summary.scanner, `**${tl.summary.grade}**`, tl.summary.minGrade, tl.summary.highOrCritical, tl.summary.medium]]),
    '',
    ...(tl.summary.capReasons.length ? [`Grade capped because: ${tl.summary.capReasons.map(esc).join('; ')}`, ''] : []),
    ...(tl.results.length ? table(['Severity', 'Check', 'Finding'], tl.results.map((f) => [f.severity, f.name, f.got])) : ['No MEDIUM or higher findings.']),
    '',
    `Raw data: [results/tls.json](../results/tls.json)`,
];

writeBlock('fuzz/README.md', fuzzLog);
writeBlock('soak/README.md', soakLog);
writeBlock('tls/README.md', tlsLog);

// SECURITY.md
const rebase = (lines) => lines.map((l) => l.replaceAll('](../', ']('));
fs.writeFileSync(new URL('SECURITY.md', root), [
    '# Security Test Report',
    '',
    '<!-- Generated by scripts/update-readme.mjs from results/. Do not edit by hand. -->',
    '',
    'Results of every suite in this repository, run against the published `kidlat` npm package by the [Security tests workflow](.github/workflows/security.yml). Each section links to its suite README for the full method and how to reproduce it.',
    '',
    '## Summary',
    '',
    ...summary,
    '',
    '## Fuzzing',
    '',
    'Black-box mutation fuzzing of the HTTP/1.1 parser over raw TCP for 120 minutes. Passes if the server never crashes and every response is well-formed. [Method](fuzz/README.md)',
    '',
    ...rebase(fuzzLog),
    '',
    '## Request smuggling',
    '',
    '39 framing tricks (CL.TE, TE.CL, malformed lengths and chunks), each hiding `GET /smuggled`, followed by a victim request. Run direct and through nginx. Passes if `/smuggled` never executes and the victim gets its own response. [Method](request-smuggling/README.md)',
    '',
    ...rebase(smuggling),
    '## Soak',
    '',
    'One hour of keep-alive load on 50 connections. Passes with zero errors and under 64 MB memory growth after warmup. [Method](soak/README.md)',
    '',
    ...rebase(soakLog),
    '',
    '## TLS',
    '',
    'testssl.sh 3.2 against Kidlat serving a root → intermediate → leaf chain. Passes with grade A or better and no HIGH/CRITICAL findings. [Method](tls/README.md)',
    '',
    ...rebase(tlsLog),
    '',
].join('\n'));

process.exitCode = Object.values(data).some((r) => r && !r.passed) ? 1 : 0;
