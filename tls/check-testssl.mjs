/*!
 * kidlat - security
 * Copyright(c) 2026 JoshLei
 * MIT Licensed
 */

// Gate on a testssl.sh JSON report: node tls/check-testssl.mjs result.json [--min-grade A]
// Fails on HIGH/CRITICAL findings or a grade below the minimum. Findings about the throwaway test certs are ignored.
import fs from 'node:fs';
import { report } from '../lib/common.mjs';

const IGNORE = [/^cert_/, /^intermediate_cert_/, /^DNS_CAArecord$/, /^OCSP/, /^scanProblem$/, /^engine_problem$/];
const GRADES = ['A+', 'A', 'A-', 'B', 'C', 'D', 'E', 'F', 'T', 'M'];

const all = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const i = process.argv.indexOf('--min-grade');
const minGrade = i === -1 ? null : process.argv[i + 1];

const findings = all
    .filter((f) => ['MEDIUM', 'HIGH', 'CRITICAL'].includes(f.severity))
    .filter((f) => f.id !== 'overall_grade' && !IGNORE.some((re) => re.test(f.id)));
const blocking = findings.filter((f) => f.severity !== 'MEDIUM');

const grade = all.find((f) => f.id === 'overall_grade')?.finding ?? '?';
const capReasons = all.filter((f) => /^grade_cap_reason/.test(f.id)).map((f) => f.finding);
const gradeOk = !minGrade || (GRADES.includes(grade) && GRADES.indexOf(grade) <= GRADES.indexOf(minGrade));

const esc = (v) => String(v).replace(/\|/g, '\|');
const rows = findings.map((f) => `| ${f.severity} | ${f.id} | ${esc(f.finding)} |`);
const summary = '### testssl.sh\n\n' +
    `Overall grade: **${grade}**${minGrade ? ` (minimum ${minGrade}) ${gradeOk ? '✅' : '❌'}` : ''}` +
    (capReasons.length ? `\n\nGrade capped because: ${capReasons.map(esc).join('; ')}` : '') + '\n\n' +
    (rows.length ? '| Severity | Check | Finding |\n|---|---|---|\n' + rows.join('\n') : 'No MEDIUM or higher findings.') +
    `\n\n${blocking.length ? '❌' : '✅'} ${blocking.length} HIGH/CRITICAL.\n`;
if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary + '\n');

report('tls', {
    passed: blocking.length === 0 && gradeOk,
    summary: { scanner: 'testssl.sh 3.2', grade, minGrade, capReasons, medium: findings.length - blocking.length, highOrCritical: blocking.length },
    results: findings.map((f) => ({ name: f.id, severity: f.severity, got: f.finding, passed: f.severity === 'MEDIUM' })),
});
