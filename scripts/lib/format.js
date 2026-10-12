'use strict';

/** Human-readable terminal report. JSON output lives in scan.js. */

const { SEVERITIES } = require('./result');
const { stripControl } = require('./util');

const STATUS_ORDER = { fail: 0, warn: 1, manual: 2, pass: 3 };

function palette(enabled) {
  const wrap = (code) => (s) => (enabled ? `\u001b[${code}m${s}\u001b[0m` : String(s));
  return { red: wrap('31'), yellow: wrap('33'), cyan: wrap('36'), green: wrap('32'), dim: wrap('2'), bold: wrap('1'), magenta: wrap('35') };
}

function useColor(stream) {
  if (process.env.NO_COLOR) return false;
  if (process.env.FORCE_COLOR && process.env.FORCE_COLOR !== '0') return true;
  return Boolean(stream && stream.isTTY);
}

function firstSentence(text) {
  const m = /^[\s\S]*?[.!?](?=\s|$)/.exec(text);
  return m ? m[0] : text;
}

function pad(s, n) {
  s = String(s);
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

function render(report, { verbose = false, color = false } = {}) {
  const c = palette(color);
  const out = [];
  const seconds = (report.durationMs / 1000).toFixed(1);
  out.push(`${c.bold(`preflight ${report.version}`)}  ${c.dim('·')}  ${report.target}  ${c.dim('·')}  ${report.results.length} checks in ${seconds}s`);
  if (report.notes && report.notes.length) for (const n of report.notes) out.push(c.dim(`note: ${n}`));
  out.push('');

  const sorted = [...report.results].sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  const label = {
    fail: c.red('✖ FAIL  '),
    warn: c.yellow('▲ WARN  '),
    manual: c.cyan('? MANUAL'),
    pass: c.green('✔ PASS  '),
  };
  const sev = (s) => (s === 'critical' ? c.red(pad(s, 8)) : s === 'high' ? c.magenta(pad(s, 8)) : pad(s, 8));
  const maxEvidence = verbose ? Infinity : 4;

  for (const r of sorted) {
    if (r.status === 'pass' && !verbose) continue;
    out.push(`${label[r.status]}  ${sev(r.severity)}  ${c.bold(pad(r.id, 8))}  ${r.title}`);
    const shown = r.evidence.slice(0, maxEvidence);
    for (const e of shown) out.push(`            ${c.dim('·')} ${stripControl(e)}`);
    if (r.evidence.length > shown.length) out.push(c.dim(`            · …${r.evidence.length - shown.length} more (--verbose or --json)`));
    if (r.question) out.push(`            ${c.cyan('?')} ${r.question}`);
    if (r.status !== 'pass') out.push(`            ${c.green('→')} ${verbose ? r.fix : firstSentence(r.fix)}`);
    out.push('');
  }

  const s = report.summary;
  const passes = s.pass;
  if (!verbose && passes) {
    out.push(c.dim(`${passes} checks passed (run with --verbose to list them).`));
    out.push('');
  }
  const failPart = s.fail ? c.red(`${s.fail} fail`) + (s.criticalFails ? c.red(` (${s.criticalFails} critical)`) : '') : `${s.fail} fail`;
  out.push(`${c.bold('Summary:')} ${failPart} · ${c.yellow(`${s.warn} warn`)} · ${c.cyan(`${s.manual} manual`)} · ${c.green(`${s.pass} pass`)}`);
  if (s.exitCode === 1) out.push(c.red(`Exit 1: at least one ${report.failOn === 'critical' ? 'critical' : `${report.failOn}-or-worse`} check failed.`));
  else out.push(c.green(`Exit 0: no ${report.failOn === 'critical' ? 'critical' : `${report.failOn}-or-worse`} failures.`) + (s.warn + s.manual ? c.dim(' Review the warn/manual items above (in Claude Code: /scan).') : ''));
  return out.join('\n');
}

module.exports = { render, useColor };
