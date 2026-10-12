'use strict';

/**
 * Result objects. Every check emits exactly one result per catalog id:
 *   { id, title, severity, status, evidence: string[], fix, question? }
 * `question` is present only on warn/manual results: the exact thing the agent must answer.
 */

const { getCheck } = require('./catalog');

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const STATUSES = ['fail', 'warn', 'manual', 'pass'];
const MAX_EVIDENCE = 25;

/** Build a result for catalog check `id`. extra: { fix, question, severity } overrides. */
function result(id, status, evidence = [], extra = {}) {
  if (!STATUSES.includes(status)) throw new Error(`Bad status ${status} for ${id}`);
  const meta = getCheck(id);
  const lines = dedupe(evidence.filter((e) => typeof e === 'string' && e.trim()));
  const capped = lines.length > MAX_EVIDENCE ? [...lines.slice(0, MAX_EVIDENCE - 1), `…and ${lines.length - MAX_EVIDENCE + 1} more`] : lines;
  const r = {
    id,
    title: meta.title,
    severity: extra.severity || meta.severity,
    status,
    evidence: capped,
    fix: extra.fix || meta.fix,
  };
  if (status === 'warn' || status === 'manual') r.question = extra.question || meta.question;
  return r;
}

const pass = (id, evidence = [], extra) => result(id, 'pass', evidence, extra);
const fail = (id, evidence, extra) => result(id, 'fail', evidence, extra);
const warn = (id, evidence, extra) => result(id, 'warn', evidence, extra);
const manual = (id, evidence, extra) => result(id, 'manual', evidence, extra);
/** Nothing to check: the feature isn't used in this repo. */
const na = (id, reason) => result(id, 'pass', [`Not applicable: ${reason}`]);

/** "path:line — note: snippet" (snippet optional). */
function ev(rel, line, note, snippet) {
  const loc = line ? `${rel}:${line}` : rel;
  return snippet ? `${loc} — ${note}: ${snippet}` : `${loc} — ${note}`;
}

function dedupe(items) {
  return [...new Set(items)];
}

module.exports = { SEVERITIES, STATUSES, result, pass, fail, warn, manual, na, ev };
