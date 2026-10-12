'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync, execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const SCAN = path.join(ROOT, 'scripts', 'scan.js');
const RESULT_KEYS = ['id', 'title', 'severity', 'status', 'evidence', 'fix'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const STATUSES = ['pass', 'fail', 'warn', 'manual'];

/** Run the scanner (default: scripts/scan.js) and parse --json output when present. */
function scan(args, { cwd = ROOT, script = SCAN, env } = {}) {
  const started = Date.now();
  const res = spawnSync(process.execPath, [script, ...args], { cwd, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', ...env }, maxBuffer: 64 * 1024 * 1024 });
  let json = null;
  if (args.includes('--json')) {
    try {
      json = JSON.parse(res.stdout);
    } catch {
      json = null;
    }
  }
  return { status: res.status, stdout: res.stdout, stderr: res.stderr, json, ms: Date.now() - started };
}

/** Async variant: needed when the test process itself serves HTTP to the scanner. */
function scanAsync(args, { cwd = ROOT, script = SCAN, env } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(process.execPath, [script, ...args], { cwd, env: { ...process.env, NO_COLOR: '1', ...env } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (status) => {
      let json = null;
      try {
        json = JSON.parse(stdout);
      } catch {
        json = null;
      }
      resolve({ status, stdout, stderr, json, ms: Date.now() - started });
    });
  });
}

/** Is `rel` inside a git work tree with commits (fixtures are committed in a normal clone)? */
function isGitCheckout(dir = ROOT) {
  try {
    return execFileSync('git', ['rev-parse', '--is-inside-work-tree'], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() === 'true';
  } catch {
    return false;
  }
}

function isTracked(rel) {
  try {
    return execFileSync('git', ['ls-files', '--error-unmatch', rel], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim().length > 0;
  } catch {
    return false;
  }
}

/** Does any evidence line point at file:line (or at the file, when line is null)? */
function pointsAt(result, file, line) {
  return result.evidence.some((e) => (line ? e.startsWith(`${file}:${line} `) || e.startsWith(`${file}:${line} `) : e.startsWith(`${file} `) || e.startsWith(`${file}:`)));
}

/** Validate one result against the published schema; returns a list of problems. */
function schemaProblems(r) {
  const problems = [];
  for (const k of RESULT_KEYS) if (!(k in r)) problems.push(`missing ${k}`);
  const extra = Object.keys(r).filter((k) => !RESULT_KEYS.includes(k) && k !== 'question');
  if (extra.length) problems.push(`unexpected keys ${extra.join(',')}`);
  if (typeof r.id !== 'string') problems.push('id not a string');
  if (typeof r.title !== 'string' || !r.title) problems.push('title not a string');
  if (!SEVERITIES.includes(r.severity)) problems.push(`bad severity ${r.severity}`);
  if (!STATUSES.includes(r.status)) problems.push(`bad status ${r.status}`);
  if (!Array.isArray(r.evidence) || !r.evidence.every((e) => typeof e === 'string')) problems.push('evidence not string[]');
  if (typeof r.fix !== 'string' || !r.fix) problems.push('fix not a string');
  if ((r.status === 'warn' || r.status === 'manual') && typeof r.question !== 'string') problems.push('warn/manual without question');
  if ((r.status === 'pass' || r.status === 'fail') && 'question' in r) problems.push('question on pass/fail');
  return problems;
}

/** Copy a directory tree (no symlinks) into a fresh temp dir. */
function tempCopy(src, name = 'preflight-test-') {
  const dest = fs.mkdtempSync(path.join(os.tmpdir(), name));
  fs.cpSync(src, dest, { recursive: true });
  return dest;
}

function tempDir(files, name = 'preflight-test-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), name));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return dir;
}

function byId(json) {
  return new Map(json.results.map((r) => [r.id, r]));
}

module.exports = { ROOT, SCAN, RESULT_KEYS, scan, scanAsync, isGitCheckout, isTracked, pointsAt, schemaProblems, tempCopy, tempDir, byId };
