#!/usr/bin/env node
'use strict';

/**
 * preflight: deterministic pre-launch scanner for vibe-coded web apps.
 *
 *   node scripts/scan.js [path] [options]
 *
 * Runs every check group in scripts/checks/ against the target repo and prints a human
 * report, or JSON with --json (for the /scan agent workflow). It never writes into the target
 * repo; live checks are single read-only GET requests and only run when you pass their flags.
 *
 * Exit codes: 0 = no failing check at or above --fail-on (default: critical)
 *             1 = at least one such failure
 *             2 = usage error or scanner crash
 */

const fs = require('fs');
const path = require('path');
const VERSION = require('./lib/version');
const { CHECKS } = require('./lib/catalog');
const { SEVERITIES, STATUSES, result } = require('./lib/result');
const { loadRepo } = require('./lib/repo');
const { render, useColor } = require('./lib/format');

// secrets runs first: it records every secret it finds so later groups' snippets mask them.
// Network/subprocess-bound groups come next, so their I/O overlaps with the CPU-bound ones.
const GROUPS = [
  require('./checks/secrets'),
  require('./checks/deps'),
  require('./checks/headers'),
  require('./checks/supabase'),
  require('./checks/env'),
  require('./checks/data'),
  require('./checks/auth'),
  require('./checks/injection'),
  require('./checks/appsec'),
  require('./checks/infra'),
  require('./checks/comms'),
  require('./checks/legal'),
  require('./checks/a11y'),
  require('./checks/ai'),
];

const HELP = `preflight ${VERSION}: pre-launch security and cost-risk scanner

Usage: node scripts/scan.js [path] [options]

  path                     repo to scan (default: current directory)
  --json                   print machine-readable JSON (used by the /scan command)
  --url <url>              deployed site to check live security headers, CORS and cookies
  --supabase-url <url>     Supabase project URL for the live RLS read test
  --supabase-key <key>     the project's anon/publishable key (service-role keys are refused)
  --offline                skip everything that needs the network (npm audit, live checks)
  --no-audit               skip npm audit only (live checks still run when requested)
  --no-history             skip the git history secret scan
  --history-depth <n>      commits of history to scan (default 200)
  --only <groups>          comma-separated groups or check ids (e.g. secrets,env or SEC-02)
  --fail-on <severity>     exit 1 on failed checks at or above this severity (default critical)
  --verbose                list passing checks and full fix text
  -v, --version            print the version
  -h, --help               show this help

Groups: ${GROUPS.map((g) => g.name).join(', ')}
Exit codes: 0 no failures at/above --fail-on, 1 failures found, 2 usage error or crash.`;

class UsageError extends Error {}

function parseArgs(argv) {
  const opts = {
    target: null,
    json: false,
    url: null,
    supabaseUrl: null,
    supabaseKey: null,
    offline: false,
    audit: true,
    history: true,
    historyDepth: 200,
    only: null,
    failOn: 'critical',
    verbose: false,
    help: false,
    version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const raw = argv[i];
    const eq = raw.startsWith('--') ? raw.indexOf('=') : -1;
    const flag = eq === -1 ? raw : raw.slice(0, eq);
    const value = () => {
      if (eq !== -1) return raw.slice(eq + 1);
      const v = argv[++i];
      if (v === undefined || (v.startsWith('--') && v.length > 2)) throw new UsageError(`${flag} needs a value`);
      return v;
    };
    switch (flag) {
      case '--json':
        opts.json = true;
        break;
      case '--url':
        opts.url = httpUrl(value(), '--url');
        break;
      case '--supabase-url':
        opts.supabaseUrl = httpUrl(value(), '--supabase-url').replace(/\/+$/, '');
        break;
      case '--supabase-key':
        opts.supabaseKey = value().trim();
        break;
      case '--offline':
        opts.offline = true;
        break;
      case '--no-audit':
        opts.audit = false;
        break;
      case '--no-history':
        opts.history = false;
        break;
      case '--history-depth': {
        const n = Number(value());
        if (!Number.isInteger(n) || n < 0) throw new UsageError('--history-depth must be a non-negative integer');
        opts.historyDepth = n;
        if (n === 0) opts.history = false;
        break;
      }
      case '--only':
        opts.only = value()
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
        break;
      case '--fail-on': {
        const s = value().toLowerCase();
        if (!SEVERITIES.includes(s)) throw new UsageError(`--fail-on must be one of ${SEVERITIES.join(', ')}`);
        opts.failOn = s;
        break;
      }
      case '--verbose':
        opts.verbose = true;
        break;
      case '-h':
      case '--help':
        opts.help = true;
        break;
      case '-v':
      case '--version':
        opts.version = true;
        break;
      default:
        if (raw.startsWith('-') && raw !== '-') throw new UsageError(`Unknown option ${raw}`);
        if (opts.target) throw new UsageError(`Unexpected argument ${raw} (only one path can be scanned at a time)`);
        opts.target = raw;
    }
  }
  if (Boolean(opts.supabaseUrl) !== Boolean(opts.supabaseKey)) throw new UsageError('--supabase-url and --supabase-key must be used together');
  return opts;
}

function httpUrl(value, flag) {
  let u;
  try {
    u = new URL(value);
  } catch {
    throw new UsageError(`${flag} must be a full URL like https://example.com`);
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new UsageError(`${flag} must use http or https`);
  return u.toString().replace(/\/$/, '') || value;
}

function selectGroups(only) {
  if (!only) return { groups: GROUPS, ids: null };
  const wanted = new Set(only.map((s) => s.toLowerCase()));
  const ids = new Set();
  const groups = GROUPS.filter((g) => {
    const byName = wanted.has(g.name.toLowerCase()) || wanted.has(`${g.name.toLowerCase()}.js`);
    const byId = g.ids.filter((id) => wanted.has(id.toLowerCase()));
    if (byName) g.ids.forEach((id) => ids.add(id));
    byId.forEach((id) => ids.add(id));
    return byName || byId.length > 0;
  });
  if (!groups.length) throw new UsageError(`--only matched nothing. Groups: ${GROUPS.map((g) => g.name).join(', ')}`);
  return { groups, ids };
}

function checkShape(r) {
  const ok =
    r &&
    typeof r.id === 'string' &&
    typeof r.title === 'string' &&
    SEVERITIES.includes(r.severity) &&
    STATUSES.includes(r.status) &&
    Array.isArray(r.evidence) &&
    r.evidence.every((e) => typeof e === 'string') &&
    typeof r.fix === 'string';
  if (!ok) throw new Error(`malformed result: ${JSON.stringify(r).slice(0, 200)}`);
}

function detectStack(repo) {
  const frameworks = [];
  const has = (d) => repo.deps.has(d);
  const add = (cond, name) => cond && frameworks.push(name);
  add(has('next'), 'Next.js');
  add(has('@sveltejs/kit'), 'SvelteKit');
  add(has('nuxt'), 'Nuxt');
  add(has('astro'), 'Astro');
  add(has('@remix-run/node') || has('@remix-run/react') || has('@react-router/dev'), 'Remix/React Router');
  add(has('vite') && !has('@sveltejs/kit') && !has('astro'), 'Vite');
  add(has('react-scripts'), 'Create React App');
  add(has('expo') || has('react-native'), 'Expo/React Native');
  add(has('express'), 'Express');
  add(has('fastify'), 'Fastify');
  add(has('hono'), 'Hono');
  add(has('koa'), 'Koa');
  add(has('@nestjs/core'), 'NestJS');
  add(repo.pythonDeps.has('django'), 'Django');
  add(repo.pythonDeps.has('flask'), 'Flask');
  add(repo.pythonDeps.has('fastapi'), 'FastAPI');
  const services = [];
  const svc = (cond, name) => cond && services.push(name);
  svc(has('@supabase/supabase-js') || has('@supabase/ssr'), 'Supabase');
  svc(has('firebase') || has('firebase-admin'), 'Firebase');
  svc(has('stripe') || has('@stripe/stripe-js'), 'Stripe');
  svc(has('twilio'), 'Twilio');
  svc(has('openai'), 'OpenAI');
  svc(has('@anthropic-ai/sdk'), 'Anthropic');
  svc(has('ai'), 'Vercel AI SDK');
  svc(has('@prisma/client') || has('prisma'), 'Prisma');
  svc(has('mongoose') || has('mongodb'), 'MongoDB');
  return { frameworks, services, git: repo.git.isRepo };
}

async function scan(opts) {
  const target = path.resolve(opts.target || process.cwd());
  let stat;
  try {
    stat = fs.statSync(target);
  } catch {
    throw new UsageError(`No such directory: ${target}`);
  }
  if (!stat.isDirectory()) throw new UsageError(`Not a directory: ${target}`);

  const started = Date.now();
  const { groups, ids } = selectGroups(opts.only);
  const repo = loadRepo(target, opts);
  const notes = [];
  if (repo.truncated) notes.push(`Stopped walking after ${repo.files.length} files; some files were not scanned.`);
  if (!repo.git.isRepo) notes.push('Not a git repository: tracked/ignored status and history checks were limited.');
  if (opts.offline) notes.push('--offline: npm audit and live checks were skipped.');

  const byId = new Map();
  const timings = {};
  // Groups run concurrently: syncMs is the CPU time a group spent before its first await
  // (most of the work), doneAtMs is when it finished, counted from the start of the scan.
  await Promise.all(
    groups.map(async (g) => {
      const t0 = Date.now();
      const timing = { syncMs: 0, doneAtMs: 0 };
      timings[g.name] = timing;
      try {
        const pending = g.run(target, opts);
        timing.syncMs = Date.now() - t0;
        const out = await pending;
        for (const r of out) {
          checkShape(r);
          if (!byId.has(r.id)) byId.set(r.id, r);
        }
      } catch (err) {
        for (const id of g.ids) {
          if (!byId.has(id)) {
            byId.set(id, result(id, 'manual', [`The ${g.name} check crashed before finishing: ${err && err.message ? err.message : err}`], { question: 'The automated check crashed. Review this area by hand, and report the crash at https://github.com/xploit007/preflight/issues.' }));
          }
        }
      }
      if (!timing.syncMs) timing.syncMs = Date.now() - t0;
      timing.doneAtMs = Date.now() - started;
    }),
  );

  const results = [];
  for (const c of CHECKS) {
    if (ids && !ids.has(c.id)) continue;
    results.push(byId.get(c.id) || result(c.id, 'manual', ['Not evaluated: no check group produced a result for this id.']));
  }

  const count = (st) => results.filter((r) => r.status === st).length;
  const failing = results.filter((r) => r.status === 'fail' && SEVERITIES.indexOf(r.severity) <= SEVERITIES.indexOf(opts.failOn));
  const summary = {
    total: results.length,
    fail: count('fail'),
    warn: count('warn'),
    manual: count('manual'),
    pass: count('pass'),
    criticalFails: results.filter((r) => r.status === 'fail' && r.severity === 'critical').length,
    highFails: results.filter((r) => r.status === 'fail' && r.severity === 'high').length,
    exitCode: failing.length ? 1 : 0,
  };

  return {
    tool: 'preflight',
    version: VERSION,
    schemaVersion: 1,
    target,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    failOn: opts.failOn,
    options: {
      url: opts.url,
      supabaseLive: Boolean(opts.supabaseUrl && opts.supabaseKey),
      offline: opts.offline,
      audit: opts.audit && !opts.offline,
      history: opts.history ? opts.historyDepth : 0,
      only: opts.only,
    },
    detected: detectStack(repo),
    notes,
    timingsMs: timings,
    summary,
    results,
  };
}

function write(text, code) {
  process.stdout.write(`${text}\n`, () => process.exit(code));
}

async function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    if (err instanceof UsageError) {
      process.stderr.write(`preflight: ${err.message}\n\n${HELP}\n`);
      process.exit(2);
    }
    throw err;
  }
  if (opts.help) return write(HELP, 0);
  if (opts.version) return write(VERSION, 0);
  try {
    const report = await scan(opts);
    if (opts.json) return write(JSON.stringify(report, null, 2), report.summary.exitCode);
    return write(render(report, { verbose: opts.verbose, color: useColor(process.stdout) }), report.summary.exitCode);
  } catch (err) {
    const message = err instanceof UsageError ? err.message : `crashed: ${err && err.stack ? err.stack : err}`;
    if (opts.json) return write(JSON.stringify({ tool: 'preflight', version: VERSION, error: message }, null, 2), 2);
    process.stderr.write(`preflight: ${message}\n`);
    process.exit(2);
  }
}

if (require.main === module) main(process.argv.slice(2));

module.exports = { main, scan, parseArgs, GROUPS };
