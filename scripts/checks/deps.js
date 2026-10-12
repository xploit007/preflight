'use strict';

/**
 * Dependencies & supply chain: DEP-01 known-vulnerable dependencies (npm/pnpm/yarn/bun audit),
 * DEP-02 missing or unpinned lockfiles, DEP-03 malicious, compromised or typosquatted packages.
 * Only DEP-01 uses the network (one audit command, 30s timeout, skipped with --offline).
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { loadRepo } = require('../lib/repo');
const { pass, fail, warn, manual, na, ev } = require('../lib/result');

const IDS = ['DEP-01', 'DEP-02', 'DEP-03'];

const LOCKFILES = [
  ['package-lock.json', 'npm'],
  ['npm-shrinkwrap.json', 'npm'],
  ['pnpm-lock.yaml', 'pnpm'],
  ['yarn.lock', 'yarn'],
  ['bun.lock', 'bun'],
  ['bun.lockb', 'bun'],
];

// Popular packages: lookalikes one edit away from these are suspicious (unless popular themselves).
const POPULAR = new Set(`react react-dom next vue nuxt svelte @sveltejs/kit angular express koa fastify hono nestjs lodash underscore axios got node-fetch superagent request moment dayjs date-fns luxon uuid nanoid chalk debug commander yargs minimist dotenv cross-env nodemon ts-node typescript eslint prettier jest mocha chai vitest vite webpack rollup esbuild parcel babel-core @babel/core tailwindcss postcss autoprefixer sass less styled-components emotion classnames clsx jquery bootstrap three d3 chart.js recharts mongoose mongodb mysql mysql2 pg postgres sequelize knex prisma @prisma/client drizzle-orm redis ioredis bull bullmq socket.io ws graphql apollo-server stripe twilio openai @anthropic-ai/sdk nodemailer multer helmet cors morgan passport jsonwebtoken bcrypt bcryptjs argon2 cookie-parser express-session body-parser zod yup joi valibot ajv react-router react-router-dom redux @reduxjs/toolkit zustand jotai swr @tanstack/react-query framer-motion lucide-react react-icons @mui/material antd firebase firebase-admin @supabase/supabase-js aws-sdk sharp jimp puppeteer playwright cheerio jsdom marked markdown-it highlight.js prismjs xml2js js-yaml yaml qs query-string validator crypto-js node-forge jose jwt-decode form-data mime mime-types ms semver glob rimraf mkdirp fs-extra chokidar inquirer ora boxen colors color picocolors kleur winston pino bunyan handlebars ejs pug nunjucks mustache lru-cache node-cache keyv ethers web3 viem wagmi discord.js telegraf electron react-native expo immer rxjs core-js regenerator-runtime tslib async bluebird p-limit execa shelljs concurrently husky lint-staged nodemailer-express-handlebars i18next react-i18next formik react-hook-form preact solid-js lit alpinejs htmx.org astro gatsby remix @remix-run/react @vercel/analytics @vercel/og ai @ai-sdk/openai langchain @langchain/core replicate cohere-ai groq-sdk @google/generative-ai @google/genai resend @sendgrid/mail mailgun.js plivo @vonage/server-sdk telnyx ua-parser-js event-stream eslint-scope coa rc node-ipc faker @faker-js/faker colors-cli supports-color ansi-styles strip-ansi ansi-regex wrap-ansi color-convert color-name is-arrayish slice-ansi color-string simple-swizzle has-ansi chalk-template backslash error-ex @ctrl/tinycolor tinycolor2 mariadb sqlite3 better-sqlite3 cookie cookies serve-static compression express-rate-limit rate-limiter-flexible @upstash/ratelimit @upstash/redis svix @clerk/nextjs next-auth @auth/core lucia better-auth`.split(/\s+/));

// Packages published as malware (2017 "hacktask" typosquats and later incidents). Any version.
const MALICIOUS_NAMES = new Set(['crossenv', 'cross-env.js', 'd3.js', 'fabric-js', 'ffmepg', 'gruntcli', 'http-proxy.js', 'jquery.js', 'mongose', 'mssql.js', 'mssql-node', 'mysqljs', 'nodecaffe', 'nodefabric', 'node-fabric', 'nodeffmpeg', 'nodemailer-js', 'nodemailer.js', 'nodemssql', 'node-opencv', 'node-opensl', 'node-openssl', 'noderequest', 'nodesass', 'nodesqlite', 'node-tkinter', 'opencv.js', 'openssl.js', 'proxy.js', 'shadowsock', 'smb', 'sqlite.js', 'sqliter', 'sqlserver', 'tkinter', 'flatmap-stream', 'getcookies', 'electorn', 'discordi.js']);

// Specific releases that were hijacked or sabotaged (versions read from the lockfile).
const COMPROMISED = {
  'event-stream': ['3.3.6'],
  'eslint-scope': ['3.7.2'],
  'ua-parser-js': ['0.7.29', '0.8.0', '1.0.0'],
  coa: ['2.0.3', '2.0.4', '2.1.1', '2.1.3', '3.0.1', '3.1.3'],
  rc: ['1.2.9', '1.3.9', '2.3.9'],
  'node-ipc': ['10.1.1', '10.1.2', '10.1.3'],
  colors: ['1.4.1', '1.4.2', '1.4.44-liberty-2'],
  faker: ['6.6.6'],
  // September 2025 npm compromise (phished maintainer).
  chalk: ['5.6.1'],
  debug: ['4.4.2'],
  'ansi-styles': ['6.2.2'],
  'supports-color': ['10.2.1'],
  'strip-ansi': ['7.1.1'],
  'ansi-regex': ['6.2.1'],
  'wrap-ansi': ['9.0.1'],
  'color-convert': ['3.1.1'],
  'color-name': ['2.0.1'],
  'is-arrayish': ['0.3.3'],
  'slice-ansi': ['7.1.1'],
  color: ['5.0.1'],
  'color-string': ['2.1.1'],
  'simple-swizzle': ['0.2.3'],
  'supports-hyperlinks': ['4.1.1'],
  'has-ansi': ['6.0.1'],
  'chalk-template': ['1.1.1'],
  backslash: ['0.2.1'],
  // Shai-Hulud worm, first wave.
  '@ctrl/tinycolor': ['4.1.1', '4.1.2'],
};

// Well-known packages whose install scripts are expected (native builds, binary downloads).
const INSTALL_SCRIPT_OK = new Set(['esbuild', 'sharp', 'bcrypt', 'argon2', '@prisma/client', 'prisma', '@prisma/engines', 'node-sass', 'sass-embedded', 'sqlite3', 'better-sqlite3', 'canvas', 'puppeteer', 'playwright', '@swc/core', 'husky', 'core-js', 'core-js-pure', 'electron', 'fsevents', 'protobufjs', 'msw', 'cypress', '@sentry/cli', '@sentry/profiling-node', 'bufferutil', 'utf-8-validate', 're2', '@parcel/watcher', 'unrs-resolver', '@tailwindcss/oxide', 'lefthook', 'nx', 'turbo', '@biomejs/biome', 'workerd', 'wrangler', 'supabase', 'vercel', 'deasync', 'grpc', '@grpc/grpc-js', 'node-gyp', 'cpu-features', 'ssh2', 'keytar', 'leveldown', 'ffmpeg-static', 'phantomjs-prebuilt', 'chromedriver', 'geckodriver', 'electron-chromedriver', 'spawn-sync', 'nodemon', 'es5-ext', 'styled-components', 'protoc', '@scarf/scarf', 'yarn', 'pnpm']);

async function run(root, opts = {}) {
  const repo = loadRepo(root, opts);
  const pkgs = repo.packages.filter((p) => !repo.isTest(p.file) && p.deps.size > 0);
  const ctx = { repo, pkgs, opts };
  return [await audit(ctx), lockfiles(ctx), supplyChain(ctx)];
}

/** Lockfile for a package: its own folder or the nearest ancestor (workspace root). */
function lockFor(repo, pkg) {
  const parts = pkg.dir ? pkg.dir.split('/') : [];
  for (let i = parts.length; i >= 0; i--) {
    const dir = parts.slice(0, i).join('/');
    for (const [name, pm] of LOCKFILES) {
      const rel = dir ? `${dir}/${name}` : name;
      const f = repo.get(rel);
      if (f) return { f, pm, dir, name };
    }
  }
  return null;
}

/** Line of "name": in package.json, for evidence. */
function depLine(pkg, name) {
  const idx = pkg.text.indexOf(`"${name}"`);
  return idx === -1 ? 1 : pkg.text.slice(0, idx).split('\n').length;
}

// ── DEP-01 ─────────────────────────────────────────────────────────────────

function runCommand(cmd, args, cwd, timeoutMs = 30000) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, { cwd, shell: process.platform === 'win32', env: { ...process.env, npm_config_fund: 'false', npm_config_update_notifier: 'false', NO_UPDATE_NOTIFIER: '1', FORCE_COLOR: '0' }, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      resolve({ error: e.message });
      return;
    }
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      child.kill();
      resolve({ error: `timed out after ${timeoutMs / 1000}s`, stdout: out });
    }, timeoutMs);
    child.stdout.on('data', (d) => {
      if (out.length < 50 * 1024 * 1024) out += d;
    });
    child.stderr.on('data', (d) => {
      if (err.length < 64 * 1024) err += d;
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      resolve({ error: e.code === 'ENOENT' ? `${cmd} is not installed` : e.message });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: out, stderr: err });
    });
  });
}

/** Normalize npm / pnpm / yarn / bun audit output to [{ name, severity, title, url, dev }]. */
function parseAudit(pm, stdout, lockText) {
  const vulns = [];
  const devOf = (() => {
    try {
      const lock = JSON.parse(lockText || '{}');
      return (node) => Boolean(lock.packages && lock.packages[node] && lock.packages[node].dev);
    } catch {
      return () => false;
    }
  })();
  const text = String(stdout || '').trim();
  if (!text) return { error: 'empty audit output' };
  if (pm === 'yarn' && !text.startsWith('{"auditReportVersion"')) {
    for (const line of text.split('\n')) {
      let j;
      try {
        j = JSON.parse(line);
      } catch {
        continue;
      }
      if (j.type === 'auditAdvisory' && j.data && j.data.advisory) {
        const a = j.data.advisory;
        vulns.push({ name: a.module_name, severity: a.severity, title: a.title, url: a.url, dev: Boolean(j.data.resolution && j.data.resolution.dev) });
      } else if (j.value && j.children) {
        vulns.push({ name: j.value, severity: String(j.children.Severity || '').toLowerCase(), title: j.children.Issue, url: j.children.URL, dev: false });
      }
    }
    return { vulns };
  }
  let j;
  try {
    j = JSON.parse(text);
  } catch {
    return { error: 'could not parse audit output' };
  }
  if (j.error) return { error: (j.error.summary || j.error.code || 'audit failed').split('\n')[0] };
  if (j.vulnerabilities && typeof j.vulnerabilities === 'object' && !Array.isArray(j.vulnerabilities)) {
    for (const [name, v] of Object.entries(j.vulnerabilities)) {
      const adv = (v.via || []).find((x) => typeof x === 'object') || {};
      const nodes = v.nodes || [];
      vulns.push({ name, severity: v.severity, title: adv.title || `via ${(v.via || []).filter((x) => typeof x === 'string').join(', ')}`, url: adv.url, dev: nodes.length > 0 && nodes.every((n) => devOf(n)) });
    }
    return { vulns };
  }
  if (j.advisories) {
    for (const a of Object.values(j.advisories)) vulns.push({ name: a.module_name, severity: a.severity, title: a.title, url: a.url, dev: false });
    return { vulns };
  }
  // bun audit --json: { "<pkg>": [ { severity, title, url } ] }
  for (const [name, list] of Object.entries(j)) {
    if (!Array.isArray(list)) continue;
    for (const a of list) if (a && a.severity) vulns.push({ name, severity: a.severity, title: a.title, url: a.url, dev: false });
  }
  return { vulns };
}

/**
 * Package managers that would execute code from the repo itself: yarn delegates to a checked-in
 * binary via yarn-path / yarnPath, and pnpm loads .pnpmfile.cjs hooks. preflight never runs those.
 */
function repoCodeRunner(dir, pm) {
  const read = (name) => {
    try {
      return fs.readFileSync(path.join(dir, name), 'utf8');
    } catch {
      return '';
    }
  };
  if (pm === 'yarn' && (/^\s*yarn-path\s/m.test(read('.yarnrc')) || /^\s*yarnPath\s*:/m.test(read('.yarnrc.yml')))) return 'the repo pins its own yarn binary (yarn-path/yarnPath)';
  if (pm === 'pnpm' && (fs.existsSync(path.join(dir, '.pnpmfile.cjs')) || fs.existsSync(path.join(dir, '.pnpmfile.mjs')))) return 'the repo has a .pnpmfile hook';
  return null;
}

async function audit({ repo, pkgs, opts }) {
  if (!pkgs.length) return na('DEP-01', 'no package.json with dependencies');
  const roots = new Map();
  for (const p of pkgs) {
    const lock = lockFor(repo, p);
    if (lock) roots.set(lock.dir, lock);
  }
  if (!roots.size) return manual('DEP-01', ['npm audit needs a lockfile and there is none (see DEP-02). Generate one, then re-run.']);
  if (opts.offline || opts.audit === false) return manual('DEP-01', [`Skipped: ${opts.offline ? '--offline' : '--no-audit'}. Run \`npm audit --audit-level=high\` (or pnpm/yarn/bun audit) with network access.`]);
  const evidence = [];
  const prod = [];
  const dev = [];
  const errors = [];
  for (const lock of [...roots.values()].slice(0, 3)) {
    const cwd = path.join(repo.root, lock.dir);
    const unsafe = repoCodeRunner(cwd, lock.pm);
    if (unsafe) {
      errors.push(`${lock.f.rel}: ${lock.pm} audit was not run because ${unsafe}, so running it would execute code from the scanned repo. Run the audit yourself if you trust this repo.`);
      continue;
    }
    const isBerry = lock.pm === 'yarn' && !/^# yarn lockfile v1/m.test(repo.read(lock.f) || '');
    const cmd = { npm: ['npm', ['audit', '--json']], pnpm: ['pnpm', ['audit', '--json']], yarn: isBerry ? ['yarn', ['npm', 'audit', '--json', '--recursive']] : ['yarn', ['audit', '--json']], bun: ['bun', ['audit', '--json']] }[lock.pm];
    const res = await runCommand(cmd[0], cmd[1], cwd);
    if (res.error && !res.stdout) {
      errors.push(`${lock.f.rel}: ${cmd[0]} audit could not run (${res.error})`);
      continue;
    }
    const parsed = parseAudit(lock.pm, res.stdout, lock.name === 'package-lock.json' ? repo.read(lock.f) : '');
    if (parsed.error) {
      errors.push(`${lock.f.rel}: ${cmd[0]} audit could not run (${parsed.error})`);
      continue;
    }
    const serious = parsed.vulns.filter((v) => ['high', 'critical'].includes(String(v.severity).toLowerCase()));
    const counts = ['critical', 'high', 'moderate', 'low'].map((s) => `${parsed.vulns.filter((v) => String(v.severity).toLowerCase() === s).length} ${s}`).join(', ');
    evidence.push(`${lock.f.rel}: ${cmd[0]} audit found ${counts}.`);
    for (const v of serious) {
      const pkg = pkgs.find((p) => p.deps.has(v.name));
      const line = pkg ? ev(pkg.rel, depLine(pkg, v.name), `${v.name} (${v.severity}${v.dev ? ', dev only' : ''}): ${v.title || 'advisory'}${v.url ? ` ${v.url}` : ''}`) : `${v.name} (${v.severity}${v.dev ? ', dev only' : ''}, transitive): ${v.title || 'advisory'}${v.url ? ` ${v.url}` : ''}`;
      (v.dev ? dev : prod).push(line);
    }
  }
  if (prod.length) return fail('DEP-01', [...evidence, ...prod, ...dev, ...errors]);
  if (dev.length) return warn('DEP-01', [...evidence, ...dev, ...errors], { question: 'These high/critical advisories are in dev-only dependencies. Do any of them run in CI or on build machines with secrets?' });
  if (errors.length && !evidence.length) return manual('DEP-01', errors);
  return pass('DEP-01', [...evidence, ...errors]);
}

// ── DEP-02 ─────────────────────────────────────────────────────────────────

function lockfiles({ repo, pkgs }) {
  if (!pkgs.length) return na('DEP-02', 'no package.json with dependencies (nothing to lock)');
  const bad = [];
  const soft = [];
  for (const p of pkgs) {
    const lock = lockFor(repo, p);
    if (!lock) {
      bad.push(ev(p.rel, 1, `${p.deps.size} dependencies and no lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock): every install can resolve different versions`));
      continue;
    }
    if (repo.git.isRepo && repo.git.isTracked(lock.f.rel) === false && repo.git.isIgnored(lock.f.rel)) soft.push(ev(lock.f.rel, null, 'lockfile is gitignored, so CI and production installs are unpinned'));
    for (const [name, v] of Object.entries(p.versions)) {
      if (/^(?:\*|latest|x|)$/.test(v.range.trim()) || /^>=?\s*\d/.test(v.range.trim())) soft.push(ev(p.rel, depLine(p, name), `"${name}": "${v.range}" floats to whatever is newest`));
    }
  }
  if (bad.length) return fail('DEP-02', [...bad, ...soft]);
  if (soft.length) return warn('DEP-02', soft);
  return pass('DEP-02', [`Lockfile present for ${pkgs.length} package(s), with no wildcard version ranges.`]);
}

// ── DEP-03 ─────────────────────────────────────────────────────────────────

/** Optimal string alignment distance (Levenshtein + adjacent transpositions), early exit above 1. */
function distance(a, b) {
  if (Math.abs(a.length - b.length) > 1) return 2;
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

function lockVersions(repo, pkgs) {
  const versions = new Map(); // name -> Set(version)
  const add = (n, v) => {
    if (!n || !v) return;
    if (!versions.has(n)) versions.set(n, new Set());
    versions.get(n).add(v);
  };
  const seen = new Set();
  for (const p of pkgs) {
    const lock = lockFor(repo, p);
    if (!lock || seen.has(lock.f.rel)) continue;
    seen.add(lock.f.rel);
    const text = repo.read(lock.f) || '';
    if (lock.name === 'package-lock.json' || lock.name === 'npm-shrinkwrap.json') {
      try {
        const j = JSON.parse(text);
        for (const [k, v] of Object.entries(j.packages || {})) if (k) add(k.slice(k.lastIndexOf('node_modules/') + 13), v.version);
        for (const [k, v] of Object.entries(j.dependencies || {})) add(k, v.version);
      } catch {
        /* unreadable lockfile */
      }
    } else if (lock.name === 'pnpm-lock.yaml') {
      for (const m of text.matchAll(/^\s{2}'?\/?((?:@[^/@\s]+\/)?[^@\s/']+)@([^:('\s]+)/gm)) add(m[1], m[2]);
    } else if (lock.name === 'yarn.lock') {
      for (const m of text.matchAll(/^"?((?:@[^/@\s]+\/)?[^@\s"]+)@[^\n]*\n\s+version:?\s+"?([^"\s]+)"?/gm)) add(m[1], m[2]);
    } else if (lock.name === 'bun.lock') {
      for (const m of text.matchAll(/"((?:@[^/@\s"]+\/)?[^@\s"]+)@([^"\s]+)"/g)) add(m[1], m[2]);
    }
  }
  return versions;
}

function supplyChain({ repo, pkgs }) {
  if (!pkgs.length) return na('DEP-03', 'no package.json with dependencies');
  const bad = [];
  const soft = [];
  const versions = lockVersions(repo, pkgs);
  for (const p of pkgs) {
    for (const [name, v] of Object.entries(p.versions)) {
      const line = depLine(p, name);
      if (MALICIOUS_NAMES.has(name)) bad.push(ev(p.rel, line, `"${name}" is a known malicious package`));
      const range = v.range.trim();
      if (/^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:\/\/)|^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(range)) soft.push(ev(p.rel, line, `"${name}" installs from ${range} instead of the npm registry (unreviewed, unpinned source)`));
      if (!POPULAR.has(name) && !name.startsWith('@')) {
        const twin = [...POPULAR].find((pop) => pop.length >= 5 && !pop.startsWith('@') && pop !== name && (distance(name, pop) === 1 || name === `${pop}.js`));
        if (twin) soft.push(ev(p.rel, line, `"${name}" is one character away from the popular package "${twin}": make sure it's the one you meant`));
      }
    }
    // install scripts of installed direct dependencies (only when node_modules exists)
    for (const name of p.deps) {
      const pj = path.join(repo.root, p.dir, 'node_modules', name, 'package.json');
      let json;
      try {
        json = JSON.parse(fs.readFileSync(pj, 'utf8'));
      } catch {
        continue;
      }
      const scripts = json.scripts || {};
      const hooks = ['preinstall', 'install', 'postinstall'].filter((h) => scripts[h]);
      if (hooks.length && !INSTALL_SCRIPT_OK.has(name)) soft.push(ev(p.rel, depLine(p, name), `"${name}" runs ${hooks.join('/')} on install: ${String(scripts[hooks[0]]).slice(0, 80)}`));
    }
  }
  for (const [name, bads] of Object.entries(COMPROMISED)) {
    const installed = versions.get(name);
    if (!installed) continue;
    for (const v of installed) if (bads.includes(v)) bad.push(`${name}@${v} in the lockfile is a known compromised release: remove it, reinstall, and rotate any secrets on machines that installed it`);
  }
  if (bad.length) return fail('DEP-03', [...bad, ...soft]);
  if (soft.length) return warn('DEP-03', soft);
  const n = pkgs.reduce((acc, p) => acc + p.deps.size, 0);
  return pass('DEP-03', [`${n} direct dependencies and ${versions.size} locked packages checked: no known-malicious names, compromised releases, lookalike names or non-registry sources.`]);
}

module.exports = { name: 'deps', ids: IDS, run, parseAudit, distance, lockFor };
