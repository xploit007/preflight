'use strict';

/**
 * Secrets & credentials: SEC-01 database credentials, SEC-03 hardcoded secrets,
 * SEC-04 secrets in git history, SEC-05 secrets in built bundles, SEC-06 JWT/session
 * signing secrets, SEC-07 default credentials. (SEC-02 and SEC-08 live in env.js.)
 */

const { spawn } = require('child_process');
const path = require('path');
const { loadRepo, ENV_FILE_RE } = require('../lib/repo');
const P = require('../lib/patterns');
const { pass, fail, warn, na, ev } = require('../lib/result');
const { splitArgs, literalValue, isCommentLine, escapeRegExp } = require('../lib/util');
const { parseEnv, secretLabel } = require('./env');

const IDS = ['SEC-01', 'SEC-03', 'SEC-04', 'SEC-05', 'SEC-06', 'SEC-07'];

/** Passwords bots try first. */
const DEFAULT_PASSWORDS = new Set(['admin', 'admin123', 'admin1234', 'administrator', 'password', 'password1', 'password123', 'passw0rd', 'p@ssw0rd', 'changeme', 'changeit', 'default', 'root', 'toor', 'letmein', 'secret', '123456', '12345678', '123456789', 'qwerty', 'test', 'test123', 'guest', 'demo', 'example', 'postgres', 'mysql', 'minioadmin', 'pass', '1234', 'welcome', 'welcome1']);

// DB password variables with a literal value: DB_PASSWORD=…, POSTGRES_PASSWORD: …
const DB_PASS_VAR_RE = /\b((?:DB|DATABASE|PG|POSTGRES|MYSQL|MYSQL_ROOT|MARIADB|MARIADB_ROOT|MONGO|MONGODB|MONGO_INITDB_ROOT|REDIS|MSSQL|SA)_?(?:PASS(?:WORD)?|PWD))\b["']?\s*[:=]\s*["']?([^\s"'`#,;})]{4,})/gi;
// Constructors / connect calls of database clients, to find `password: '…'` inside their options.
const DB_CLIENT_RE = /\b(?:new\s+(?:Pool|Client|Sequelize|PrismaClient|Redis|MongoClient)|createPool|createConnection|knex|drizzle|postgres|mongoose\.connect|mysql\.createConnection|mysql\.createPool)\s*\(/g;
// jwt.sign / jwt.verify (jsonwebtoken and friends).
const JWT_CALL_RE = /\b(?:jwt|jsonwebtoken|JWT|jsonWebToken|jws)\s*\.\s*(sign|verify)\s*\(/g;
// const JWT_SECRET = '…' and friends.
const SECRET_CONST_RE = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>[\]|]+\s*)?=\s*(['"`])([^'"`\n]{3,256})\2/g;
const SECRET_CONST_NAME_RE = /^(?:JWT_?SECRET(?:_?KEY)?|JWT_?KEY|SECRET_?KEY|SESSION_?SECRET|TOKEN_?SECRET|AUTH_?SECRET|NEXTAUTH_?SECRET|COOKIE_?SECRET|SIGNING_?KEY|APP_?SECRET|ACCESS_?TOKEN_?SECRET|REFRESH_?TOKEN_?SECRET|jwtSecret|jwtKey|secretKey|sessionSecret|tokenSecret|authSecret|cookieSecret|signingKey|appSecret|accessTokenSecret|refreshTokenSecret)$/;
// process.env.JWT_SECRET || 'fallback'
const ENV_FALLBACK_RE = /process\.env\.([A-Z0-9_]*(?:SECRET|JWT|SIGNING|SESSION|COOKIE)[A-Z0-9_]*)\s*(?:\|\||\?\?)\s*(['"`])([^'"`\n]{1,256})\2/g;
// Files that configure a session / JWT library.
const SESSION_LIB_RE = /express-session|cookie-session|next-auth|NextAuth|@auth\/|express-jwt|expressjwt|koa-jwt|@fastify\/jwt|fastify-jwt|passport-jwt|jsonwebtoken|iron-session|getIronSession|sealData|@hapi\/jwt|hono\/jwt|\bjose\b|['"]jose['"]/;
const LIB_SECRET_RE = /\b(secret|secretOrKey|secretOrPrivateKey)\s*:\s*(['"`])([^'"`\n]{3,256})\2/g;
const IRON_PASSWORD_RE = /\bpassword\s*:\s*(['"`])([^'"`\n]{8,256})\1/g;
const COOKIE_KEYS_RE = /\bkeys\s*:\s*\[\s*(['"`])([^'"`\n]{3,256})\1/g;
const JOSE_LITERAL_RE = /new\s+TextEncoder\(\)\.encode\(\s*(['"`])([^'"`\n]{3,256})\1\s*\)/g;
const CONFIG_SECRET_RE = /["']?(jwtSecret|jwt_secret|JWT_SECRET|sessionSecret|session_secret|secretKey|secret_key|tokenSecret|appSecret|cookieSecret)["']?\s*[:=]\s*["']([^"'\n]{3,256})["']/g;
// Docker/infra env vars that commonly ship with default passwords.
const INFRA_DEFAULT_RE = /\b((?:POSTGRES|MYSQL|MYSQL_ROOT|MARIADB|MARIADB_ROOT|MONGO_INITDB_ROOT|RABBITMQ_DEFAULT|MINIO_ROOT|PGADMIN_DEFAULT|GF_SECURITY_ADMIN|REDIS|ADMIN|DEFAULT_ADMIN|KEYCLOAK_ADMIN|ELASTIC)_(?:PASSWORD|PASS))\b["']?\s*[:=]\s*["']?([^\s"'#,]+)/gi;
const AI_CONTEXT_RE = /gemini|generativeai|@google\/genai|@google\/generative-ai|generativelanguage|GoogleGenerativeAI|GoogleGenAI/i;

async function run(root, opts = {}) {
  const repo = loadRepo(root, opts);
  const claimed = new Set(); // rel:line already attributed to SEC-01/06/07, skipped by SEC-03's generic rule
  const sec01 = dbCredentials(repo, claimed);
  const sec06 = jwtSecrets(repo, claimed);
  const sec07 = defaultCredentials(repo, claimed);
  const sec03 = hardcodedSecrets(repo, claimed);
  const sec05 = bundleSecrets(repo);
  const sec04 = await gitHistory(repo, opts);
  return [sec01, sec03, sec04, sec05, sec06, sec07];
}

/** Source, config and docs outside build output, excluding env files (SEC-02) and lockfiles. */
function scanFiles(repo) {
  return repo.files.filter((f) => !f.build && ['code', 'markup', 'config', 'doc', 'style'].includes(f.kind));
}

/** Untracked and gitignored = a local-only file (like a .env); not "in source". */
function localOnly(repo, f) {
  return repo.git.isRepo && repo.git.isTracked(f.rel) === false && repo.git.isIgnored(f.rel);
}

function where(repo, f) {
  const t = repo.git.isTracked(f.rel);
  return t === true ? ' (committed)' : '';
}

// ── SEC-01 ─────────────────────────────────────────────────────────────────

function dbCredentials(repo, claimed) {
  const hits = [];
  const add = (f, index, note, weak = false) => {
    const line = repo.lineOf(f, index);
    if (repo.suppressed(f, line) || localOnly(repo, f)) return;
    claimed.add(`${f.rel}:${line}`);
    hits.push({ e: ev(f.rel, line, `${note}${where(repo, f)}`, repo.snippet(f, line)), weak });
  };
  for (const f of scanFiles(repo)) {
    if (f.kind === 'doc') continue;
    const text = repo.read(f);
    if (!text) continue;
    for (const d of P.findDbUrls(text)) {
      if (d.placeholder || /^[$%{]/.test(d.password)) continue;
      if (DEFAULT_PASSWORDS.has(d.password.toLowerCase())) continue; // SEC-07
      if (d.local) add(f, d.index, `${d.scheme} URL with an inline password for local host "${d.host}"`, true);
      else add(f, d.index, `${d.scheme} connection string with an inline password for ${d.host}`);
    }
    for (const m of text.matchAll(DB_PASS_VAR_RE)) {
      const value = m[2];
      if (P.isPlaceholder(value) || /^[$%{]/.test(value) || /process\.env|import\.meta/.test(value)) continue;
      if (DEFAULT_PASSWORDS.has(value.toLowerCase())) continue; // SEC-07
      add(f, m.index, `${m[1]} set to a literal value`);
    }
    for (const m of text.matchAll(DB_CLIENT_RE)) {
      const windowText = text.slice(m.index, m.index + 800);
      const pm = /\bpassword\s*:\s*(['"`])([^'"`\n]{4,})\1/.exec(windowText);
      if (!pm || P.isPlaceholder(pm[2]) || pm[2].includes('${')) continue;
      add(f, m.index + pm.index, 'literal password in a database client config');
    }
  }
  const strong = hits.filter((h) => !h.weak);
  if (strong.length) return fail('SEC-01', hits.map((h) => h.e));
  if (hits.length) return warn('SEC-01', hits.map((h) => h.e), { question: 'These credentials point at local hosts. Are they dev-only, and is the same password used anywhere reachable?' });
  return pass('SEC-01', ['No database connection strings or DB passwords with literal values found in source or config.']);
}

// ── SEC-03 ─────────────────────────────────────────────────────────────────

function hardcodedSecrets(repo, claimed) {
  const hits = [];
  const seen = new Set();
  const add = (f, line, label, weak) => {
    const key = `${f.rel}:${line}:${label}`;
    if (seen.has(key)) return;
    seen.add(key);
    hits.push({ e: ev(f.rel, line, `${label}${where(repo, f)}`, repo.snippet(f, line)), weak });
  };
  for (const f of scanFiles(repo)) {
    const text = repo.read(f);
    if (!text) continue;
    const aiFile = AI_CONTEXT_RE.test(text);
    for (const s of P.findSecrets(text)) {
      if (s.google && !aiFile) continue; // Firebase/Maps browser keys are public by design
      const line = repo.lineOf(f, s.index);
      if (repo.suppressed(f, line) || localOnly(repo, f)) continue;
      add(f, line, s.google ? 'Google AI (Gemini) API key' : s.label, Boolean(s.lowImpact));
    }
    if (f.kind === 'doc' || f.rel.endsWith('.d.ts') || repo.isMinified(f) || /(?:^|\/)(?:locales?|i18n|lang|translations|messages)\//.test(f.rel)) continue;
    for (const m of text.matchAll(P.GENERIC_ASSIGN_RE)) {
      const name = m[1];
      const value = m[3];
      const line = repo.lineOf(f, m.index);
      if (claimed.has(`${f.rel}:${line}`)) continue;
      if (P.PUBLIC_NAME_RE.test(name) || P.PUBLIC_VALUE_RE.test(value)) continue;
      if (P.isPlaceholder(value) || !P.looksSecret(value) || DEFAULT_PASSWORDS.has(value.toLowerCase())) continue;
      if (P.findSecrets(value).length || P.findDbUrls(value).length) continue; // reported by the strong rules
      if (/^eyJ/.test(value) && P.supabaseRole(value) === 'anon') continue;
      if (isCommentLine(repo.lineText(f, line)) || repo.suppressed(f, line) || localOnly(repo, f)) continue;
      add(f, line, `hardcoded value for "${name}"`, false);
    }
  }
  if (hits.some((h) => !h.weak)) return fail('SEC-03', hits.map((h) => h.e));
  if (hits.length) return warn('SEC-03', hits.map((h) => h.e), { question: 'Only test-mode keys were found. Are they really test keys, and are live keys kept out of the repo?' });
  return pass('SEC-03', ['No high-confidence secret formats or hardcoded credential assignments found outside .env files and build output.']);
}

// ── SEC-04 ─────────────────────────────────────────────────────────────────

const GIT_ENV = { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0', GIT_PAGER: 'cat', LC_ALL: 'C' };

/** Stream `git log -p` and call onAdded for every added line. Resolves { commits, truncated }. */
function streamGitLog(root, depth, onAdded) {
  return new Promise((resolve) => {
    const args = ['-c', 'core.fsmonitor=false', '-c', 'core.quotepath=off', 'log', '-p', '-U0', '--no-color', '--no-ext-diff', '--no-textconv', '--relative', '--format=%x00%h%x09%ad', '--date=short', `-n${depth}`, '--', '.', ':(exclude,glob)**/package-lock.json', ':(exclude,glob)**/yarn.lock', ':(exclude,glob)**/pnpm-lock.yaml', ':(exclude,glob)**/*.map', ':(exclude,glob)**/*.svg'];
    let child;
    try {
      child = spawn('git', args, { cwd: root, env: GIT_ENV, stdio: ['ignore', 'pipe', 'ignore'] });
    } catch {
      resolve({ commits: 0, truncated: false, error: true });
      return;
    }
    let buf = '';
    let bytes = 0;
    let commits = 0;
    let truncated = false;
    let commit = null;
    let date = null;
    let file = null;
    let inHeader = false;
    let newLine = 0;
    const handle = (line) => {
      if (line.startsWith('\0')) {
        [commit, date] = line.slice(1).split('\t');
        commits++;
        file = null;
        inHeader = false;
        return;
      }
      if (line.startsWith('diff --git ')) {
        inHeader = true;
        file = null;
        return;
      }
      if (inHeader) {
        if (line.startsWith('+++ ')) file = line.startsWith('+++ b/') ? line.slice(6) : null;
        else if (line.startsWith('@@')) {
          inHeader = false;
          const m = /\+(\d+)/.exec(line);
          newLine = m ? Number(m[1]) : 1;
        }
        return;
      }
      if (line.startsWith('@@')) {
        const m = /\+(\d+)/.exec(line);
        newLine = m ? Number(m[1]) : 1;
        return;
      }
      if (!file) return;
      if (line.startsWith('+')) {
        onAdded({ commit, date, file, line: newLine, text: line.slice(1, 4001) });
        newLine++;
      } else if (line.startsWith(' ')) newLine++;
    };
    const timer = setTimeout(() => {
      truncated = true;
      child.kill();
    }, 25000);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > 200 * 1024 * 1024) {
        truncated = true;
        child.kill();
        return;
      }
      buf += chunk;
      let nl = buf.indexOf('\n');
      while (nl !== -1) {
        handle(buf.slice(0, nl));
        buf = buf.slice(nl + 1);
        nl = buf.indexOf('\n');
      }
    });
    child.on('error', () => {
      clearTimeout(timer);
      resolve({ commits, truncated, error: true });
    });
    child.on('close', () => {
      clearTimeout(timer);
      if (buf) handle(buf);
      resolve({ commits, truncated });
    });
  });
}

/**
 * One history scan per repo, shared by SEC-04 and AI-03 (the groups run concurrently).
 * Resolves { skipped?, error?, commits, truncated, found: Map, envAdds: [] }.
 */
function historyFindings(repo, opts) {
  if (repo._history) return repo._history;
  repo._history = (async () => {
    if (opts.history === false) return { skipped: 'history scan disabled (--no-history)' };
    if (!repo.git.isRepo) return { na: 'not a git repository, so there is no history to scan' };
    if (!repo.git.hasCommits) return { na: 'the repository has no commits yet' };
    const depth = opts.historyDepth || 200;
    const found = new Map(); // value|file -> hit (oldest occurrence wins: log is newest-first)
    const { commits, truncated, error } = await streamGitLog(repo.root, depth, (a) => {
      for (const s of P.findSecrets(a.text)) {
        if (s.google && !AI_CONTEXT_RE.test(a.text)) continue;
        found.set(`${s.value}|${a.file}`, { ...a, label: s.google ? 'Google AI API key' : s.label, value: s.value, lowImpact: s.lowImpact, ai: s.ai || (s.google ? 'Google AI' : null) });
      }
      for (const d of P.findDbUrls(a.text)) {
        if (d.placeholder || d.local || /^[$%{]/.test(d.password)) continue;
        found.set(`${d.password}|${a.file}`, { ...a, label: `${d.scheme} connection string with a password`, value: d.password });
      }
    });
    if (error) return { na: 'git is not available, so history could not be scanned' };
    const envAdds = [];
    const added = repo.git.run(['log', `-n${depth}`, '--diff-filter=A', '--name-only', '--relative', '--format=%x00%h %ad', '--date=short', '--', '.']);
    if (added) {
      let header = '';
      for (const line of added.split('\n')) {
        if (line.startsWith('\0')) header = line.slice(1).trim();
        else if (line.trim()) {
          const base = path.posix.basename(line.trim());
          if (!ENV_FILE_RE.test(base) || /(?:example|sample|template|dist|defaults|schema)/i.test(base)) continue;
          // Only env files that held secret-looking values count (public config like NEXT_PUBLIC_* is fine).
          const sha = header.split(' ')[0];
          const content = repo.git.run(['cat-file', 'blob', `${sha}:./${line.trim()}`]) || ''; // cat-file never runs textconv/filters
          const secrets = parseEnv(content).filter((e) => secretLabel(e));
          if (secrets.length) envAdds.push({ file: line.trim(), header, count: secrets.length });
        }
      }
    }
    return { commits, truncated, found, envAdds };
  })();
  return repo._history;
}

/** "file:line — label masked added in sha (date) — still present / removed" */
function historyEvidence(repo, h) {
  const current = repo.read(h.file);
  const still = current ? current.includes(h.value) : false;
  return ev(h.file, h.line, `${h.label} ${P.mask(h.value)} added in ${h.commit} (${h.date}) — ${still ? 'still in the working tree' : 'no longer in the working tree but still in history: rotate it'}`);
}

async function gitHistory(repo, opts) {
  const h = await historyFindings(repo, opts);
  if (h.skipped) return pass('SEC-04', [`Not checked: ${h.skipped}.`]);
  if (h.na) return na('SEC-04', h.na);
  const evidence = [...h.found.values()].map((x) => historyEvidence(repo, x));
  for (const a of h.envAdds) evidence.push(ev(a.file, null, `env file with ${a.count} secret-looking value${a.count > 1 ? 's' : ''} committed in ${a.header}; every value in it is readable in history`));
  if (h.truncated) evidence.push(`History scan stopped early (time/size budget); scanned ${h.commits} commits.`);
  if (h.found.size || h.envAdds.length) {
    if ([...h.found.values()].every((x) => x.lowImpact) && !h.envAdds.length) return warn('SEC-04', evidence, { question: 'Only test-mode keys were found in history. Confirm they are test keys.' });
    return fail('SEC-04', evidence);
  }
  return pass('SEC-04', [`Scanned the last ${h.commits} commit(s) touching this directory: no high-confidence secrets in added lines and no committed env files.${h.truncated ? ' (stopped early on the time/size budget)' : ''}`]);
}

// ── SEC-05 ─────────────────────────────────────────────────────────────────

function bundleSecrets(repo) {
  const files = repo.buildFiles().filter((f) => ['code', 'markup', 'map', 'config', 'doc', 'style'].includes(f.kind));
  if (!files.length) {
    return pass('SEC-05', ['Not checked: no build output found (dist/, build/, out/, .next/static, .vercel/output/static…). Build the app and re-run to scan bundles. SEC-08, DATA-02 and AI-03 cover the usual causes statically.']);
  }
  const byValue = new Map();
  for (const f of files) {
    const text = repo.read(f);
    if (!text) continue;
    const aiFile = AI_CONTEXT_RE.test(text);
    const add = (index, label, value, weak) => {
      if (byValue.has(value)) {
        byValue.get(value).also++;
        return;
      }
      const line = repo.lineOf(f, index);
      byValue.set(value, { e: ev(f.rel, line, `${label} ${P.mask(value)} shipped in build output`), weak, also: 0 });
    };
    for (const s of P.findSecrets(text)) {
      if (s.google && !aiFile) continue;
      add(s.index, s.google ? 'Google AI (Gemini) API key' : s.label, s.value, Boolean(s.lowImpact));
    }
    for (const d of P.findDbUrls(text)) {
      if (d.placeholder || d.local) continue;
      add(d.index, `${d.scheme} connection string`, d.password, false);
    }
  }
  const roots = [...new Set(files.map((f) => f.build.root))].join(', ');
  const hits = [...byValue.values()].map((h) => ({ ...h, e: h.also ? `${h.e} (also in ${h.also} more file${h.also > 1 ? 's' : ''})` : h.e }));
  if (hits.some((h) => !h.weak)) return fail('SEC-05', hits.map((h) => h.e));
  if (hits.length) return warn('SEC-05', hits.map((h) => h.e), { question: 'Only test-mode keys were found in the bundle. Confirm they are test keys.' });
  return pass('SEC-05', [`Scanned ${files.length} build file(s) in ${roots}: no secrets found.`]);
}

// ── SEC-06 ─────────────────────────────────────────────────────────────────

function jwtSecrets(repo, claimed) {
  const hits = [];
  const seen = new Set();
  const add = (f, index, note) => {
    const line = repo.lineOf(f, index);
    if (repo.suppressed(f, line) || seen.has(`${f.rel}:${line}`)) return;
    seen.add(`${f.rel}:${line}`);
    claimed.add(`${f.rel}:${line}`);
    hits.push(ev(f.rel, line, note, repo.snippet(f, line)));
  };
  const bad = (v) => !/^\$\{|process\.env|import\.meta|Deno\.env/.test(v) && !v.includes('${');
  const files = repo.files.filter((f) => !f.build && (f.kind === 'code' || f.kind === 'config') && !repo.isTest(f) && !localOnly(repo, f));
  for (const f of files) {
    const text = repo.code(f);
    if (!text) continue;
    if (f.kind === 'code') {
      const literalDefs = new Map();
      for (const m of text.matchAll(SECRET_CONST_RE)) {
        literalDefs.set(m[1], { index: m.index, value: m[3] });
        if (SECRET_CONST_NAME_RE.test(m[1]) && bad(m[3])) add(f, m.index, `signing secret "${m[1]}" is a string literal`);
      }
      for (const m of text.matchAll(JWT_CALL_RE)) {
        const call = splitArgs(text, m.index + m[0].length - 1);
        if (!call || call.args.length < 2) continue;
        const secretArg = call.args[1].text;
        const lit = literalValue(secretArg);
        if (lit !== null && bad(lit)) add(f, call.args[1].start, `jwt.${m[1]}() uses a string literal as the secret`);
        else if (/^[A-Za-z_$][\w$]*$/.test(secretArg) && literalDefs.has(secretArg) && bad(literalDefs.get(secretArg).value)) {
          add(f, literalDefs.get(secretArg).index, `jwt.${m[1]}() secret "${secretArg}" is a string literal`);
        }
      }
      for (const m of text.matchAll(ENV_FALLBACK_RE)) add(f, m.index, `${m[1]} falls back to a hardcoded string when the env var is missing`);
      if (SESSION_LIB_RE.test(text)) {
        for (const m of text.matchAll(LIB_SECRET_RE)) if (bad(m[3])) add(f, m.index, `session/JWT library "${m[1]}" is a string literal`);
        if (/iron-session|getIronSession|sealData/.test(text)) for (const m of text.matchAll(IRON_PASSWORD_RE)) if (bad(m[2])) add(f, m.index, 'iron-session password is a string literal');
        if (/cookie-session/.test(text)) for (const m of text.matchAll(COOKIE_KEYS_RE)) if (bad(m[2])) add(f, m.index, 'cookie-session signing key is a string literal');
        if (/\bjose\b|SignJWT|jwtVerify/.test(text)) for (const m of text.matchAll(JOSE_LITERAL_RE)) if (bad(m[2])) add(f, m.index, 'jose signing key is encoded from a string literal');
      }
    } else if (/(?:^|\/)(?:config|settings)[^/]*\.(?:json|ya?ml|toml)$|(?:^|\/)config\//.test(f.rel)) {
      for (const m of text.matchAll(CONFIG_SECRET_RE)) if (bad(m[2]) && !P.isPlaceholder(m[2])) add(f, m.index, `"${m[1]}" is set in a committed config file`);
    }
  }
  if (hits.length) return fail('SEC-06', hits);
  return pass('SEC-06', ['No literal JWT/session signing secrets or hardcoded fallbacks found.']);
}

// ── SEC-07 ─────────────────────────────────────────────────────────────────

function defaultCredentials(repo, claimed) {
  const hard = [];
  const soft = [];
  const defaults = [...DEFAULT_PASSWORDS].map(escapeRegExp).join('|');
  const compareRe = new RegExp(`\\b(?:password|passwd|pwd|pass)\\b\\s*(?:===?|!==?)\\s*(['"\`])(${defaults})\\1|(['"\`])(${defaults})\\3\\s*(?:===?|!==?)\\s*[\\w.]*(?:password|passwd|pwd)\\b`, 'gi');
  const pwLiteralRe = new RegExp(`\\bpassword\\s*:\\s*(['"\`])(${defaults})\\1`, 'gi');
  const files = repo.files.filter((f) => !f.build && (f.kind === 'code' || f.kind === 'config') && !localOnly(repo, f));
  for (const f of files) {
    const text = repo.code(f);
    if (!text) continue;
    const at = (index) => repo.lineOf(f, index);
    if (f.kind === 'code' && !repo.isTest(f)) {
      for (const m of text.matchAll(compareRe)) {
        const line = at(m.index);
        if (repo.suppressed(f, line)) continue;
        claimed.add(`${f.rel}:${line}`);
        hard.push(ev(f.rel, line, 'login compares against a default password', repo.snippet(f, line)));
      }
      for (const m of text.matchAll(pwLiteralRe)) {
        const line = at(m.index);
        if (repo.suppressed(f, line)) continue;
        const around = text.slice(Math.max(0, m.index - 250), m.index + 250);
        const adminish = /\brole\s*:\s*['"`](?:admin|owner|superuser|superadmin)['"`]|\b(?:user(?:name)?|email|login)\s*:\s*['"`](?:admin|root|administrator|superuser)/i.test(around);
        claimed.add(`${f.rel}:${line}`);
        (adminish ? hard : soft).push(ev(f.rel, line, adminish ? 'admin account seeded with a default password' : 'account created with a default password', repo.snippet(f, line)));
      }
    }
    for (const d of P.findDbUrls(text)) {
      if (!DEFAULT_PASSWORDS.has(d.password.toLowerCase())) continue;
      const line = at(d.index);
      if (repo.suppressed(f, line)) continue;
      claimed.add(`${f.rel}:${line}`);
      if (!d.local) hard.push(ev(f.rel, line, `default password on a remote ${d.scheme} database (${d.host})`, repo.snippet(f, line)));
    }
    if (f.kind === 'config') {
      const published = /^\s*-\s*["']?(?:0\.0\.0\.0:)?(?:5432|3306|27017|6379|5672|9200|9000|1433):\d+["']?\s*$/m.test(text);
      for (const m of text.matchAll(INFRA_DEFAULT_RE)) {
        if (!DEFAULT_PASSWORDS.has(m[2].toLowerCase())) continue;
        const line = at(m.index);
        if (repo.suppressed(f, line)) continue;
        claimed.add(`${f.rel}:${line}`);
        soft.push(ev(f.rel, line, `${m[1]} uses a default password${published ? ', and the service port is published on all interfaces' : ''}`, repo.snippet(f, line)));
      }
    }
  }
  if (hard.length) return fail('SEC-07', [...hard, ...soft]);
  if (soft.length) return warn('SEC-07', soft);
  return pass('SEC-07', ['No default passwords found in login code, seed data or deployment config.']);
}

module.exports = { name: 'secrets', ids: IDS, run, DEFAULT_PASSWORDS, streamGitLog, historyFindings, historyEvidence, AI_CONTEXT_RE };
