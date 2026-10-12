'use strict';

/**
 * AppSec checks that aren't injection: APP-04 CSRF, APP-07 file uploads, APP-11 input
 * validation, APP-16 debug tools in production, APP-17 verbose errors, APP-18 exposed logs,
 * APP-19 exposed source maps.
 */

const fs = require('fs');
const path = require('path');
const { loadRepo } = require('../lib/repo');
const { getRoutes, routeBody } = require('../lib/routes');
const { VALIDATION_RE, VALIDATION_LIBS } = require('../lib/primitives');
const { pass, fail, warn, na, ev } = require('../lib/result');
const { objectAt } = require('../lib/util');

const IDS = ['APP-04', 'APP-07', 'APP-11', 'APP-16', 'APP-17', 'APP-18', 'APP-19'];

async function run(root, opts = {}) {
  const repo = loadRepo(root, opts);
  const { routes } = getRoutes(repo);
  const server = repo.sources({ kinds: ['code'], tests: false, js: true }).filter((f) => repo.side(f) !== 'client' && !repo.isTooling(f));
  const ctx = { repo, routes, server };
  return [csrf(ctx), uploads(ctx), validation(ctx), debugTools(ctx), verboseErrors(ctx), logs(ctx), sourceMaps(ctx)];
}

function collector(repo) {
  const hits = [];
  const seen = new Set();
  return {
    hits,
    add(f, index, note, { snippet = true } = {}) {
      const line = repo.lineOf(f, index);
      const key = `${f.rel}:${line}:${note}`;
      if (seen.has(key) || repo.suppressed(f, line)) return;
      seen.add(key);
      hits.push(ev(f.rel, line, note, snippet ? repo.snippet(f, line) : undefined));
    },
  };
}

const isWrite = (r) => ['POST', 'PUT', 'PATCH', 'DELETE', 'ANY', 'ALL'].includes(r.method);

// ── APP-04 ─────────────────────────────────────────────────────────────────

function csrf({ repo, routes, server }) {
  const sessions = [];
  let sameSite = false;
  let protectedByLib = false;
  for (const f of server) {
    const text = repo.code(f) || '';
    if (/csurf|csrf-csrf|csrf-sync|\blusca\b|tiny-csrf|@fastify\/csrf-protection|koa-csrf|hono\/csrf|\bcsrfProtection\b|\bdoubleCsrf\b|x-csrf-token|x-xsrf-token|\bcsrfToken\b|headers\.origin\s*!==|get\(\s*['"]origin['"]\s*\)\s*!==|verifyOrigin|checkOrigin/i.test(text)) protectedByLib = true;
    const m = /\b(?:express-session|cookie-session|iron-session|getIronSession)\b|\bres\.cookie\(\s*['"`]\w*(?:sess|token|auth|jwt|sid)\w*['"`]|\bpassport\.session\(\)/i.exec(text);
    if (m) {
      sessions.push(ev(f.rel, repo.lineOf(f, m.index), 'cookie-based session/auth', repo.snippet(f, repo.lineOf(f, m.index))));
      if (/sameSite\s*:\s*['"`]?(?:lax|strict)/i.test(text)) sameSite = true;
    }
  }
  if (!sessions.length) {
    const managed = repo.hasDep('next-auth') || repo.hasDepMatching(/^@auth\//) || repo.hasDep('@supabase/ssr');
    return na('APP-04', managed ? 'auth cookies come from Auth.js / Supabase SSR, which set SameSite=Lax by default' : 'auth is not cookie-based (bearer tokens are not sent cross-site automatically)');
  }
  const writes = routes.filter((r) => isWrite(r) && !/webhook/i.test(r.path));
  if (!writes.length) return pass('APP-04', ['Cookie sessions are used, but no state-changing routes were found.']);
  if (protectedByLib || sameSite) return pass('APP-04', [protectedByLib ? 'CSRF token or Origin check found.' : 'Session cookies are set with SameSite=Lax/Strict.']);
  return warn('APP-04', [...sessions, ...writes.slice(0, 8).map((r) => ev(r.file.rel, r.line, `${r.method} ${r.path} changes state with no CSRF token, Origin check or SameSite cookie`))]);
}

// formData.get('file' | 'upload' | 'avatarFile' …), but not 'profile'. Fields like 'image' or
// 'avatar' are often URL strings, so those only count with instanceof File / arrayBuffer().
const FILE_FIELD_RE = /\.get(?:All)?\(\s*['"`](?:\w*(?:File|Upload|Attachment)s?|\w*[_-](?:file|upload|attachment)s?|files?|uploads?|attachments?)['"`]\s*\)/;

// ── APP-07 ─────────────────────────────────────────────────────────────────

function uploads({ repo, server }) {
  const c = collector(repo);
  let found = false;
  for (const f of server) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/\bmulter\s*\(\s*(\{)?/g)) {
      found = true;
      const opts = m[1] ? objectAt(text, m.index + m[0].length - 1) : '';
      const missing = [!/\blimits\s*:/.test(opts) && 'size limit', !/\bfileFilter\s*:/.test(opts) && 'file type filter'].filter(Boolean);
      const publicDest = /\b(?:dest|destination)\s*:\s*['"`][./]*(?:public|static|www|dist)\b/.test(opts);
      if (missing.length || publicDest) c.add(f, m.index, `multer upload without ${missing.length ? missing.join(' or ') : 'issues'}${publicDest ? `${missing.length ? ', and' : ''} saving into a public folder (uploaded HTML/SVG becomes stored XSS on your domain)` : ''}`.replace('without issues, and', '').replace('without issues', ''));
    }
    for (const m of text.matchAll(/\b(?:formidable|new\s+IncomingForm)\s*\(\s*(\{[^)]*\})?/g)) {
      found = true;
      if (!/maxFileSize/.test(m[1] || '')) c.add(f, m.index, 'formidable upload without maxFileSize');
    }
    for (const m of text.matchAll(/\b(?:busboy|Busboy)\s*\(\s*(\{[^)]*\})?/g)) {
      found = true;
      if (!/\blimits\b/.test(m[1] || '')) c.add(f, m.index, 'busboy upload without limits');
    }
    for (const m of text.matchAll(/\bfileUpload\s*\(\s*(\{[^)]*\})?\s*\)/g)) {
      found = true;
      if (!/\blimits\b/.test(m[1] || '')) c.add(f, m.index, 'express-fileupload without limits');
    }
    if (/\.formData\(\)/.test(text) && (FILE_FIELD_RE.test(text) || /instanceof\s+File\b|\.arrayBuffer\(\)/.test(text))) {
      found = true;
      const sizeCheck = /\.size\s*[<>]=?|maxSize|MAX_(?:FILE|UPLOAD)_SIZE|\bsize\s*>/.test(text);
      const typeCheck = /\.type\s*(?:===|!==|\.startsWith|\.includes)|ALLOWED_(?:TYPES|MIME)|allowedTypes|mimetype|file-type/.test(text);
      if (!sizeCheck || !typeCheck) {
        const idx = text.search(/\.formData\(\)/);
        c.add(f, idx, `form upload handler without a ${[!sizeCheck && 'size', !typeCheck && 'type'].filter(Boolean).join(' or ')} check`);
      }
    }
    for (const m of text.matchAll(/\bcreatePresignedPost\s*\(/g)) {
      found = true;
      if (!/content-length-range/.test(text)) c.add(f, m.index, 'presigned POST without a content-length-range condition');
    }
    for (const m of text.matchAll(/\bgetSignedUrl\s*\([^)]*PutObjectCommand/g)) {
      found = true;
      c.add(f, m.index, 'presigned PUT URL: S3 cannot enforce a size limit on these; prefer createPresignedPost with content-length-range');
    }
  }
  if (c.hits.length) return warn('APP-07', c.hits);
  if (!found) return na('APP-07', 'no file upload handling found');
  return pass('APP-07', ['Upload handlers set size limits and type checks, and don\'t save into public folders.']);
}

// ── APP-11 ─────────────────────────────────────────────────────────────────

const BODY_READ_RE = /\breq\.body\b|\b(?:req|request)\.json\(\)|\.formData\(\)|\bc\.req\.(?:json|parseBody)\(|\bctx\.request\.body\b|\bevent\.body\b|\brequest\.text\(\)/;

function validation({ repo, routes }) {
  const hasLib = VALIDATION_LIBS.some((d) => repo.hasDep(d));
  const gaps = [];
  let reading = 0;
  for (const r of routes) {
    if (/webhook/i.test(r.path)) continue;
    const body = routeBody(r);
    if (!BODY_READ_RE.test(body)) continue;
    reading++;
    if (VALIDATION_RE.test(body) || VALIDATION_RE.test(r.mountMiddleware || '')) continue;
    const at = r.handler && BODY_READ_RE.test(r.handler.text) ? { f: r.handler.file, i: r.handler.start + r.handler.text.search(BODY_READ_RE) } : { f: r.file, i: r.start + Math.max(0, r.text.search(BODY_READ_RE)) };
    const line = repo.lineOf(at.f, at.i);
    gaps.push(ev(at.f.rel, line, `${r.method} ${r.path} reads the request body without schema validation`, repo.snippet(at.f, line)));
  }
  if (!reading) return na('APP-11', 'no server handlers that read request bodies');
  if (gaps.length) return warn('APP-11', [...gaps, ...(hasLib ? [] : ['No schema validation library (zod, joi, yup, valibot, class-validator, express-validator, ajv…) is installed.'])]);
  return pass('APP-11', [`${reading} handler(s) read request bodies, and each validates them with a schema.`]);
}

// ── APP-16 ─────────────────────────────────────────────────────────────────

function debugTools({ repo, routes, server }) {
  const bad = [];
  const c = collector(repo);
  const startScripts = /^(?:start|serve|prod|production|start:prod|launch)$/;
  for (const p of repo.packages) {
    const scripts = (p.json && p.json.scripts) || {};
    for (const [name, cmd] of Object.entries(scripts)) {
      if (!startScripts.test(name) || typeof cmd !== 'string') continue;
      const line = Math.max(1, p.text.split('\n').findIndex((l) => l.includes(`"${name}"`)) + 1);
      const inspect = /--inspect(?:-brk)?(?:=(\S+))?/.exec(cmd);
      if (inspect && /^(?:0\.0\.0\.0|\[::\]|::)/.test(inspect[1] || '')) bad.push(ev(p.rel, line, `"${name}" starts node with ${inspect[0]}: the debugger is reachable from the network, which is remote code execution`, `"${name}": "${cmd}"`));
      else if (inspect) c.add(p.file, p.text.indexOf(`"${name}"`), `"${name}" starts node with ${inspect[0]} (debugger enabled in production)`);
      if (/\bnext\s+dev\b|(?:^|[\s;&])vite(?:\s+(?!build|preview)\S*)*\s*$|\bvite\s+(?:dev|serve)\b|\bnodemon\b|\bts-node-dev\b|\breact-scripts\s+start\b|\bwebpack-dev-server\b|\bwebpack\s+serve\b/.test(cmd)) c.add(p.file, p.text.indexOf(`"${name}"`), `"${name}" runs a development server (${cmd})`);
    }
  }
  for (const f of repo.files) {
    if (f.build) continue;
    const text = repo.code(f);
    if (!text) continue;
    if (/^Dockerfile|^Procfile$/.test(f.name) || f.name === 'fly.toml' || f.name === 'render.yaml') {
      for (const m of text.matchAll(/--inspect(?:-brk)?(?:=(\S+))?/g)) {
        if (/^(?:0\.0\.0\.0|\[::\]|::)/.test(m[1] || '')) bad.push(ev(f.rel, repo.lineOf(f, m.index), 'node debugger bound to all interfaces (remote code execution)', repo.snippet(f, repo.lineOf(f, m.index))));
        else c.add(f, m.index, 'node --inspect in a deployment config');
      }
      for (const m of text.matchAll(/\bNODE_ENV\s*[= ]\s*["']?development\b/g)) c.add(f, m.index, 'NODE_ENV=development in a deployment config (frameworks show debug pages and stack traces)');
      for (const m of text.matchAll(/\bnext\s+dev\b|\bnpm\s+run\s+dev\b/g)) c.add(f, m.index, 'development server used as the production command');
    }
    if (f.kind === 'code' && !repo.isTest(f) && repo.side(f) !== 'client') {
      for (const m of text.matchAll(/\b(?:introspection|playground|graphiql)\s*:\s*true\b/g)) c.add(f, m.index, `GraphQL ${m[0].split(':')[0]} is enabled unconditionally`);
      for (const m of text.matchAll(/\bswaggerUi\.serve\b|\bSwaggerModule\.setup\(|@fastify\/swagger-ui|\bredoc\(/g)) c.add(f, m.index, 'API docs UI is mounted: make sure it is behind auth or disabled in production');
      for (const m of text.matchAll(/\b(?:app|server)\.use\(\s*errorhandler\(\)\s*\)/g)) if (!/NODE_ENV/.test(text.slice(Math.max(0, m.index - 200), m.index))) c.add(f, m.index, 'the errorhandler() middleware (development only) is enabled unconditionally');
      if (f.ext === '.py') {
        for (const m of text.matchAll(/\bapp\.run\([^)]*debug\s*=\s*True/g)) bad.push(ev(f.rel, repo.lineOf(f, m.index), 'Flask debug mode: the Werkzeug debugger allows remote code execution', repo.snippet(f, repo.lineOf(f, m.index))));
        if (/settings\.py$/.test(f.name)) for (const m of text.matchAll(/^\s*DEBUG\s*=\s*True\b/gm)) bad.push(ev(f.rel, repo.lineOf(f, m.index), 'Django DEBUG = True leaks settings and stack traces', repo.snippet(f, repo.lineOf(f, m.index))));
      }
    }
  }
  for (const r of routes) {
    if (/(?:^|\/)(?:debug|_debug|__debug|test|tests|seed|reset-db|reset_db|resetdb|dev|__dev|phpinfo|env|\.env|config\.json)(?:\/|$)/i.test(r.path)) c.add(r.file, r.start, `${r.method} ${r.path} looks like a debug/test/seed endpoint`);
  }
  for (const dir of ['public', 'static', 'dist', 'build', 'out']) {
    if (fs.existsSync(path.join(repo.root, dir, '.git'))) bad.push(ev(`${dir}/.git`, null, 'a git repository inside a public folder: the whole source history can be downloaded'));
  }
  void server;
  if (bad.length) return fail('APP-16', [...bad, ...c.hits]);
  if (c.hits.length) return warn('APP-16', c.hits);
  return pass('APP-16', ['No debuggers, dev servers, GraphQL playgrounds, unguarded API docs or debug routes found in production paths.']);
}

const DEV_GUARD_RE = /NODE_ENV|\benv\s*[!=]==?\s*['"`](?:development|dev|production|prod)['"`]|\bis(?:Dev|Development|Prod|Production|Debug)\b|\bdev(?:Mode)?\s*(?:&&|\?)|import\.meta\.env\.(?:DEV|PROD)|\bdebug\s*(?:&&|\?)/;
const LOG_CALL_RE = /\b(?:console|logger|log|winston|pino|bunyan|Sentry|captureException|reportError|this\.logger)\b[\w.]*\s*\(/;
const RESPONSE_CTX_RE = /\b(?:res|reply|ctx|response)\b[\w.]*\.(?:json|send|status|body)\b|\bNextResponse\.|\bnew\s+Response\(|\bResponse\.json\(|\bctx\.body\s*=|\.json\(|\breturn\s+(?:json|error)\(/;

// ── APP-17 ─────────────────────────────────────────────────────────────────

function verboseErrors({ repo, server }) {
  const c = collector(repo);
  for (const f of server) {
    const text = repo.code(f) || '';
    const lines = new Set();
    const once = (index, note) => {
      const line = repo.lineOf(f, index);
      if (lines.has(line)) return;
      lines.add(line);
      c.add(f, index, note);
    };
    const devOnly = (index, extra = '') => DEV_GUARD_RE.test(`${text.slice(Math.max(0, index - 250), index)}${extra}`);
    for (const m of text.matchAll(/\b(?:res|reply|ctx)\b[^;\n]{0,40}?\.(?:json|send)\(([^;\n]*)\)/g)) {
      if (/\b(?:err|error|e|ex|exception)\.stack\b/.test(m[1])) {
        if (!devOnly(m.index, m[1])) once(m.index, 'the error stack trace is sent to the client');
      }
      else if (/^\s*(?:err|error|e|ex)\s*$/.test(m[1])) once(m.index, 'the raw error object is sent to the client');
    }
    for (const m of text.matchAll(/\b(?:NextResponse|Response)\.json\(\s*(?:err|error|e)\s*[,)]/g)) once(m.index, 'the raw error object is returned to the client');
    for (const m of text.matchAll(/\bstack\s*:\s*(?:err|error|e)\.stack\b/g)) {
      // only response bodies: logger.error({ stack }) is fine, and so is a development-only branch
      const lineStart = text.lastIndexOf('\n', m.index) + 1;
      const before = text.slice(Math.max(0, m.index - 300), m.index);
      if (LOG_CALL_RE.test(text.slice(lineStart, m.index)) || LOG_CALL_RE.test(before.slice(before.lastIndexOf(';') + 1))) continue;
      if (!RESPONSE_CTX_RE.test(text.slice(Math.max(0, m.index - 300), m.index + 300)) || devOnly(m.index, text.slice(m.index, m.index + 80))) continue;
      once(m.index, 'the error stack trace is included in a response');
    }
  }
  // Self-hosted Express without NODE_ENV=production prints stack traces in its default error page.
  if (repo.hasDep('express')) {
    const deployFiles = repo.files.filter((f) => !f.build && (/^Dockerfile/.test(f.name) || ['Procfile', 'fly.toml', 'render.yaml', 'ecosystem.config.js', 'app.yaml'].includes(f.name)));
    const setsProd = deployFiles.some((f) => /NODE_ENV\s*[=: ]\s*["']?production/.test(repo.code(f) || '')) || repo.packages.some((p) => /NODE_ENV=production/.test(JSON.stringify((p.json && p.json.scripts) || {})));
    if (deployFiles.length && !setsProd) c.add(deployFiles[0], 0, `${deployFiles[0].name} deploys Express without NODE_ENV=production, so Express's default error handler shows stack traces`, { snippet: false });
  }
  if (c.hits.length) return warn('APP-17', c.hits);
  return pass('APP-17', ['No stack traces or raw error objects sent to clients found.']);
}

// ── APP-18 ─────────────────────────────────────────────────────────────────

function logs({ repo, server }) {
  const bad = [];
  const c = collector(repo);
  const logFiles = repo.files.filter((f) => /\.log(?:\.\d+)?$/.test(f.name) || /^(?:npm-debug|yarn-error|yarn-debug|lerna-debug|firebase-debug|pnpm-debug)\.log/.test(f.name));
  for (const f of logFiles) {
    const tracked = repo.git.isTracked(f.rel);
    const pub = f.build || /(?:^|\/)(?:public|static|www|wwwroot|htdocs)\//.test(f.rel);
    let content = '';
    try {
      content = fs.readFileSync(f.abs, 'utf8').slice(0, 200000);
    } catch {
      content = '';
    }
    const sensitive = /password|passwd|token|secret|authorization|bearer|api[_-]?key|cookie|ssn|card/i.test(content) ? ' and it contains passwords/tokens' : '';
    if (pub) bad.push(ev(f.rel, null, `log file inside a public folder${sensitive}`));
    else if (tracked === true) bad.push(ev(f.rel, null, `log file committed to git${sensitive}`));
    else if (!repo.git.isIgnored(f.rel)) c.hits.push(ev(f.rel, null, `log file not covered by .gitignore${sensitive}`));
  }
  for (const f of server) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/\bexpress\.static\(\s*['"`][^'"`]*\blogs?\b[^'"`]*['"`]|\bserveIndex\(/g)) c.add(f, m.index, 'a logs folder (or directory listing) is served over HTTP');
    const sensitiveFile = /(?:auth|login|session|pay|checkout|stripe|billing|webhook|password|token)/i.test(f.rel);
    for (const m of text.matchAll(/\b(?:console\.(?:log|info|debug|warn|error)|logger\.(?:info|debug|log|warn|error)|log\.(?:info|debug))\(([^;\n]*)\)/g)) {
      // presence checks (!!token, Boolean(key), secret.length, key ? '…' : '…') don't log the value
      const args = m[1]
        .replace(/(['"`])(?:\\.|(?!\1)[^\\])*\1/g, '""')
        .replace(/!!\s*[\w$.?]+|\bBoolean\(\s*[\w$.?]+\s*\)|\btypeof\s+[\w$.?]+|[\w$.]+\??\.length\b|[\w$.?]+\s*\?\s*""\s*:\s*""|[\w$.?]+\s*[!=]==?\s*(?:undefined|null)/g, '');
      if (/\b(?:password|passwd|secret|apiKey|api_key|authorization|accessToken|refreshToken|cardNumber|card_number|cvv|ssn)\b/.test(args)) c.add(f, m.index, 'a password/token/secret value is written to the logs');
      else if (sensitiveFile && /\breq\.(?:body|headers)\b/.test(args)) c.add(f, m.index, 'the whole request body/headers is logged in auth/payment code');
    }
  }
  if (bad.length) return fail('APP-18', [...bad, ...c.hits]);
  if (c.hits.length) return warn('APP-18', c.hits);
  return pass('APP-18', ['No committed or public log files, and no logging of secrets or whole request bodies in auth/payment code found.']);
}

// ── APP-19 ─────────────────────────────────────────────────────────────────

function sourceMaps({ repo }) {
  const maps = repo.files.filter((f) => f.build && f.ext === '.map');
  const publicMaps = repo.files.filter((f) => !f.build && f.ext === '.map' && /(?:^|\/)(?:public|static)\//.test(f.rel));
  const all = [...maps, ...publicMaps];
  const bad = [];
  if (all.length) {
    const withSource = all.filter((f) => /"sourcesContent"\s*:\s*\[\s*"/.test((repo.code(f) || '').slice(0, 500000)));
    bad.push(`${all.length} source map file(s) in deployable output${withSource.length ? `; ${withSource.length} embed the full original source (sourcesContent)` : ''}:`);
    for (const f of all.slice(0, 8)) bad.push(ev(f.rel, null, 'public source map'));
  }
  const c = collector(repo);
  for (const f of repo.files.filter((x) => !x.build && /^(?:vite|vitest)\.config\.|^next\.config\.|^webpack[\w.-]*\.config\.|^angular\.json$|^craco\.config\./.test(x.name))) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/\bsourcemap\s*:\s*true\b/g)) c.add(f, m.index, "Vite build.sourcemap: true publishes source maps (use 'hidden' if you upload them to an error tracker)");
    for (const m of text.matchAll(/\bproductionBrowserSourceMaps\s*:\s*true\b/g)) c.add(f, m.index, 'Next.js productionBrowserSourceMaps publishes source maps');
    for (const m of text.matchAll(/\bdevtool\s*:\s*['"](?:source-map|inline-source-map|eval[\w-]*|cheap[\w-]*)['"]/g)) c.add(f, m.index, 'webpack devtool emits browser source maps');
    for (const m of text.matchAll(/"sourceMap"\s*:\s*true/g)) c.add(f, m.index, 'Angular production sourceMap: true');
  }
  if (repo.hasDep('react-scripts')) {
    const off = repo.envFiles().some((f) => /GENERATE_SOURCEMAP\s*=\s*false/.test(repo.code(f) || '')) || repo.packages.some((p) => /GENERATE_SOURCEMAP=false/.test(JSON.stringify((p.json && p.json.scripts) || {})));
    if (!off) {
      const p = repo.packages.find((x) => x.deps.has('react-scripts'));
      c.hits.push(ev(p ? p.rel : 'package.json', null, 'Create React App builds include source maps unless GENERATE_SOURCEMAP=false'));
    }
  }
  if (bad.length) return fail('APP-19', [...bad, ...c.hits]);
  if (c.hits.length) return warn('APP-19', c.hits, { question: 'Do these source maps get deployed publicly, or are they uploaded to an error tracker and deleted?' });
  return pass('APP-19', repo.buildFiles().length ? ['Build output contains no .map files, and build config does not publish source maps.'] : ['No source maps in the repo, and build config does not publish them (no build output present to inspect).']);
}

module.exports = { name: 'appsec', ids: IDS, run };
