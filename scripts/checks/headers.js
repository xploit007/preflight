'use strict';

/**
 * HTTP headers: APP-15 security headers (static config, or the live site with --url) and
 * APP-13 permissive CORS (static, plus one live GET with a probe Origin header).
 * Missing headers are a warn with a copy-paste block for the detected host.
 */

const { loadRepo } = require('../lib/repo');
const net = require('../lib/net');
const { getCheck } = require('../lib/catalog');
const { pass, fail, warn, na, ev } = require('../lib/result');
const { objectAt } = require('../lib/util');

const IDS = ['APP-13', 'APP-15'];

const HEADERS = [
  { key: 'content-security-policy', label: 'Content-Security-Policy', helmetOff: /contentSecurityPolicy\s*:\s*false/ },
  { key: 'strict-transport-security', label: 'Strict-Transport-Security', helmetOff: /(?:hsts|strictTransportSecurity)\s*:\s*false/ },
  { key: 'x-frame-options', label: 'X-Frame-Options', helmetOff: /(?:frameguard|xFrameOptions)\s*:\s*false/ },
  { key: 'x-content-type-options', label: 'X-Content-Type-Options', helmetOff: /(?:noSniff|xContentTypeOptions)\s*:\s*false/ },
  { key: 'referrer-policy', label: 'Referrer-Policy', helmetOff: /referrerPolicy\s*:\s*false/ },
];
const HELMET_RE = /\bhelmet\s*\(|@fastify\/helmet|fastify-helmet|koa-helmet|\bsecureHeaders\s*\(|hono\/secure-headers|next-safe|@nosecone\/|\bnosecone\b/;
const PROBE_ORIGIN = 'https://preflight-cors-probe.example';
const CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'";
const VALUES = {
  'Content-Security-Policy': CSP,
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
};

async function run(root, opts = {}) {
  const repo = loadRepo(root, opts);
  const live = opts.url && !opts.offline ? await fetchLive(opts.url) : null;
  return [cors(repo, opts, live), securityHeaders(repo, opts, live)];
}

async function fetchLive(url) {
  const [page, probe] = await Promise.all([net.getOnce(url, { timeoutMs: 10000 }), net.get(url, { headers: { origin: PROBE_ORIGIN }, timeoutMs: 10000 })]);
  let httpRedirect = null;
  try {
    const u = new URL(page.url || url);
    if (u.protocol === 'https:') {
      const plain = await net.get(`http://${u.host}${u.pathname}`, { maxRedirects: 0, timeoutMs: 8000 });
      httpRedirect = plain.error ? null : { status: plain.status, location: plain.headers && plain.headers.location };
    }
  } catch {
    httpRedirect = null;
  }
  return { page, probe, httpRedirect };
}

function providers(repo) {
  const has = (name) => repo.files.some((f) => !f.build && f.name === name);
  const list = [];
  if (has('vercel.json') || repo.files.some((f) => f.rel.startsWith('.vercel/'))) list.push('vercel');
  if (has('netlify.toml')) list.push('netlify');
  if (repo.files.some((f) => /^wrangler\.(?:toml|jsonc?)$/.test(f.name))) list.push('cloudflare');
  if (has('firebase.json')) list.push('firebase');
  if (has('fly.toml')) list.push('fly');
  if (has('render.yaml')) list.push('render');
  return list;
}

function snippetFor(repo, missing) {
  const p = providers(repo);
  const pick = (labels) => labels.map((l) => [l, VALUES[l]]);
  const rows = pick(missing.length ? missing : Object.keys(VALUES));
  const blocks = [];
  if (p.includes('vercel')) {
    blocks.push(`vercel.json:\n"headers": [\n  {\n    "source": "/(.*)",\n    "headers": [\n${rows.map(([k, v]) => `      { "key": "${k}", "value": "${v}" }`).join(',\n')}\n    ]\n  }\n]`);
  }
  if (p.includes('netlify')) {
    blocks.push(`netlify.toml:\n[[headers]]\n  for = "/*"\n  [headers.values]\n${rows.map(([k, v]) => `    ${k} = "${v}"`).join('\n')}`);
  }
  if (p.includes('cloudflare') || (p.includes('netlify') && !blocks.length)) {
    blocks.push(`_headers (in your publish folder, e.g. public/_headers):\n/*\n${rows.map(([k, v]) => `  ${k}: ${v}`).join('\n')}`);
  }
  if (p.includes('firebase')) {
    blocks.push(`firebase.json → "hosting": {\n  "headers": [{ "source": "**", "headers": [\n${rows.map(([k, v]) => `    { "key": "${k}", "value": "${v}" }`).join(',\n')}\n  ] }]\n}`);
  }
  if (repo.hasDep('next') && !p.includes('vercel') && !p.includes('netlify')) {
    blocks.push(`next.config.js:\nasync headers() {\n  return [{ source: '/(.*)', headers: [\n${rows.map(([k, v]) => `    { key: '${k}', value: "${v}" }`).join(',\n')}\n  ] }];\n}`);
  }
  if (repo.hasDep('express') || repo.hasDep('fastify') || repo.hasDep('koa') || repo.hasDep('hono') || p.includes('fly') || p.includes('render')) {
    blocks.push("App server: `npm i helmet` then `app.use(helmet())` (Express; @fastify/helmet, koa-helmet and hono's secureHeaders() are the equivalents). Helmet sets all five headers.");
  }
  if (!blocks.length) blocks.push(`_headers / server config:\n${rows.map(([k, v]) => `${k}: ${v}`).join('\n')}`);
  return `${getCheck('APP-15').fix}\n\nCopy-paste for your setup:\n\n${blocks.join('\n\n')}`;
}

function staticHeaders(repo) {
  const found = new Map(); // label -> "file:line"
  const files = repo.files.filter((f) => !f.build && ['code', 'config', 'markup'].includes(f.kind) && !repo.isTest(f) && !(f.kind === 'code' && repo.side(f) === 'client' && !/middleware\.[jt]s$/.test(f.rel)));
  for (const f of files) {
    const text = repo.code(f);
    if (!text) continue;
    if (f.kind === 'code' && HELMET_RE.test(text)) {
      const idx = text.search(HELMET_RE);
      const call = text.slice(idx, idx + 1500);
      for (const h of HEADERS) if (!h.helmetOff.test(call) && !found.has(h.label)) found.set(h.label, `${f.rel}:${repo.lineOf(f, idx)} (helmet/secureHeaders)`);
    }
    for (const h of HEADERS) {
      if (found.has(h.label)) continue;
      const re = f.kind === 'markup' ? (h.key === 'content-security-policy' ? /http-equiv\s*=\s*["']Content-Security-Policy["']/i : null) : new RegExp(h.label.replace(/-/g, '[-_]?'), 'i');
      if (!re) continue;
      const m = re.exec(text);
      if (m) found.set(h.label, `${f.rel}:${repo.lineOf(f, m.index)}`);
    }
    if (!found.has('X-Frame-Options') && /frame-ancestors/i.test(text) && f.kind !== 'markup') {
      found.set('X-Frame-Options', `${f.rel}:${repo.lineOf(f, text.search(/frame-ancestors/i))} (CSP frame-ancestors)`);
    }
    if (f.name === 'svelte.config.js' && /\bcsp\s*:/.test(text) && !found.has('Content-Security-Policy')) found.set('Content-Security-Policy', `${f.rel}:${repo.lineOf(f, text.search(/\bcsp\s*:/))} (SvelteKit kit.csp)`);
  }
  return found;
}

function hasWebApp(repo) {
  return repo.files.some((f) => !f.build && (f.ext === '.html' || /\.(?:jsx|tsx|vue|svelte|astro)$/.test(f.ext))) || ['next', 'express', 'fastify', 'koa', 'hono', '@sveltejs/kit', 'nuxt', 'astro', 'vite', 'react-scripts'].some((d) => repo.hasDep(d)) || ['django', 'flask', 'fastapi'].some((d) => repo.pythonDeps.has(d)) || providers(repo).length > 0;
}

function securityHeaders(repo, opts, live) {
  if (!hasWebApp(repo) && !opts.url) return na('APP-15', 'no web app or deployment config found');
  const evidence = [];
  if (live && !live.page.error) {
    const h = live.page.headers || {};
    const missing = [];
    const present = [];
    const csp = h['content-security-policy'];
    if (!csp) missing.push(h['content-security-policy-report-only'] ? 'Content-Security-Policy (only Report-Only is set, so nothing is enforced)' : 'Content-Security-Policy');
    else present.push('Content-Security-Policy');
    const finalHttps = String(live.page.url || opts.url).startsWith('https:');
    const hsts = h['strict-transport-security'];
    const maxAge = hsts ? Number((/max-age=(\d+)/i.exec(hsts) || [])[1] || 0) : 0;
    if (!hsts && finalHttps) missing.push('Strict-Transport-Security');
    else if (hsts && maxAge < 15552000) missing.push(`Strict-Transport-Security (max-age=${maxAge} is under 180 days)`);
    else if (hsts) present.push('Strict-Transport-Security');
    if (!h['x-frame-options'] && !/frame-ancestors/i.test(csp || '')) missing.push('X-Frame-Options (or CSP frame-ancestors)');
    else present.push('X-Frame-Options');
    if (String(h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') missing.push('X-Content-Type-Options: nosniff');
    else present.push('X-Content-Type-Options');
    if (!h['referrer-policy']) missing.push('Referrer-Policy');
    else present.push('Referrer-Policy');
    evidence.push(`live ${live.page.url || opts.url} (HTTP ${live.page.status}) — ${missing.length ? `missing: ${missing.join(', ')}` : 'all five headers present'}${present.length ? `; present: ${present.join(', ')}` : ''}`);
    if (h['x-powered-by']) evidence.push(`live — X-Powered-By: ${h['x-powered-by']} reveals the framework (remove it, e.g. app.disable('x-powered-by'))`);
    if (live.httpRedirect && !(live.httpRedirect.status >= 300 && live.httpRedirect.status < 400 && /^https:/i.test(live.httpRedirect.location || ''))) {
      missing.push('HTTP→HTTPS redirect');
      evidence.push(`live — http:// version answered ${live.httpRedirect.status} instead of redirecting to https://`);
    }
    const labels = missing.map((m) => m.split(' ')[0].replace(/:$/, '')).filter((l) => VALUES[l]);
    if (missing.length) return warn('APP-15', evidence, { fix: snippetFor(repo, labels) });
    return pass('APP-15', evidence);
  }
  if (live && live.page.error) evidence.push(`live fetch of ${opts.url} failed (${live.page.error}); falling back to static config`);
  const found = staticHeaders(repo);
  const vercel = providers(repo).includes('vercel');
  const missing = HEADERS.map((h) => h.label).filter((l) => !found.has(l) && !(l === 'Strict-Transport-Security' && vercel));
  for (const [label, at] of found) evidence.push(`${at} — ${label} configured`);
  if (vercel && !found.has('Strict-Transport-Security')) evidence.push('Strict-Transport-Security: Vercel adds it by default on its domains (confirm with --url).');
  if (!missing.length) return pass('APP-15', [...evidence, 'Static check only: re-run with --url to confirm the deployed site sends them.']);
  const where = providers(repo)[0];
  const configFile = { vercel: 'vercel.json', netlify: 'netlify.toml', firebase: 'firebase.json', fly: 'fly.toml', render: 'render.yaml', cloudflare: 'wrangler.toml' }[where];
  const cf = configFile ? repo.files.find((f) => f.name === configFile || (where === 'cloudflare' && /^wrangler\./.test(f.name))) : null;
  evidence.unshift(cf ? ev(cf.rel, 1, `no ${missing.join(', ')} configured for ${where} (checked ${cf.name}, _headers, framework config and server code)`) : `No ${missing.join(', ')} configured in vercel.json, netlify.toml, _headers, next.config, firebase.json, helmet/secureHeaders or server code.`);
  evidence.push('Static check only: re-run with --url https://your-site to test the live response.');
  return warn('APP-15', evidence, { fix: snippetFor(repo, missing) });
}

function cors(repo, opts, live) {
  const bad = [];
  const soft = [];
  let scanned = false;
  const add = (list, f, index, note) => {
    const line = repo.lineOf(f, index);
    if (!repo.suppressed(f, line)) list.push(ev(f.rel, line, note, repo.snippet(f, line)));
  };
  for (const f of repo.files) {
    if (f.build || repo.isTest(f) || !['code', 'config'].includes(f.kind)) continue;
    if (f.kind === 'code' && repo.side(f) === 'client') continue;
    const text = repo.code(f);
    if (!text) continue;
    scanned = true;
    const credsInFile = /credentials\s*:\s*true|Access-Control-Allow-Credentials['"`]?\s*[,:=]\s*['"`]?true/i.test(text);
    for (const m of text.matchAll(/\bcors\(\s*\)/g)) add(soft, f, m.index, 'cors() with default options sends Access-Control-Allow-Origin: * to every site');
    for (const m of text.matchAll(/\b(?:cors|register\(\s*(?:cors|fastifyCors|require\(['"]@fastify\/cors['"]\))\s*,)\s*\(?\s*\{/g)) {
      const obj = objectAt(text, m.index + m[0].lastIndexOf('{'));
      if (!/\borigin\b/.test(obj) && !/\bcredentials\s*:\s*true/.test(obj)) continue;
      const creds = /\bcredentials\s*:\s*true/.test(obj);
      if (/\borigin\s*:\s*true\b/.test(obj) || /\borigin\s*:\s*\([^)]*\)\s*=>\s*true\b/.test(obj) || /callback\(\s*null\s*,\s*true\s*\)|cb\(\s*null\s*,\s*true\s*\)/.test(obj) || /\borigin\s*:\s*(?:req|request)\.headers\.origin/.test(obj)) {
        add(creds ? bad : soft, f, m.index, creds ? 'CORS reflects any Origin and allows credentials: any website can make logged-in requests and read the responses' : 'CORS reflects any Origin');
      } else if (/\borigin\s*:\s*['"`]\*['"`]/.test(obj)) add(soft, f, m.index, `CORS allows origin '*'${creds ? ' together with credentials (browsers reject this; the usual "fix" of origin: true makes it exploitable)' : ''}`);
    }
    for (const m of text.matchAll(/['"`]?Access-Control-Allow-Origin['"`]?\s*[,:=]\s*['"`]?\*/gi)) add(soft, f, m.index, 'Access-Control-Allow-Origin: * set explicitly');
    for (const m of text.matchAll(/['"`]Access-Control-Allow-Origin['"`]\s*,\s*(?:req|request)\.headers(?:\.origin|\.get\(\s*['"]origin['"]\s*\)|\[['"]origin['"]\])/gi)) {
      add(credsInFile ? bad : soft, f, m.index, credsInFile ? 'the request Origin is echoed back with Allow-Credentials: true' : 'the request Origin is echoed back into Access-Control-Allow-Origin');
    }
  }
  if (live && live.probe && !live.probe.error && live.probe.headers) {
    const acao = live.probe.headers['access-control-allow-origin'];
    const acac = String(live.probe.headers['access-control-allow-credentials'] || '').toLowerCase() === 'true';
    if (acao === PROBE_ORIGIN) (acac ? bad : soft).push(`live ${opts.url} — a request with Origin: ${PROBE_ORIGIN} got that origin echoed back${acac ? ' with Access-Control-Allow-Credentials: true' : ''}`);
    else if (acao === '*') soft.push(`live ${opts.url} — responds with Access-Control-Allow-Origin: *`);
  }
  if (bad.length) return fail('APP-13', [...bad, ...soft]);
  if (soft.length) return warn('APP-13', soft);
  if (!scanned && !live) return na('APP-13', 'no server code or header config found');
  return pass('APP-13', ['No wildcard or reflected CORS origins found.']);
}

module.exports = { name: 'headers', ids: IDS, run, staticHeaders, snippetFor };
