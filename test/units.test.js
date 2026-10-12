'use strict';

// Focused tests for the pieces that are easy to get subtly wrong. Secret-shaped test values are
// assembled at runtime so this file never contains a literal that a secret scanner would flag.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { ROOT, scan, tempCopy, tempDir, byId } = require('./helpers');
const P = require('../scripts/lib/patterns');
const { ignoreMatcher, blankComments, splitArgs } = require('../scripts/lib/util');
const { distance } = require('../scripts/checks/deps');

const rand = (n, chars = 'aB3dE5gH7jK9mN1pQ2sT4vW6xY8zC0') => Array.from({ length: n }, (_, i) => chars[(i * 7 + n) % chars.length]).join('');
const SAMPLES = {
  'Stripe live secret key': `sk_${'live'}_${rand(30)}`,
  'OpenAI API key': `sk-${'proj'}-${rand(40)}`,
  'Anthropic API key': `sk-${'ant'}-api03-${rand(60)}`,
  'GitHub token': `gh${'p'}_${rand(36)}`,
  'AWS access key ID': `AK${'IA'}${'QW3RT5YU7IO2PL4K'}`,
  'Slack token': `xox${'b'}-${rand(24)}`,
  'npm access token': `np${'m'}_${rand(36)}`,
  'Groq API key': `gs${'k'}_${rand(52)}`,
};

test('every sample secret is detected and never survives redaction', () => {
  for (const [label, value] of Object.entries(SAMPLES)) {
    const hits = P.findSecrets(`const key = "${value}";`);
    assert.ok(hits.some((h) => h.value === value), `${label} not detected`);
    const line = P.redact(`const key = "${value}"; // ${label}`);
    assert.ok(!line.includes(value), `${label} leaked through redact(): ${line}`);
    const masked = P.mask(value);
    assert.ok(masked.length < value.length && masked.includes('…'), `${label} mask: ${masked}`);
  }
});

test('Supabase JWTs: service_role is a secret, anon is public', () => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const jwt = (role) => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', ref: 'abcdefghijklmnop', role })}.${rand(43)}`;
  assert.equal(P.supabaseRole(jwt('service_role')), 'service_role');
  assert.ok(P.findSecrets(`k = '${jwt('service_role')}'`).some((h) => h.id === 'supabase-service-role'));
  assert.equal(P.findSecrets(`k = '${jwt('anon')}'`).length, 0);
});

test('DB URLs: real passwords flagged, placeholders and local hosts recognized', () => {
  const [remote] = P.findDbUrls(`postgres://app:${rand(16)}@db.example-prod.io:5432/app`);
  assert.equal(remote.local, false);
  assert.equal(remote.placeholder, false);
  assert.equal(P.findDbUrls('postgres://postgres:postgres@localhost:5432/dev')[0].local, true);
  assert.equal(P.findDbUrls('mongodb+srv://user:[YOUR-PASSWORD]@cluster0.mongodb.net')[0].placeholder, true);
  assert.equal(P.findDbUrls('redis://:password@host:6379')[0].placeholder, true);
});

test('public env prefixes: secrets, service-role and AI keys are told apart', () => {
  const cases = {
    VITE_STRIPE_SECRET_KEY: 'secret',
    NEXT_PUBLIC_DATABASE_URL: 'secret',
    VITE_SUPABASE_SERVICE_ROLE_KEY: 'service-role',
    NEXT_PUBLIC_OPENAI_API_KEY: 'ai',
    NEXT_PUBLIC_HF_TOKEN: 'ai',
    NEXT_PUBLIC_SUPABASE_ANON_KEY: null,
    NEXT_PUBLIC_SUPABASE_URL: null,
    VITE_STRIPE_PUBLISHABLE_KEY: null,
    NEXT_PUBLIC_FIREBASE_API_KEY: null,
  };
  for (const [name, want] of Object.entries(cases)) assert.equal(P.classifyPublicEnv(name, ''), want, name);
  assert.equal(P.publicPrefix('PUBLIC_SECRET', new Set()), null, 'bare PUBLIC_ only counts for SvelteKit/Astro');
  assert.ok(P.publicPrefix('PUBLIC_SECRET', new Set(['@sveltejs/kit'])));
});

test('gitignore-style matching for .preflightignore', () => {
  const m = ignoreMatcher(['node_modules/', '*.log', '/build', 'docs/**/*.md', '!keep.log', 'a/**/b']);
  assert.equal(m('src/node_modules/x.js'), true);
  assert.equal(m('logs/app.log'), true);
  assert.equal(m('keep.log'), false);
  assert.equal(m('build/out.js'), true);
  assert.equal(m('src/build/out.js'), false);
  assert.equal(m('docs/x/y/z.md'), true);
  assert.equal(m('a/b'), true);
  assert.equal(m('a/x/y/b'), true);
});

test('comment blanking keeps offsets and leaves strings alone', () => {
  const src = "const u = 'https://x.io'; // eval(req.body.x)\n/* exec(cmd) */ run();";
  const out = blankComments(src, '.js');
  assert.equal(out.length, src.length);
  assert.ok(out.includes("'https://x.io'"));
  assert.ok(!out.includes('eval'));
  assert.ok(!out.includes('exec'));
  assert.ok(out.includes('run();'));
  assert.equal(blankComments('key: v # c\nx: "a # b"', '.yml'), 'key: v    \nx: "a # b"');
});

test('splitArgs handles nested calls, strings and templates', () => {
  const text = "f(a(1, 2), 'x, y', `t ${g(3, 4)}`, { k: [1, 2] })";
  const { args } = splitArgs(text, 1);
  assert.deepEqual(args.map((a) => a.text), ['a(1, 2)', "'x, y'", '`t ${g(3, 4)}`', '{ k: [1, 2] }']);
});

test('typosquat distance', () => {
  assert.equal(distance('expresss', 'express'), 1);
  assert.equal(distance('lodahs', 'lodash'), 1);
  assert.equal(distance('react', 'preact'), 1);
  assert.ok(distance('vite', 'vitest') > 1);
});

test('DEP-03: known-malicious names, compromised lockfile versions and lookalikes', () => {
  const dir = tempDir({
    'package.json': JSON.stringify({ name: 'x', dependencies: { crossenv: '^1.0.0', expresss: '^4.0.0', chalk: '^5.0.0' } }, null, 2),
    'package-lock.json': JSON.stringify({ name: 'x', lockfileVersion: 3, packages: { '': {}, 'node_modules/chalk': { version: '5.6.1' }, 'node_modules/crossenv': { version: '1.0.0' }, 'node_modules/expresss': { version: '4.0.0' } } }),
  });
  const r = byId(scan([dir, '--json', '--offline', '--only', 'deps']).json).get('DEP-03');
  assert.equal(r.status, 'fail');
  assert.ok(r.evidence.some((e) => e.includes('"crossenv" is a known malicious package')));
  assert.ok(r.evidence.some((e) => e.startsWith('chalk@5.6.1 in the lockfile is a known compromised release')));
  assert.ok(r.evidence.some((e) => e.includes('"expresss" is one character away from the popular package "express"')));
});

test('suppression: preflight-ignore comments and .preflightignore', () => {
  const key = SAMPLES['Stripe live secret key'];
  const dir = tempDir({
    'server.js': `const a = "${key}"; // preflight-ignore\n`,
    'vendor-secrets/keys.js': `module.exports = "${key}";\n`,
    '.preflightignore': 'vendor-secrets/\n',
  });
  const r = byId(scan([dir, '--json', '--offline', '--only', 'SEC-03']).json).get('SEC-03');
  assert.equal(r.status, 'pass', r.evidence.join('\n'));
  const dir2 = tempDir({ 'server.js': `const a = "${key}";\n` });
  const r2 = byId(scan([dir2, '--json', '--offline', '--only', 'SEC-03']).json).get('SEC-03');
  assert.equal(r2.status, 'fail');
  assert.ok(!r2.evidence.join('\n').includes(key), 'evidence is masked');
});

test('commented-out code does not trigger heuristics', () => {
  const dir = tempDir({
    'package.json': JSON.stringify({ name: 'x', dependencies: { express: '^5.0.0' } }),
    'server/index.js': "const express = require('express');\nconst app = express();\n// app.post('/api/calc', (req, res) => res.json(eval(req.body.x)));\napp.listen(3000);\n",
  });
  assert.equal(byId(scan([dir, '--json', '--offline', '--only', 'APP-09']).json).get('APP-09').status, 'pass');
  fs.writeFileSync(path.join(dir, 'server/index.js'), "const express = require('express');\nconst app = express();\napp.post('/api/calc', (req, res) => res.json(eval(req.body.x)));\napp.listen(3000);\n");
  const r = byId(scan([dir, '--json', '--offline', '--only', 'APP-09']).json).get('APP-09');
  assert.equal(r.status, 'warn');
  assert.ok(r.evidence[0].startsWith('server/index.js:3 '));
});

test('outside a git repo: history is n/a and an untracked .env is a warning', () => {
  const dir = tempCopy(path.join(ROOT, 'fixtures', 'vulnerable'));
  const res = scan([dir, '--json', '--offline']);
  assert.equal(res.status, 1);
  const r = byId(res.json);
  assert.equal(r.get('SEC-04').status, 'pass');
  assert.match(r.get('SEC-04').evidence[0], /^Not applicable: not a git repository/);
  assert.equal(r.get('SEC-02').status, 'warn');
  assert.ok(res.json.notes.some((n) => /Not a git repository/.test(n)));
});

test('the scanner writes nothing into the target repo', () => {
  const dir = tempCopy(path.join(ROOT, 'fixtures', 'vulnerable'));
  const snapshot = () => {
    const out = [];
    const walk = (d) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else out.push(`${path.relative(dir, p)}:${fs.statSync(p).size}:${fs.statSync(p).mtimeMs}`);
      }
    };
    walk(dir);
    return out.sort();
  };
  const before = snapshot();
  scan([dir, '--json', '--offline']);
  scan([dir, '--offline']);
  assert.deepEqual(snapshot(), before);
});

test('CLI: --only, --fail-on and usage errors', () => {
  const only = scan(['fixtures/vulnerable', '--json', '--offline', '--only', 'SEC-02,DATA-01']);
  assert.deepEqual(only.json.results.map((r) => r.id), ['SEC-02', 'DATA-01']);
  // INFRA-04 (high) fails here, nothing critical does
  const dir = tempDir({
    'package.json': JSON.stringify({ name: 'x', dependencies: { express: '^5.0.0' } }),
    'package-lock.json': JSON.stringify({ name: 'x', lockfileVersion: 3, packages: { '': {} } }),
    'server.js': "const express = require('express');\nconst app = express();\napp.get('/api/health', (req, res) => res.json({ ok: true }));\n",
  });
  assert.equal(scan([dir, '--offline']).status, 0);
  assert.equal(scan([dir, '--offline', '--fail-on', 'high']).status, 1);
  assert.equal(scan(['--bogus']).status, 2);
  assert.equal(scan(['/definitely/not/here']).status, 2);
  assert.equal(scan(['.', '--supabase-url', 'https://x.supabase.co']).status, 2);
  assert.match(scan(['--help']).stdout, /Usage: node scripts\/scan\.js/);
});

test('never runs a package manager binary pinned inside the scanned repo', () => {
  const dir = tempDir({
    'package.json': JSON.stringify({ name: 'x', dependencies: { express: '^5.0.0' } }),
    'yarn.lock': '# yarn lockfile v1\n\nexpress@^5.0.0:\n  version "5.1.0"\n',
    '.yarnrc': 'yarn-path "./.yarn/releases/evil.js"\n',
    '.yarn/releases/evil.js': "require('fs').writeFileSync(require('path').join(__dirname, 'PWNED'), 'x');\n",
  });
  const r = byId(scan([dir, '--json', '--only', 'DEP-01']).json).get('DEP-01');
  assert.equal(r.status, 'manual');
  assert.match(r.evidence.join('\n'), /would execute code from the scanned repo/);
  assert.equal(fs.existsSync(path.join(dir, '.yarn', 'releases', 'PWNED')), false);
});

test('terminal escape sequences in scanned files never reach the output', () => {
  const key = SAMPLES['Stripe live secret key'];
  const dir = tempDir({ 'server.js': `const a = "${key}"; // \u001b[2J\u001b]0;pwned\u0007‮\n` });
  const res = scan([dir, '--offline', '--only', 'SEC-03']);
  assert.ok(!/[\u001b\u0007‮]/.test(res.stdout), JSON.stringify(res.stdout.slice(0, 300)));
  const json = scan([dir, '--json', '--offline', '--only', 'SEC-03']).json;
  assert.ok(!/[\u001b\u0007‮]/.test(json.results[0].evidence.join('')));
});

test('regex worst cases stay fast on huge minified/adversarial input', () => {
  const word = 'abcdefghijklmnopqrstuvwxyz';
  const inputs = [
    Array.from({ length: 60000 }, (_, i) => word.slice(0, (i % 20) + 3)).join('.'),
    'eyJ-'.repeat(150000),
    'sk.eyJ-'.repeat(80000),
    ('var a=function(e,t){return e.apiKeyValue=t,e.secretToken&&e.password_x;};').repeat(8000),
  ];
  for (const text of inputs) {
    const t0 = Date.now();
    for (const m of text.matchAll(P.GENERIC_ASSIGN_RE)) void m;
    P.findSecrets(text);
    P.findDbUrls(text);
    P.redact(text.slice(0, 1000));
    assert.ok(Date.now() - t0 < 3000, `took ${Date.now() - t0}ms on ${text.slice(0, 20)}…`);
  }
});

test('every secret pattern has a sample it detects, and the history prefilter lets it through', () => {
  let seed = 7;
  const r = (n, abc = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') => Array.from({ length: n }, () => abc[(seed = (seed * 1103515245 + 12345) % 2147483648) % abc.length]).join('');
  const hex = '0123456789abcdef';
  const b32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const samples = {
    'aws-access-key-id': `AK${'IA'}${r(16, b32)}`,
    'aws-secret-access-key': `aws_secret_access_key = "${r(40)}"`,
    'stripe-live-secret': `sk_${'live'}_${r(24)}`,
    'stripe-test-secret': `sk_${'test'}_${r(24)}`,
    'stripe-webhook-secret': `wh${'sec'}_${r(32)}`,
    'github-token': `gh${'p'}_${r(36)}`,
    'github-fine-grained': `github${'_pat'}_${r(70)}`,
    'gitlab-token': `gl${'pat'}-${r(20)}`,
    'anthropic-key': `sk-${'ant'}-api03-${r(40)}`,
    'openrouter-key': `sk-${'or'}-v1-${r(64, hex)}`,
    'openai-key': `sk-${'proj'}-${r(40)}`,
    'sk-hex-key': `sk-${r(32, hex)}`,
    'groq-key': `gs${'k'}_${r(52)}`,
    'replicate-key': `r8${'_'}${r(40)}`,
    'huggingface-token': `hf${'_'}${r(34)}`,
    'xai-key': `xa${'i'}-${r(70)}`,
    'perplexity-key': `pp${'lx'}-${r(48)}`,
    'google-api-key': `AI${'za'}${r(35)}`,
    'slack-token': `xo${'xb'}-${r(12, '0123456789')}-${r(24)}`,
    'slack-webhook': `https://hooks.slack.com/services/T${r(8, b32)}/B${r(8, b32)}/${r(24)}`,
    'discord-webhook': `https://discord.com/api/webhooks/${r(18, '0123456789')}/${r(68)}`,
    'telegram-bot-token': `${r(9, '123456789')}:AA${r(33)}`,
    'twilio-api-key': `S${'K'}${r(32, hex)}`,
    'sendgrid-key': `S${'G'}.${r(22)}.${r(43)}`,
    'mailgun-key': `ke${'y'}-${r(32, hex)}`,
    'npm-token': `np${'m'}_${r(36)}`,
    'npmrc-auth': `//registry.npmjs.org/:_auth${'Token'}=${r(36)}`,
    'shopify-token': `shp${'at'}_${r(32, hex)}`,
    'linear-key': `lin${'_api'}_${r(40)}`,
    'doppler-token': `dp${'.pt'}.${r(43)}`,
    'planetscale-token': `pscale${'_tkn'}_${r(43)}`,
    'mapbox-secret': `sk${'.eyJ'}${r(60)}.${r(22)}`,
    'supabase-secret-key': `sb_${'secret'}_${r(32)}`,
    'supabase-pat': `sb${'p'}_${r(40, hex)}`,
    'private-key': `-----BEGIN ${'PRIVATE'} KEY-----\nMII${r(64)}\n${r(64)}`,
  };
  for (const p of P.SECRET_PATTERNS) {
    const text = samples[p.id];
    assert.ok(text, `add a sample for the new pattern ${p.id} (and make sure SECRET_HINT_RE matches it)`);
    assert.ok(P.findSecrets(text).some((h) => h.id === p.id), `${p.id} sample not detected`);
    assert.ok(P.SECRET_HINT_RE.test(text), `SECRET_HINT_RE would skip ${p.id} in the history scan`);
  }
  assert.ok(P.SECRET_HINT_RE.test(`postgres://app:${r(12)}@db.example-co.io/app`), 'DB URLs pass the prefilter');
  assert.ok(P.SECRET_HINT_RE.test(`eyJ${r(20)}.eyJ${r(20)}.${r(20)}`), 'JWTs pass the prefilter');
});

test('secret values never leak into evidence, in JSON or terminal output', () => {
  const values = ['my prod pw 2024', 'Pr0dJwtS3cret2024', 'Pr0dSessS3cret2024', 'Pr0dDbS3cret2024', 'An0therS3cret!'];
  const dir = tempDir({
    'package.json': JSON.stringify({ name: 'leak', dependencies: { pg: '8.0.0', jsonwebtoken: '9.0.0', 'express-session': '1.0.0' } }),
    'server.js': [
      "const { Pool } = require('pg');",
      "const jwt = require('jsonwebtoken');",
      "const session = require('express-session');",
      `const pool = new Pool({ host: 'db.prod.internal.example-co.io', password: '${values[0]}' });`,
      `function sign(u) { return jwt.sign({ id: u.id }, '${values[1]}'); }`,
      `app.use(session({ secret: '${values[2]}', resave: false }));`,
      '',
    ].join('\n'),
    'docker-compose.yml': `services:\n  db:\n    image: postgres\n    environment:\n      POSTGRES_PASSWORD: ${values[3]}\n      MYSQL_ROOT_PASSWORD: "${values[4]}"\n    ports:\n      - "5432:5432"\n`,
  });
  const json = scan([dir, '--json', '--offline', '--no-history']);
  const pretty = scan([dir, '--offline', '--no-history', '--verbose']);
  for (const v of values) {
    assert.ok(!json.stdout.includes(v), `"${v}" leaked into --json output`);
    assert.ok(!pretty.stdout.includes(v), `"${v}" leaked into terminal output`);
  }
});

test('routes: wrappers, chained methods, array mounts, proxy.ts, NestJS windows and Vercel functions', () => {
  const { loadRepo } = require('../scripts/lib/repo');
  const { getRoutes, routeBody } = require('../scripts/lib/routes');
  const dir = tempDir({
    'package.json': JSON.stringify({ name: 'app', dependencies: { express: '4.0.0' } }),
    'src/app.js': "const express = require('express');\nconst routes = require('./routes');\nconst app = express();\napp.use('/v1', routes);\n",
    'src/routes/index.js': "const express = require('express');\nconst authRoute = require('./auth.route');\nconst router = express.Router();\nconst defaultRoutes = [{ path: '/auth', route: authRoute }];\ndefaultRoutes.forEach((route) => { router.use(route.path, route.route); });\nmodule.exports = router;\n",
    'src/routes/auth.route.js': "const express = require('express');\nconst router = express.Router();\nrouter.route('/users').get(auth('getUsers'), list).post(create);\nrouter\n  .route('/users/:id')\n  .delete(auth('manageUsers'), remove);\nmodule.exports = router;\n",
    'web/package.json': JSON.stringify({ name: 'web', dependencies: { next: '15.0.0' } }),
    'web/app/api/items/route.ts': "import { withAuth } from '@/lib/guard';\nasync function postHandler(req) { return Response.json({}); }\nexport const POST = withAuth(postHandler);\n",
    'web/src/lib/guard.ts': 'export function withAuth(fn) { return async (req) => { const session = await getServerSession(); if (!session) return new Response(null, { status: 401 }); return fn(req); }; }\n',
    'web/proxy.ts': "import { auth } from './auth';\nexport default auth((req) => {});\nexport const config = { matcher: ['/dashboard/:path*'] };\n",
    'api/package.json': JSON.stringify({ name: 'fn', dependencies: { '@vercel/node': '3.0.0' } }),
    'api/api/hello.ts': 'export default function handler(req, res) { res.json({ ok: true }); }\n',
    'api/api/config.ts': 'export default { region: "iad1" };\n',
    'nest/package.json': JSON.stringify({ name: 'nest', dependencies: { '@nestjs/core': '10.0.0' } }),
    'nest/src/users.controller.ts': "@Controller('users')\nexport class UsersController {\n  @UseGuards(AuthGuard)\n  @Post()\n  create() {}\n\n  @Delete(':id')\n  remove() {}\n}\n",
  });
  const repo = loadRepo(dir, { history: false });
  const { routes, nextMiddleware } = getRoutes(repo);
  const find = (method, p) => routes.find((x) => x.method === method && x.path === p);
  assert.ok(find('GET', '/v1/auth/users'), `array-mounted chained GET missing: ${routes.map((x) => `${x.method} ${x.path}`).join(', ')}`);
  assert.ok(find('POST', '/v1/auth/users'), 'chained POST missing');
  assert.ok(find('DELETE', '/v1/auth/users/:id'), 'multi-line chained DELETE missing');
  assert.ok(!/auth\(/.test(find('POST', '/v1/auth/users').text), 'POST window must not include the GET handler chain');
  assert.match(routeBody(find('POST', '/api/items')), /getServerSession/, 'wrapper resolved through the @/ alias');
  assert.ok(find('ANY', '/api/hello'), 'Vercel function missing');
  assert.ok(!routes.some((x) => x.path === '/api/config'), 'config modules under api/ are not functions');
  assert.ok(nextMiddleware && nextMiddleware.auth && /proxy\.ts$/.test(nextMiddleware.file.rel), 'Next 16 proxy.ts is middleware');
  const nestPost = find('POST', '/users');
  const nestDelete = find('DELETE', '/users/:id');
  assert.match(nestPost.text, /@UseGuards/, 'NestJS window starts at the decorators');
  assert.ok(!/@UseGuards/.test(nestDelete.text), 'the next method does not inherit the previous guard');
  assert.equal(repo.lineOf(nestPost.file, nestPost.start), 3);
});

test('false-positive guards: tokens, JWT payloads, cookies, SQL functions, navigation, a11y, deps, logs', () => {
  const dir = tempDir({
    'package.json': JSON.stringify({ name: 'fp', dependencies: { express: '4.0.0', jsonwebtoken: '9.0.0', motion: '11.0.0', querystring: '0.2.1', '@acme/ui': '*' }, peerDependencies: { react: '>=18' } }),
    'package-lock.json': '{"lockfileVersion":3,"packages":{}}',
    'packages/ui/package.json': JSON.stringify({ name: '@acme/ui', version: '1.0.0' }),
    'server/tokens.js': [
      "const jwt = require('jsonwebtoken');",
      'const isTokenValid = record.expires > Date.now();',
      'const tokenExpiresAt = Date.now() + 3600000;',
      'function sign(user) {',
      '  const payload = { sub: user.id, iat: now, exp: now + 3600 };',
      '  return jwt.sign(payload, process.env.JWT_SECRET);',
      '}',
      'function setCookie(res, token) {',
      '  const httpOnly = true, secure = true, sameSite = "lax";',
      "  res.cookie('session', token, { httpOnly, secure, sameSite });",
      '}',
      "console.log('key configured', !!process.env.API_KEY, Boolean(secret), password.length);",
      "logger.error({ message: err.message, stack: err.stack });",
      "const response = { code, message, ...(config.env === 'development' && { stack: err.stack }) };",
      '',
    ].join('\n'),
    'supabase/migrations/1_init.sql': "create function public.f() returns trigger language plpgsql security definer as $$ begin return new; end; $$ set search_path = '';\n",
    'src/App.jsx': "export default function App() { return <Router location={location}><div onClick={(e) => e.stopPropagation()}><h1>Hi</h1></div></Router>; }\n",
  });
  const res = scan([dir, '--json', '--offline', '--no-history']);
  const results = byId(res.json);
  const get = (id) => results.get(id);
  const text = (id) => get(id).evidence.join('\n');
  assert.ok(!/isTokenValid|tokenExpiresAt/.test(text('AUTH-05')), text('AUTH-05'));
  assert.ok(!/never expire/.test(text('AUTH-06')), text('AUTH-06'));
  assert.equal(get('AUTH-10').status, 'pass', text('AUTH-10'));
  assert.equal(get('AUTH-06').status, 'pass', text('AUTH-06'));
  assert.ok(!/search_path/.test(text('DATA-03')), text('DATA-03'));
  assert.ok(!/App\.jsx/.test(text('APP-14')), text('APP-14'));
  assert.ok(!/clickable <div>/.test(text('LEGAL-02')), text('LEGAL-02'));
  assert.ok(!/@acme\/ui|react/.test(text('DEP-02')), text('DEP-02'));
  assert.ok(!/motion|querystring/.test(text('DEP-03')), text('DEP-03'));
  assert.ok(!/tokens\.js/.test(text('APP-18')), text('APP-18'));
  assert.ok(!/tokens\.js/.test(text('APP-17')), text('APP-17'));
});

test('webhook receivers and admin pages: stubs, delegation, manual HMAC, layouts and components', () => {
  const dir = tempDir({
    'package.json': JSON.stringify({ name: 'app', dependencies: { next: '15.0.0' } }),
    'app/api/webhooks/stub/route.ts': 'export async function POST() { return new Response(null, { status: 410 }); }\n',
    'app/api/webhooks/hmac/route.ts': "import { createHmac } from 'crypto';\nexport async function POST(request) {\n  const body = await request.text();\n  const expected = createHmac('sha256', process.env.HOOK_SECRET).update(body).digest('hex');\n  if (request.headers.get('x-signature') !== expected) return new Response(null, { status: 401 });\n  return Response.json({ ok: true });\n}\n",
    'app/api/webhooks/calendar/route.ts': "import { service } from '@/lib/service';\nasync function postHandler(request) { await service.processWebhook(request); return Response.json({}); }\nexport const POST = wrap(postHandler);\n",
    'app/(admin)/users/page.tsx': 'export default async function Page() { return <h1>Users</h1>; }\n',
    'app/(admin)/layout.tsx': "import { requireAdmin } from '@/lib/guard';\nexport default async function Layout({ children }) { await requireAdmin(); return children; }\n",
    'src/lib/guard.ts': "export async function requireAdmin() { const s = await getServerSession(); if (s?.user?.role !== 'admin') redirect('/'); }\n",
    'components/AdminBadge.tsx': 'export function AdminBadge() { return <span>admin</span>; }\n',
  });
  const res = scan([dir, '--json', '--offline', '--no-history', '--only', 'APP-12,AUTH-04']);
  const results = byId(res.json);
  const hooks = results.get('APP-12');
  assert.equal(hooks.status, 'warn', hooks.evidence.join('\n'));
  const text = hooks.evidence.join('\n');
  assert.match(text, /calendar hands the request to service\.processWebhook\(\)/);
  assert.match(text, /webhooks\/hmac verifies the signature/);
  assert.ok(!/stub/.test(text), 'a stub that never reads the request is not a receiver');
  const admin = results.get('AUTH-04');
  assert.equal(admin.status, 'pass', admin.evidence.join('\n'));
  assert.match(admin.evidence[0], /^1 admin/, 'components named Admin* are not pages');
});
