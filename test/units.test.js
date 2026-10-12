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
