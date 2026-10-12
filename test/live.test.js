'use strict';

// Live checks (--url, --supabase-url/--supabase-key) against a local mock server: a site that
// sends no security headers, reflects any Origin with credentials and sets a session cookie
// without flags, plus a PostgREST endpoint where one table is readable anonymously.

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const path = require('path');
const { ROOT, scanAsync, tempCopy, byId } = require('./helpers');

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (role) => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', ref: 'mockmockmockmock', role })}.${'x'.repeat(43)}`;

function startServer() {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push({ method: req.method, url: req.url, apikey: req.headers.apikey });
    if (req.url.startsWith('/rest/v1/')) {
      const table = req.url.slice('/rest/v1/'.length).split('?')[0];
      if (table === 'notes') return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify([{ id: 1, user_id: 'u1', title: 'secret plans', body: 'hi' }]));
      if (table === 'profiles') return res.writeHead(200, { 'content-type': 'application/json' }).end('[]');
      return res.writeHead(404, { 'content-type': 'application/json' }).end(JSON.stringify({ code: 'PGRST205', message: 'Could not find the table' }));
    }
    const headers = { 'content-type': 'text/html', 'set-cookie': 'session=abc123; Path=/', 'x-powered-by': 'Express' };
    if (req.headers.origin) Object.assign(headers, { 'access-control-allow-origin': req.headers.origin, 'access-control-allow-credentials': 'true' });
    res.writeHead(200, headers).end('<!doctype html><html lang="en"><title>mock</title></html>');
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, seen, url: `http://127.0.0.1:${server.address().port}` })));
}

test('live headers, CORS, cookies and Supabase RLS checks', async () => {
  const { server, seen, url } = await startServer();
  try {
    const dir = tempCopy(path.join(ROOT, 'fixtures', 'clean'));
    const res = await scanAsync([dir, '--json', '--no-audit', '--no-history', '--url', url, '--supabase-url', url, '--supabase-key', jwt('anon')]);
    const r = byId(res.json);

    const headers = r.get('APP-15');
    assert.equal(headers.status, 'warn');
    assert.ok(headers.evidence.some((e) => e.startsWith(`live ${url}`) && e.includes('missing: Content-Security-Policy')), headers.evidence.join('\n'));

    const cors = r.get('APP-13');
    assert.equal(cors.status, 'fail');
    assert.ok(cors.evidence.some((e) => e.includes('got that origin echoed back with Access-Control-Allow-Credentials: true')));

    const cookies = r.get('AUTH-10');
    assert.equal(cookies.status, 'fail');
    assert.ok(cookies.evidence.some((e) => e.includes('Set-Cookie "session" lacks HttpOnly')));

    const rls = r.get('DATA-01');
    assert.equal(rls.status, 'fail');
    assert.ok(rls.evidence.some((e) => e.startsWith(`live: GET ${url}/rest/v1/notes?select=*&limit=1`) && e.includes('columns: id, user_id, title, body')), rls.evidence.join('\n'));
    assert.ok(!rls.evidence.join('\n').includes('secret plans'), 'row values never appear in evidence');

    const reads = seen.filter((s) => s.url.startsWith('/rest/v1/'));
    assert.ok(reads.length >= 2 && reads.every((s) => s.method === 'GET' && s.url.endsWith('?select=*&limit=1')), 'only read-only GETs');
    assert.ok(seen.every((s) => s.method === 'GET'), 'no non-GET requests to the live site');
  } finally {
    server.close();
  }
});

test('a service-role key is refused for the live RLS test', async () => {
  const { server, seen, url } = await startServer();
  try {
    const dir = tempCopy(path.join(ROOT, 'fixtures', 'clean'));
    const res = await scanAsync([dir, '--json', '--no-audit', '--no-history', '--only', 'supabase', '--supabase-url', url, '--supabase-key', jwt('service_role')]);
    const rls = byId(res.json).get('DATA-01');
    assert.equal(rls.status, 'pass');
    assert.ok(rls.evidence.some((e) => e.startsWith('Live check refused')));
    assert.equal(seen.length, 0, 'no request is sent with a service-role key');
  } finally {
    server.close();
  }
});

test('--offline skips live checks entirely', async () => {
  const { server, seen, url } = await startServer();
  try {
    await scanAsync([path.join(ROOT, 'fixtures', 'clean'), '--json', '--offline', '--url', url, '--supabase-url', url, '--supabase-key', jwt('anon')]);
    assert.equal(seen.length, 0);
  } finally {
    server.close();
  }
});
