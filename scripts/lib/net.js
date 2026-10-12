'use strict';

/**
 * Minimal HTTP(S) GET for the live checks (security headers, Supabase RLS). Read-only,
 * bounded: timeout, redirect limit, and a body cap. Built on node:http / node:https only.
 */

const http = require('http');
const https = require('https');
const VERSION = require('./version');

function get(url, { headers = {}, timeoutMs = 10000, maxRedirects = 5, maxBytes = 512 * 1024 } = {}) {
  return new Promise((resolve) => {
    const redirects = [];
    const visit = (current, left) => {
      let u;
      try {
        u = new URL(current);
      } catch {
        resolve({ error: `invalid URL: ${current}` });
        return;
      }
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        resolve({ error: `unsupported protocol: ${u.protocol}` });
        return;
      }
      const lib = u.protocol === 'https:' ? https : http;
      const req = lib.request(
        u,
        { method: 'GET', headers: { 'user-agent': `preflight/${VERSION} (+https://github.com/xploit007/preflight)`, accept: '*/*', ...headers }, timeout: timeoutMs },
        (res) => {
          const status = res.statusCode || 0;
          if (status >= 300 && status < 400 && res.headers.location && left > 0) {
            res.resume();
            const next = new URL(res.headers.location, u).toString();
            redirects.push({ from: u.toString(), to: next, status });
            visit(next, left - 1);
            return;
          }
          const chunks = [];
          let size = 0;
          res.on('data', (c) => {
            size += c.length;
            if (size <= maxBytes) chunks.push(c);
            else res.destroy();
          });
          const done = () => resolve({ status, headers: res.headers, body: Buffer.concat(chunks).toString('utf8'), url: u.toString(), redirects });
          res.on('end', done);
          res.on('close', done);
        },
      );
      req.on('timeout', () => req.destroy(new Error(`timed out after ${timeoutMs}ms`)));
      req.on('error', (e) => resolve({ error: e.message, url: u.toString(), redirects }));
      req.end();
    };
    visit(url, maxRedirects);
  });
}

/** Memoized GET so several check groups can share one request to the live site. */
const shared = new Map();
function getOnce(url, opts) {
  const key = `${url}|${JSON.stringify((opts && opts.headers) || {})}`;
  if (!shared.has(key)) shared.set(key, get(url, opts));
  return shared.get(key);
}

module.exports = { get, getOnce };
