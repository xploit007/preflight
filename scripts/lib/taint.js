'use strict';

/**
 * Tiny, per-file taint tracking for the injection heuristics: which identifiers hold request
 * data? It follows `const x = req.query.url`, destructuring (`const { url } = req.body`) and a
 * few levels of reassignment. It does not follow function calls across files.
 */

const { escapeRegExp } = require('./util');

/** Request data on the server (Express/Koa/Next/Hono/Lambda/SvelteKit shapes). */
const SERVER_SOURCE_RE = /\b(?:req|request|ctx\.request)\.(?:body|query|params|headers|cookies|files?)\b|\bctx\.(?:query|params)\b|\bsearchParams\.get\(|\b(?:req|request)\.(?:json|formData|text)\(\)|\bformData\.get\(|\bevent\.(?:body|queryStringParameters|pathParameters|params|url\.searchParams)\b|\bc\.req\.(?:query|param|json|parseBody|header|formData)\b|\burl\.searchParams\b|\bparams\.\w+|\bquery\.\w+/;
/** Attacker-controlled data in the browser. */
const CLIENT_SOURCE_RE = /\blocation\.(?:search|hash|href)\b|\bnew URLSearchParams\(|\bsearchParams\.get\(|\buseSearchParams\(|\brouter\.query\b|\buseParams\(|\bdocument\.referrer\b|\bwindow\.name\b|\bevent\.data\b|\bparams\.get\(/;
/** Coercions that make a value safe for injection sinks. */
const NEUTRALIZER_RE = /^\s*(?:await\s+)?(?:parseInt|parseFloat|Number|Boolean|encodeURIComponent|path\.basename|basename|Math\.\w+|uuidValidate|isUUID)\s*\(/;

function declaredNames(m) {
  if (m[1]) return [m[1]];
  const list = m[2] || m[3] || '';
  return list
    .split(',')
    .map((part) => {
      let p = part.trim().replace(/^\.\.\./, '');
      if (p.includes(':')) p = p.split(':').slice(1).join(':');
      return p.split('=')[0].trim();
    })
    .filter((n) => /^[A-Za-z_$][\w$]*$/.test(n));
}

/** Identifiers in `text` that hold data from `sourceRe` (default: server request data). */
function taintedNames(text, sourceRe = SERVER_SOURCE_RE) {
  const names = new Set();
  const assign = /\b(?:const|let|var)\s+(?:([A-Za-z_$][\w$]*)|\{([^}]*)\}|\[([^\]]*)\])\s*=\s*([^;\n]+)/g;
  for (let round = 0; round < 3; round++) {
    let changed = false;
    for (const m of text.matchAll(assign)) {
      const rhs = m[4];
      if (NEUTRALIZER_RE.test(rhs)) continue;
      const tainted = sourceRe.test(rhs) || [...names].some((n) => new RegExp(`(?<![\\w$.])${escapeRegExp(n)}\\b`).test(rhs));
      if (!tainted) continue;
      for (const d of declaredNames(m)) {
        if (!names.has(d)) {
          names.add(d);
          changed = true;
        }
      }
    }
    if (!changed) break;
  }
  return names;
}

/** Does `expr` contain request data (directly or through a tainted identifier)? */
function isTainted(expr, names, sourceRe = SERVER_SOURCE_RE) {
  if (sourceRe.test(expr)) return true;
  for (const n of names) if (new RegExp(`(?<![\\w$.])${escapeRegExp(n)}\\b`).test(expr)) return true;
  return false;
}

module.exports = { SERVER_SOURCE_RE, CLIENT_SOURCE_RE, taintedNames, isTainted };
