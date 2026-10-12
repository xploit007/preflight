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

/** One regex matching any of `names` as a standalone identifier (not a property). */
const namesRegexCache = new WeakMap();
function namesRegex(names) {
  if (!names.size) return null;
  const cached = namesRegexCache.get(names);
  if (cached && cached.size === names.size) return cached.re;
  const re = new RegExp(`(?<![\\w$.])(?:${[...names].map(escapeRegExp).join('|')})\\b`);
  namesRegexCache.set(names, { re, size: names.size });
  return re;
}

/** Identifiers in `text` that hold data from `sourceRe` (default: server request data). */
function taintedNames(text, sourceRe = SERVER_SOURCE_RE) {
  const names = new Set();
  const assign = /\b(?:const|let|var)\s+(?:([A-Za-z_$][\w$]*)|\{([^}]*)\}|\[([^\]]*)\])\s*=\s*([^;\n]+)/g;
  const assignments = [...text.matchAll(assign)];
  for (let round = 0; round < 3; round++) {
    let changed = false;
    for (const m of assignments) {
      const rhs = m[4];
      if (NEUTRALIZER_RE.test(rhs)) continue;
      const known = namesRegex(names); // cached until the set grows
      if (!sourceRe.test(rhs) && !(known && known.test(rhs))) continue;
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
  const re = namesRegex(names);
  return Boolean(re && re.test(expr));
}

module.exports = { SERVER_SOURCE_RE, CLIENT_SOURCE_RE, taintedNames, isTainted };
