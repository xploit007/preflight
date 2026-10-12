'use strict';

/**
 * Small dependency-free helpers shared by the runner and the check groups.
 */

/** Offsets of every line start, so a character index maps to a 1-based line number. */
function lineStarts(text) {
  const starts = [0];
  let i = text.indexOf('\n');
  while (i !== -1) {
    starts.push(i + 1);
    i = text.indexOf('\n', i + 1);
  }
  return starts;
}

/** 1-based line number of a character index, given lineStarts(text). */
function lineAt(starts, index) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/** Collapse whitespace and cut to `max` characters. */
function clip(text, max = 140) {
  const s = String(text).replace(/\s+/g, ' ').trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** Shannon entropy in bits per character. */
function entropy(s) {
  if (!s) return 0;
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function uniq(items) {
  return [...new Set(items)];
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Non-capturing alternation of literal words, for building documented regexes from lists. */
function alt(words) {
  return `(?:${words.map(escapeRegExp).join('|')})`;
}

// ── Lightweight JS tokenizing ──────────────────────────────────────────────
// Enough to split call arguments and skip strings/templates/comments. It is not a
// parser: regex literals and JSX text can confuse it, which only costs a missed hit.

/** Index of the closing quote of a '…' or "…" string starting at i. */
function skipQuoted(text, i, quote, limit) {
  for (let j = i + 1; j < limit; j++) {
    const ch = text[j];
    if (ch === '\\') {
      j++;
      continue;
    }
    if (ch === quote || ch === '\n') return j;
  }
  return limit;
}

/** Index of the closing backtick of a template literal starting at i (handles ${…} nesting). */
function skipTemplate(text, i, limit) {
  for (let j = i + 1; j < limit; j++) {
    const ch = text[j];
    if (ch === '\\') {
      j++;
      continue;
    }
    if (ch === '`') return j;
    if (ch === '$' && text[j + 1] === '{') j = skipExpression(text, j + 2, limit);
  }
  return limit;
}

/** Index of the "}" that closes an expression starting at i (depth 0). */
function skipExpression(text, i, limit) {
  let depth = 0;
  for (let j = i; j < limit; j++) {
    const ch = text[j];
    if (ch === '"' || ch === "'") {
      j = skipQuoted(text, j, ch, limit);
      continue;
    }
    if (ch === '`') {
      j = skipTemplate(text, j, limit);
      continue;
    }
    if (ch === '{') depth++;
    else if (ch === '}') {
      if (depth === 0) return j;
      depth--;
    }
  }
  return limit;
}

/**
 * Split the top-level arguments of a call whose "(" is at openIdx.
 * Returns { args: [{ text, start, end }], end } or null if the call doesn't close within maxLen.
 */
function splitArgs(text, openIdx, maxLen = 6000) {
  if (text[openIdx] !== '(') return null;
  const limit = Math.min(text.length, openIdx + maxLen);
  const args = [];
  let depth = 0;
  let start = openIdx + 1;
  const push = (end) => {
    const raw = text.slice(start, end);
    if (raw.trim()) args.push({ text: raw.trim(), start, end });
  };
  for (let i = openIdx; i < limit; i++) {
    const ch = text[i];
    if (ch === '"' || ch === "'") {
      i = skipQuoted(text, i, ch, limit);
      continue;
    }
    if (ch === '`') {
      i = skipTemplate(text, i, limit);
      continue;
    }
    if (ch === '/' && text[i + 1] === '/') {
      const nl = text.indexOf('\n', i);
      i = nl === -1 ? limit : nl;
      continue;
    }
    if (ch === '/' && text[i + 1] === '*') {
      const close = text.indexOf('*/', i + 2);
      i = close === -1 ? limit : close + 1;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') {
      depth++;
      continue;
    }
    if (ch === ')' || ch === ']' || ch === '}') {
      depth--;
      if (depth === 0) {
        push(i);
        return { args, end: i };
      }
      continue;
    }
    if (ch === ',' && depth === 1) {
      push(i);
      start = i + 1;
    }
  }
  return null;
}

/** Value of a plain string literal ('…', "…" or `…` without ${}), else null. */
function literalValue(expr) {
  const s = String(expr).trim();
  const quoted = /^(['"])((?:\\.|(?!\1)[^\\\n])*)\1$/.exec(s);
  if (quoted) return quoted[2];
  const tpl = /^`((?:\\.|[^`\\])*)`$/.exec(s);
  if (tpl && !tpl[1].includes('${')) return tpl[1];
  return null;
}

/** True for template literals with ${…} or expressions joined with + that include a non-literal. */
function isDynamicString(expr) {
  const s = String(expr).trim();
  if (/^`[\s\S]*\$\{[\s\S]*`$/.test(s)) return true;
  if (/(['"`])\s*\+|\+\s*(['"`])/.test(s)) return true;
  return false;
}

/** Text of a balanced { … } object literal starting at index i (or ''). */
function objectAt(text, i, maxLen = 4000) {
  if (text[i] !== '{') return '';
  const end = skipExpression(text, i + 1, Math.min(text.length, i + maxLen));
  return text.slice(i, end + 1);
}

/** Lines are "comments" if they start with //, #, *, /* or <!--. */
function isCommentLine(line) {
  return /^\s*(?:\/\/|#|\*|\/\*|<!--|--)/.test(line);
}

// ── Comment blanking ───────────────────────────────────────────────────────
// Heuristic checks run on a "code view" where comments are replaced with spaces, so
// commented-out code doesn't trigger them. Offsets and line numbers stay identical.

const JS_LIKE = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.vue', '.svelte', '.astro', '.rules', '.java', '.kt', '.cs', '.go', '.rs', '.swift', '.dart', '.php', '.jsonc', '.json5', '.prisma', '.graphql', '.gql']);
const HASH_LIKE = new Set(['.py', '.rb', '.sh', '.bash', '.zsh', '.yaml', '.yml', '.toml', '.tf', '.tfvars', '.hcl', '.ini', '.cfg', '.conf', '.properties', '.ex', '.exs', '.ps1']);
const MARKUP_LIKE = new Set(['.html', '.htm', '.vue', '.svelte', '.astro', '.ejs', '.hbs', '.handlebars', '.xml', '.md', '.mdx']);
const REGEX_PREV = new Set(['', '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '<', '>', '~', '^']);

function blankRange(out, from, to) {
  for (let k = from; k < to; k++) if (out[k] !== '\n') out[k] = ' ';
}

function blankJs(text, out) {
  const n = text.length;
  let prev = '';
  let i = 0;
  while (i < n) {
    const ch = text[i];
    const next = text[i + 1];
    if (ch === '/' && next === '/') {
      const end = text.indexOf('\n', i);
      const stop = end === -1 ? n : end;
      blankRange(out, i, stop);
      i = stop;
      continue;
    }
    if (ch === '/' && next === '*') {
      const end = text.indexOf('*/', i + 2);
      const stop = end === -1 ? n : end + 2;
      blankRange(out, i, stop);
      i = stop;
      continue;
    }
    if (ch === '"' || ch === "'") {
      i = skipQuoted(text, i, ch, n) + 1;
      prev = ch;
      continue;
    }
    if (ch === '`') {
      i = skipTemplate(text, i, n) + 1;
      prev = '`';
      continue;
    }
    if (ch === '/' && REGEX_PREV.has(prev)) {
      let j = i + 1;
      let inClass = false;
      for (; j < n; j++) {
        const c = text[j];
        if (c === '\\') {
          j++;
          continue;
        }
        if (c === '\n') break;
        if (inClass) {
          if (c === ']') inClass = false;
          continue;
        }
        if (c === '[') inClass = true;
        else if (c === '/') break;
      }
      if (j < n && text[j] === '/') {
        blankRange(out, i + 1, j); // regex body: not code
        i = j + 1;
        while (i < n && /[a-z]/i.test(text[i])) i++;
        prev = '/';
        continue;
      }
    }
    if (!/\s/.test(ch)) prev = ch;
    i++;
  }
}

function blankHash(text, out) {
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '\n') {
      quote = null;
      continue;
    }
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === '#' && (i === 0 || /[\s;]/.test(text[i - 1]))) {
      const end = text.indexOf('\n', i);
      const stop = end === -1 ? text.length : end;
      blankRange(out, i, stop);
      i = stop - 1;
    }
  }
}

/** Replace comments with spaces (newlines kept), choosing comment syntax by file type. */
function blankComments(text, ext, name = '') {
  if (!text) return text;
  const out = text.split('');
  if (MARKUP_LIKE.has(ext)) {
    for (const m of text.matchAll(/<!--[\s\S]*?-->/g)) blankRange(out, m.index, m.index + m[0].length);
  }
  if (JS_LIKE.has(ext)) blankJs(MARKUP_LIKE.has(ext) ? out.join('') : text, out);
  else if (HASH_LIKE.has(ext) || /^(?:Dockerfile|Procfile|Makefile|Caddyfile|\.npmrc|\.env.*|\.dev\.vars)/.test(name)) blankHash(text, out);
  else if (ext === '.sql') {
    for (const m of text.matchAll(/--[^\n]*/g)) blankRange(out, m.index, m.index + m[0].length);
    for (const m of text.matchAll(/\/\*[\s\S]*?\*\//g)) blankRange(out, m.index, m.index + m[0].length);
  }
  return out.join('');
}

// ── gitignore-style globs (used for .gitignore fallback and .preflightignore) ──

function globToRegExp(pattern) {
  const dirOnly = pattern.endsWith('/');
  let body = dirOnly ? pattern.slice(0, -1) : pattern;
  const anchored = body.startsWith('/') || body.includes('/');
  if (body.startsWith('/')) body = body.slice(1);
  let re = '';
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === '*') {
      if (body[i + 1] === '*') {
        const atSegmentStart = i === 0 || body[i - 1] === '/';
        const atSegmentEnd = i + 2 === body.length || body[i + 2] === '/';
        if (atSegmentStart && atSegmentEnd) {
          if (i + 2 === body.length) re += '.*';
          else {
            re += '(?:.*/)?';
            i += 2; // also swallow the "/"
            continue;
          }
          i += 1;
          continue;
        }
      }
      re += '[^/]*';
    } else if (ch === '?') re += '[^/]';
    else if (ch === '[') {
      const close = body.indexOf(']', i + 1);
      if (close === -1) re += '\\[';
      else {
        re += `[${body.slice(i + 1, close).replace(/^!/, '^').replace(/\\/g, '\\\\')}]`;
        i = close;
      }
    } else re += escapeRegExp(ch);
  }
  return { re: new RegExp(`^${anchored ? '' : '(?:.*/)?'}${re}$`), dirOnly };
}

/**
 * Build a matcher from gitignore-style lines. Returns (relPath) => boolean, where a pattern
 * matches the path itself or any of its parent directories. The last matching rule wins.
 */
function ignoreMatcher(lines) {
  const rules = [];
  for (const raw of lines) {
    let line = raw.replace(/\r$/, '');
    if (!line.trim() || line.startsWith('#')) continue;
    line = line.replace(/(?<!\\)\s+$/, '');
    let negate = false;
    if (line.startsWith('!')) {
      negate = true;
      line = line.slice(1);
    }
    if (line.startsWith('\\')) line = line.slice(1);
    rules.push({ negate, ...globToRegExp(line) });
  }
  return (relPath) => {
    if (!rules.length) return false;
    const parts = relPath.split('/');
    const candidates = [];
    for (let i = 1; i <= parts.length; i++) candidates.push({ p: parts.slice(0, i).join('/'), isDir: i < parts.length });
    let ignored = false;
    for (const rule of rules) {
      const hit = candidates.some((c) => (!rule.dirOnly || c.isDir) && rule.re.test(c.p));
      if (hit) ignored = !rule.negate;
    }
    return ignored;
  };
}

module.exports = {
  lineStarts,
  lineAt,
  clip,
  entropy,
  uniq,
  escapeRegExp,
  alt,
  skipQuoted,
  skipTemplate,
  skipExpression,
  splitArgs,
  literalValue,
  isDynamicString,
  objectAt,
  isCommentLine,
  blankComments,
  globToRegExp,
  ignoreMatcher,
};
