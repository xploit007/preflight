'use strict';

/**
 * Injection heuristics: APP-01 XSS, APP-02 SQL injection, APP-03 NoSQL injection, APP-05 SSRF,
 * APP-06 path traversal, APP-08 command injection, APP-09 code injection (eval),
 * APP-10 insecure deserialization, APP-14 open redirects.
 *
 * Every finding is a warn: the /scan agent reads each location and confirms or dismisses it.
 */

const { loadRepo } = require('../lib/repo');
const { SANITIZER_RE } = require('../lib/primitives');
const { taintedNames, isTainted, CLIENT_SOURCE_RE } = require('../lib/taint');
const { pass, warn, na, ev } = require('../lib/result');
const { splitArgs, literalValue, isDynamicString } = require('../lib/util');

const IDS = ['APP-01', 'APP-02', 'APP-03', 'APP-05', 'APP-06', 'APP-08', 'APP-09', 'APP-10', 'APP-14'];

const SQL_KEYWORD_RE = /^\s*[`'"]?\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH|CREATE|DROP|ALTER|REPLACE|MERGE|CALL|EXEC|TRUNCATE|UPSERT)\b/i;
// Calls whose first argument is SQL text. Tagged templates (sql`…`, $queryRaw`…`) never match: they have no "(".
const SQL_CALL_RE = /(?:\.|\b)(?:query|execute|exec|raw|unsafe|\$queryRawUnsafe|\$executeRawUnsafe|queryRawUnsafe|executeRawUnsafe|whereRaw|orderByRaw|havingRaw|joinRaw|selectRaw|fromRaw|prepare|run|all|get)\s*\(/g;

async function run(root, opts = {}) {
  const repo = loadRepo(root, opts);
  const all = repo.sources({ kinds: ['code', 'markup'], tests: false }).filter((f) => !/\.min\.js$/.test(f.name) && !/(?:^|\/)(?:vendor|lib\/vendor|public\/vendor)\//.test(f.rel));
  const server = all.filter((f) => f.kind === 'code' && repo.side(f) !== 'client' && !repo.isTooling(f));
  const ctx = { repo, all, server, taint: new Map() };
  ctx.tainted = (f) => {
    if (!ctx.taint.has(f.rel)) ctx.taint.set(f.rel, taintedNames(repo.code(f) || ''));
    return ctx.taint.get(f.rel);
  };
  return [xss(ctx), sqli(ctx), nosqli(ctx), ssrf(ctx), pathTraversal(ctx), commandInjection(ctx), codeInjection(ctx), deserialization(ctx), openRedirect(ctx)];
}

function collector(repo) {
  const hits = [];
  const seen = new Set();
  return {
    hits,
    add(f, index, note) {
      const line = repo.lineOf(f, index);
      const key = `${f.rel}:${line}:${note}`;
      if (seen.has(key) || repo.suppressed(f, line)) return;
      seen.add(key);
      hits.push(ev(f.rel, line, note, repo.snippet(f, line)));
    },
  };
}

const result = (id, hits, okText) => (hits.length ? warn(id, hits) : pass(id, [okText]));
const sanitizedVar = (text, name) => new RegExp(`\\b${name.replace(/[$]/g, '\\$')}\\s*=\\s*[^;\\n]*${SANITIZER_RE.source}`).test(text);

// ── APP-01 ─────────────────────────────────────────────────────────────────

function xss({ repo, all, tainted }) {
  const c = collector(repo);
  for (const f of all) {
    const text = repo.code(f) || '';
    const dynamic = (expr) => {
      const e = expr.trim();
      if (literalValue(e) !== null || /^['"`]\s*['"`]$/.test(e)) return false;
      if (SANITIZER_RE.test(e)) return false;
      if (/^[A-Za-z_$][\w$]*$/.test(e) && sanitizedVar(text, e)) return false;
      return true;
    };
    for (const m of text.matchAll(/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([\s\S]*?)\}\s*\}/g)) if (dynamic(m[1])) c.add(f, m.index, `dangerouslySetInnerHTML renders ${m[1].trim().slice(0, 40)} without a sanitizer`);
    for (const m of text.matchAll(/\.(innerHTML|outerHTML)\s*\+?=\s*([^;\n]+)/g)) if (dynamic(m[2])) c.add(f, m.index, `${m[1]} is assigned dynamic HTML`);
    for (const m of text.matchAll(/\.insertAdjacentHTML\(\s*[^,]+,\s*([^)]+)\)/g)) if (dynamic(m[1])) c.add(f, m.index, 'insertAdjacentHTML with dynamic HTML');
    for (const m of text.matchAll(/\bdocument\.write(?:ln)?\(\s*([^)]+)\)/g)) if (dynamic(m[1])) c.add(f, m.index, 'document.write with dynamic content');
    for (const m of text.matchAll(/\bv-html\s*=\s*["']([^"']+)["']/g)) if (!SANITIZER_RE.test(m[1])) c.add(f, m.index, `v-html renders ${m[1]} as raw HTML`);
    for (const m of text.matchAll(/\{@html\s+([^}]+)\}/g)) if (!SANITIZER_RE.test(m[1])) c.add(f, m.index, `{@html} renders ${m[1].trim()} as raw HTML`);
    for (const m of text.matchAll(/\bbypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)\(/g)) c.add(f, m.index, 'Angular sanitization is bypassed');
    for (const m of text.matchAll(/\$\([^)]*\)\.(?:html|append|prepend|after|before|replaceWith)\(\s*([^)]+)\)/g)) if (dynamic(m[1]) && !/^\s*['"`]/.test(m[1])) c.add(f, m.index, 'jQuery inserts dynamic HTML');
    if (/\.(?:ejs|html?)$/.test(f.rel)) for (const m of text.matchAll(/<%-\s*(?!\s*include\b)([^%]+)%>/g)) c.add(f, m.index, `EJS outputs ${m[1].trim()} unescaped (<%-)`);
    if (/\.(?:hbs|handlebars|html?)$/.test(f.rel)) for (const m of text.matchAll(/\{\{\{\s*([^}]+)\}\}\}/g)) c.add(f, m.index, `Handlebars outputs ${m[1].trim()} unescaped ({{{ }}})`);
    if (/\.pug$/.test(f.rel)) for (const m of text.matchAll(/!\{([^}]+)\}|^\s*[\w.#-]+!=\s*\S/gm)) c.add(f, m.index, 'Pug outputs unescaped content');
    if (f.kind === 'code' && repo.side(f) !== 'client') {
      const names = tainted(f);
      for (const m of text.matchAll(/\bres\.send\(\s*(`[^`]*`)/g)) if (/<[a-z]/i.test(m[1]) && isTainted(m[1], names)) c.add(f, m.index, 'request data is interpolated into an HTML response');
    }
  }
  return result('APP-01', c.hits, 'No unsanitized HTML sinks (dangerouslySetInnerHTML, innerHTML, v-html, {@html}, unescaped templates) with dynamic values found.');
}

// ── APP-02 ─────────────────────────────────────────────────────────────────

function sqli({ repo, server, tainted }) {
  const c = collector(repo);
  for (const f of server) {
    const text = repo.code(f) || '';
    const names = tainted(f);
    const defs = new Map();
    for (const m of text.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;]+);?/g)) defs.set(m[1], { index: m.index, rhs: m[2] });
    for (const m of text.matchAll(SQL_CALL_RE)) {
      const call = splitArgs(text, m.index + m[0].length - 1);
      if (!call || !call.args.length) continue;
      let sql = call.args[0].text;
      let at = m.index;
      if (/^[A-Za-z_$][\w$]*$/.test(sql) && defs.has(sql)) {
        at = defs.get(sql).index;
        sql = defs.get(sql).rhs.trim();
      }
      if (!SQL_KEYWORD_RE.test(sql.replace(/^\(+/, ''))) continue;
      if (!isDynamicString(sql)) continue;
      const userData = isTainted(sql, names);
      c.add(f, at, `SQL built with ${sql.startsWith('`') ? 'a template literal' : 'string concatenation'}${userData ? ' from request data' : ''}`);
    }
    for (const m of text.matchAll(/\.(?:or|filter|textSearch|match)\(\s*`[^`]*\$\{([^}]+)\}/g)) if (isTainted(m[1], names)) c.add(f, m.index, 'PostgREST filter string interpolates request data (filter injection)');
  }
  for (const f of repo.sources({ kinds: ['code'], tests: false }).filter((x) => x.ext === '.py')) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/\.execute\(\s*(?:f["']|["'][^"'\n]*["']\s*%|["'][^"'\n]*["']\s*\.format\(|["'][^"'\n]*["']\s*\+)/g)) c.add(f, m.index, 'SQL built with an f-string, % or .format()');
  }
  return result('APP-02', c.hits, 'No SQL built from template literals or string concatenation found; queries use parameters or tagged templates.');
}

// ── APP-03 ─────────────────────────────────────────────────────────────────

function nosqli({ repo, server, tainted }) {
  if (!repo.hasDep('mongodb') && !repo.hasDep('mongoose') && !repo.pythonDeps.has('pymongo')) return na('APP-03', 'MongoDB is not used');
  const c = collector(repo);
  const ops = 'find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate|exists|replaceOne';
  for (const f of server) {
    const text = repo.code(f) || '';
    const sanitized = /express-mongo-sanitize|mongo-sanitize|sanitizeFilter|\$eq\s*:/.test(text);
    const names = tainted(f);
    for (const m of text.matchAll(new RegExp(`\\.(?:${ops})\\(\\s*(req\\.(?:body|query)|body|query|filter|where)\\s*[,)]`, 'g'))) {
      if (m[1].startsWith('req') || names.has(m[1])) c.add(f, m.index, `the whole request object (${m[1]}) is used as a MongoDB filter`);
    }
    if (!sanitized) {
      for (const m of text.matchAll(new RegExp(`\\.(?:${ops})\\(\\s*\\{([^}]*)\\}`, 'g'))) {
        if (/:\s*req\.(?:body|query)\.\w+/.test(m[1]) || [...names].some((n) => new RegExp(`:\\s*${n}\\b`).test(m[1]))) c.add(f, m.index, 'request values go into a MongoDB filter without sanitizing operators like {"$ne": null}');
      }
    }
    for (const m of text.matchAll(/['"]?\$where['"]?\s*:/g)) c.add(f, m.index, '$where runs JavaScript inside MongoDB');
  }
  return result('APP-03', c.hits, 'No MongoDB filters built from raw request objects and no $where usage found.');
}

// ── APP-05 ─────────────────────────────────────────────────────────────────

const FETCH_RE = /(?<![\w.$])(?:fetch|axios(?:\.(?:get|post|put|patch|delete|head|request))?|got(?:\.(?:get|post|stream))?|ky(?:\.(?:get|post))?|needle|superagent\.(?:get|post)|request(?:\.(?:get|post))?|https?\.(?:get|request)|undici\.request|\$fetch|ofetch)\s*\(/g;

function ssrf({ repo, server, tainted }) {
  const c = collector(repo);
  for (const f of server) {
    const text = repo.code(f) || '';
    const names = tainted(f);
    if (!names.size && !/req\.|request\.|searchParams|params\./.test(text)) continue;
    for (const m of text.matchAll(FETCH_RE)) {
      const call = splitArgs(text, m.index + m[0].length - 1);
      if (!call || !call.args.length) continue;
      let url = call.args[0].text;
      if (url.startsWith('{')) url = (/\burl\s*:\s*([^,}]+)/.exec(url) || [])[1] || '';
      if (!url || literalValue(url) !== null) continue;
      if (url.startsWith('`')) {
        const prefix = url.slice(1, url.indexOf('${') === -1 ? undefined : url.indexOf('${'));
        if (/^[a-z][a-z0-9+.-]*:\/\/[^/$]+\//i.test(prefix) || /^\//.test(prefix)) continue; // host pinned (or relative)
      }
      if (/^[A-Z_][A-Z0-9_]*\s*\+/.test(url) || /^process\.env\.\w+\s*\+/.test(url)) continue; // BASE_URL + path
      if (isTainted(url, names)) c.add(f, m.index, `server-side request to a URL from request data (${url.slice(0, 40)})`);
    }
  }
  return result('APP-05', c.hits, 'No server-side fetches to request-controlled URLs found.');
}

// ── APP-06 ─────────────────────────────────────────────────────────────────

function pathTraversal({ repo, server, tainted }) {
  const c = collector(repo);
  for (const f of server) {
    const text = repo.code(f) || '';
    const usesFs = /require\(\s*['"](?:node:)?fs(?:\/promises)?['"]\s*\)|from\s+['"](?:node:)?fs(?:\/promises)?['"]|\bres\.(?:sendFile|download)\(/.test(text);
    if (!usesFs) continue;
    const names = tainted(f);
    const guarded = /\.startsWith\(\s*(?:path\.resolve|base|root|dir|uploadsDir|UPLOAD|ROOT|BASE)|sanitize-filename|path\.basename\(|\bbasename\(/i.test(text);
    const sinks = /\b(?:(?:fs|fsp|fsPromises|promises)\.)?(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|unlinkSync|rm|rmSync|readdir|readdirSync|copyFile|copyFileSync|rename|renameSync|access|open)\s*\(|\bres\.(?:sendFile|download|render)\s*\(|\bpath\.(?:join|resolve)\s*\(/g;
    for (const m of text.matchAll(sinks)) {
      if (/^(?:readFile|writeFile|unlink|rm|open|access|rename|readdir)\s*\(/.test(m[0]) && !/fs\/promises|\{[^}]*\b(?:readFile|writeFile|unlink|rm)\b[^}]*\}\s*=\s*require\(\s*['"](?:node:)?fs/.test(text)) continue;
      const call = splitArgs(text, m.index + m[0].length - 1);
      if (!call || !call.args.length) continue;
      const args = call.args.map((a) => a.text).join(', ');
      if (!isTainted(args, names) || guarded) continue;
      c.add(f, m.index, `${m[0].replace(/\s*\($/, '')}() builds a path from request data`);
    }
  }
  return result('APP-06', c.hits, 'No filesystem paths built from request data found (or a basename/startsWith guard is in place).');
}

// ── APP-08 ─────────────────────────────────────────────────────────────────

function commandInjection({ repo, server, tainted }) {
  const c = collector(repo);
  for (const f of server) {
    const text = repo.code(f) || '';
    if (!/child_process|shelljs|execa|['"]zx['"]/.test(text)) continue;
    const names = tainted(f);
    const bareExec = /\{[^}]*\b(?:exec|execSync)\b[^}]*\}\s*=\s*require\(\s*['"](?:node:)?child_process['"]\s*\)|import\s*\{[^}]*\b(?:exec|execSync)\b[^}]*\}\s*from\s*['"](?:node:)?child_process['"]/.test(text);
    const re = bareExec ? /(?<![\w.$])(?:exec|execSync)\s*\(|\b(?:child_process|cp|childProcess|shell)\.(?:exec|execSync)\s*\(/g : /\b(?:child_process|cp|childProcess|shell)\.(?:exec|execSync)\s*\(/g;
    for (const m of text.matchAll(re)) {
      const call = splitArgs(text, m.index + m[0].length - 1);
      if (!call || !call.args.length) continue;
      const cmd = call.args[0].text;
      if (literalValue(cmd) !== null) continue;
      const user = isTainted(cmd, names);
      if (isDynamicString(cmd) || user) c.add(f, m.index, `shell command built from ${user ? 'request data' : 'variables'}`);
    }
    for (const m of text.matchAll(/(?<![\w.$])(?:spawn|spawnSync|execFile|execFileSync)\s*\(/g)) {
      const call = splitArgs(text, m.index + m[0].length - 1);
      if (!call) continue;
      const args = call.args.map((a) => a.text).join(', ');
      if (/shell\s*:\s*true/.test(args) && isTainted(args, names)) c.add(f, m.index, 'spawn/execFile with shell: true and request data');
    }
  }
  for (const f of repo.sources({ kinds: ['code'], tests: false }).filter((x) => x.ext === '.py' && !repo.isTooling(x))) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/\bos\.system\(\s*(?!['"][^'"\n]*['"]\s*\))|\bsubprocess\.\w+\([^)\n]*shell\s*=\s*True/g)) c.add(f, m.index, 'shell command with a non-literal argument (Python)');
  }
  return result('APP-08', c.hits, 'No shell commands built from variables or request data found.');
}

// ── APP-09 ─────────────────────────────────────────────────────────────────

function codeInjection({ repo, all, tainted }) {
  const c = collector(repo);
  for (const f of all.filter((x) => x.kind === 'code')) {
    const text = repo.code(f) || '';
    const names = repo.side(f) === 'client' ? new Set() : tainted(f);
    const label = (expr) => (isTainted(expr, names) ? 'request data' : 'a non-literal value');
    for (const m of text.matchAll(/(?<![\w.$])eval\s*\(/g)) {
      const call = splitArgs(text, m.index + m[0].length - 1);
      if (call && call.args[0] && literalValue(call.args[0].text) === null) c.add(f, m.index, `eval() runs ${label(call.args[0].text)}`);
    }
    for (const m of text.matchAll(/\bnew\s+Function\s*\(/g)) {
      const call = splitArgs(text, m.index + m[0].length - 1);
      if (call && call.args.some((a) => literalValue(a.text) === null)) c.add(f, m.index, 'new Function() compiles a non-literal string');
    }
    for (const m of text.matchAll(/\bvm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(|\bnew\s+vm\.Script\s*\(/g)) {
      const call = splitArgs(text, m.index + m[0].lastIndexOf('('));
      if (call && call.args[0] && literalValue(call.args[0].text) === null) c.add(f, m.index, `node:vm runs ${label(call.args[0].text)} (vm is not a security sandbox)`);
    }
    for (const m of text.matchAll(/\bset(?:Timeout|Interval)\s*\(\s*(['"`]|[A-Za-z_$][\w$]*\s*\+)/g)) c.add(f, m.index, 'setTimeout/setInterval with a string argument is eval');
    for (const m of text.matchAll(/\b(?:require|import)\s*\(\s*(?:req|request|params|body|query)\b/g)) c.add(f, m.index, 'module loaded from request data');
    for (const m of text.matchAll(/require\(\s*['"]vm2['"]\s*\)|from\s+['"]vm2['"]/g)) c.add(f, m.index, 'vm2 is deprecated and has known sandbox escapes');
  }
  return result('APP-09', c.hits, 'No eval, new Function, vm.run* or string timers on non-literal input found.');
}

// ── APP-10 ─────────────────────────────────────────────────────────────────

function deserialization({ repo, server, tainted }) {
  const c = collector(repo);
  const yamlRange = (repo.packages.map((p) => p.versions['js-yaml']).find(Boolean) || {}).range || '';
  const oldYaml = /^[~^]?\s*[0-3]\./.test(yamlRange.replace(/^[<>=\s]+/, ''));
  for (const f of server) {
    const text = repo.code(f) || '';
    const names = tainted(f);
    for (const m of text.matchAll(/require\(\s*['"]node-serialize['"]\s*\)|from\s+['"]node-serialize['"]|\.unserialize\s*\(/g)) c.add(f, m.index, 'node-serialize can execute code embedded in serialized data');
    if (/js-yaml/.test(text)) {
      for (const m of text.matchAll(/\b(?:yaml|jsyaml|YAML)\.load\s*\(([^)]*)\)/g)) {
        if (oldYaml || /DEFAULT_FULL_SCHEMA|FULL_SCHEMA/.test(m[1])) c.add(f, m.index, `js-yaml load() ${oldYaml ? `with js-yaml ${yamlRange} (< 4 is unsafe by default)` : 'with the full (unsafe) schema'}`);
      }
    }
    for (const m of text.matchAll(/\bfuncster\b|\bcryo\.parse\(/gi)) c.add(f, m.index, 'deserializer that can revive functions');
    for (const m of text.matchAll(/\b(?:_|lodash)\.(?:merge|mergeWith|defaultsDeep|set|setWith)\(\s*[^,]+,\s*([^)]+)\)|\bdeepmerge\(\s*[^,]+,\s*([^)]+)\)|\$\.extend\(\s*true\s*,([^)]+)\)/g)) {
      if (isTainted(m[1] || m[2] || m[3] || '', names)) c.add(f, m.index, 'deep merge of request data (prototype pollution)');
    }
  }
  const other = repo.sources({ kinds: ['code'], tests: false }).filter((f) => /\.(?:py|php|rb|java|kt|cs)$/.test(f.rel));
  for (const f of other) {
    const text = repo.code(f) || '';
    const rules = {
      '.py': [/\b(?:c?[Pp]ickle|marshal|dill|shelve)\.loads?\(|\bjsonpickle\.decode\(|\byaml\.unsafe_load\(|\byaml\.load\((?![^)\n]*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe)Loader)[^)\n]*\)/g, 'unsafe deserializer (pickle/marshal/yaml.load without SafeLoader)'],
      '.php': [/\bunserialize\s*\(/g, 'PHP unserialize() on data that may be user-controlled'],
      '.rb': [/\bMarshal\.load\(|\bYAML\.unsafe_load\(/g, 'Ruby Marshal.load / YAML.unsafe_load'],
      '.java': [/new\s+ObjectInputStream\(|\.readObject\(\)/g, 'Java native deserialization (ObjectInputStream)'],
      '.kt': [/ObjectInputStream\(/g, 'Java native deserialization (ObjectInputStream)'],
      '.cs': [/\bBinaryFormatter\b|\bNetDataContractSerializer\b|\bLosFormatter\b/g, '.NET BinaryFormatter-style deserialization'],
    }[f.ext];
    if (!rules) continue;
    for (const m of text.matchAll(rules[0])) c.add(f, m.index, rules[1]);
  }
  return result('APP-10', c.hits, 'No unsafe deserializers (node-serialize, js-yaml < 4, pickle, unserialize, ObjectInputStream…) or deep merges of request data found.');
}

// ── APP-14 ─────────────────────────────────────────────────────────────────

const REDIRECT_GUARD_RE = /startsWith\(\s*['"`]\/['"`]\s*\)|isSafeRedirect|safeRedirect|isValidRedirect|allowedRedirects|ALLOWED_REDIRECTS|allowedHosts|isRelativeUrl|isLocalUrl|new URL\([^)]*\)\.(?:origin|host(?:name)?)\s*[!=]==/;

function openRedirect({ repo, server, all, tainted }) {
  const c = collector(repo);
  const near = (text, index) => text.slice(Math.max(0, index - 600), index + 200);
  for (const f of server) {
    const text = repo.code(f) || '';
    const names = tainted(f);
    const sinks = /\bres\.redirect\(\s*(?:\d{3}\s*,\s*)?([^)]+)\)|\b(?:redirect|permanentRedirect)\(\s*(?:\d{3}\s*,\s*)?([^)]+)\)|\b(?:NextResponse|Response)\.redirect\(\s*(?:new URL\(\s*)?([^,)]+)/g;
    for (const m of text.matchAll(sinks)) {
      const target = (m[1] || m[2] || m[3] || '').trim();
      if (!target || literalValue(target) !== null || /^['"`]\//.test(target)) continue;
      if (!isTainted(target, names) || REDIRECT_GUARD_RE.test(near(text, m.index))) continue;
      c.add(f, m.index, `redirect target comes from request data (${target.slice(0, 40)})`);
    }
  }
  for (const f of all.filter((x) => x.kind === 'code' && repo.side(x) === 'client')) {
    const text = repo.code(f) || '';
    const names = taintedNames(text, CLIENT_SOURCE_RE);
    for (const m of text.matchAll(/\b(?:window\.)?location(?:\.href)?\s*=\s*([^;\n]+)|\blocation\.(?:assign|replace)\(\s*([^)]+)\)/g)) {
      const target = (m[1] || m[2] || '').trim();
      if (!target || literalValue(target) !== null || /^['"`]\//.test(target)) continue;
      if (!isTainted(target, names, CLIENT_SOURCE_RE) || REDIRECT_GUARD_RE.test(near(text, m.index))) continue;
      c.add(f, m.index, 'browser navigates to a URL taken from the query string or hash');
    }
  }
  return result('APP-14', c.hits, 'No redirects to request-controlled URLs found.');
}

module.exports = { name: 'injection', ids: IDS, run };
