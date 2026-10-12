'use strict';

/**
 * Server route discovery for the auth, rate-limit, validation, CSRF and webhook checks.
 *
 * Covers Express/Fastify/Hono/Koa-style routers (with cross-file mount prefixes and
 * middleware), Next.js route handlers, pages/api and server actions, SvelteKit +server and
 * form actions, Remix/React Router actions and loaders, NestJS controllers, and Netlify,
 * Vercel, Supabase and Firebase functions. Heuristic (regex + light tokenizing), never a parser.
 */

const path = require('path');
const { splitArgs, literalValue } = require('./util');

const METHODS = 'get|post|put|patch|delete|del|all|options|head';
// <name>.<method>('<path>' — the path literal must start with / or * to count as a route.
const ROUTE_CALL_RE = new RegExp(`\\b([A-Za-z_$][\\w$]*)\\s*\\.\\s*(${METHODS})\\s*\\(\\s*(['"\`])([/*][^'"\`\\n]*)\\3`, 'g');
// const app = express() / express.Router() / Router() / new Hono() / Fastify() / new Router() / new Elysia()
const ROUTER_CREATE_RE = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:express\s*\(\s*\)|express\.Router\s*\(|Router\s*\(|new\s+(?:Hono|Router|KoaRouter|Elysia|OpenAPIHono)\b|(?:Fastify|fastify)\s*\(|createRouter\s*\(|new\s+Koa\s*\()/g;
const FRAMEWORK_IMPORT_RE = /(?:require\(\s*|\bfrom\s+)['"](?:express|fastify|koa|@koa\/router|koa-router|hono|elysia|restify|polka|@hono\/node-server)['"]/;
const DEFAULT_ROUTER_NAMES = ['app', 'router', 'server', 'api', 'fastify', 'r', 'routes', 'route', 'apiRouter', 'v1'];
const IMPORT_RE = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)|\bimport\s+([A-Za-z_$][\w$]*)\s+from\s+['"](\.{1,2}\/[^'"]+)['"]/g;
const NEXT_EXPORT_RE = /\bexport\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|\bexport\s+const\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*=/g;
const NEXT_REEXPORT_RE = /\bexport\s*\{([^}]*)\}/g;
const NEST_CONTROLLER_RE = /@Controller\(\s*(?:['"`]([^'"`]*)['"`])?/;
const NEST_ROUTE_RE = /@(Get|Post|Put|Patch|Delete|All)\(\s*(?:['"`]([^'"`]*)['"`])?\s*\)/g;

const cache = new WeakMap();

function getRoutes(repo) {
  if (cache.has(repo)) return cache.get(repo);
  const result = discover(repo);
  cache.set(repo, result);
  return result;
}

function discover(repo) {
  const routes = [];
  const code = repo.sources({ kinds: ['code'], tests: false, js: true }).filter((f) => !f.rel.endsWith('.d.ts'));
  const mounts = []; // { from, target, prefix, middleware, line }
  const fileMiddleware = new Map(); // rel -> middleware text from .use(<no path>, …)

  for (const f of code) {
    const text = repo.code(f);
    if (!text) continue;
    const side = repo.side(f);
    const rel = f.rel;

    // ── file-system routed frameworks ──
    if (/(?:^|\/)(?:src\/)?app\/(?:.+\/)?route\.[cm]?[jt]s$/.test(rel)) {
      addNextAppRoutes(repo, f, text, routes);
      continue;
    }
    if (/(?:^|\/)(?:src\/)?pages\/api\//.test(rel)) {
      routes.push(fileRoute(repo, f, text, 'ANY', `/${rel.replace(/^.*?pages\//, '').replace(/\.[cm]?[jt]sx?$/, '').replace(/\/index$/, '')}`, 'next-pages-api'));
      continue;
    }
    if (/\+server\.[jt]s$/.test(rel)) {
      addNextAppRoutes(repo, f, text, routes, 'sveltekit');
      continue;
    }
    if (/\+page\.server\.[jt]s$/.test(rel) && /\bexport\s+const\s+actions\b/.test(text)) {
      routes.push(fileRoute(repo, f, text, 'POST', routePathFromDir(rel, 'routes'), 'sveltekit-action', text.search(/\bexport\s+const\s+actions\b/)));
    }
    if (/(?:^|\/)netlify\/(?:edge-)?functions\//.test(rel)) {
      routes.push(fileRoute(repo, f, text, 'ANY', `/.netlify/functions/${path.posix.basename(rel).replace(/\.[cm]?[jt]s$/, '')}`, 'netlify-function'));
      continue;
    }
    if (/(?:^|\/)supabase\/functions\/([^/]+)\/index\.[jt]s$/.test(rel)) {
      const name = /supabase\/functions\/([^/]+)\//.exec(rel)[1];
      routes.push(fileRoute(repo, f, text, 'ANY', `/functions/v1/${name}`, 'supabase-edge-function'));
      continue;
    }
    if (/(?:^|\/)api\//.test(rel) && !/(?:^|\/)src\//.test(rel) && !repo.depsFor(rel).has('next') && /\bexport\s+default\b|module\.exports\s*=|exports\.handler/.test(text) && !FRAMEWORK_IMPORT_RE.test(text)) {
      routes.push(fileRoute(repo, f, text, 'ANY', `/${rel.slice(rel.search(/(?:^|\/)api\//)).replace(/^\//, '').replace(/\.[cm]?[jt]s$/, '')}`, 'vercel-function'));
      continue;
    }
    if (/(?:^|\/)functions\//.test(rel) && /\b(?:onRequest|onCall)\s*\(/.test(text)) {
      for (const m of text.matchAll(/\bexports\.(\w+)\s*=|export\s+const\s+(\w+)\s*=\s*(?:functions\.)?(?:https\.)?(?:onRequest|onCall)/g)) {
        routes.push(fileRoute(repo, f, text, 'ANY', `fn:${m[1] || m[2]}`, 'firebase-function', m.index));
      }
    }
    if (hasUseServer(text)) {
      for (const m of text.matchAll(/\bexport\s+(?:default\s+)?async\s+function\s+(\w+)|\bexport\s+const\s+(\w+)\s*=\s*async\b/g)) {
        routes.push(windowRoute(repo, f, text, m.index, 'POST', `action:${m[1] || m[2]}`, 'server-action'));
      }
    }
    if (/(?:^|\/)app\/routes\//.test(rel) && (repo.depsFor(rel).has('@remix-run/node') || repo.depsFor(rel).has('@remix-run/react') || repo.depsFor(rel).has('@react-router/dev') || repo.depsFor(rel).has('react-router'))) {
      for (const m of text.matchAll(/\bexport\s+(?:async\s+)?function\s+(action|loader)\b|\bexport\s+const\s+(action|loader)\s*=/g)) {
        const kind = m[1] || m[2];
        routes.push(windowRoute(repo, f, text, m.index, kind === 'action' ? 'POST' : 'GET', `/${rel.replace(/^.*?app\/routes\//, '').replace(/\.[cm]?[jt]sx?$/, '')}`, `remix-${kind}`));
      }
    }

    // ── NestJS controllers ──
    if (/@Controller\(/.test(text)) {
      const ctrl = NEST_CONTROLLER_RE.exec(text);
      const prefix = ctrl && ctrl[1] ? `/${ctrl[1].replace(/^\//, '')}` : '';
      const classGuards = /@UseGuards\([^)]*\)\s*(?:@\w+\([^)]*\)\s*)*export\s+class/.test(text) ? '@UseGuards' : '';
      for (const m of text.matchAll(NEST_ROUTE_RE)) {
        const r = windowRoute(repo, f, text, m.index, m[1].toUpperCase(), `${prefix}/${(m[2] || '').replace(/^\//, '')}`.replace(/\/$/, '') || '/', 'nestjs');
        // decorators above the method also count
        r.text = `${text.slice(Math.max(0, m.index - 300), m.index)}\n${r.text}`;
        r.mountMiddleware = classGuards;
        routes.push(r);
      }
    }

    // ── router-style frameworks (Express, Fastify, Hono, Koa, Elysia…) ──
    if (side === 'client') continue;
    const created = [...text.matchAll(ROUTER_CREATE_RE)].map((m) => m[1]);
    const frameworkFile = FRAMEWORK_IMPORT_RE.test(text) || created.length > 0;
    if (!frameworkFile && side !== 'server') continue;
    const names = new Set([...created, ...(frameworkFile ? DEFAULT_ROUTER_NAMES : ['app', 'router'])]);
    const imports = resolveImports(repo, f, text);
    const named = resolveNamedImports(repo, f, text);

    const fileRoutes = [];
    for (const m of text.matchAll(ROUTE_CALL_RE)) {
      if (!names.has(m[1])) continue;
      const method = m[2] === 'del' ? 'DELETE' : m[2].toUpperCase();
      fileRoutes.push({ index: m.index, method, path: m[4] });
    }
    // router.route('/x').get(...).post(...)
    for (const m of text.matchAll(/\b([A-Za-z_$][\w$]*)\s*\.\s*route\s*\(\s*(['"`])([/*][^'"`\n]*)\2\s*\)/g)) {
      if (!names.has(m[1])) continue;
      const tail = text.slice(m.index + m[0].length, m.index + m[0].length + 600);
      for (const c of tail.matchAll(new RegExp(`^\\s*\\.\\s*(${METHODS})\\s*\\(|\\)\\s*\\.\\s*(${METHODS})\\s*\\(`, 'g'))) {
        fileRoutes.push({ index: m.index, method: (c[1] || c[2]).toUpperCase(), path: m[3] });
      }
    }
    // fastify.route({ method: 'POST', url: '/x', ... })
    for (const m of text.matchAll(/\b([A-Za-z_$][\w$]*)\s*\.\s*route\s*\(\s*\{/g)) {
      if (!names.has(m[1])) continue;
      const body = text.slice(m.index, m.index + 1500);
      const method = /method\s*:\s*\[?\s*['"]([A-Z]+)['"]/.exec(body);
      const url = /url\s*:\s*['"]([^'"]+)['"]/.exec(body);
      if (url) fileRoutes.push({ index: m.index, method: method ? method[1] : 'ANY', path: url[1] });
    }
    fileRoutes.sort((a, b) => a.index - b.index);
    for (let i = 0; i < fileRoutes.length; i++) {
      const r = fileRoutes[i];
      const next = fileRoutes[i + 1];
      const end = Math.min(next ? next.index : text.length, r.index + 4000);
      const route = {
        file: f,
        line: repo.lineOf(f, r.index),
        method: r.method,
        path: r.path,
        localPath: r.path,
        framework: 'router',
        start: r.index,
        end,
        text: text.slice(r.index, end),
        mountMiddleware: '',
        handler: null,
      };
      route.handler = resolveHandler(repo, f, text, r.index, imports, named);
      routes.push(route);
    }

    // .use(...) calls: global middleware and router mounts
    for (const m of text.matchAll(/\b([A-Za-z_$][\w$]*)\s*\.\s*(?:use|register|route)\s*\(/g)) {
      if (!names.has(m[1])) continue;
      const call = splitArgs(text, m.index + m[0].length - 1);
      if (!call || !call.args.length) continue;
      const args = call.args.map((a) => a.text);
      let prefix = '';
      let rest = args;
      const first = literalValue(args[0]);
      if (first !== null && /^[/*]/.test(first)) {
        prefix = first.replace(/\/\*$/, '').replace(/\*$/, '');
        rest = args.slice(1);
      } else if (/\{[^}]*prefix\s*:\s*['"]([^'"]+)['"]/.test(args[1] || '')) {
        prefix = /prefix\s*:\s*['"]([^'"]+)['"]/.exec(args[1])[1]; // fastify.register(plugin, { prefix })
      }
      const targets = [];
      for (const a of rest) {
        const id = /^[A-Za-z_$][\w$]*$/.test(a) ? a : null;
        const req = /^require\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)$/.exec(a);
        if (id && imports.has(id)) targets.push(imports.get(id));
        else if (req) {
          const target = resolveModule(repo, f.rel, req[1]);
          if (target) targets.push(target);
        }
      }
      const middleware = rest.filter((a) => !targets.length || !(imports.has(a) || /^require\(/.test(a))).join(', ');
      if (targets.length) {
        for (const t of targets) mounts.push({ from: f.rel, target: t, prefix, middleware, line: repo.lineOf(f, m.index) });
      } else if (!prefix || prefix === '/' || prefix === '*') {
        fileMiddleware.set(f.rel, `${fileMiddleware.get(f.rel) || ''}\n${args.join(', ')}`);
      } else {
        // path-scoped middleware: applies to routes under that prefix in this file and mounted routers
        mounts.push({ from: f.rel, target: null, prefix, middleware: rest.join(', '), line: repo.lineOf(f, m.index) });
      }
    }
  }

  // Apply mounts: prefix + inherited middleware, following parent chains a few levels up.
  const byTarget = new Map();
  for (const m of mounts) if (m.target) byTarget.set(m.target, [...(byTarget.get(m.target) || []), m]);
  const chainFor = (rel, depth = 0) => {
    if (depth > 4) return [{ prefix: '', middleware: '' }];
    const parents = byTarget.get(rel);
    if (!parents) return [{ prefix: '', middleware: fileMiddleware.get(rel) || '' }];
    const out = [];
    for (const p of parents) {
      for (const up of chainFor(p.from, depth + 1)) {
        const scoped = mounts.filter((x) => !x.target && x.from === p.from && (`${up.prefix}${p.prefix}`.startsWith(x.prefix) || p.prefix.startsWith(x.prefix)));
        out.push({
          prefix: `${up.prefix}${p.prefix}`,
          middleware: [up.middleware, p.middleware, fileMiddleware.get(rel) || '', ...scoped.map((x) => x.middleware)].filter(Boolean).join('\n'),
        });
      }
    }
    return out;
  };
  for (const r of routes) {
    if (r.framework !== 'router') continue;
    const chain = chainFor(r.file.rel);
    const c = chain[0];
    r.path = joinPath(c.prefix, r.localPath);
    const scoped = mounts.filter((x) => !x.target && x.from === r.file.rel && r.localPath.startsWith(x.prefix));
    r.mountMiddleware = [c.middleware, ...scoped.map((x) => x.middleware)].filter(Boolean).join('\n');
    r.mountedFrom = byTarget.has(r.file.rel) ? byTarget.get(r.file.rel)[0] : null;
  }

  return { routes, mounts, fileMiddleware, nextMiddleware: findNextMiddleware(repo) };
}

/**
 * For `app.post('/x', mw, controller.create)` find the body of controller.create (in this file
 * or an imported module), so checks can look inside handlers defined elsewhere.
 */
function resolveHandler(repo, f, text, callIndex, imports, named = new Map()) {
  const open = text.indexOf('(', callIndex);
  const call = splitArgs(text, open);
  if (!call || call.args.length < 2) return null;
  const last = call.args[call.args.length - 1].text;
  const ref = /^([A-Za-z_$][\w$]*)(?:\.([A-Za-z_$][\w$]*))?$/.exec(last);
  if (!ref) return null;
  let file = f;
  let name = ref[1];
  if (ref[2]) {
    const target = imports.get(ref[1]);
    if (!target) return null;
    file = repo.get(target);
    name = ref[2];
  } else if (named.has(ref[1])) {
    file = repo.get(named.get(ref[1]).target);
    name = named.get(ref[1]).name;
  } else if (imports.has(ref[1])) {
    file = repo.get(imports.get(ref[1]));
    name = null; // default export of the module is the handler
  }
  if (!file) return null;
  const body = repo.code(file) || '';
  let start = -1;
  if (name) {
    const def = new RegExp(`(?:async\\s+)?function\\s+${name.replace(/[$]/g, '\\$')}\\s*\\(|\\b(?:const|let|var)\\s+${name.replace(/[$]/g, '\\$')}\\s*=\\s*(?:async\\s*)?(?:function\\b|\\()|\\b${name.replace(/[$]/g, '\\$')}\\s*:\\s*(?:async\\s*)?(?:function\\b|\\()|\\b(?:async\\s+)?${name.replace(/[$]/g, '\\$')}\\s*\\([^)]*\\)\\s*\\{`).exec(body);
    if (!def) return null;
    start = def.index;
    if (file === f && start >= callIndex && start < callIndex + 50) return null; // the route call itself
  } else {
    const def = /\bmodule\.exports\s*=\s*(?:async\s*)?(?:function\b|\()|\bexport\s+default\s+(?:async\s+)?(?:function\b|\()/.exec(body);
    if (!def) return null;
    start = def.index;
  }
  const rest = body.slice(start + 10);
  const stop = rest.search(/\n(?:async\s+)?function\s|\n(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?(?:function\b|\()|\nmodule\.exports|\nexport\s/);
  const end = stop === -1 ? body.length : start + 10 + stop;
  return { file, start, end, text: body.slice(start, Math.min(end, start + 6000)) };
}

/** Text segments of a route to scan: the route call itself, plus the resolved handler body. */
function segments(r) {
  const out = [{ file: r.file, start: r.start, text: r.text }];
  if (r.handler && !(r.handler.file === r.file && r.handler.start >= r.start && r.handler.start < r.end)) out.push({ file: r.handler.file, start: r.handler.start, text: r.handler.text });
  return out;
}

/** Route call + handler body as one string (for presence tests, not for line numbers). */
function routeBody(r) {
  return segments(r)
    .map((s) => s.text)
    .join('\n');
}

function joinPath(prefix, p) {
  if (!prefix) return p;
  return `${prefix.replace(/\/$/, '')}/${String(p).replace(/^\//, '')}`.replace(/\/$/, '') || '/';
}

function hasUseServer(text) {
  const head = text.slice(0, 2000).replace(/^(?:\s*(?:\/\/[^\n]*\n|\/\*[\s\S]*?\*\/))*/, '');
  return /^\s*['"]use server['"]/.test(head);
}

function routePathFromDir(rel, marker) {
  const idx = rel.indexOf(`${marker}/`);
  const dir = path.posix.dirname(idx === -1 ? rel : rel.slice(idx + marker.length));
  return (
    `/${dir}`
      .replace(/\/\([^/]+\)/g, '') // route groups
      .replace(/\[\.\.\.[^\]]+\]/g, '*')
      .replace(/\[([^\]]+)\]/g, ':$1')
      .replace(/\/+/g, '/')
      .replace(/\/\.$/, '')
      .replace(/(.)\/$/, '$1') || '/'
  );
}

function addNextAppRoutes(repo, f, text, routes, framework = 'next-app') {
  const marker = framework === 'sveltekit' ? 'routes' : 'app';
  const routePath = routePathFromDir(f.rel, marker);
  const exports = [...text.matchAll(NEXT_EXPORT_RE)].map((m) => ({ index: m.index, method: m[1] || m[2] }));
  for (const m of text.matchAll(NEXT_REEXPORT_RE)) {
    for (const part of m[1].matchAll(/\bas\s+(GET|POST|PUT|PATCH|DELETE)\b/g)) exports.push({ index: m.index, method: part[1], whole: true });
  }
  exports.sort((a, b) => a.index - b.index);
  exports.forEach((e, i) => {
    if (e.whole) routes.push(fileRoute(repo, f, text, e.method, routePath, framework, e.index));
    else {
      const next = exports[i + 1];
      const end = next && !next.whole ? next.index : text.length;
      routes.push({ file: f, line: repo.lineOf(f, e.index), method: e.method, path: routePath, framework, start: e.index, end, text: text.slice(e.index, end), mountMiddleware: '' });
    }
  });
}

/** A route whose handler is the whole file (pages/api, functions). */
function fileRoute(repo, f, text, method, routePath, framework, index = null) {
  const at = index === null ? firstHandlerIndex(text) : index;
  return { file: f, line: repo.lineOf(f, at), method, path: routePath, framework, start: 0, end: text.length, text, mountMiddleware: '' };
}

/** A route whose handler starts at `index` and runs until the next top-level export. */
function windowRoute(repo, f, text, index, method, routePath, framework) {
  const nextExport = text.slice(index + 10).search(/\n\s*export\s/);
  const end = nextExport === -1 ? text.length : index + 10 + nextExport;
  return { file: f, line: repo.lineOf(f, index), method, path: routePath, framework, start: index, end, text: text.slice(index, end), mountMiddleware: '' };
}

function firstHandlerIndex(text) {
  const m = /\bexport\s+default\b|\bmodule\.exports\s*=|\bexports\.handler\s*=|\bexport\s+(?:const|async\s+function|function)\s+handler\b|\bDeno\.serve\s*\(|\bserve\s*\(/.exec(text);
  return m ? m.index : 0;
}

function resolveImports(repo, f, text) {
  const map = new Map();
  for (const m of text.matchAll(IMPORT_RE)) {
    const name = m[1] || m[3];
    const spec = m[2] || m[4];
    const target = resolveModule(repo, f.rel, spec);
    if (target) map.set(name, target);
  }
  return map;
}

/** Named imports: `import { a, b as c } from './x'` and `const { a } = require('./x')` → local → { target, name }. */
function resolveNamedImports(repo, f, text) {
  const map = new Map();
  const re = /\bimport\s*\{([^}]*)\}\s*from\s*['"](\.{1,2}\/[^'"]+)['"]|\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)/g;
  for (const m of text.matchAll(re)) {
    const target = resolveModule(repo, f.rel, m[2] || m[4]);
    if (!target) continue;
    for (const part of (m[1] || m[3]).split(',')) {
      const bits = part.trim().split(/\s+as\s+|\s*:\s*/);
      const original = bits[0] && bits[0].trim();
      const local = (bits[1] || bits[0] || '').trim();
      if (/^[A-Za-z_$][\w$]*$/.test(local) && /^[A-Za-z_$][\w$]*$/.test(original)) map.set(local, { target, name: original });
    }
  }
  return map;
}

function resolveModule(repo, fromRel, spec) {
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromRel), spec));
  const candidates = [base, ...['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'].map((e) => base + e), ...['index.js', 'index.ts', 'index.mjs'].map((i) => `${base}/${i}`)];
  for (const c of candidates) if (repo.get(c)) return c;
  return null;
}

// ── Next.js middleware.ts ──────────────────────────────────────────────────

const NEXT_MW_AUTH_RE = /\b(?:clerkMiddleware|authMiddleware|withAuth|auth\s*\(|NextAuth|getToken\s*\(|updateSession\s*\(|createServerClient\s*\(|supabase\.auth\.getUser|getSession\s*\(|verifyToken|jwtVerify|kindeAuth|withMiddlewareAuthRequired|authkitMiddleware|betterFetch|getSessionCookie)/;

function findNextMiddleware(repo) {
  const f = repo.files.find((x) => /^(?:(?:[^/]+\/)*?)(?:src\/)?middleware\.[jt]s$/.test(x.rel) && !x.build && repo.depsFor(x.rel).has('next'));
  if (!f) return null;
  const text = repo.code(f) || '';
  const auth = NEXT_MW_AUTH_RE.test(text) || /export\s*\{\s*default\s*\}\s*from\s*['"]next-auth\/middleware['"]/.test(text);
  const matchers = [];
  const cfg = /export\s+const\s+config\s*=\s*\{([\s\S]*?)\n\}/.exec(text);
  if (cfg) for (const m of cfg[1].matchAll(/['"`](\/[^'"`]*)['"`]/g)) matchers.push(m[1]);
  return {
    file: f,
    auth,
    matchers,
    /** Does this middleware run for the given request path? */
    covers(routePath) {
      if (!matchers.length) return true;
      return matchers.some((m) => {
        if (/\(\?!/.test(m)) return true; // negative-lookahead "everything except static" matcher
        const prefix = m.replace(/[:(].*$/, '').replace(/\/$/, '');
        return !prefix || routePath === prefix || routePath.startsWith(`${prefix}/`);
      });
    },
  };
}

module.exports = { getRoutes, joinPath, segments, routeBody };
