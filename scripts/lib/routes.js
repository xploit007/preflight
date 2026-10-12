'use strict';

/**
 * Server route discovery for the auth, rate-limit, validation, CSRF and webhook checks.
 *
 * Covers Express/Fastify/Hono/Koa-style routers (with cross-file mount prefixes and
 * middleware, including routers mounted from arrays), Next.js route handlers, pages/api and
 * server actions, SvelteKit +server and form actions, Remix/React Router actions and loaders,
 * NestJS controllers, and Netlify, Vercel, Supabase and Firebase functions.
 *
 * Each route carries text segments to inspect: the route itself, the handler it references
 * (possibly in another file), and one hop of helpers it calls or wraps. Heuristic (regex +
 * light tokenizing), never a parser.
 */

const path = require('path');
const { splitArgs, literalValue, escapeRegExp } = require('./util');

const METHODS = 'get|post|put|patch|delete|del|all|options|head';
// <name>.<method>('<path>' — the path literal must start with / or * to count as a route.
const ROUTE_CALL_RE = new RegExp(`\\b([A-Za-z_$][\\w$]*)\\s*\\.\\s*(${METHODS})\\s*\\(\\s*(['"\`])([/*][^'"\`\\n]*)\\3`, 'g');
// const app = express() / express.Router() / Router() / new Hono() / Fastify() / new Router() / new Elysia()
const ROUTER_CREATE_RE = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:express\s*\(\s*\)|express\.Router\s*\(|Router\s*\(|new\s+(?:Hono|Router|KoaRouter|Elysia|OpenAPIHono)\b|(?:Fastify|fastify)\s*\(|createRouter\s*\(|new\s+Koa\s*\()/g;
const FRAMEWORK_IMPORT_RE = /(?:require\(\s*|\bfrom\s+)['"](?:express|fastify|koa|@koa\/router|koa-router|hono|elysia|restify|polka|@hono\/node-server)['"]/;
const DEFAULT_ROUTER_NAMES = ['app', 'router', 'server', 'api', 'fastify', 'r', 'routes', 'route', 'apiRouter', 'v1'];
// default/namespace imports: const x = require('…'), import x from '…', import * as x from '…'
const IMPORT_RE = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)|\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s+['"]([^'"]+)['"]/g;
const NAMED_IMPORT_RE = /\bimport\s*(?:[A-Za-z_$][\w$]*\s*,\s*)?\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]|\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)/g;
const NEXT_EXPORT_RE = /\bexport\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|\bexport\s+const\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*=/g;
const NEXT_REEXPORT_RE = /\bexport\s*\{([^}]*)\}/g;
const NEST_CONTROLLER_RE = /@Controller\(\s*(?:['"`]([^'"`]*)['"`])?/;
const NEST_ROUTE_RE = /@(Get|Post|Put|Patch|Delete|All)\(\s*(?:['"`]([^'"`]*)['"`])?\s*\)/g;
// A default export that is a request handler (not a config object).
const HANDLER_EXPORT_RE = /\bexport\s+default\s+(?:async\s+)?function\b|\bexport\s+default\s+(?:async\s*)?\(|\bmodule\.exports\s*=\s*(?:async\s*)?(?:function\b|\()|\bexports\.handler\s*=|\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|handler)\b|\bexport\s+const\s+(?:GET|POST|PUT|PATCH|DELETE|handler)\s*=/;
// Calls that are never user helpers worth following.
const NOT_HELPERS = new Set(['if', 'for', 'while', 'switch', 'catch', 'return', 'function', 'require', 'import', 'await', 'async', 'typeof', 'new', 'super', 'json', 'send', 'status', 'end', 'next', 'then', 'parse', 'stringify', 'String', 'Number', 'Boolean', 'Object', 'Array', 'Promise', 'Error', 'Date', 'Math', 'JSON', 'Response', 'NextResponse', 'console', 'setTimeout', 'fetch', 'req', 'res', 'request', 'response', 'ctx', 'c', 'reply', 'event', 'context', 'err', 'error', 'e', 'data', 'body', 'params', 'query', 'id']);

const cache = new WeakMap();
const ctxCache = new WeakMap();

/** Per-repo caches for function lookups and import maps, shared by discovery and fileHelpers. */
function ctxFor(repo) {
  if (!ctxCache.has(repo)) ctxCache.set(repo, { repo, fnCache: new Map(), importCache: new Map() });
  return ctxCache.get(repo);
}

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
  const ctx = ctxFor(repo);

  for (const f of code) {
    const text = repo.code(f);
    if (!text) continue;
    const side = repo.side(f);
    const rel = f.rel;
    const before = routes.length;

    // ── file-system routed frameworks ──
    if (/(?:^|\/)(?:src\/)?app\/(?:.+\/)?route\.[cm]?[jt]s$/.test(rel)) {
      addNextAppRoutes(repo, f, text, routes);
    } else if (/(?:^|\/)(?:src\/)?pages\/api\//.test(rel)) {
      routes.push(fileRoute(repo, f, text, 'ANY', `/${rel.replace(/^.*?pages\//, '').replace(/\.[cm]?[jt]sx?$/, '').replace(/\/index$/, '')}`, 'next-pages-api'));
    } else if (/\+server\.[jt]s$/.test(rel)) {
      addNextAppRoutes(repo, f, text, routes, 'sveltekit');
    } else if (/(?:^|\/)netlify\/(?:edge-)?functions\//.test(rel)) {
      routes.push(fileRoute(repo, f, text, 'ANY', `/.netlify/functions/${path.posix.basename(rel).replace(/\.[cm]?[jt]s$/, '')}`, 'netlify-function'));
    } else if (/(?:^|\/)supabase\/functions\/([^/]+)\/index\.[jt]s$/.test(rel)) {
      const name = /supabase\/functions\/([^/]+)\//.exec(rel)[1];
      routes.push(fileRoute(repo, f, text, 'ANY', `/functions/v1/${name}`, 'supabase-edge-function'));
    } else if (isVercelFunction(repo, f, text)) {
      const pkg = repo.pkgFor(rel);
      const local = pkg && pkg.dir ? rel.slice(pkg.dir.length + 1) : rel;
      routes.push(fileRoute(repo, f, text, 'ANY', `/${local.replace(/\.[cm]?[jt]s$/, '').replace(/\/index$/, '')}`, 'vercel-function'));
    }
    if (/\+page\.server\.[jt]s$/.test(rel) && /\bexport\s+const\s+actions\b/.test(text)) {
      routes.push(fileRoute(repo, f, text, 'POST', routePathFromDir(rel, 'routes'), 'sveltekit-action', text.search(/\bexport\s+const\s+actions\b/)));
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
    if (/(?:^|\/)app\/routes\//.test(rel) && ['@remix-run/node', '@remix-run/react', '@react-router/dev', 'react-router'].some((d) => repo.depsFor(rel).has(d))) {
      for (const m of text.matchAll(/\bexport\s+(?:async\s+)?function\s+(action|loader)\b|\bexport\s+const\s+(action|loader)\s*=/g)) {
        const kind = m[1] || m[2];
        routes.push(windowRoute(repo, f, text, m.index, kind === 'action' ? 'POST' : 'GET', `/${rel.replace(/^.*?app\/routes\//, '').replace(/\.[cm]?[jt]sx?$/, '')}`, `remix-${kind}`));
      }
    }

    // ── NestJS controllers: one window per route method, decorators included ──
    if (/@Controller\(/.test(text)) {
      const ctrl = NEST_CONTROLLER_RE.exec(text);
      const prefix = ctrl && ctrl[1] ? `/${ctrl[1].replace(/^\//, '')}` : '';
      const classGuards = /@UseGuards\([^)]*\)\s*(?:@\w+\([^)]*\)\s*)*export\s+class/.test(text) ? '@UseGuards' : '';
      const found = [...text.matchAll(NEST_ROUTE_RE)];
      const starts = found.map((m) => decoratorStart(text, m.index));
      found.forEach((m, i) => {
        const start = starts[i];
        const end = i + 1 < found.length ? starts[i + 1] : text.length;
        routes.push({
          file: f,
          line: repo.lineOf(f, m.index),
          method: m[1].toUpperCase(),
          path: `${prefix}/${(m[2] || '').replace(/^\//, '')}`.replace(/\/$/, '') || '/',
          framework: 'nestjs',
          start,
          end,
          text: text.slice(start, Math.min(end, start + 8000)),
          mountMiddleware: classGuards,
        });
      });
    }

    const imports = resolveImports(ctx, f, text);
    const named = resolveNamedImports(ctx, f, text);
    if (routes.length > before) {
      const reexports = reexportSegments(ctx, f, text);
      for (let i = before; i < routes.length; i++) routes[i].extra = [...helperSegments(ctx, f, routes[i].text, imports, named), ...reexports];
    }

    // ── router-style frameworks (Express, Fastify, Hono, Koa, Elysia…) ──
    if (side === 'client') continue;
    const created = [...text.matchAll(ROUTER_CREATE_RE)].map((m) => m[1]);
    const frameworkFile = FRAMEWORK_IMPORT_RE.test(text) || created.length > 0;
    if (!frameworkFile && side !== 'server') continue;
    const names = new Set([...created, ...(frameworkFile ? DEFAULT_ROUTER_NAMES : ['app', 'router'])]);

    const fileRoutes = [];
    for (const m of text.matchAll(ROUTE_CALL_RE)) {
      if (!names.has(m[1])) continue;
      fileRoutes.push({ index: m.index, method: m[2] === 'del' ? 'DELETE' : m[2].toUpperCase(), path: m[4] });
    }
    // router.route('/x').get(...).post(...): each chained method is its own route, with its own window
    for (const m of text.matchAll(/\b([A-Za-z_$][\w$]*)\s*\.\s*route\s*\(\s*(['"`])([/*][^'"`\n]*)\2\s*\)/g)) {
      if (!names.has(m[1])) continue;
      const tailStart = m.index + m[0].length;
      const stop = text.slice(tailStart).search(/;|\n\s*\n|\.\s*route\s*\(/);
      const tail = text.slice(tailStart, stop === -1 ? text.length : tailStart + stop);
      let depth = 0;
      for (let i = 0; i < tail.length; i++) {
        const ch = tail[i];
        if (ch === '(' || ch === '[' || ch === '{') depth++;
        else if (ch === ')' || ch === ']' || ch === '}') depth--;
        else if (ch === '.' && depth === 0) {
          const mm = new RegExp(`^\\.\\s*(${METHODS})\\s*\\(`).exec(tail.slice(i));
          if (mm) fileRoutes.push({ index: tailStart + i, method: mm[1] === 'del' ? 'DELETE' : mm[1].toUpperCase(), path: m[3], chained: true });
        }
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
      // the route call itself (handler included) when it closes; else up to the next route
      const open = text.indexOf('(', r.index);
      const call = open !== -1 && splitArgs(text, open);
      const end = call ? call.end + 1 : Math.min(next ? next.index : text.length, r.index + 4000);
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
        handler: resolveHandler(ctx, f, text, r.index + (r.chained ? text.slice(r.index).indexOf('(') : 0), imports, named),
      };
      route.extra = helperSegments(ctx, f, route.text, imports, named);
      if (route.handler) route.extra.push(...helperSegments(ctx, route.handler.file, route.handler.text, resolveImports(ctx, route.handler.file, repo.code(route.handler.file) || ''), resolveNamedImports(ctx, route.handler.file, repo.code(route.handler.file) || '')));
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
        const req = /^require\(\s*['"]([^'"]+)['"]\s*\)$/.exec(a);
        if (id && imports.has(id)) targets.push(imports.get(id));
        else if (req) {
          const target = resolveModule(repo, f.rel, req[1]);
          if (target) targets.push(target);
        }
      }
      const middleware = rest.filter((a) => !targets.length || !(imports.has(a) || /^require\(/.test(a))).join(', ');
      if (targets.length) {
        for (const t of targets) mounts.push({ from: f.rel, target: t, prefix, middleware, line: repo.lineOf(f, m.index) });
      } else if (/^\w+\.path$/.test(args[0] || '') && /^\w+\.route$/.test(args[1] || '')) {
        // routers mounted from an array: [{ path: '/auth', route: authRoute }].forEach((r) => router.use(r.path, r.route))
        for (const e of text.matchAll(/\{\s*path\s*:\s*(['"`])([^'"`]+)\1\s*,\s*route\s*:\s*([A-Za-z_$][\w$]*)\s*,?\s*\}/g)) {
          if (imports.has(e[3])) mounts.push({ from: f.rel, target: imports.get(e[3]), prefix: e[2], middleware: '', line: repo.lineOf(f, e.index) });
        }
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
        const full = `${up.prefix}${p.prefix}`;
        const scoped = mounts.filter((x) => !x.target && x.from === p.from && (full.startsWith(x.prefix) || p.prefix.startsWith(x.prefix)));
        out.push({
          prefix: full,
          middleware: [up.middleware, p.middleware, fileMiddleware.get(rel) || '', ...scoped.map((x) => x.middleware)].filter(Boolean).join('\n'),
        });
      }
    }
    return out;
  };
  for (const r of routes) {
    if (r.framework !== 'router') continue;
    const c = chainFor(r.file.rel)[0];
    r.path = joinPath(c.prefix, r.localPath);
    const scoped = mounts.filter((x) => !x.target && x.from === r.file.rel && r.localPath.startsWith(x.prefix));
    r.mountMiddleware = [c.middleware, ...scoped.map((x) => x.middleware)].filter(Boolean).join('\n');
    r.mountedFrom = byTarget.has(r.file.rel) ? byTarget.get(r.file.rel)[0] : null;
  }

  return { routes, mounts, fileMiddleware, nextMiddleware: findNextMiddleware(repo) };
}

/** Vercel-style function: a file under api/ at a package root whose default export handles requests. */
function isVercelFunction(repo, f, text) {
  if (repo.depsFor(f.rel).has('next') || FRAMEWORK_IMPORT_RE.test(text)) return false;
  if (/\.config\.[cm]?[jt]s$|(?:^|\/)types?\.[jt]s$|(?:^|\/)_[^/]*$/.test(f.rel)) return false;
  const pkg = repo.pkgFor(f.rel);
  const base = pkg && pkg.dir ? `${pkg.dir}/` : '';
  if (!f.rel.startsWith(`${base}api/`)) return false;
  if (HANDLER_EXPORT_RE.test(text)) return true;
  const named = /\bexport\s+default\s+([A-Za-z_$][\w$]*)\s*;?/.exec(text);
  return Boolean(named && new RegExp(`(?:function\\s+${escapeRegExp(named[1])}\\s*\\(|(?:const|let|var)\\s+${escapeRegExp(named[1])}\\s*=\\s*(?:async\\s*)?(?:function\\b|\\())`).test(text));
}

/** Index where a decorated method's decorator block starts (walks up over lines starting with @). */
function decoratorStart(text, index) {
  let start = text.lastIndexOf('\n', index - 1) + 1;
  for (;;) {
    const prevEnd = start - 1;
    if (prevEnd <= 0) break;
    const prevStart = text.lastIndexOf('\n', prevEnd - 1) + 1;
    const line = text.slice(prevStart, prevEnd).trim();
    if (line.startsWith('@') || (line.endsWith(')') && /^[\w\s,'"`{}:.\-[\]]*\)$/.test(line) && /@\w+\(/.test(text.slice(Math.max(0, prevStart - 200), prevStart)))) start = prevStart;
    else break;
  }
  return start;
}

/** Find a function named `name` in `text`: declaration, const arrow/function, or object/class method. */
function findFunction(ctx, file, name) {
  const key = `${file.rel}#${name}`;
  if (ctx.fnCache.has(key)) return ctx.fnCache.get(key);
  const text = ctx.repo.code(file) || '';
  const n = escapeRegExp(name);
  // declarations, const arrows/functions, wrapped handlers (const x = catchAsync(async (req) => …)), methods
  const def = new RegExp(`(?:async\\s+)?function\\s*\\*?\\s*${n}\\s*\\(|\\b(?:const|let|var)\\s+${n}\\s*(?::[^=]{1,200})?=\\s*(?:async\\s*)?(?:function\\b|\\(|[A-Za-z_$][\\w$]*\\s*=>|(?!require\\b|import\\b)[A-Za-z_$][\\w$.]*\\s*\\(\\s*(?:async\\b|function\\b|\\(|[A-Za-z_$][\\w$]*\\s*=>))|\\b${n}\\s*:\\s*(?:async\\s*)?(?:function\\b|\\()|^\\s*(?:public\\s+|private\\s+|protected\\s+|static\\s+)*(?:async\\s+)?${n}\\s*\\([^)]*\\)\\s*(?::[^{]{1,200})?\\{`, 'm').exec(text);
  let result = null;
  if (def) {
    const rest = text.slice(def.index + 10);
    const stop = rest.search(/\n(?:export\s+)?(?:async\s+)?function\s|\n(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?(?:function\b|\()|\nmodule\.exports|\nexport\s/);
    const end = stop === -1 ? text.length : def.index + 10 + stop;
    result = { file, start: def.index, end, text: text.slice(def.index, Math.min(end, def.index + 6000)) };
  }
  ctx.fnCache.set(key, result);
  return result;
}

/** A module's default-exported function (module.exports = function…, export default function…). */
function defaultExport(ctx, rel) {
  const file = ctx.repo.get(rel);
  if (!file) return null;
  const body = ctx.repo.code(file) || '';
  const def = /\bmodule\.exports\s*=\s*(?:async\s*)?(?:function\b|\()|\bexport\s+default\s+(?:async\s+)?(?:function\b|\()/.exec(body);
  if (def) return { file, start: def.index, end: body.length, text: body.slice(def.index, def.index + 6000) };
  const named = /\bexport\s+default\s+([A-Za-z_$][\w$]*)\s*;?\s*$/m.exec(body) || /\bmodule\.exports\s*=\s*([A-Za-z_$][\w$]*)\s*;?\s*$/m.exec(body);
  return named ? findFunction(ctx, file, named[1]) : null;
}

/** The whole module (capped) as a segment: route files that re-export their handler from it. */
function moduleSegment(ctx, rel) {
  const file = ctx.repo.get(rel);
  if (!file) return null;
  const text = ctx.repo.code(file) || '';
  return { file, start: 0, end: text.length, text: text.slice(0, 20000) };
}

/**
 * One hop of helpers: functions this text calls or passes along (getHandler in
 * `export const GET = withX(getHandler)`, verifyAccess(...) in a handler), resolved in the same
 * file or through imports, plus imported objects passed as arguments (a tRPC router).
 */
function helperSegments(ctx, file, text, imports, named, limit = 6) {
  const out = [];
  const seen = new Set();
  const consider = (name) => {
    if (seen.has(name) || NOT_HELPERS.has(name) || out.length >= limit) return;
    seen.add(name);
    const local = findFunction(ctx, file, name);
    if (local) {
      out.push(local);
      return;
    }
    // Imported functions only, never whole modules (a shared prisma/db module would make every
    // route look like it checks auth because it mentions a session), except routers handed to
    // an adapter: createNextApiHandler(adminRouter) is guarded by its procedures.
    if (named.has(name)) {
      const target = ctx.repo.get(named.get(name).target);
      const fn = target && findFunction(ctx, target, named.get(name).name);
      const seg = fn || (/[a-z]Router$|^router$/.test(name) && moduleSegment(ctx, named.get(name).target));
      if (seg) out.push(seg);
    } else if (imports.has(name)) {
      const fn = defaultExport(ctx, imports.get(name));
      if (fn) out.push(fn);
    }
  };
  for (const m of text.matchAll(/(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(/g)) consider(m[1]);
  for (const m of text.matchAll(/[(,]\s*([A-Za-z_$][\w$]*)\s*(?=[,)])/g)) consider(m[1]);
  return out;
}

/**
 * For `app.post('/x', mw, controller.create)` find the body of controller.create (in this file
 * or an imported module), so checks can look inside handlers defined elsewhere.
 */
function resolveHandler(ctx, f, text, callIndex, imports, named = new Map()) {
  const open = text.indexOf('(', callIndex);
  const call = splitArgs(text, open);
  if (!call || !call.args.length) return null;
  const last = call.args[call.args.length - 1].text;
  const ref = /^([A-Za-z_$][\w$]*)(?:\.([A-Za-z_$][\w$]*))?$/.exec(last);
  if (!ref) return null;
  let file = f;
  let name = ref[1];
  if (ref[2]) {
    const target = imports.get(ref[1]);
    if (!target) return null;
    file = ctx.repo.get(target);
    name = ref[2];
  } else if (named.has(ref[1])) {
    file = ctx.repo.get(named.get(ref[1]).target);
    name = named.get(ref[1]).name;
  } else if (imports.has(ref[1])) {
    file = ctx.repo.get(imports.get(ref[1]));
    name = null; // default export of the module is the handler
  }
  if (!file) return null;
  if (name) {
    const fn = findFunction(ctx, file, name);
    if (!fn || (file === f && fn.start >= callIndex && fn.start < callIndex + 50)) return null; // the route call itself
    return fn;
  }
  return defaultExport(ctx, file.rel);
}

/** Modules a route file re-exports its handlers from: export { default } from '…', export { POST } from '…'. */
function reexportSegments(ctx, f, text) {
  const out = [];
  for (const m of text.matchAll(/\bexport\s*(?:\*|\{[^}]*\b(?:default|GET|POST|PUT|PATCH|DELETE|handler|action|loader)\b[^}]*\})\s*from\s*['"]([^'"]+)['"]/g)) {
    const target = resolveModule(ctx.repo, f.rel, m[1]);
    const seg = target && moduleSegment(ctx, target);
    if (!seg) continue;
    // the re-exported module is the real route file: include its helpers too
    const text2 = ctx.repo.code(seg.file) || '';
    out.push(seg, ...helperSegments(ctx, seg.file, text2, resolveImports(ctx, seg.file, text2), resolveNamedImports(ctx, seg.file, text2)));
  }
  return out;
}

/** One hop of helpers a whole file calls (same file or imported), e.g. the guard an admin page awaits. */
function fileHelpers(repo, f) {
  const ctx = ctxFor(repo);
  const text = repo.code(f) || '';
  return helperSegments(ctx, f, text, resolveImports(ctx, f, text), resolveNamedImports(ctx, f, text), 12).filter((s) => s.file !== f);
}

/**
 * Text segments of a route: the route itself, the handler it references and one hop of
 * helpers. With helpers: false, only helpers defined in the route's own file are kept
 * (export const POST = withX(postHandler) → postHandler). Presence tests (is there an auth
 * check?) want every helper; checks that flag code (this query lists every row) should not
 * look inside shared helpers, whose generic queries are not the route's.
 */
function segments(r, { helpers = true } = {}) {
  const out = [{ file: r.file, start: r.start, text: r.text }];
  const covered = (s) => out.some((o) => o.file === s.file && s.start >= o.start && s.start < o.start + o.text.length);
  const extra = (r.extra || []).filter((s) => helpers || s.file === r.file);
  for (const s of [r.handler, ...extra]) if (s && !covered(s)) out.push({ file: s.file, start: s.start, text: s.text });
  return out;
}

/** Route + handler + helpers as one string (for presence tests, not for line numbers). */
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

function resolveImports(ctx, f, text) {
  const key = `d:${f.rel}`;
  if (ctx.importCache.has(key)) return ctx.importCache.get(key);
  const map = new Map();
  for (const m of text.matchAll(IMPORT_RE)) {
    const target = resolveModule(ctx.repo, f.rel, m[2] || m[4]);
    if (target) map.set(m[1] || m[3], target);
  }
  ctx.importCache.set(key, map);
  return map;
}

/** Named imports: `import { a, b as c } from './x'` and `const { a } = require('./x')` → local → { target, name }. */
function resolveNamedImports(ctx, f, text) {
  const key = `n:${f.rel}`;
  if (ctx.importCache.has(key)) return ctx.importCache.get(key);
  const map = new Map();
  for (const m of text.matchAll(NAMED_IMPORT_RE)) {
    const target = resolveModule(ctx.repo, f.rel, m[2] || m[4]);
    if (!target) continue;
    for (const part of (m[1] || m[3]).split(',')) {
      const bits = part.trim().replace(/^type\s+/, '').split(/\s+as\s+|\s*:\s*/);
      const original = bits[0] && bits[0].trim();
      const local = (bits[1] || bits[0] || '').trim();
      if (/^[A-Za-z_$][\w$]*$/.test(local) && /^[A-Za-z_$][\w$]*$/.test(original)) map.set(local, { target, name: original });
    }
  }
  ctx.importCache.set(key, map);
  return map;
}

/** Resolve an import specifier to a repo file: relative paths, @/ and ~/ aliases, and workspace packages. */
function resolveModule(repo, fromRel, spec) {
  const bases = [];
  if (spec.startsWith('.')) bases.push(path.posix.normalize(path.posix.join(path.posix.dirname(fromRel), spec)));
  else if (/^[@~]\//.test(spec)) {
    const pkg = repo.pkgFor(fromRel);
    const root = pkg && pkg.dir ? `${pkg.dir}/` : '';
    bases.push(`${root}src/${spec.slice(2)}`, `${root}${spec.slice(2)}`);
  } else {
    for (const p of repo.packages) {
      const name = p.json && p.json.name;
      if (name && (spec === name || spec.startsWith(`${name}/`))) {
        const sub = spec.slice(name.length).replace(/^\//, '');
        const dir = p.dir ? `${p.dir}/` : '';
        bases.push(sub ? `${dir}${sub}` : `${dir}index`, sub ? `${dir}src/${sub}` : `${dir}src/index`);
      }
    }
  }
  for (const base of bases) {
    const candidates = [base, ...['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'].map((e) => base + e), ...['index.js', 'index.ts', 'index.mjs', 'index.tsx'].map((i) => `${base}/${i}`)];
    for (const c of candidates) if (repo.get(c)) return c;
  }
  return null;
}

// ── Next.js middleware.ts / proxy.ts ──────────────────────────────────────

const NEXT_MW_AUTH_RE = /\b(?:clerkMiddleware|authMiddleware|withAuth|auth\s*\(|NextAuth|getToken\s*\(|updateSession\s*\(|createServerClient\s*\(|supabase\.auth\.getUser|getSession\s*\(|verifyToken|jwtVerify|kindeAuth|withMiddlewareAuthRequired|authkitMiddleware|betterFetch|getSessionCookie)/;

function findNextMiddleware(repo) {
  // Next.js 16 renamed middleware.ts to proxy.ts; both run before routes. They live at the
  // app root or in src/ (a lib/proxy.ts helper elsewhere is not middleware).
  const f = repo.files.find((x) => {
    if (x.build || !/^(?:middleware|proxy)\.[jt]s$/.test(x.name) || !repo.depsFor(x.rel).has('next')) return false;
    const pkg = repo.pkgFor(x.rel);
    const dir = path.posix.dirname(x.rel) === '.' ? '' : path.posix.dirname(x.rel);
    const root = pkg ? pkg.dir : '';
    return dir === root || dir === (root ? `${root}/src` : 'src');
  });
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

module.exports = { getRoutes, joinPath, segments, routeBody, resolveModule, fileHelpers };
