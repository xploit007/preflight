'use strict';

/**
 * Loads a target repository once: walks the tree, classifies files (build output, client vs
 * server code, tests), reads content lazily, and wraps the read-only git commands the checks
 * need. Every check group calls loadRepo(root, opts); the result is memoized per root.
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { lineStarts, lineAt, ignoreMatcher, clip, blankComments } = require('./util');
const { redact } = require('./patterns');

// Directories that never hold the app's own code: dependencies, VCS, caches, virtualenvs.
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'bower_components', 'jspm_packages', 'vendor',
  '.venv', 'venv', '__pycache__', '.pytest_cache', '.mypy_cache', '.tox', '.idea', '.gradle',
  'coverage', '.nyc_output', '.turbo', '.cache', '.parcel-cache', '.yarn', '.pnpm-store', 'Pods',
  'DerivedData', '.terraform', '.serverless', '.expo', '.angular', '.wrangler', '.firebase',
  '.docusaurus', '.nuxt', '.astro', '.context', '.vercel-cache',
]);

// Directories that hold build output. Only their browser-facing parts are kept (see buildKeep).
const BUILD_DIRS = new Set(['dist', 'build', 'out', '.next', '.output', '.svelte-kit', '.vercel', '.netlify', 'storybook-static']);

const ENV_FILE_RE = /^(?:\.env(?:\..+)?|.+\.env|\.dev\.vars|\.envrc)$/i;
const ENV_EXAMPLE_RE = /(?:example|sample|template|dist|defaults|schema|tpl)/i;
const LOCK_NAMES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb', 'composer.lock', 'Gemfile.lock', 'poetry.lock', 'Pipfile.lock', 'Cargo.lock', 'go.sum', 'uv.lock', 'deno.lock']);
const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.vue', '.svelte', '.astro', '.py', '.rb', '.php', '.go', '.java', '.kt', '.cs', '.rs', '.ex', '.exs', '.sh', '.bash', '.zsh', '.ps1', '.sql', '.prisma', '.graphql', '.gql', '.dart', '.swift']);
const JS_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.vue', '.svelte', '.astro']);
const MARKUP_EXT = new Set(['.html', '.htm', '.ejs', '.hbs', '.handlebars', '.pug', '.njk', '.liquid', '.erb', '.mustache', '.twig']);
const STYLE_EXT = new Set(['.css', '.scss', '.sass', '.less', '.styl']);
const CONFIG_EXT = new Set(['.json', '.jsonc', '.json5', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.xml', '.properties', '.tf', '.tfvars', '.hcl', '.plist', '.rules']);
const DOC_EXT = new Set(['.md', '.mdx', '.txt', '.rst', '.adoc']);
const CONFIG_NAMES = new Set(['Dockerfile', 'Procfile', 'Makefile', 'Caddyfile', '_headers', '_redirects', '.npmrc', '.yarnrc', '.htaccess', 'Gemfile', 'Vagrantfile']);

const MAX_FILES = 25000;
const MAX_TEXT_BYTES = 2 * 1024 * 1024;
const MAX_BUILD_BYTES = 12 * 1024 * 1024;
const MAX_LOCK_BYTES = 30 * 1024 * 1024;

// Server-only code by path: API routes, server folders, edge/serverless functions, *.server.* files.
const SERVER_PATH_RE = /(?:^|\/)(?:server|servers|backend)\/|(?:^|\/)(?:src\/)?pages\/api\/|(?:^|\/)(?:src\/)?app\/(?:.+\/)?route\.[cm]?[jt]s$|(?:^|\/)(?:src\/)?app\/api\/|\+(?:server|page\.server|layout\.server)\.[jt]s$|(?:^|\/)hooks\.server\.[jt]s$|\.server\.[cm]?[jt]sx?$|(?:^|\/)(?:netlify|supabase)\/(?:edge-)?functions\/|(?:^|\/)lib\/server\/|(?:^|\/)middleware\.[jt]s$/;
// Static assets served as-is to browsers.
const CLIENT_PATH_RE = /(?:^|\/)(?:public|static|www|wwwroot|htdocs)\//;
// UI folders that are client code outside of Next.js server components.
const CLIENT_DIR_RE = /(?:^|\/)(?:components|hooks|contexts?|views|screens|ui|widgets|stores?|composables|layouts)\//;
// Imports that only make sense on a server.
const SERVER_IMPORT_RE = /(?:require\(\s*|\bfrom\s+|\bimport\s+)['"](?:node:)?(?:fs|fs\/promises|child_process|os|net|http|https|express|fastify|koa|hono|@hono\/node-server|pg|mysql2?|mongoose|mongodb|sequelize|knex|@prisma\/client|drizzle-orm\/[\w-]+|redis|ioredis|stripe|twilio|nodemailer|@sendgrid\/mail|jsonwebtoken|bcrypt|bcryptjs|argon2|firebase-admin|firebase-admin\/[\w-]+|@supabase\/ssr|next\/server|next\/headers|server-only|@vercel\/functions|@netlify\/functions|multer|@aws-sdk\/[\w-]+)['"]|\bDeno\.(?:serve|env)\b|\bexports\.handler\s*=|\bexport\s+(?:const|async\s+function|function)\s+handler\b/;
// Strong signs of code that runs in the browser.
const CLIENT_SIGNAL_RE = /\b(?:window|document|localStorage|sessionStorage|navigator)\.|\buse(?:State|Effect|LayoutEffect|Ref|Reducer|Context|Navigate|Router|SearchParams|Query|Mutation)\s*\(|import\.meta\.env\.VITE_|\bonClick\s*=|\bfrom\s+['"](?:react-dom(?:\/client)?|react-router(?:-dom)?|@stripe\/stripe-js|@stripe\/react-stripe-js)['"]/;
const TEST_PATH_RE = /(?:^|\/)(?:__tests__|__mocks__|tests?|spec|specs|e2e|cypress|playwright|fixtures?|mocks?|stories|\.storybook)\/|\.(?:test|spec|stories|e2e)\.[cm]?[jt]sx?$|(?:^|\/)test_[^/]*\.py$|_test\.(?:py|go)$/;
// Tooling that runs on a developer machine or in CI, not in the deployed app.
const TOOLING_PATH_RE = /(?:^|\/)(?:scripts|tools|bin|\.github|\.husky|config|migrations|seed|seeds|remix\.init|management\/commands|cli)\/|(?:^|\/)(?:cli|manage)\.(?:py|[cm]?[jt]s)$|(?:^|\/)[\w.-]+\.config\.[cm]?[jt]s$|(?:^|\/)(?:gulpfile|gruntfile|webpack|rollup|vite|next|nuxt|svelte|astro|tailwind|postcss|babel|jest|vitest|playwright|eslint|prettier)\.[\w.]*$/i;

const cache = new Map();

function loadRepo(rootArg, opts = {}) {
  const root = path.resolve(rootArg);
  if (cache.has(root)) return cache.get(root);
  const repo = createRepo(root, opts);
  cache.set(root, repo);
  return repo;
}

function createRepo(root, opts) {
  const preflightIgnore = readLines(path.join(root, '.preflightignore'));
  const isIgnoredByUser = ignoreMatcher(preflightIgnore);
  const rootGitignore = ignoreMatcher(readLines(path.join(root, '.gitignore')));

  const { files, truncated } = walk(root, isIgnoredByUser, rootGitignore);
  const byRel = new Map(files.map((f) => [f.rel, f]));
  const textCache = new Map();
  const codeCache = new Map();
  const startsCache = new Map();
  const sideCache = new Map();

  const g = gitInfo(root, rootGitignore);

  const repo = {
    root,
    opts,
    files,
    truncated,
    byRel,
    git: g,
    get(rel) {
      return byRel.get(rel) || null;
    },
    read(f) {
      if (typeof f === 'string') f = byRel.get(f);
      if (!f) return null;
      if (textCache.has(f.rel)) return textCache.get(f.rel);
      let text = null;
      const limit = f.kind === 'lock' ? MAX_LOCK_BYTES : f.build ? MAX_BUILD_BYTES : MAX_TEXT_BYTES;
      if (f.kind !== 'other' && f.size <= limit) {
        try {
          const buf = fs.readFileSync(f.abs);
          if (!looksBinary(buf)) text = buf.toString('utf8');
        } catch {
          text = null;
        }
      }
      textCache.set(f.rel, text);
      return text;
    },
    /** Content with comments blanked out (same offsets as read()). Heuristic checks use this. */
    code(f) {
      if (typeof f === 'string') f = byRel.get(f);
      if (!f) return null;
      if (codeCache.has(f.rel)) return codeCache.get(f.rel);
      const text = repo.read(f);
      const blanked = text && (f.kind === 'code' || f.kind === 'markup' || f.kind === 'config') ? blankComments(text, f.ext, f.name) : text;
      codeCache.set(f.rel, blanked);
      return blanked;
    },
    lineOf(f, index) {
      if (!startsCache.has(f.rel)) startsCache.set(f.rel, lineStarts(repo.read(f) || ''));
      return lineAt(startsCache.get(f.rel), index);
    },
    lineText(f, line) {
      const text = repo.read(f) || '';
      if (!startsCache.has(f.rel)) startsCache.set(f.rel, lineStarts(text));
      const starts = startsCache.get(f.rel);
      const s = starts[line - 1];
      if (s === undefined) return '';
      const e = line < starts.length ? starts[line] - 1 : text.length;
      return text.slice(s, e);
    },
    /** Redacted, clipped source line for evidence (only a bounded window is redacted, so huge minified lines stay fast). */
    snippet(f, line, max = 120) {
      return clip(redact(repo.lineText(f, line).slice(0, 1000)), max);
    },
    /** Minified/bundled-looking file: *.min.* or long average line length. Heuristics skip these. */
    isMinified(f) {
      if (/\.min\.[a-z]+$/.test(f.name)) return true;
      const text = repo.read(f);
      if (!text || text.length < 20000) return false;
      const lines = repo.lineOf(f, text.length);
      return text.length / lines > 400;
    },
    /** `// preflight-ignore` on the line (or the line above) suppresses findings there. */
    suppressed(f, line) {
      return /preflight-ignore/.test(repo.lineText(f, line)) || (line > 1 && /preflight-ignore/.test(repo.lineText(f, line - 1)));
    },
    isTest(f) {
      return TEST_PATH_RE.test(f.rel);
    },
    isTooling(f) {
      return TOOLING_PATH_RE.test(f.rel);
    },
    /** 'client' | 'server' | 'unknown' for code, 'build' for build output, 'none' otherwise. */
    side(f) {
      if (sideCache.has(f.rel)) return sideCache.get(f.rel);
      const s = classifySide(repo, f);
      sideCache.set(f.rel, s);
      return s;
    },
    /** Non-build source files of the given kinds (default: code + markup), optionally without tests. */
    sources({ kinds = ['code', 'markup'], tests = true, tooling = true, js = false, minified = false } = {}) {
      return files.filter((f) => !f.build && kinds.includes(f.kind) && (tests || !repo.isTest(f)) && (tooling || !repo.isTooling(f)) && (!js || JS_EXT.has(f.ext)) && (minified || !repo.isMinified(f)));
    },
    buildFiles() {
      return files.filter((f) => f.build);
    },
    envFiles() {
      return files.filter((f) => f.kind === 'env');
    },
    isEnvExample(f) {
      return f.kind === 'env' && ENV_EXAMPLE_RE.test(f.name.replace(/^\.env/i, '').replace(/\.env$/i, ''));
    },
    /** Iterate regex matches over files: yields { f, m, index, line }. `re` must be global. */
    *matches(fileList, re, { raw = false } = {}) {
      for (const f of fileList) {
        const text = raw ? repo.read(f) : repo.code(f);
        if (!text) continue;
        re.lastIndex = 0;
        if (!re.test(text)) continue;
        re.lastIndex = 0;
        for (const m of text.matchAll(re)) {
          const line = repo.lineOf(f, m.index);
          if (repo.suppressed(f, line)) continue;
          yield { f, m, index: m.index, line };
        }
      }
    },
  };

  repo.packages = loadPackages(repo);
  repo.deps = new Set(repo.packages.flatMap((p) => [...p.deps]));
  repo.pkgFor = (rel) => {
    let best = null;
    for (const p of repo.packages) {
      if ((p.dir === '' || rel === p.dir || rel.startsWith(`${p.dir}/`)) && (!best || p.dir.length > best.dir.length)) best = p;
    }
    return best;
  };
  repo.depsFor = (rel) => {
    const p = repo.pkgFor(rel);
    return p ? p.deps : repo.deps;
  };
  repo.hasDep = (name) => repo.deps.has(name);
  repo.hasDepMatching = (re) => [...repo.deps].some((d) => re.test(d));
  repo.pythonDeps = loadPythonDeps(repo);
  return repo;
}

function readLines(file) {
  try {
    return fs.readFileSync(file, 'utf8').split('\n');
  } catch {
    return [];
  }
}

function looksBinary(buf) {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

function fileKind(name, ext) {
  if (ENV_FILE_RE.test(name)) return 'env';
  if (LOCK_NAMES.has(name)) return 'lock';
  if (ext === '.map') return 'map';
  if (CODE_EXT.has(ext)) return 'code';
  if (MARKUP_EXT.has(ext)) return 'markup';
  if (STYLE_EXT.has(ext)) return 'style';
  if (CONFIG_EXT.has(ext) || CONFIG_NAMES.has(name) || /^Dockerfile/.test(name) || /^docker-compose/.test(name)) return 'config';
  if (DOC_EXT.has(ext)) return 'doc';
  return 'other';
}

/** Which parts of a build directory are worth keeping (browser-facing output only). */
function buildKeep(kind, sub, isDir) {
  switch (kind) {
    case '.next':
      if (isDir) return sub === 'static' || sub.startsWith('static/') || sub === 'server' || sub.startsWith('server/');
      return sub.startsWith('static/') || (sub.startsWith('server/') && sub.endsWith('.html'));
    case '.vercel':
      if (isDir) return sub === 'output' || sub === 'output/static' || sub.startsWith('output/static/');
      return sub.startsWith('output/static/');
    case '.output':
      if (isDir) return sub === 'public' || sub.startsWith('public/');
      return sub.startsWith('public/');
    case '.svelte-kit':
      if (isDir) return sub === 'output' || sub === 'output/client' || sub.startsWith('output/client/');
      return sub.startsWith('output/client/');
    case '.netlify':
      return false;
    default:
      return !(isDir && (sub === 'cache' || sub.endsWith('/cache')));
  }
}

/** dist/, build/ and out/ are ambiguous (a few projects keep sources there): require bundle artifacts or a gitignore entry. */
function looksLikeBuildOutput(absDir, name, rel, gitignored) {
  if (!['dist', 'build', 'out'].includes(name)) return true;
  if (gitignored(rel)) return true;
  let entries = [];
  try {
    entries = fs.readdirSync(absDir);
  } catch {
    return false;
  }
  return entries.some((e) => /\.(?:html|map)$/.test(e) || /^(?:assets|static|_next|chunks|_app|asset-manifest\.json|manifest\.json)$/.test(e) || /[.-][a-f0-9]{8,}\.(?:js|css)$/.test(e));
}

function walk(root, userIgnored, gitignored) {
  const files = [];
  const stack = [{ abs: root, rel: '', build: null }];
  let truncated = false;
  while (stack.length && !truncated) {
    const { abs, rel, build } = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(abs, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      if (ent.isSymbolicLink()) continue;
      const childRel = rel ? `${rel}/${ent.name}` : ent.name;
      const childAbs = path.join(abs, ent.name);
      if (userIgnored(childRel)) continue;
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name)) continue;
        if (build) {
          const sub = childRel.slice(build.root.length + 1);
          if (!buildKeep(build.kind, sub, true)) continue;
          stack.push({ abs: childAbs, rel: childRel, build });
        } else if (BUILD_DIRS.has(ent.name) && looksLikeBuildOutput(childAbs, ent.name, childRel, gitignored)) {
          stack.push({ abs: childAbs, rel: childRel, build: { root: childRel, kind: ent.name } });
        } else {
          stack.push({ abs: childAbs, rel: childRel, build: null });
        }
      } else if (ent.isFile()) {
        if (build && !buildKeep(build.kind, childRel.slice(build.root.length + 1), false)) continue;
        let size = 0;
        try {
          size = fs.statSync(childAbs).size;
        } catch {
          continue;
        }
        const ext = path.extname(ent.name).toLowerCase();
        files.push({ rel: childRel, abs: childAbs, name: ent.name, ext, size, kind: fileKind(ent.name, ext), build });
        if (files.length >= MAX_FILES) {
          truncated = true;
          break;
        }
      }
    }
  }
  files.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  return { files, truncated };
}

// ── git (read-only) ────────────────────────────────────────────────────────

const GIT_ENV = { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0', GIT_PAGER: 'cat', LC_ALL: 'C' };
const GIT_SAFE = ['-c', 'core.fsmonitor=false', '-c', 'core.quotepath=off'];

/** Run a read-only git command. Returns stdout, or null on failure (exit codes in okCodes count as success). */
function runGit(cwd, args, { input, okCodes = [0], timeout = 20000 } = {}) {
  try {
    return execFileSync('git', [...GIT_SAFE, ...args], { cwd, input, encoding: 'utf8', env: GIT_ENV, timeout, maxBuffer: 128 * 1024 * 1024, stdio: ['pipe', 'pipe', 'ignore'] });
  } catch (e) {
    if (e && typeof e.status === 'number' && okCodes.includes(e.status) && typeof e.stdout === 'string') return e.stdout;
    return null;
  }
}

function gitInfo(root, rootGitignore) {
  const inside = (runGit(root, ['rev-parse', '--is-inside-work-tree']) || '').trim() === 'true';
  const info = { isRepo: inside, tracked: null, hasCommits: false, ignoredCache: new Map() };
  if (inside) {
    const out = runGit(root, ['ls-files', '-z']);
    info.tracked = out === null ? null : new Set(out.split('\0').filter(Boolean));
    info.hasCommits = runGit(root, ['rev-parse', '--verify', '--quiet', 'HEAD']) !== null;
  }
  /** Is `rel` tracked? true/false, or null when unknown (not a git repo). */
  info.isTracked = (rel) => (info.tracked ? info.tracked.has(rel) : null);
  /** Is `rel` matched by .gitignore rules (regardless of whether it is tracked)? */
  info.isIgnored = (rel) => {
    if (info.ignoredCache.has(rel)) return info.ignoredCache.get(rel);
    let result;
    if (inside) {
      // Prints the path and exits 0 when ignored, prints nothing and exits 1 when not.
      const out = runGit(root, ['check-ignore', '--no-index', '--', rel], { okCodes: [0, 1] });
      result = out === null ? rootGitignore(rel) : out.trim().length > 0;
    } else result = rootGitignore(rel);
    info.ignoredCache.set(rel, result);
    return result;
  };
  info.run = (args, o) => (inside ? runGit(root, args, o) : null);
  return info;
}

// ── package metadata ───────────────────────────────────────────────────────

function loadPackages(repo) {
  const out = [];
  for (const f of repo.files) {
    if (f.name !== 'package.json' || f.build) continue;
    const text = repo.read(f);
    if (!text) continue;
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      continue;
    }
    const sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
    const deps = new Set();
    const versions = {};
    for (const s of sections) {
      const block = json[s];
      if (!block || typeof block !== 'object') continue;
      for (const [name, range] of Object.entries(block)) {
        deps.add(name);
        versions[name] = { range: String(range), section: s };
      }
    }
    out.push({ file: f, rel: f.rel, dir: path.posix.dirname(f.rel) === '.' ? '' : path.posix.dirname(f.rel), json, deps, versions, text });
  }
  return out;
}

function loadPythonDeps(repo) {
  const names = new Set();
  for (const f of repo.files) {
    if (f.build) continue;
    if (!/^(?:requirements[\w.-]*\.txt|pyproject\.toml|Pipfile)$/.test(f.name)) continue;
    const text = repo.read(f) || '';
    for (const m of text.matchAll(/^\s*["']?([A-Za-z0-9_.-]+)\s*(?:[=<>~!]|$|\[|["'])/gm)) names.add(m[1].toLowerCase());
  }
  return names;
}

// ── client / server classification ─────────────────────────────────────────

function hasDirective(text, directive) {
  const head = text.slice(0, 2000).replace(/^(?:\s*(?:\/\/[^\n]*\n|\/\*[\s\S]*?\*\/))*/, '');
  return new RegExp(`^\\s*['"]use ${directive}['"]`).test(head);
}

function isSpa(deps) {
  if (deps.has('@sveltejs/kit') || deps.has('@remix-run/dev') || deps.has('@react-router/dev') || deps.has('astro') || deps.has('nuxt') || deps.has('next')) return false;
  return deps.has('vite') || deps.has('react-scripts') || deps.has('@vue/cli-service') || deps.has('@angular/core') || deps.has('parcel');
}

function classifySide(repo, f) {
  if (f.build) return 'build';
  if (f.kind !== 'code' && f.kind !== 'markup') return 'none';
  const rel = f.rel;
  if (/\.(?:py|rb|php|go|java|kt|cs|rs|ex|exs|sql|prisma|sh|bash|zsh|ps1|graphql|gql)$/.test(rel)) return 'server';
  if (/\.(?:ejs|hbs|handlebars|pug|njk|liquid|erb|twig|mustache)$/.test(rel)) return 'server';
  if (/\.html?$/.test(rel)) return 'client';
  const text = repo.read(f) || '';
  if (hasDirective(text, 'client')) return 'client';
  if (hasDirective(text, 'server')) return 'server';
  if (SERVER_PATH_RE.test(rel)) return 'server';
  if (/(?:^|\/)(?:api|functions)\//.test(rel) && !/(?:^|\/)src\//.test(rel)) return 'server';
  if (CLIENT_PATH_RE.test(rel)) return 'client';
  const deps = repo.depsFor(rel);
  const serverImports = SERVER_IMPORT_RE.test(text);
  const clientSignals = CLIENT_SIGNAL_RE.test(text);
  if (deps.has('expo') || deps.has('react-native')) return serverImports ? 'server' : 'client';
  if (deps.has('next')) {
    if (/(?:^|\/)(?:src\/)?pages\/(?!api\/)/.test(rel)) return 'client';
    if (clientSignals) return 'client';
    if (serverImports || /process\.env\.(?!NEXT_PUBLIC_)[A-Z]/.test(text)) return 'server';
    return 'unknown';
  }
  if (deps.has('@sveltejs/kit')) {
    if (/\.svelte$/.test(rel) || /\+(?:page|layout)\.[jt]s$/.test(rel)) return 'client';
  }
  if (deps.has('nuxt') && /(?:^|\/)(?:pages|components|composables|layouts|plugins)\//.test(rel)) return 'client';
  if (isSpa(deps) && /(?:^|\/)src\//.test(rel)) return serverImports ? 'server' : 'client';
  if (/\.(?:jsx|tsx|vue|svelte)$/.test(rel) && !serverImports) return 'client';
  if (CLIENT_DIR_RE.test(rel) && !serverImports) return 'client';
  if (clientSignals && !serverImports) return 'client';
  if (serverImports) return 'server';
  return 'unknown';
}

module.exports = {
  loadRepo,
  runGit,
  ENV_FILE_RE,
  JS_EXT,
  SERVER_IMPORT_RE,
  CLIENT_SIGNAL_RE,
  _clearCache: () => cache.clear(),
};
