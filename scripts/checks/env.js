'use strict';

/**
 * Env files: SEC-02 (.env tracked by git / inside a public web root / not gitignored) and
 * SEC-08 (secrets behind public env prefixes, or bundler config that ships process.env).
 */

const { loadRepo } = require('../lib/repo');
const P = require('../lib/patterns');
const { pass, fail, warn, na, ev } = require('../lib/result');
const { entropy } = require('../lib/util');

const IDS = ['SEC-02', 'SEC-08'];

// Folders a host serves as static files (plus build output, handled via f.build).
const PUBLIC_ROOT_RE = /(?:^|\/)(public|static|www|wwwroot|htdocs|_site)\//;
// Names that hint at a secret when the value isn't a known format.
const SECRETISH_NAME_RE = /(SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE|_KEY$|APIKEY|API_KEY|CREDENTIAL|_AUTH$|DSN_PASSWORD)/i;

async function run(root, opts = {}) {
  const repo = loadRepo(root, opts);
  return [envFilesCheck(repo), publicPrefixCheck(repo)];
}

/** KEY=value pairs with 1-based line numbers. */
function parseEnv(text) {
  const out = [];
  String(text || '')
    .split('\n')
    .forEach((raw, i) => {
      const line = raw.replace(/\r$/, '');
      const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(line);
      if (!m) return;
      let value = m[2].trim();
      if (/^['"`]/.test(value)) {
        const q = value[0];
        const end = value.indexOf(q, 1);
        value = end === -1 ? value.slice(1) : value.slice(1, end);
      } else value = value.replace(/\s+#.*$/, '').trim();
      out.push({ name: m[1], value, line: i + 1 });
    });
  return out;
}

/** Label for a secret-looking env entry, or null. */
function secretLabel(e) {
  if (!e.value || P.isPlaceholder(e.value)) return null;
  const hit = P.findSecrets(e.value)[0];
  if (hit && !hit.google) return hit.label;
  if (P.findDbUrls(e.value).some((d) => !d.placeholder)) return 'database URL with a password';
  if (/^eyJ/.test(e.value) && P.supabaseRole(e.value) === 'anon') return null;
  if (SECRETISH_NAME_RE.test(e.name) && !P.PUBLIC_NAME_RE.test(e.name) && !P.PUBLIC_VALUE_RE.test(e.value) && (P.looksSecret(e.value) || e.value.length >= 16)) return `${e.name}`;
  return null;
}

/** Like secretLabel, but only provider formats and DB URLs with real passwords. */
function strongLabel(e) {
  if (!e.value || P.isPlaceholder(e.value)) return null;
  const hit = P.findSecrets(e.value)[0];
  if (hit && !hit.google) return hit.label;
  if (P.findDbUrls(e.value).some((d) => !d.placeholder && !d.local)) return 'database URL with a password';
  return null;
}

/** Example-file values that match no provider format but look like a real random secret. */
function randomLooking(e) {
  const v = e.value;
  if (!v || P.isPlaceholder(v) || P.PUBLIC_VALUE_RE.test(v) || !SECRETISH_NAME_RE.test(e.name) || P.PUBLIC_NAME_RE.test(e.name)) return false;
  if (v.length < 24 || /\s/.test(v) || /^https?:\/\//i.test(v) || /^[a-z]+(?:[_-][a-z0-9]+)+$/i.test(v)) return false; // words-with-dashes placeholders
  return entropy(v) >= 3.5;
}

function envFilesCheck(repo) {
  const files = repo.envFiles();
  if (!files.length) return na('SEC-02', 'no .env files in the repo');
  const failing = [];
  const warning = [];
  const fine = [];
  const hasGitignore = Boolean(repo.get('.gitignore'));
  for (const f of files) {
    const entries = parseEnv(repo.read(f));
    const example = repo.isEnvExample(f);
    // Example files hold placeholders by design: only provider-format secrets and real DB URLs count there.
    const secrets = entries.map((e) => ({ e, label: example ? strongLabel(e) : secretLabel(e) })).filter((x) => x.label);
    const line = secrets.length ? secrets[0].e.line : 1;
    const holds = secrets.length ? `holds ${secrets.length} secret-looking value${secrets.length > 1 ? 's' : ''} (first: ${secrets[0].label}, line ${secrets[0].e.line})` : 'holds no secret-looking values right now';
    if (example) {
      const odd = secrets.length ? [] : entries.filter(randomLooking);
      if (secrets.length) failing.push(ev(f.rel, line, `example env file contains a real-looking secret (${secrets[0].label}); example files are committed and public`));
      else if (odd.length) warning.push(ev(f.rel, odd[0].line, `example env file has a random-looking ${odd.map((e) => e.name).slice(0, 3).join(', ')} value; if it was ever used for real, rotate it (example files are committed and public)`));
      else fine.push(ev(f.rel, null, 'example file with placeholders only (fine to commit)'));
      continue;
    }
    const tracked = repo.git.isTracked(f.rel);
    const ignored = repo.git.isIgnored(f.rel);
    const pub = f.build ? f.build.root : (PUBLIC_ROOT_RE.exec(f.rel) || [])[1];
    if (pub) {
      const servedAt = f.rel.slice(f.rel.indexOf(`${pub}/`) + pub.length);
      failing.push(ev(f.rel, line, `inside a public web root (${pub}/), so it is served to anyone at ${servedAt}; ${holds}`));
      continue;
    }
    if (tracked === true) {
      const note = `committed to git${ignored ? ' (.gitignore covers it now, but tracked files stay tracked)' : ' and not covered by .gitignore'}; ${holds}`;
      (secrets.length ? failing : warning).push(ev(f.rel, line, note));
      continue;
    }
    if (!ignored) {
      const why = tracked === null ? 'not a git repo here, and no .gitignore rule covers it' : `untracked but not covered by ${hasGitignore ? '.gitignore' : 'a .gitignore (there is none)'}: one \`git add .\` away from being committed`;
      warning.push(ev(f.rel, line, `${why}; ${holds}`));
      continue;
    }
    fine.push(ev(f.rel, null, 'gitignored and untracked (good)'));
  }
  if (failing.length) return fail('SEC-02', [...failing, ...warning]);
  if (warning.length) return warn('SEC-02', warning, { question: 'Should these env files be gitignored? Do they hold (or will they hold) real secrets?' });
  return pass('SEC-02', fine);
}

function publicPrefixCheck(repo) {
  const hits = [];
  const routed = { ai: new Set(), 'service-role': new Set() };
  const seen = new Set();
  const consider = (name, value, f, line, where) => {
    const deps = repo.depsFor(f.rel);
    const pp = P.publicPrefix(name, deps);
    if (!pp) return;
    const cls = P.classifyPublicEnv(name, value);
    if (!cls) return;
    if (cls !== 'secret') {
      routed[cls].add(name);
      return;
    }
    const key = `${name}|${f.rel}`;
    if (seen.has(key)) return;
    seen.add(key);
    hits.push(ev(f.rel, line, `${name} ${where}; the ${pp.prefix} prefix tells ${pp.framework} to inline it into the browser bundle`, repo.snippet(f, line)));
  };

  for (const f of repo.envFiles()) {
    const example = repo.isEnvExample(f);
    for (const e of parseEnv(repo.read(f))) consider(e.name, example ? '' : e.value, f, e.line, 'looks secret');
  }

  const refRe = /\b(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]*)/g;
  for (const { f, m, line } of repo.matches(repo.sources({ kinds: ['code', 'markup'], tests: false }), refRe)) consider(m[1], '', f, line, 'is read in code and looks secret');

  // Bundler config that hands the whole environment to the browser.
  const configs = repo.files.filter((f) => !f.build && /^(?:vite|vitest)\.config\.[cm]?[jt]s$|^webpack[\w.-]*\.config\.[cm]?[jt]s$|^next\.config\.[cm]?[jt]s$|^rsbuild\.config\.[cm]?[jt]s$|^craco\.config\.[cm]?js$|^astro\.config\.[cm]?[jt]s$/.test(f.name));
  for (const f of configs) {
    const text = repo.code(f) || '';
    const allVarsLoaded = /loadEnv\((?:[^()]|\([^()]*\))*,\s*(['"`])\1\s*\)/.test(text); // loadEnv(mode, root, '') = every variable, not just VITE_*
    for (const m of text.matchAll(/['"]process\.env['"]\s*:\s*(?!\{)([^,}\n]+)/g)) {
      const value = m[1].trim();
      const dumpsAll = /^(?:process\.env|JSON\.stringify\(\s*process\.env\s*\))/.test(value) || (/^(?:JSON\.stringify\(\s*)?\w+/.test(value) && allVarsLoaded);
      if (!dumpsAll) continue;
      const line = repo.lineOf(f, m.index);
      if (repo.suppressed(f, line)) continue;
      hits.push(ev(f.rel, line, `'process.env' is defined as the whole environment, so every variable (secrets included, prefix or not) is compiled into the client bundle`, repo.snippet(f, line)));
    }
    if (/^next\.config\./.test(f.name)) {
      const envBlock = /\benv\s*:\s*\{([\s\S]*?)\}/.exec(text);
      if (envBlock) {
        for (const k of envBlock[1].matchAll(/\b([A-Z][A-Z0-9_]*)\s*:/g)) {
          if (!P.SECRET_ENV_NAME_RE.test(k[1]) && !P.AI_ENV_NAME_RE.test(k[1]) && !P.SERVICE_ROLE_NAME_RE.test(k[1])) continue;
          const line = repo.lineOf(f, envBlock.index + envBlock[0].indexOf(k[0]));
          hits.push(ev(f.rel, line, `next.config \`env\` exposes ${k[1]}; values listed in \`env\` are inlined into client JavaScript`, repo.snippet(f, line)));
        }
      }
    }
  }

  const also = [];
  if (routed.ai.size) also.push(`Also found public-prefixed AI keys (${[...routed.ai].join(', ')}): reported under AI-03.`);
  if (routed['service-role'].size) also.push(`Also found public-prefixed service-role keys (${[...routed['service-role']].join(', ')}): reported under DATA-02.`);
  if (hits.length) return fail('SEC-08', [...hits, ...also]);
  return pass('SEC-08', also.length ? also : ['No secret-looking variables behind NEXT_PUBLIC_/VITE_/REACT_APP_/EXPO_PUBLIC_-style prefixes, and no bundler config that ships process.env.']);
}

module.exports = { name: 'env', ids: IDS, run, parseEnv, secretLabel };
