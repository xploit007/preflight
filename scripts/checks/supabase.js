'use strict';

/**
 * Supabase: DATA-01 RLS (static migration analysis + optional live anon read test) and
 * DATA-02 service_role / secret keys reachable from the browser.
 *
 * The live test sends one read-only GET per table: /rest/v1/<table>?select=*&limit=1 with the
 * anon key. Rows coming back = the table is readable by anyone who has your frontend.
 */

const { loadRepo } = require('../lib/repo');
const P = require('../lib/patterns');
const net = require('../lib/net');
const { pass, fail, warn, manual, na, ev } = require('../lib/result');

const IDS = ['DATA-01', 'DATA-02'];

const IDENT = '(?:"?[A-Za-z_][\\w$]*"?\\.)?"?[A-Za-z_][\\w$]*"?';
// create table [if not exists] [schema.]name   (temp tables are never exposed, so they're skipped)
const CREATE_TABLE_RE = new RegExp(`\\bcreate\\s+(temp(?:orary)?\\s+|unlogged\\s+)?table\\s+(?:if\\s+not\\s+exists\\s+)?(${IDENT})`, 'gi');
const ENABLE_RLS_RE = new RegExp(`\\balter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?(${IDENT})\\s+enable\\s+row\\s+level\\s+security`, 'gi');
const DISABLE_RLS_RE = new RegExp(`\\balter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?(${IDENT})\\s+disable\\s+row\\s+level\\s+security`, 'gi');
const DROP_TABLE_RE = new RegExp(`\\bdrop\\s+table\\s+(?:if\\s+exists\\s+)?(${IDENT})`, 'gi');
// .from('table') in supabase-js queries
const FROM_RE = /\.from\(\s*['"`]([A-Za-z_][\w$]*)['"`]\s*\)/g;
const SERVICE_ENV_REF_RE = /\b(?:process\.env|import\.meta\.env|Deno\.env\.get\(\s*['"])\.?([A-Z0-9_]*(?:SERVICE_?ROLE|SERVICE_?KEY|SUPABASE_SECRET|SB_SECRET)[A-Z0-9_]*)/g;
const ANON_REF_RE = /\b(?:process\.env|import\.meta\.env)\.([A-Z0-9_]*(?:ANON|PUBLISHABLE)[A-Z0-9_]*)/g;
const COMMON_TABLES = ['profiles', 'users', 'accounts', 'customers', 'orders', 'payments', 'subscriptions', 'messages', 'posts', 'comments', 'notes', 'todos', 'items', 'products', 'documents', 'files', 'chats', 'conversations', 'leads', 'contacts', 'invoices', 'transactions', 'waitlist', 'feedback', 'api_keys'];

async function run(root, opts = {}) {
  const repo = loadRepo(root, opts);
  if (!usesSupabase(repo)) return [na('DATA-01', 'Supabase is not used in this repo'), na('DATA-02', 'Supabase is not used in this repo')];
  return [await rlsCheck(repo, opts), serviceRoleCheck(repo)];
}

function usesSupabase(repo) {
  return repo.hasDepMatching(/^@supabase\//) || repo.pythonDeps.has('supabase') || repo.files.some((f) => /(?:^|\/)supabase\/(?:migrations|schemas|functions)\/|(?:^|\/)supabase\/config\.toml$/.test(f.rel));
}

/** Blank out SQL comments while keeping offsets (and so line numbers) intact. */
function stripSqlComments(text) {
  return text.replace(/--[^\n]*/g, (m) => ' '.repeat(m.length)).replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
}

/** "public"."notes" / public.notes / notes → notes; other schemas → null (not exposed by default). */
function tableName(raw) {
  const parts = raw.replace(/"/g, '').split('.');
  if (parts.length === 2 && parts[0].toLowerCase() !== 'public') return null;
  return parts[parts.length - 1].toLowerCase();
}

function analyzeMigrations(repo) {
  const tables = new Map();
  const sql = repo.files.filter((f) => !f.build && f.ext === '.sql' && !repo.isTest(f));
  for (const f of sql) {
    const raw = repo.read(f);
    if (!raw) continue;
    const text = stripSqlComments(raw);
    const events = [];
    for (const m of text.matchAll(CREATE_TABLE_RE)) if (!m[1] || !/temp/i.test(m[1])) events.push({ i: m.index, kind: 'create', raw: m[2] });
    for (const m of text.matchAll(ENABLE_RLS_RE)) events.push({ i: m.index, kind: 'enable', raw: m[1] });
    for (const m of text.matchAll(DISABLE_RLS_RE)) events.push({ i: m.index, kind: 'disable', raw: m[1] });
    for (const m of text.matchAll(DROP_TABLE_RE)) events.push({ i: m.index, kind: 'drop', raw: m[1] });
    events.sort((a, b) => a.i - b.i);
    for (const e of events) {
      const name = tableName(e.raw);
      if (!name) continue;
      const at = { f, line: repo.lineOf(f, e.i) };
      const t = tables.get(name);
      if (e.kind === 'create') {
        if (!t) tables.set(name, { name, created: at, rls: false, disabled: null });
      } else if (e.kind === 'enable') {
        tables.set(name, { ...(t || { name, created: at }), rls: true, disabled: null });
      } else if (e.kind === 'disable') {
        tables.set(name, { ...(t || { name, created: at }), rls: false, disabled: at });
      } else if (e.kind === 'drop') tables.delete(name);
    }
  }
  return { tables, sqlFiles: sql.length };
}

function queriedTables(repo) {
  const names = new Set();
  for (const { m } of repo.matches(repo.sources({ kinds: ['code'], tests: false }), FROM_RE)) names.add(m[1].toLowerCase());
  return names;
}

async function liveRead(opts, names) {
  const key = opts.supabaseKey;
  const headers = { apikey: key, accept: 'application/json' };
  if (/^eyJ/.test(key)) headers.authorization = `Bearer ${key}`;
  const queue = [...names];
  const results = [];
  const worker = async () => {
    while (queue.length) {
      const t = queue.shift();
      const res = await net.get(`${opts.supabaseUrl}/rest/v1/${encodeURIComponent(t)}?select=*&limit=1`, { headers, timeoutMs: 8000, maxRedirects: 0 });
      let outcome = 'other';
      let columns = [];
      if (res.error) outcome = 'error';
      else if (res.status === 200) {
        try {
          const body = JSON.parse(res.body);
          if (Array.isArray(body) && body.length) {
            outcome = 'readable';
            columns = Object.keys(body[0] || {});
          } else outcome = 'empty';
        } catch {
          outcome = 'other';
        }
      } else if (res.status === 401 || res.status === 403) outcome = 'denied';
      else if (res.status === 404 || /PGRST205|42P01|does not exist|Could not find the table/.test(res.body || '')) outcome = 'missing';
      results.push({ t, outcome, status: res.status, error: res.error, columns });
    }
  };
  await Promise.all(Array.from({ length: Math.min(5, queue.length) }, worker));
  return results.sort((a, b) => (a.t < b.t ? -1 : 1));
}

async function rlsCheck(repo, opts) {
  const { tables, sqlFiles } = analyzeMigrations(repo);
  const evidence = [];
  const noRls = [...tables.values()].filter((t) => !t.rls);
  for (const t of noRls) {
    const at = t.disabled || t.created;
    const note = t.disabled ? `RLS explicitly disabled on public.${t.name}` : `public.${t.name} is created without "enable row level security": anyone with your anon key can read and write it`;
    evidence.push(ev(at.f.rel, at.line, note));
  }

  let live = null;
  if (opts.supabaseUrl && opts.supabaseKey) {
    if (opts.offline) evidence.push('Live check skipped: --offline.');
    else if (/^sb_secret_/.test(opts.supabaseKey) || P.supabaseRole(opts.supabaseKey) === 'service_role') {
      evidence.push('Live check refused: --supabase-key is a service-role/secret key. It bypasses RLS, so a read with it proves nothing, and it should never leave your server. Re-run with the anon/publishable key.');
    } else {
      const names = new Set([...tables.keys(), ...queriedTables(repo)]);
      if (!names.size) COMMON_TABLES.forEach((n) => names.add(n));
      live = await liveRead(opts, [...names].slice(0, 25));
      const readable = live.filter((r) => r.outcome === 'readable');
      for (const r of readable) evidence.unshift(`live: GET ${opts.supabaseUrl}/rest/v1/${r.t}?select=*&limit=1 with the anon key returned rows (columns: ${r.columns.slice(0, 12).join(', ')}): RLS is off or a SELECT policy allows anonymous reads`);
      const summary = ['readable', 'empty', 'denied', 'missing', 'error', 'other'].map((k) => [k, live.filter((r) => r.outcome === k).map((r) => r.t)]).filter(([, v]) => v.length);
      evidence.push(`live: checked ${live.length} table name(s) with the anon key: ${summary.map(([k, v]) => `${k} ${v.join(', ')}`).join('; ')}. "empty" means no rows were visible: RLS hid them, or the table is empty.`);
    }
  }

  const anonUses = [];
  for (const { f, m, line } of repo.matches(repo.sources({ kinds: ['code'], tests: false }).filter((f) => repo.side(f) === 'client'), ANON_REF_RE)) anonUses.push(`${f.rel}:${line} (${m[1]})`);
  if (anonUses.length) evidence.push(`The anon key is used in browser code at ${anonUses.slice(0, 3).join(', ')}${anonUses.length > 3 ? '…' : ''}. That is expected, and it means RLS is the only thing protecting your tables.`);

  const liveReadable = live ? live.filter((r) => r.outcome === 'readable') : [];
  if (liveReadable.length) return fail('DATA-01', evidence);
  if (noRls.length) {
    if (live && live.length) {
      const stillOpen = noRls.filter((t) => !live.some((r) => r.t === t.name && ['denied', 'empty', 'missing'].includes(r.outcome)));
      if (!stillOpen.length) {
        return warn('DATA-01', evidence, { question: 'The migrations create these tables without RLS, but the live anon read returned nothing. Was RLS enabled outside the migrations (dashboard)? Add the enable statements to your migrations so new environments are safe too.' });
      }
    }
    return fail('DATA-01', evidence);
  }
  if (tables.size) return pass('DATA-01', [`${tables.size} public table(s) in ${sqlFiles} SQL file(s), all with row level security enabled (policies are reviewed under DATA-03).`, ...evidence]);
  if (live && live.length) return pass('DATA-01', evidence);
  return manual('DATA-01', ['No CREATE TABLE statements found in SQL files (tables were probably created in the Supabase dashboard), so RLS could not be verified statically.', ...evidence]);
}

function serviceRoleCheck(repo) {
  const exposed = [];
  const soft = [];
  const files = [...repo.sources({ kinds: ['code', 'markup'], tests: false }).filter((f) => repo.side(f) === 'client'), ...repo.buildFiles()];
  for (const f of files) {
    const text = repo.read(f);
    if (!text) continue;
    for (const s of P.findSecrets(text)) {
      if (s.id !== 'supabase-service-role' && s.id !== 'supabase-secret-key') continue;
      const line = repo.lineOf(f, s.index);
      if (repo.suppressed(f, line)) continue;
      exposed.push(ev(f.rel, line, `${s.label} ${P.mask(s.value)} in ${f.build ? 'build output' : 'browser code'}`));
    }
    for (const m of (repo.code(f) || '').matchAll(SERVICE_ENV_REF_RE)) {
      const line = repo.lineOf(f, m.index);
      if (repo.suppressed(f, line)) continue;
      const pp = P.publicPrefix(m[1], repo.depsFor(f.rel));
      if (pp) exposed.push(ev(f.rel, line, `browser code reads ${m[1]}; with the ${pp.prefix} prefix ${pp.framework} inlines the service-role key into the bundle`, repo.snippet(f, line)));
      else soft.push(ev(f.rel, line, `browser code references ${m[1]} (not inlined without a public prefix, but this is a server-only key)`, repo.snippet(f, line)));
    }
  }
  for (const f of repo.envFiles()) {
    if (repo.isEnvExample(f)) continue;
    const text = repo.read(f) || '';
    text.split('\n').forEach((raw, i) => {
      const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(raw);
      if (!m) return;
      const pp = P.publicPrefix(m[1], repo.depsFor(f.rel));
      if (pp && P.classifyPublicEnv(m[1], raw.slice(raw.indexOf('=') + 1).trim()) === 'service-role') {
        exposed.push(ev(f.rel, i + 1, `${m[1]} puts a service-role key behind the ${pp.prefix} prefix, so ${pp.framework} exposes it to the browser`, P.redact(raw.trim()).slice(0, 120)));
      }
    });
  }
  if (exposed.length) return fail('DATA-02', [...exposed, ...soft]);
  if (soft.length) return warn('DATA-02', soft, { question: 'Why does browser code reference the service-role key? Move that call to a server route.' });
  return pass('DATA-02', ['No service-role or sb_secret_ keys in browser code, public env vars or build output.']);
}

module.exports = { name: 'supabase', ids: IDS, run, analyzeMigrations, stripSqlComments, usesSupabase };
