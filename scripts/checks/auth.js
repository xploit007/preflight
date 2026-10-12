'use strict';

/**
 * Auth & access (agent-guided): AUTH-01…AUTH-10. These are heuristics over discovered routes
 * and server code. Most findings are warn/manual with a precise question; only patterns that
 * are unambiguous (plaintext password comparison, jwt.decode without verify, Math.random
 * reset tokens, admin routes with no auth anywhere) fail.
 */

const { loadRepo } = require('../lib/repo');
const { getRoutes, segments, routeBody } = require('../lib/routes');
const { AUTH_RE, ROLE_RE } = require('../lib/primitives');
const net = require('../lib/net');
const { pass, fail, warn, manual, na, ev } = require('../lib/result');
const { splitArgs, literalValue } = require('../lib/util');
const { collectColumns } = require('./data');

const IDS = ['AUTH-01', 'AUTH-02', 'AUTH-03', 'AUTH-04', 'AUTH-05', 'AUTH-06', 'AUTH-07', 'AUTH-08', 'AUTH-09', 'AUTH-10'];

// Routes that are public by design (auth flows, webhooks with signatures, health checks, public forms).
const PUBLIC_PATH_RE = /(?:^|\/)(?:login|log-in|logout|signin|sign-in|signup|sign-up|register|auth|oauth|callback|forgot[\w-]*|reset[\w-]*|verify[\w-]*|confirm[\w-]*|magic[\w-]*|otp|webhooks?|[\w-]*webhook[\w-]*|health|healthz|status|ping|ready|version|robots\.txt|sitemap[\w.]*|og|contact|subscribe|newsletter|waitlist|unsubscribe|csp-report|cron)(?:\/|$|\.)/i;
const SENSITIVE_GET_RE = /(?:^|\/)(?:users?|me|account|accounts|admin|orders?|payments?|invoices?|billing|profiles?|messages?|settings|customers?|notes|documents|files|exports?|reports?|subscriptions?|transactions?|conversations?|chats?)(?:\/|$)/i;
const ADMIN_PATH_RE = /(?:^|\/)(?:admin|internal|staff|superuser|super-admin|backoffice|back-office|moderation|moderator|ops)(?:\/|$)/i;
const MANAGED_AUTH_RE = /\bsupabase\.auth\.|\.auth\.(?:getUser|getSession|signInWith\w+|signUp)\b|@clerk\/|next-auth|@auth\/|firebase\/auth|firebase-admin\/auth|getAuth\(|@auth0\/|better-auth|\blucia\b|@kinde-oss\/|@workos-inc\/|@stackframe\/|@descope\/|supertokens|aws-amplify|@stytch\//;
const USER_OWNED_TABLES = new Set(['users', 'profiles', 'accounts', 'orders', 'payments', 'invoices', 'messages', 'notes', 'todos', 'documents', 'files', 'subscriptions', 'carts', 'addresses', 'transactions', 'conversations', 'chats', 'bookings', 'appointments', 'tickets', 'uploads']);
// Strict ownership predicates (stronger than "references the user somewhere").
const OWNERSHIP_RE = /\.eq\(\s*['"`](?:user_?id|owner_?id|author_?id|created_?by|profile_?id|customer_?id|member_?id)['"`]|\b(?:userId|ownerId|authorId|user_id|owner_id|author_id|createdBy|created_by|customerId)\s*:\s*(?:req\.user|session|user|ctx|locals|auth|currentUser|claims)|\bAND\s+"?(?:user_id|owner_id|author_id|created_by)"?\s*=|\b(?:WHERE)\s+"?(?:user_id|owner_id|author_id|created_by)"?\s*=|\.(?:user_?id|owner_?id|author_?id|userId|ownerId)\s*[!=]==?\s*(?:req\.user|session\.user|user|currentUser)\??\.id|auth\.uid\(\)|\buserClient\(|\bcreateServerClient\(|\bcreateRouteHandlerClient\(|\bcreateServerComponentClient\(/;

async function run(root, opts = {}) {
  const repo = loadRepo(root, opts);
  const { routes, nextMiddleware } = getRoutes(repo);
  const server = repo.sources({ kinds: ['code'], tests: false, js: true }).filter((f) => repo.side(f) !== 'client' && !repo.isTooling(f));
  const ctx = { repo, routes, nextMiddleware, server, opts };
  return [weakAuth(ctx), missingAuthz(ctx), crossUser(ctx), adminRoutes(ctx), passwordReset(ctx), sessions(ctx), idor(ctx), massAssignment(ctx), oauth(ctx), await cookies(ctx)];
}

const chain = (r) => `${r.mountMiddleware || ''}\n${routeBody(r)}`;

function isProtected(ctx, r) {
  if (AUTH_RE.test(chain(r))) return true;
  const mw = ctx.nextMiddleware;
  if (mw && mw.auth && mw.covers(r.path) && /^(?:next|server-action)/.test(r.framework)) return true;
  return false;
}

const isWrite = (r) => ['POST', 'PUT', 'PATCH', 'DELETE', 'ANY', 'ALL'].includes(r.method);
const routeLabel = (r) => `${r.method === 'ANY' || r.method === 'ALL' ? 'ANY' : r.method} ${r.path}`;
/** Absolute line of an offset inside a route segment. */
const lineIn = (repo, seg, offset) => repo.lineOf(seg.file, seg.start + offset);

// ── AUTH-01 ────────────────────────────────────────────────────────────────

function weakAuth({ repo, server, routes }) {
  const bad = [];
  const soft = [];
  let customAuth = false;
  const rules = [
    { re: /createHash\(\s*['"`](md5|sha1|sha256|sha512)['"`]\s*\)\s*\.update\(\s*([^)]*)\)/g, test: (m) => /pass(?:word)?|pwd/i.test(m[2]), note: (m) => `password hashed with fast unsalted ${m[1]}`, list: bad },
    { re: /\b\w+\??\.(?:password|passwd|pwd)\s*(?:===?|!==?)\s*[\w.]+/g, test: (m) => !/confirm|repeat|again/i.test(m[0]), note: () => 'password compared as plaintext, so passwords are stored unhashed', list: bad },
    { re: /\b(?:password|passwd|pwd)\s*(?:===?|!==?)\s*\w+\??\.(?:password|passwd|pwd)\b/g, test: () => true, note: () => 'password compared as plaintext, so passwords are stored unhashed', list: bad },
    { re: /\bbcrypt(?:js)?\.(?:hash|hashSync)\(\s*[^,]+,\s*([0-9]+)\s*\)|\bgenSalt(?:Sync)?\(\s*([0-9]+)\s*\)/g, test: (m) => Number(m[1] || m[2]) < 10, note: (m) => `bcrypt cost ${m[1] || m[2]} is below 10`, list: soft },
    { re: /\bpassword[\w.]*\.length\s*<\s*([1-7])\b/gi, test: () => true, note: (m) => `passwords as short as ${m[1]} characters are accepted`, list: soft },
    { re: /\bpassword\s*:\s*z\.string\(\)[^,}\n]*\.min\(\s*([1-7])\s*[,)]/g, test: () => true, note: (m) => `password schema allows ${m[1]}-character passwords`, list: soft },
  ];
  for (const f of server) {
    const text = repo.code(f) || '';
    if (/\b(?:bcrypt|argon2|scrypt|pbkdf2)\b|createHash\(/.test(text) && /password/i.test(text)) customAuth = true;
    for (const rule of rules) {
      for (const m of text.matchAll(rule.re)) {
        if (!rule.test(m)) continue;
        const line = repo.lineOf(f, m.index);
        if (repo.suppressed(f, line)) continue;
        customAuth = true;
        rule.list.push(ev(f.rel, line, rule.note(m), repo.snippet(f, line)));
      }
    }
  }
  const loginRoutes = routes.filter((r) => /(?:^|\/)(?:login|signin|sign-in|log-in|register|signup|sign-up)(?:\/|$)/i.test(r.path));
  const managed = repo.files.some((f) => !f.build && f.kind === 'code' && MANAGED_AUTH_RE.test(repo.code(f) || '')) || repo.hasDepMatching(/^(?:@clerk\/|next-auth$|@auth\/|@auth0\/|better-auth$|lucia$|@kinde-oss\/|@workos-inc\/|@stackframe\/|@descope\/|supertokens)/);
  if (bad.length) return fail('AUTH-01', [...bad, ...soft]);
  if (soft.length) return warn('AUTH-01', soft);
  if (customAuth || (loginRoutes.length && !managed)) {
    return manual('AUTH-01', loginRoutes.length ? loginRoutes.map((r) => ev(r.file.rel, r.line, `custom ${routeLabel(r)} handler`)) : ['Custom password handling found (bcrypt/argon2/scrypt or hashing code).'], { question: 'For these login/signup handlers: are passwords hashed with argon2id or bcrypt (cost 12 or more), compared with the library\'s verify function, at least 8 characters long, and are failed logins throttled per account and IP?' });
  }
  if (managed) return pass('AUTH-01', ['Authentication is handled by a managed provider; no custom password storage or comparison found.']);
  return na('AUTH-01', 'no login, signup or password handling code found');
}

// ── AUTH-02 ────────────────────────────────────────────────────────────────

function missingAuthz(ctx) {
  const { routes } = ctx;
  if (!routes.length) return na('AUTH-02', 'no server routes found (if the browser talks to Supabase/Firebase directly, access control is RLS/rules: see DATA-01 and DATA-03)');
  const open = [];
  let considered = 0;
  for (const r of routes) {
    if (PUBLIC_PATH_RE.test(r.path)) continue;
    const sensitiveGet = (r.method === 'GET' || r.method === 'HEAD') && SENSITIVE_GET_RE.test(r.path);
    if (!isWrite(r) && !sensitiveGet) continue;
    considered++;
    if (isProtected(ctx, r)) continue;
    open.push(ev(r.file.rel, r.line, `${routeLabel(r)} has no auth check in its handler, middleware chain or mount`, ctx.repo.snippet(r.file, r.line)));
  }
  if (open.length) return warn('AUTH-02', open);
  return pass('AUTH-02', [`Checked ${considered} state-changing or user-data route(s): each has an auth check in its handler, middleware chain or mount.`]);
}

// ── AUTH-03 ────────────────────────────────────────────────────────────────

function adminClientNames(repo) {
  const names = new Set();
  for (const f of repo.sources({ kinds: ['code'], tests: false })) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/\b(?:const|let|var|export\s+const)\s+(\w+)\s*=\s*createClient\(([^;]*?)\)/g)) if (/SERVICE_?ROLE|SERVICE_?KEY|SUPABASE_SECRET|SB_SECRET/.test(m[2])) names.add(m[1]);
  }
  return names;
}

function userOwnedTables(repo) {
  const owned = new Set(USER_OWNED_TABLES);
  for (const c of collectColumns(repo)) if (/^(?:user_?id|owner_?id|author_?id|created_?by|profile_?id|customer_?id)$/.test(c.column)) owned.add(c.table);
  return owned;
}

function crossUser(ctx) {
  const { repo, routes } = ctx;
  if (!routes.length) return na('AUTH-03', 'no server routes found');
  const admins = adminClientNames(repo);
  const owned = userOwnedTables(repo);
  const hits = [];
  for (const r of routes) {
    for (const seg of segments(r)) {
    const t = seg.text;
    // Supabase: <client>.from('t').select(…) chains with no owner filter, run with an RLS-bypassing client.
    for (const m of t.matchAll(/\b(\w+)(?:\([^)]*\))?\s*\.from\(\s*['"`](\w+)['"`]\s*\)\s*\.select\(([^)]*)\)((?:\s*\.\s*\w+\([^)]*\))*)/g)) {
      const [, client, table, , rest] = m;
      if (!admins.has(client)) continue;
      if (/\.eq\(\s*['"`]id['"`]|\.single\(|\.maybeSingle\(/.test(rest)) continue; // single lookups: AUTH-07
      if (OWNERSHIP_RE.test(rest) || !owned.has(table.toLowerCase())) continue;
      hits.push(ev(seg.file.rel, lineIn(repo, seg, m.index), `${routeLabel(r)} lists ${table} with the service-role client and no owner filter`, repo.snippet(seg.file, lineIn(repo, seg, m.index))));
    }
    // Raw SQL: SELECT … FROM <user-owned table> with no WHERE on an owner column.
    for (const m of t.matchAll(/(['"`])\s*SELECT\b((?:(?!\1)[\s\S])*?)\bFROM\s+"?(\w+)"?((?:(?!\1)[\s\S])*)\1/gi)) {
      const table = m[3].toLowerCase();
      const tail = m[4];
      if (!owned.has(table)) continue;
      // Lookups by an identity column (id, email, username, token…) are single-record reads, not listings.
      if (/\bWHERE\b/i.test(tail) && (/\b(?:id|email|username|user_name|slug|token|reset_token|api_key|uuid)\s*=\s*(?:\$\d|\?|:\w+|'\$\{)/i.test(tail) || OWNERSHIP_RE.test(tail) || /\b(?:user_id|owner_id|author_id)\b/i.test(tail))) continue;
      hits.push(ev(seg.file.rel, lineIn(repo, seg, m.index), `${routeLabel(r)} runs SELECT on ${table} without filtering by the signed-in user`, repo.snippet(seg.file, lineIn(repo, seg, m.index))));
    }
    // Prisma findMany() without a user-scoped where; Mongo find({}).
    for (const m of t.matchAll(/\.(\w+)\.findMany\(\s*(\{[\s\S]{0,400}?\})?\s*\)/g)) {
      if (m[2] && /\bwhere\b/.test(m[2]) && OWNERSHIP_RE.test(m[2])) continue;
      if (!owned.has(m[1].toLowerCase()) && !owned.has(`${m[1].toLowerCase()}s`)) continue;
      hits.push(ev(seg.file.rel, lineIn(repo, seg, m.index), `${routeLabel(r)} calls ${m[1]}.findMany() without a user-scoped where`, repo.snippet(seg.file, lineIn(repo, seg, m.index))));
    }
    for (const m of t.matchAll(/\b(\w+)\.find\(\s*(?:\{\s*\})?\s*\)/g)) {
      if (/^(?:array|arr|list|items|rows|data|results|\w+s)$/i.test(m[1]) && !/^[A-Z]/.test(m[1])) continue; // Array.prototype.find on a list
      hits.push(ev(seg.file.rel, lineIn(repo, seg, m.index), `${routeLabel(r)} returns every document from ${m[1]}`, repo.snippet(seg.file, lineIn(repo, seg, m.index))));
    }
    }
  }
  if (hits.length) return warn('AUTH-03', hits);
  return pass('AUTH-03', ['No server-side list queries on user-owned tables without an owner filter (or an RLS-scoped client) found.']);
}

// ── AUTH-04 ────────────────────────────────────────────────────────────────

function adminRoutes(ctx) {
  const { repo, routes, nextMiddleware } = ctx;
  const bad = [];
  const soft = [];
  let found = 0;
  for (const r of routes) {
    if (!ADMIN_PATH_RE.test(r.path) && !/(?:^|\/)admin[\w-]*\.[cm]?[jt]s$|(?:^|\/)admin\//.test(r.file.rel)) continue;
    found++;
    const c = chain(r);
    if (ROLE_RE.test(c)) continue;
    if (isProtected(ctx, r)) soft.push(ev(r.file.rel, r.line, `${routeLabel(r)} checks that a user is signed in but not that they are an admin`, repo.snippet(r.file, r.line)));
    else bad.push(ev(r.file.rel, r.line, `${routeLabel(r)} has no authentication or role check anywhere in its chain`, repo.snippet(r.file, r.line)));
  }
  // Admin pages: protection has to happen on the server, not in a client redirect.
  for (const f of repo.sources({ kinds: ['code'], tests: false, js: true })) {
    if (!/(?:^|\/)(?:app|pages|routes|src\/pages|src\/routes|src\/app)\/(?:\([^)]*\)\/)?admin(?:\/|\.|$)|(?:^|\/)Admin[\w]*\.(?:jsx|tsx|vue|svelte)$/.test(f.rel)) continue;
    if (/(?:^|\/)api\//.test(f.rel) || /route\.[cm]?[jt]s$|\+server\./.test(f.rel)) continue;
    const uiFile = /\.(?:jsx|tsx|vue|svelte|astro)$/.test(f.rel) || /(?:^|\/)page\.[cm]?[jt]sx?$/.test(f.rel);
    if (!uiFile || repo.side(f) === 'server') continue; // routers are covered above; this is for UI pages
    found++;
    const text = repo.code(f) || '';
    const serverGuard = repo.side(f) !== 'client' && (ROLE_RE.test(text) || AUTH_RE.test(text));
    const mwGuard = nextMiddleware && nextMiddleware.auth && nextMiddleware.covers('/admin');
    if (serverGuard || mwGuard) continue;
    soft.push(ev(f.rel, 1, repo.side(f) === 'client' ? 'admin page is a client component: any redirect here is cosmetic, so the server routes it calls must check the admin role' : 'admin page with no server-side role check'));
  }
  if (!found) return na('AUTH-04', 'no admin, internal or staff routes or pages found');
  if (bad.length) return fail('AUTH-04', [...bad, ...soft]);
  if (soft.length) return warn('AUTH-04', soft);
  return pass('AUTH-04', [`${found} admin route(s)/page(s) found, each behind a server-side role check.`]);
}

// ── AUTH-05 ────────────────────────────────────────────────────────────────

function passwordReset({ repo, server, routes }) {
  const bad = [];
  const soft = [];
  let custom = false;
  let managed = false;
  const resetFiles = new Set(routes.filter((r) => /forgot|reset|recover/i.test(r.path)).map((r) => r.file.rel));
  for (const f of server) {
    const text = repo.code(f) || '';
    if (/resetPasswordForEmail|sendPasswordResetEmail|\bforgotPassword\(\s*\{|resetPassword\(\s*\{|@clerk\//.test(text)) managed = true;
    const resetCtx = resetFiles.has(f.rel) || /reset_?token|resetPasswordToken|passwordResetToken|forgot.?password/i.test(text);
    for (const m of text.matchAll(/\b(?:const|let|var)\s+(\w*(?:token|code|otp|secret|reset|nonce|salt|pin|invite|verification)\w*)\s*=\s*[^;\n]*\b(Math\.random\(\)|Date\.now\(\))/gi)) {
      const line = repo.lineOf(f, m.index);
      if (repo.suppressed(f, line)) continue;
      custom = true;
      bad.push(ev(f.rel, line, `"${m[1]}" is generated with ${m[2]}, which is predictable`, repo.snippet(f, line)));
    }
    if (!resetCtx) continue;
    custom = true;
    for (const m of text.matchAll(/\$\{\s*req\.(?:headers\.host|headers\[['"]host['"]\]|get\(\s*['"]host['"]\s*\)|hostname|headers\.origin)\s*\}/g)) {
      const line = repo.lineOf(f, m.index);
      soft.push(ev(f.rel, line, 'reset link is built from the request Host header (an attacker can point it at their domain)', repo.snippet(f, line)));
    }
    for (const m of text.matchAll(/['"`][^'"`\n]*(?:user not found|no user|not registered|does not exist|doesn't exist|no account|unknown email)[^'"`\n]*['"`]/gi)) {
      const line = repo.lineOf(f, m.index);
      soft.push(ev(f.rel, line, 'reset flow tells callers whether an email is registered (user enumeration)', repo.snippet(f, line)));
    }
    if (/reset_?token|resetPasswordToken|passwordResetToken/i.test(text) && !/expir|ttl|valid_?until|validUntil/i.test(text)) {
      const idx = text.search(/reset_?token|resetPasswordToken|passwordResetToken/i);
      soft.push(ev(f.rel, repo.lineOf(f, idx), 'reset tokens are stored with no expiry', repo.snippet(f, repo.lineOf(f, idx))));
    }
  }
  if (bad.length) return fail('AUTH-05', [...bad, ...soft]);
  if (soft.length) return warn('AUTH-05', soft);
  if (custom) return manual('AUTH-05', [...resetFiles].map((rel) => ev(rel, null, 'custom password reset flow')), { question: 'Is the reset token from crypto.randomBytes/randomUUID, stored only as a hash, single-use, and expired within an hour?' });
  if (managed) return pass('AUTH-05', ['Password reset is handled by the auth provider; check that its redirect URL allowlist only contains your domains.']);
  return na('AUTH-05', 'no password reset flow found');
}

// ── AUTH-06 ────────────────────────────────────────────────────────────────

function sessions({ repo, server }) {
  const bad = [];
  const soft = [];
  let any = false;
  const all = repo.sources({ kinds: ['code'], tests: false, js: true });
  for (const f of server) {
    const text = repo.code(f) || '';
    const add = (list, index, note) => {
      const line = repo.lineOf(f, index);
      if (!repo.suppressed(f, line)) list.push(ev(f.rel, line, note, repo.snippet(f, line)));
    };
    if (/jsonwebtoken|\bjwt\./.test(text)) any = true;
    for (const m of text.matchAll(/\b(?:jwt|jsonwebtoken)\.decode\(/g)) if (!/\.verify\(/.test(text)) add(bad, m.index, 'jwt.decode() is used without jwt.verify(): any forged token is accepted');
    for (const m of text.matchAll(/\balgorithms?\s*:\s*\[?\s*['"]none['"]/gi)) add(bad, m.index, 'JWT algorithm "none" accepted');
    for (const m of text.matchAll(/\bignoreExpiration\s*:\s*true/g)) add(bad, m.index, 'JWT expiry is ignored');
    for (const m of text.matchAll(/\b(?:jwt|jsonwebtoken)\.sign\(/g)) {
      const call = splitArgs(text, m.index + m[0].length - 1);
      if (!call) continue;
      const optsArg = call.args[2] ? call.args[2].text : '';
      const payload = call.args[0] ? call.args[0].text : '';
      const exp = /expiresIn\s*:\s*(['"`]?)(\d+)\s*([a-z]*)\1/i.exec(optsArg);
      if (!/expiresIn/.test(optsArg) && !/\bexp\s*:/.test(payload)) add(soft, m.index, 'jwt.sign() sets no expiresIn: these tokens never expire');
      else if (exp) {
        const n = Number(exp[2]);
        const unit = (exp[3] || 's').toLowerCase();
        const days = /^y/.test(unit) ? n * 365 : /^w/.test(unit) ? n * 7 : /^d/.test(unit) ? n : /^h/.test(unit) ? n / 24 : /^m(?!s)/.test(unit) ? n / 1440 : n / 86400;
        if (days > 30) add(soft, m.index, `tokens live for ${exp[2]}${exp[3] || 's'} (over 30 days)`);
      }
    }
    if (/express-session/.test(text)) {
      any = true;
      for (const m of text.matchAll(/\bsession\(\s*\{/g)) {
        const body = text.slice(m.index, m.index + 1200);
        if (!/\bstore\s*:/.test(body)) add(soft, m.index, 'express-session uses the default MemoryStore (leaks memory, logs everyone out on restart, not for production)');
      }
    }
  }
  for (const f of all) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/\blocalStorage\.setItem\(\s*['"`](\w*(?:token|jwt|auth|session|access|refresh)\w*)['"`]/gi)) {
      any = true;
      const line = repo.lineOf(f, m.index);
      if (!repo.suppressed(f, line)) soft.push(ev(f.rel, line, `auth token "${m[1]}" is stored in localStorage, where any XSS can read it`, repo.snippet(f, line)));
    }
  }
  if (bad.length) return fail('AUTH-06', [...bad, ...soft]);
  if (soft.length) return warn('AUTH-06', soft);
  if (!any) return na('AUTH-06', 'no custom JWT or session handling found (managed auth providers handle expiry and rotation)');
  return pass('AUTH-06', ['JWTs are verified and expire; no tokens in localStorage; sessions use a persistent store.']);
}

// ── AUTH-07 ────────────────────────────────────────────────────────────────

function idor(ctx) {
  const { repo, routes } = ctx;
  if (!routes.length) return na('AUTH-07', 'no server routes found');
  const hits = [];
  const tainted = /req\.(?:params|query|body)\.\w+|\bparams\.\w+|\bbody\.\w+|searchParams\.get\(|\bctx\.params\.\w+|\bc\.req\.param\(|\bevent\.params\.\w+/;
  const lookups = [
    /\.eq\(\s*['"`]id['"`]\s*,\s*([^)]+)\)/g,
    /\.(?:findById|findByPk|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove)\(\s*([^),]+)/g,
    /\.(?:findUnique|findFirst|update|delete|upsert)\(\s*\{\s*where\s*:\s*\{\s*id\s*:\s*([^},]+)/g,
    /\bdoc\(\s*\w+\s*,\s*['"`]\w+['"`]\s*,\s*([^)]+)\)/g,
    /(['"`])[^'"`]*\bWHERE\s+"?id"?\s*=\s*(?:\$1|\?|:id)[^'"`]*\1\s*,\s*(\[[^\]]*\])/gi,
  ];
  for (const r of routes) {
    if (OWNERSHIP_RE.test(routeBody(r)) || ROLE_RE.test(chain(r))) continue;
    for (const seg of segments(r)) {
      for (const re of lookups) {
        for (const m of seg.text.matchAll(re)) {
          const arg = m[2] || m[1];
          if (!tainted.test(arg) && !/^\s*id\s*$/.test(arg)) continue;
          const line = lineIn(repo, seg, m.index);
          hits.push(ev(seg.file.rel, line, `${routeLabel(r)} loads or changes a record by a request-supplied id without checking who owns it`, repo.snippet(seg.file, line)));
        }
      }
    }
  }
  if (hits.length) return warn('AUTH-07', [...new Set(hits)]);
  return pass('AUTH-07', ['No id-based lookups without an ownership check (or an RLS-scoped client) found in server routes.']);
}

// ── AUTH-08 ────────────────────────────────────────────────────────────────

function massAssignment({ repo, server }) {
  const hits = [];
  const direct = /\.(?:create|insert|insertOne|insertMany|update|updateOne|updateMany|upsert|save|build|bulkCreate|findOneAndUpdate|findByIdAndUpdate|values)\(\s*(req\.body|request\.body|ctx\.request\.body|await\s+req(?:uest)?\.json\(\)|body|input|payload|data)\s*[,)]/g;
  const spread = /\{\s*\.\.\.(req\.body|request\.body|ctx\.request\.body|body|payload)\s*[,}]/g;
  const assign = /Object\.assign\(\s*\w+\s*,\s*(req\.body|request\.body|body)\s*\)/g;
  const prisma = /\bdata\s*:\s*(req\.body|request\.body|await\s+req(?:uest)?\.json\(\)|body|input|payload)\s*[,}]/g;
  const model = /\bnew\s+[A-Z]\w*\(\s*(req\.body|request\.body|body)\s*\)/g;
  for (const f of server) {
    const text = repo.code(f) || '';
    const raw = (name) => /^req|^request|^ctx|^await/.test(name) || new RegExp(`\\b(?:const|let|var)\\s+${name}\\s*=\\s*(?:await\\s+)?(?:req\\.body|request\\.body|ctx\\.request\\.body|req(?:uest)?\\.json\\(\\))`).test(text);
    for (const re of [direct, spread, assign, prisma, model]) {
      for (const m of text.matchAll(re)) {
        if (!raw(m[1].replace(/^await\s+/, 'await'))) continue;
        const line = repo.lineOf(f, m.index);
        if (repo.suppressed(f, line)) continue;
        hits.push(ev(f.rel, line, `the raw request body (${m[1]}) goes straight into a database write`, repo.snippet(f, line)));
      }
    }
  }
  if (hits.length) return warn('AUTH-08', [...new Set(hits)]);
  return pass('AUTH-08', ['No database writes that take the raw request body found.']);
}

// ── AUTH-09 ────────────────────────────────────────────────────────────────

function oauth({ repo }) {
  const flags = [];
  let used = false;
  let handRolled = false;
  const lib = repo.hasDepMatching(/^(?:next-auth|@auth\/|passport-[\w-]*oauth[\w-]*|passport-google[\w-]*|passport-github\d?|passport-facebook|passport-twitter|simple-oauth2|openid-client|arctic|@badgateway\/oauth2-client|grant|@octokit\/oauth-app|oauth4webapi)$/);
  for (const f of repo.sources({ kinds: ['code'], tests: false })) {
    const text = repo.code(f) || '';
    if (!/oauth|openid|signInWithOAuth|response_type|authorize\?|NextAuth|passport-|allowDangerousEmailAccountLinking/i.test(text)) continue;
    used = true;
    const add = (index, note) => {
      const line = repo.lineOf(f, index);
      if (!repo.suppressed(f, line)) flags.push(ev(f.rel, line, note, repo.snippet(f, line)));
    };
    for (const m of text.matchAll(/allowDangerousEmailAccountLinking\s*:\s*true/g)) add(m.index, 'accounts are linked by email without verification (allowDangerousEmailAccountLinking)');
    for (const m of text.matchAll(/\b(redirect_?uri|redirectUri|redirectTo|callback_?url|callbackURL|callbackUrl|returnTo|return_to)\b\s*[:=]\s*(?:req\.(?:query|body|params)|searchParams\.get|params\.|query\.)/gi)) add(m.index, `${m[1]} comes from the request`);
    for (const m of text.matchAll(/response_type=token\b|responseType\s*:\s*['"`]token['"`]/g)) add(m.index, 'implicit OAuth flow (tokens in the URL fragment)');
    for (const m of text.matchAll(/\b(?:callbackURL|redirect_?uri|redirectUri)\s*[:=]\s*['"`]http:\/\/(?!localhost|127\.0\.0\.1)/g)) add(m.index, 'OAuth callback over plain http');
    for (const m of text.matchAll(/(['"`])((?:(?!\1)[\s\S]){0,800}?response_type=code(?:(?!\1)[\s\S]){0,800}?)\1/g)) {
      handRolled = true;
      if (!/state=/.test(m[2])) add(m.index, 'authorize URL is built without a state parameter');
    }
    if (/new\s+URLSearchParams\(\s*\{[^}]*response_type\s*:\s*['"`]code/.test(text)) {
      handRolled = true;
      for (const m of text.matchAll(/new\s+URLSearchParams\(\s*\{([^}]*response_type\s*:\s*['"`]code[^}]*)\}/g)) if (!/\bstate\b/.test(m[1])) add(m.index, 'authorize parameters have no state');
    }
    if (/openid-client|simple-oauth2|arctic|oauth4webapi/.test(text)) handRolled = true;
  }
  if (flags.length) return warn('AUTH-09', flags);
  if (!used && !lib) return na('AUTH-09', 'no OAuth/OIDC sign-in found');
  if (handRolled) return manual('AUTH-09', ['Hand-rolled OAuth/OIDC flow found.'], { question: 'Is every redirect URI registered in the provider console an exact HTTPS URL, is a random state verified on callback, and is PKCE used?' });
  return pass('AUTH-09', ['OAuth is handled by a library that manages state/PKCE; no request-controlled redirects or dangerous account linking found. Check that redirect URIs in the provider console are exact HTTPS URLs.']);
}

// ── AUTH-10 ────────────────────────────────────────────────────────────────

const AUTHISH_COOKIE_RE = /sess|token|auth|jwt|\bsid\b|refresh|access|login|remember/i;

function parseSetCookie(header) {
  const [pair, ...attrs] = header.split(';');
  const name = pair.split('=')[0].trim();
  const flags = attrs.map((a) => a.trim().toLowerCase());
  return { name, httpOnly: flags.includes('httponly'), secure: flags.includes('secure'), sameSite: (flags.find((a) => a.startsWith('samesite=')) || '').split('=')[1] || null };
}

async function cookies(ctx) {
  const { repo, opts } = ctx;
  const bad = [];
  const soft = [];
  let any = false;
  const calls = /\b(?:res|response|reply|ctx|event|c)\.cookies?\.set\(|\bres\.cookie\(|\bcookies\(\)\.set\(|\bcookieStore\.set\(|\bsetCookie\(|\breply\.setCookie\(|\bcookie\.serialize\(|\bserialize\(\s*['"`]/g;
  for (const f of repo.sources({ kinds: ['code'], tests: false })) {
    const text = repo.code(f) || '';
    const svelte = repo.depsFor(f.rel).has('@sveltejs/kit') && /\bcookies\.set\(/.test(text);
    for (const m of text.matchAll(calls)) {
      const call = splitArgs(text, m.index + m[0].lastIndexOf('('));
      if (!call || !call.args.length) continue;
      any = true;
      const line = repo.lineOf(f, m.index);
      if (repo.suppressed(f, line)) continue;
      const args = call.args.map((a) => a.text);
      const single = args.length === 1 && args[0].startsWith('{');
      const name = single ? (/\bname\s*:\s*['"`]([^'"`]+)/.exec(args[0]) || [])[1] || '' : literalValue(args[0]) || args[0];
      const options = single ? args[0] : args.slice(2).find((a) => a.startsWith('{')) || '';
      const valueArg = single ? (/\bvalue\s*:\s*([^,}]+)/.exec(args[0]) || [])[1] || '' : args[1] || '';
      if (!AUTHISH_COOKIE_RE.test(name) && !/token|jwt|session/i.test(valueArg)) continue;
      const httpOnly = /httpOnly\s*:\s*true/i.test(options) || (svelte && !/httpOnly\s*:\s*false/i.test(options));
      const secure = /\bsecure\s*:\s*(?:true|process\.env|!dev|isProd|prod)/i.test(options) || (svelte && !/\bsecure\s*:\s*false/i.test(options));
      const sameSite = /sameSite\s*:\s*['"`]?(?:lax|strict)/i.test(options) || (svelte && !/sameSite\s*:\s*['"`]?none/i.test(options));
      const missing = [!httpOnly && 'HttpOnly', !secure && 'Secure', !sameSite && 'SameSite'].filter(Boolean);
      if (!missing.length) continue;
      (missing.includes('HttpOnly') ? bad : soft).push(ev(f.rel, line, `auth cookie "${name}" is set without ${missing.join(', ')}`, repo.snippet(f, line)));
    }
    for (const m of text.matchAll(/\bdocument\.cookie\s*=\s*[^;\n]*(?:token|jwt|session|auth)/gi)) {
      any = true;
      const line = repo.lineOf(f, m.index);
      if (!repo.suppressed(f, line)) bad.push(ev(f.rel, line, 'auth cookie is written from browser JavaScript, so it can never be HttpOnly', repo.snippet(f, line)));
    }
    if (/express-session|cookie-session/.test(text)) {
      for (const m of text.matchAll(/\b(?:session|cookieSession)\(\s*\{/g)) {
        any = true;
        const body = text.slice(m.index, m.index + 1200);
        const line = repo.lineOf(f, m.index);
        if (/httpOnly\s*:\s*false/.test(body)) bad.push(ev(f.rel, line, 'session cookie has httpOnly: false', repo.snippet(f, line)));
        if (!/\bsecure\s*:\s*(?:true|process\.env|isProd|prod|'auto'|"auto")/.test(body)) soft.push(ev(f.rel, line, 'session cookie is not marked Secure', repo.snippet(f, line)));
        if (!/sameSite\s*:\s*['"`]?(?:lax|strict)/i.test(body)) soft.push(ev(f.rel, line, 'session cookie has no SameSite setting', repo.snippet(f, line)));
      }
    }
  }
  if (opts.url && !opts.offline) {
    const res = await net.getOnce(opts.url, { timeoutMs: 10000 });
    if (!res.error && res.headers) {
      const raw = res.headers['set-cookie'] || [];
      for (const header of Array.isArray(raw) ? raw : [raw]) {
        any = true;
        const c = parseSetCookie(header);
        if (!AUTHISH_COOKIE_RE.test(c.name)) continue;
        const missing = [!c.httpOnly && 'HttpOnly', !c.secure && 'Secure', !c.sameSite && 'SameSite'].filter(Boolean);
        if (missing.length) (missing.includes('HttpOnly') ? bad : soft).push(`live ${opts.url} — Set-Cookie "${c.name}" lacks ${missing.join(', ')}`);
      }
    }
  }
  if (bad.length) return fail('AUTH-10', [...bad, ...soft]);
  if (soft.length) return warn('AUTH-10', soft);
  if (!any) return na('AUTH-10', 'the app sets no cookies itself (managed auth SDKs set their own)');
  return pass('AUTH-10', ['Auth/session cookies are set with HttpOnly, Secure and SameSite.']);
}

module.exports = { name: 'auth', ids: IDS, run, PUBLIC_PATH_RE, isProtected };
