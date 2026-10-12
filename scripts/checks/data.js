'use strict';

/**
 * Data & database beyond Supabase RLS: DATA-03 open database/storage rules, DATA-04 excessive
 * privileges, DATA-05 unencrypted sensitive data, DATA-06 tenant isolation, DATA-07 backups.
 */

const { loadRepo } = require('../lib/repo');
const { getRoutes, routeBody } = require('../lib/routes');
const { ROLE_RE } = require('../lib/primitives');
const P = require('../lib/patterns');
const { pass, fail, warn, manual, na, ev } = require('../lib/result');
const { stripSqlComments, usesSupabase } = require('./supabase');

const IDS = ['DATA-03', 'DATA-04', 'DATA-05', 'DATA-06', 'DATA-07'];

const IDENT = '(?:"?[A-Za-z_][\\w$]*"?\\.)?"?[A-Za-z_][\\w$]*"?';
const POLICY_RE = new RegExp(`\\bcreate\\s+policy\\s+(?:"[^"]*"|[\\w$]+)\\s+on\\s+(${IDENT})([\\s\\S]*?);`, 'gi');
const VIEW_RE = new RegExp(`\\bcreate\\s+(?:or\\s+replace\\s+)?view\\s+(${IDENT})([\\s\\S]*?)\\bas\\b`, 'gi');
const CREATE_FN_RE = /\bcreate\s+(?:or\s+replace\s+)?function\s+(?:"?\w+"?\.)?"?(\w+)"?/gi;

/**
 * Whole CREATE FUNCTION statements: header, body (dollar-quoted or single-quoted) and the
 * trailing options, up to the terminating semicolon. `options` excludes the body, so a
 * SECURITY DEFINER written inside a function's code doesn't count.
 */
function sqlFunctions(sql) {
  const out = [];
  for (const m of sql.matchAll(CREATE_FN_RE)) {
    let i = m.index + m[0].length;
    let options = '';
    let end = sql.length;
    for (let guard = 0; i < sql.length && guard < 200000; guard++) {
      const rest = sql.slice(i);
      const next = rest.search(/\$[A-Za-z_]*\$|'|;/);
      if (next === -1) break;
      options += rest.slice(0, next);
      const at = i + next;
      if (sql[at] === ';') {
        end = at + 1;
        break;
      }
      if (sql[at] === "'") {
        let j = at + 1;
        while (j < sql.length && !(sql[j] === "'" && sql[j + 1] !== "'")) j += sql[j] === "'" ? 2 : 1;
        i = j + 1;
      } else {
        const tag = /^\$[A-Za-z_]*\$/.exec(sql.slice(at))[0];
        const close = sql.indexOf(tag, at + tag.length);
        i = close === -1 ? sql.length : close + tag.length;
      }
    }
    out.push({ name: m[1], index: m.index, options, text: sql.slice(m.index, end) });
  }
  return out;
}
const CREATE_TABLE_BODY_RE = new RegExp(`\\bcreate\\s+(?:unlogged\\s+)?table\\s+(?:if\\s+not\\s+exists\\s+)?(${IDENT})\\s*\\(`, 'gi');

const CARD_COLUMN_RE = /^(?:card_?number|cc_?number|credit_?card(?:_?number)?|cardnum|card_?no|pan|cvv2?|cvc2?|card_?cvc|card_?cvv|card_?security_?code|security_?code)$/;
const SENSITIVE_COLUMN_RE = /^(?:ssn|social_?security(?:_?number)?|sin_?number|national_?id(?:_?number)?|passport(?:_?(?:number|no))?|tax_?id|tin|ein|drivers?_?licen[cs]e(?:_?(?:number|no))?|dl_?number|bank_?account(?:_?(?:number|no))?|account_?number|routing_?number|iban|date_?of_?birth|dob|birth_?date|medical_?\w+|diagnosis|health_?\w+)$/;
const TENANT_COLUMN_RE = /^(?:org_?id|organi[sz]ation_?id|tenant_?id|team_?id|workspace_?id|company_?id)$/;
const SAFE_SUFFIX_RE = /(?:_?(?:encrypted|enc|hash|hashed|digest|token|last4|last_4|masked|ciphertext|iv))$/;

async function run(root, opts = {}) {
  const repo = loadRepo(root, opts);
  const schema = collectColumns(repo);
  return [openRules(repo), privileges(repo), sensitiveData(repo, schema), tenants(repo, schema), backups(repo)];
}

const snake = (name) => name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/-/g, '_').toLowerCase();

/** Columns from SQL, Prisma, Drizzle and Mongoose schemas: [{ f, line, table, column }]. */
function collectColumns(repo) {
  const cols = [];
  for (const f of repo.files) {
    if (f.build || repo.isTest(f)) continue;
    const text = repo.code(f);
    if (!text) continue;
    if (f.ext === '.sql') {
      const clean = stripSqlComments(text);
      for (const m of clean.matchAll(CREATE_TABLE_BODY_RE)) {
        const table = m[1].replace(/"/g, '').split('.').pop().toLowerCase();
        let depth = 0;
        let i = m.index + m[0].length - 1;
        const start = i;
        for (; i < clean.length; i++) {
          if (clean[i] === '(') depth++;
          else if (clean[i] === ')') {
            depth--;
            if (depth === 0) break;
          }
        }
        const body = clean.slice(start + 1, i);
        let offset = start + 1;
        for (const part of body.split(/,(?![^(]*\))/)) {
          const cm = /^\s*"?([A-Za-z_][\w$]*)"?\s+([A-Za-z]\w*)/.exec(part);
          if (cm && !/^(?:constraint|primary|foreign|unique|check|exclude|like)$/i.test(cm[1])) {
            cols.push({ f, line: repo.lineOf(f, offset + part.search(/\S/)), table, column: cm[1].toLowerCase(), type: cm[2].toLowerCase() });
          }
          offset += part.length + 1;
        }
      }
    } else if (f.ext === '.prisma') {
      for (const model of text.matchAll(/\bmodel\s+(\w+)\s*\{([\s\S]*?)\n\}/g)) {
        const base = model.index + model[0].indexOf('{') + 1;
        for (const fm of model[2].matchAll(/^\s*(\w+)\s+(String|Int|BigInt|DateTime|Bytes|Decimal|Float|Json)\b/gm)) {
          cols.push({ f, line: repo.lineOf(f, base + fm.index + fm[0].search(/\S/)), table: model[1].toLowerCase(), column: snake(fm[1]), type: fm[2].toLowerCase() });
        }
      }
    } else if (f.kind === 'code' && repo.side(f) !== 'client') {
      if (/drizzle-orm/.test(text)) {
        for (const dm of text.matchAll(/\b(\w+)\s*:\s*(?:text|varchar|char|integer|bigint|numeric|date|timestamp|uuid|serial)\(\s*['"]([\w$]+)['"]/g)) {
          cols.push({ f, line: repo.lineOf(f, dm.index), table: '(drizzle)', column: dm[2].toLowerCase(), type: 'drizzle' });
        }
      }
      if (/\bnew\s+(?:mongoose\.)?Schema\s*\(/.test(text)) {
        for (const mm of text.matchAll(/\b(\w+)\s*:\s*(?:\{\s*type\s*:\s*)?(String|Number|Date|Buffer)\b/g)) {
          cols.push({ f, line: repo.lineOf(f, mm.index), table: '(mongoose)', column: snake(mm[1]), type: mm[2].toLowerCase() });
        }
      }
    }
  }
  return cols;
}

// ── DATA-03 ────────────────────────────────────────────────────────────────

function openRules(repo) {
  const bad = [];
  const soft = [];
  const add = (list, f, index, note) => {
    const line = repo.lineOf(f, index);
    if (!repo.suppressed(f, line)) list.push(ev(f.rel, line, note, repo.snippet(f, line)));
  };
  let checkedSomething = false;
  const supabase = usesSupabase(repo);
  for (const f of repo.files) {
    if (f.build) continue;
    const text = repo.code(f);
    if (!text) continue;
    if (/(?:^|\/)(?:[\w.-]*\.)?(?:firestore|storage)\.rules$|\.rules$/.test(f.rel) && /\ballow\b/.test(text)) {
      checkedSomething = true;
      const kind = /storage/.test(f.name) ? 'Storage' : 'Firestore';
      const writes = (ops) => /\b(?:write|create|update|delete)\b/.test(ops);
      for (const m of text.matchAll(/\ballow\s+([\w\s,]+?)\s*:\s*if\s+true\s*;/g)) add(writes(m[1]) ? bad : soft, f, m.index, `${kind} rule allows ${m[1].trim()} for everyone (if true)${writes(m[1]) ? '' : ': fine for public data, a leak for anything else'}`);
      for (const m of text.matchAll(/\ballow\s+([\w\s,]+?)\s*;/g)) add(writes(m[1]) ? bad : soft, f, m.index, `${kind} rule allows ${m[1].trim()} with no condition at all${writes(m[1]) ? '' : ': fine for public data, a leak for anything else'}`);
      for (const m of text.matchAll(/\bif\s+request\.time\s*<\s*timestamp\.date\(/g)) add(bad, f, m.index, `${kind} is still on test-mode rules: open to everyone until the date passes`);
      for (const m of text.matchAll(/\ballow\s+([\w\s,]+?)\s*:\s*if\s+request\.auth\s*!=\s*null\s*;/g)) add(soft, f, m.index, `${kind} rule lets any signed-in user ${m[1].trim()} every document it matches (no ownership check)`);
    }
    if (/(?:^|\/)database\.rules\.json$/.test(f.rel)) {
      checkedSomething = true;
      for (const m of text.matchAll(/"\.(read|write)"\s*:\s*(?:true|"true")/g)) add(bad, f, m.index, `Realtime Database ".${m[1]}" is true: open to everyone`);
      for (const m of text.matchAll(/"\.(read|write)"\s*:\s*"auth\s*!=\s*null"/g)) add(soft, f, m.index, `Realtime Database ".${m[1]}" only requires any signed-in user`);
    }
    if (f.ext === '.sql') {
      checkedSomething = true;
      const clean = stripSqlComments(text);
      for (const m of clean.matchAll(POLICY_RE)) {
        const body = m[2];
        const cmd = ((/\bfor\s+(all|select|insert|update|delete)\b/i.exec(body) || [])[1] || 'all').toLowerCase();
        const roles = ((/\bto\s+([\w\s,"]+?)(?:\busing\b|\bwith\b|$)/i.exec(body) || [])[1] || 'public').trim();
        const usingTrue = /\busing\s*\(\s*true\s*\)/i.test(body);
        const checkTrue = /\bwith\s+check\s*\(\s*true\s*\)/i.test(body);
        const table = m[1].replace(/"/g, '');
        if ((usingTrue || checkTrue) && cmd !== 'select') add(bad, f, m.index, `policy on ${table} lets ${roles === 'public' ? 'anyone' : roles} ${cmd === 'all' ? 'read and write' : cmd} with an always-true condition`);
        else if (usingTrue && cmd === 'select') add(soft, f, m.index, `policy on ${table} makes every row readable by ${roles === 'public' ? 'anyone, including anonymous users' : roles}`);
      }
      // Owner-privileged views and definer functions only bypass anything where the API exposes
      // the schema under RLS (Supabase/PostgREST); in a plain Postgres app they are normal.
      if (supabase) {
        for (const m of clean.matchAll(VIEW_RE)) {
          const name = m[1].replace(/"/g, '');
          if (/^(?:public\.)?\w+$/.test(name) && !/security_invoker/i.test(m[2])) add(soft, f, m.index, `view ${name} runs with its owner's privileges and bypasses RLS (add "with (security_invoker = true)")`);
        }
        for (const fn of sqlFunctions(clean)) {
          if (/\bsecurity\s+definer\b/i.test(fn.options) && !/\bset\s+search_path\b/i.test(fn.text)) add(soft, f, fn.index, `security definer function ${fn.name} has no fixed search_path`);
        }
      }
      for (const m of clean.matchAll(/insert\s+into\s+storage\.buckets\s*\(([^)]*)\)\s*values\s*\(([^)]*)\)/gi)) {
        const colsList = m[1].split(',').map((s) => s.trim().replace(/"/g, ''));
        const vals = m[2].split(',').map((s) => s.trim());
        const idx = colsList.indexOf('public');
        if (idx !== -1 && /^true$/i.test(vals[idx] || '')) add(soft, f, m.index, 'storage bucket created as public: anyone with a file URL can read it');
      }
    }
    if (f.kind === 'code') {
      for (const m of text.matchAll(/\bcreateBucket\(\s*['"`][^'"`]+['"`]\s*,\s*\{[^}]*\bpublic\s*:\s*true/g)) add(soft, f, m.index, 'storage bucket created as public');
      for (const m of text.matchAll(/\bACL\s*:\s*['"`]public-read(?:-write)?['"`]/g)) add(soft, f, m.index, 'S3 object uploaded with a public ACL');
    }
    if (f.kind === 'config' && /^docker-compose|compose\.ya?ml$/.test(f.name)) {
      checkedSomething = true;
      // trust auth is an open database once the port is reachable: fail when Postgres is published on all interfaces
      const pgPublished = /^\s*-\s*["']?(?:0\.0\.0\.0:)?\d+:5432\b/m.test(text);
      for (const m of text.matchAll(/POSTGRES_HOST_AUTH_METHOD\s*[:=]\s*["']?trust/g)) add(pgPublished ? bad : soft, f, m.index, `Postgres accepts connections without a password (trust auth)${pgPublished ? ', and its port is published on all interfaces' : ''}`);
      for (const m of text.matchAll(/xpack\.security\.enabled\s*[:=]\s*["']?false/g)) add(soft, f, m.index, 'Elasticsearch security is disabled');
      for (const m of text.matchAll(/^\s*-\s*["']?(?:0\.0\.0\.0:)?(5432|3306|27017|6379|9200|5672|1433):\d+["']?\s*$/gm)) add(soft, f, m.index, `database port ${m[1]} is published on all interfaces; on a server this is reachable from the internet`);
    }
    if (f.ext === '.tf') {
      checkedSomething = true;
      for (const m of text.matchAll(/\bpublicly_accessible\s*=\s*true/g)) add(bad, f, m.index, 'database instance is publicly accessible');
      for (const m of text.matchAll(/\bacl\s*=\s*"public-read(?:-write)?"/g)) add(soft, f, m.index, 'bucket ACL is public-read');
      for (const m of text.matchAll(/\bblock_public_(?:acls|policy)\s*=\s*false/g)) add(soft, f, m.index, 'S3 public access block is turned off');
    }
  }
  if (bad.length) return fail('DATA-03', [...bad, ...soft]);
  if (soft.length) return warn('DATA-03', soft);
  if (repo.hasDep('firebase') || repo.hasDep('firebase-admin')) {
    const hasRules = repo.files.some((f) => /\.rules$|database\.rules\.json$/.test(f.rel));
    if (!hasRules) return manual('DATA-03', ['Firebase is used, but no firestore.rules / storage.rules / database.rules.json is in the repo. The live rules are in the Firebase console.'], { question: 'Open the Firestore and Storage rules in the Firebase console: are they still the 30-day test-mode rules, or `allow read, write: if true`?' });
  }
  if (!checkedSomething) return na('DATA-03', 'no database or storage rules, SQL policies, compose files or Terraform found');
  return pass('DATA-03', ['No always-true rules, open policies, public buckets or publicly bound database ports found.']);
}

// ── DATA-04 ────────────────────────────────────────────────────────────────

const SUPERUSERS = { postgres: 'postgres', postgresql: 'postgres', cockroachdb: 'root', mysql: 'root', mariadb: 'root', mssql: 'sa', sqlserver: 'sa', mongodb: 'root|admin', 'mongodb+srv': 'root|admin' };

function privileges(repo) {
  const hits = [];
  const add = (f, index, note) => {
    const line = repo.lineOf(f, index);
    if (!repo.suppressed(f, line)) hits.push(ev(f.rel, line, note));
  };
  for (const f of repo.files) {
    if (f.build || !['code', 'config', 'env'].includes(f.kind) || repo.isTest(f) || (f.kind === 'env' && repo.isEnvExample(f))) continue;
    const text = repo.code(f);
    if (!text) continue;
    for (const d of P.findDbUrls(text)) {
      const su = SUPERUSERS[d.scheme];
      if (!su || d.local || d.placeholder) continue;
      const user = d.user.split('.')[0].toLowerCase(); // Supabase pooler users look like postgres.<project-ref>
      if (new RegExp(`^(?:${su})$`).test(user)) add(f, d.index, `connects to ${d.host} as the "${user}" superuser`);
    }
    if (f.ext === '.sql') {
      const clean = stripSqlComments(text);
      for (const m of clean.matchAll(/\balter\s+role\s+[\w"]+\s+(?:with\s+)?superuser\b|\bgrant\s+all\s+privileges\s+on\s+database\b|\bwith\s+grant\s+option\b/gi)) add(f, m.index, 'migration grants superuser-level or GRANT OPTION privileges');
    }
  }
  // Service-role Supabase clients used by request handlers that ordinary users can reach.
  const adminClients = new Map(); // rel -> [identifier]
  for (const f of repo.sources({ kinds: ['code'], tests: false })) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/\b(?:const|let|var|export\s+const)\s+(\w+)\s*=\s*createClient\(([^;]*?)\)\s*;?/g)) {
      if (/SERVICE_?ROLE|SERVICE_?KEY|SUPABASE_SECRET|SB_SECRET|sb_secret_/.test(m[2]) || P.findSecrets(m[2]).some((s) => s.id === 'supabase-service-role')) {
        adminClients.set(f.rel, [...(adminClients.get(f.rel) || []), m[1]]);
      }
    }
  }
  if (adminClients.size) {
    const { routes } = getRoutes(repo);
    for (const r of routes) {
      const text = repo.code(r.file) || '';
      const local = adminClients.get(r.file.rel) || [];
      const imported = [];
      for (const [rel, ids] of adminClients) {
        if (rel === r.file.rel) continue;
        for (const id of ids) if (new RegExp(`\\b${id}\\b`).test(text) && new RegExp(`require\\([^)]*${rel.split('/').pop().replace(/\.[^.]+$/, '')}|from\\s+['"][^'"]*${rel.split('/').pop().replace(/\.[^.]+$/, '')}`).test(text)) imported.push(id);
      }
      const body = routeBody(r);
      const handlerFile = r.handler ? r.handler.file.rel : r.file.rel;
      const handlerLocal = adminClients.get(handlerFile) || [];
      const used = [...new Set([...local, ...imported, ...handlerLocal])].filter((id) => new RegExp(`\\b${id}\\b`).test(body));
      if (!used.length) continue;
      if (ROLE_RE.test(body) || ROLE_RE.test(r.mountMiddleware || '')) continue; // admin-only route: service role is expected
      hits.push(ev(r.file.rel, r.line, `${r.method} ${r.path} uses the service-role client (${used[0]}), which bypasses RLS, in a route ordinary users can reach`, repo.snippet(r.file, r.line)));
    }
  }
  if (hits.length) return warn('DATA-04', hits);
  return pass('DATA-04', ['No superuser connection strings, broad grants, or service-role clients in user-facing routes found.']);
}

// ── DATA-05 ────────────────────────────────────────────────────────────────

function sensitiveData(repo, cols) {
  const card = [];
  const soft = [];
  for (const c of cols) {
    if (SAFE_SUFFIX_RE.test(c.column) || c.type === 'bytea') continue;
    const where = c.table && !c.table.startsWith('(') ? `${c.table}.${c.column}` : c.column;
    if (CARD_COLUMN_RE.test(c.column)) card.push(ev(c.f.rel, c.line, `card data column ${where}: storing card numbers or CVVs violates PCI DSS`));
    else if (SENSITIVE_COLUMN_RE.test(c.column)) soft.push(ev(c.f.rel, c.line, `sensitive column ${where} stored as ${c.type}; is it encrypted or tokenized?`));
  }
  const tlsOff = /sslmode=disable|\bssl\s*:\s*false\b|\brejectUnauthorized\s*:\s*false\b|\bssl_mode\s*=\s*['"]?disable/g;
  for (const f of repo.files) {
    if (f.build || !['code', 'config', 'env'].includes(f.kind) || repo.isTest(f)) continue;
    const text = repo.code(f);
    if (!text || !/postgres|mysql|mongo|redis|Pool|createConnection|sequelize|knex|prisma|DATABASE_URL/i.test(text)) continue;
    for (const m of text.matchAll(tlsOff)) {
      const line = repo.lineOf(f, m.index);
      if (repo.suppressed(f, line)) continue;
      soft.push(ev(f.rel, line, m[0].startsWith('rejectUnauthorized') ? 'database TLS certificate verification is disabled (rejectUnauthorized: false)' : 'database connection has TLS disabled', repo.snippet(f, line)));
    }
  }
  if (card.length) return fail('DATA-05', [...card, ...soft]);
  if (soft.length) return warn('DATA-05', soft);
  if (!cols.length) return pass('DATA-05', ['No schema files found to inspect (SQL, Prisma, Drizzle, Mongoose), and no DB connections with TLS disabled.']);
  return pass('DATA-05', [`Checked ${cols.length} column(s): no card data or ID/bank/health-style columns, and no DB connections with TLS disabled.`]);
}

// ── DATA-06 ────────────────────────────────────────────────────────────────

function tenants(repo, cols) {
  const tenantCols = cols.filter((c) => TENANT_COLUMN_RE.test(c.column));
  if (!tenantCols.length) return na('DATA-06', 'no tenant columns (org_id, team_id, workspace_id, tenant_id…) in the schema, so this looks single-tenant');
  const evidence = tenantCols.slice(0, 10).map((c) => ev(c.f.rel, c.line, `${c.table}.${c.column} marks a multi-tenant table`));
  const names = [...new Set(tenantCols.map((c) => c.column))];
  const fromRequest = new RegExp(`\\b(?:req\\.(?:body|query|params)|body|params|searchParams\\.get\\(\\s*['"])\\.?(?:${names.map((n) => `${n}|${n.replace(/_(\w)/g, (_, ch) => ch.toUpperCase())}`).join('|')})\\b`, 'g');
  for (const { f, line } of repo.matches(repo.sources({ kinds: ['code'], tests: false }).filter((x) => repo.side(x) !== 'client'), fromRequest)) {
    evidence.push(ev(f.rel, line, 'tenant id is read from the request: make sure it is checked against the caller\'s memberships', repo.snippet(f, line)));
  }
  return manual('DATA-06', evidence);
}

// ── DATA-07 ────────────────────────────────────────────────────────────────

function backups(repo) {
  const dbs = [];
  const has = (d) => repo.hasDep(d);
  if (usesSupabase(repo)) dbs.push('Supabase Postgres');
  if (has('pg') || has('postgres') || has('@neondatabase/serverless') || has('@vercel/postgres')) dbs.push('Postgres');
  if (has('mysql') || has('mysql2') || has('@planetscale/database')) dbs.push('MySQL');
  if (has('mongodb') || has('mongoose')) dbs.push('MongoDB');
  if (has('@prisma/client') || has('prisma')) dbs.push('Prisma-managed database');
  if (has('drizzle-orm')) dbs.push('Drizzle-managed database');
  if (has('firebase') || has('firebase-admin')) dbs.push('Firebase (Firestore/RTDB)');
  if (has('better-sqlite3') || has('sqlite3') || has('@libsql/client')) dbs.push('SQLite/libSQL');
  if (has('redis') || has('ioredis') || has('@upstash/redis')) dbs.push('Redis');
  if (['django', 'sqlalchemy', 'psycopg2', 'psycopg', 'pymongo'].some((d) => repo.pythonDeps.has(d))) dbs.push('database via Python ORM/driver');
  if (!dbs.length && repo.files.some((f) => f.ext === '.sql' && !f.build)) dbs.push('SQL database (migrations present)');
  if (!dbs.length) return na('DATA-07', 'no database client or migrations detected');

  const found = [];
  const backupRe = /\b(?:pg_dump|pg_dumpall|pg_basebackup|mongodump|mysqldump|supabase\s+db\s+dump|litestream|wal-g|pgbackrest|restic|borg\s+create|rclone\s+(?:copy|sync))\b|\.backup\s+['"]?\w|backup_retention_period\s*=\s*(\d+)|point_in_time_recovery_enabled\s*=\s*true|snapshot_retention|BackupRetentionPeriod|EnablePointInTimeRecovery/gi;
  for (const f of repo.files) {
    if (f.build || !['code', 'config', 'doc'].includes(f.kind) && !/litestream/.test(f.name)) continue;
    if (/litestream\.ya?ml$/.test(f.name)) {
      found.push(ev(f.rel, null, 'Litestream replication config'));
      continue;
    }
    const text = repo.code(f);
    if (!text || f.kind === 'doc') continue;
    for (const m of text.matchAll(backupRe)) {
      const line = repo.lineOf(f, m.index);
      const retention = m[1] !== undefined ? Number(m[1]) : null;
      found.push(ev(f.rel, line, retention === 0 ? 'backup retention is set to 0 (backups disabled)' : `backup tooling/config: ${m[0].trim()}`));
      break;
    }
  }
  const evidence = [`Databases detected: ${[...new Set(dbs)].join(', ')}.`, ...(found.length ? found : ['No backup configuration found in the repo (provider-managed backups and PITR are configured in dashboards and aren\'t visible here).'])];
  return manual('DATA-07', evidence);
}

module.exports = { name: 'data', ids: IDS, run, collectColumns, sqlFunctions };
