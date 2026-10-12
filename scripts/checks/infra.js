'use strict';

/**
 * Infra & cost: INFRA-01 cloud misconfiguration, INFRA-02 spend caps (always a manual note),
 * INFRA-03 unbounded serverless execution, INFRA-04 rate limiting, INFRA-05 DDoS/bandwidth.
 *
 * Provider dashboards can't be seen from a repo, so nothing here claims to verify them; those
 * parts are manual notes tied to the providers detected in the repo.
 */

const { loadRepo } = require('../lib/repo');
const { getRoutes } = require('../lib/routes');
const { RATE_LIMIT_RE } = require('../lib/primitives');
const P = require('../lib/patterns');
const { pass, fail, warn, manual, na, ev } = require('../lib/result');

const IDS = ['INFRA-01', 'INFRA-02', 'INFRA-03', 'INFRA-04', 'INFRA-05'];

const SECRET_KEY_RE = /(SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE|API_?KEY|_KEY$|DATABASE_URL|DB_URL|CONNECTION_STRING|CREDENTIALS?)/i;
const PUBLICISH_KEY_RE = /(ANON|PUBLISHABLE|PUBLIC_KEY|_URL$|SITE_KEY|CLIENT_ID)/i;
const SENSITIVE_ROUTE_RE = /(?:^|\/)(?:login|signin|sign-in|signup|sign-up|register|forgot[\w-]*|reset[\w-]*|otp|verify|sms|text|chat|ai|completion[s]?|generate|ask|assistant|upload|contact|subscribe|waitlist|checkout)(?:\/|$)/i;

async function run(root, opts = {}) {
  const repo = loadRepo(root, opts);
  const detected = detectProviders(repo);
  return [misconfig(repo, detected), spendCaps(repo, detected), serverless(repo, detected), rateLimiting(repo), bandwidth(repo, detected)];
}

// ── provider detection ─────────────────────────────────────────────────────

function detectProviders(repo) {
  const find = (re) => repo.files.filter((f) => !f.build && re.test(f.name));
  const out = {
    vercel: find(/^vercel\.json$/),
    netlify: find(/^netlify\.toml$/),
    cloudflare: find(/^wrangler\.(?:toml|jsonc?)$/),
    fly: find(/^fly\.toml$/),
    render: find(/^render\.ya?ml$/),
    firebase: find(/^firebase\.json$/),
    gae: find(/^app\.ya?ml$/).filter((f) => /^\s*runtime\s*:/m.test(repo.code(f) || '')),
    serverless: find(/^serverless\.(?:ya?ml|ts|js)$/),
    railway: find(/^railway\.(?:json|toml)$/),
    docker: find(/^Dockerfile(?:\.[\w-]+)?$/),
    terraform: repo.files.filter((f) => !f.build && f.ext === '.tf'),
  };
  out.supabase = repo.hasDepMatching(/^@supabase\//) || repo.files.some((f) => /(?:^|\/)supabase\/config\.toml$/.test(f.rel));
  out.cdk = repo.hasDep('aws-cdk-lib');
  out.aws = out.terraform.some((f) => /provider\s+"aws"|resource\s+"aws_/.test(repo.code(f) || '')) || out.cdk || out.serverless.length > 0 || repo.hasDepMatching(/^@aws-sdk\//);
  out.gcp = out.terraform.some((f) => /provider\s+"google"|resource\s+"google_/.test(repo.code(f) || '')) || out.gae.length > 0;
  out.hostNames = ['vercel', 'netlify', 'cloudflare', 'fly', 'render', 'firebase', 'gae', 'railway'].filter((k) => out[k].length);
  return out;
}

const literal = (v) => v !== undefined && v !== null && String(v).trim() !== '' && !/^\$\{|^\$\(|^@|^\{\{|^env\(|ssm:|secretsmanager|^<|^\[/.test(String(v).trim()) && !P.isPlaceholder(String(v).trim());
const secretish = (k) => SECRET_KEY_RE.test(k) && !PUBLICISH_KEY_RE.test(k);

// ── INFRA-01 ───────────────────────────────────────────────────────────────

function misconfig(repo, d) {
  const bad = [];
  const soft = [];
  const at = (f, index, note, list) => {
    const line = repo.lineOf(f, index);
    if (!repo.suppressed(f, line)) list.push(ev(f.rel, line, note, repo.snippet(f, line)));
  };
  for (const f of d.vercel) {
    const text = repo.code(f) || '';
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
    if (json) {
      for (const block of [json.env, json.build && json.build.env]) {
        if (!block || typeof block !== 'object') continue;
        for (const [k, v] of Object.entries(block)) if (secretish(k) && literal(v)) at(f, text.indexOf(`"${k}"`), `${k} is set in plain text in vercel.json (committed with the repo)`, bad);
      }
      if (json.public === true) at(f, text.indexOf('"public"'), '"public": true exposes the deployment source', soft);
    }
  }
  const tomlEnv = (f, sections, note) => {
    const text = repo.code(f) || '';
    for (const sec of text.matchAll(new RegExp(`^\\s*\\[(${sections})\\]\\s*$([\\s\\S]*?)(?=^\\s*\\[|$(?![\\s\\S]))`, 'gm'))) {
      const base = sec.index + sec[0].indexOf(sec[2]);
      for (const kv of sec[2].matchAll(/^\s*([A-Za-z_][\w-]*)\s*=\s*["']([^"'\n]*)["']/gm)) if (secretish(kv[1]) && literal(kv[2])) at(f, base + kv.index, `${kv[1]} ${note}`, bad);
    }
  };
  for (const f of d.netlify) tomlEnv(f, 'build\\.environment|context\\.[\\w-]+\\.environment|context\\.[\\w-]+\\.build\\.environment|functions\\.environment', 'is set in plain text in netlify.toml');
  for (const f of d.cloudflare) {
    const text = repo.code(f) || '';
    if (/\.toml$/.test(f.name)) tomlEnv(f, 'vars|env\\.[\\w-]+\\.vars', 'is a plain-text [vars] entry: use `wrangler secret put` for secrets');
    else for (const m of text.matchAll(/"([A-Za-z_][\w-]*)"\s*:\s*"([^"\n]*)"/g)) if (/"vars"\s*:\s*\{[^}]*$/.test(text.slice(0, m.index)) && secretish(m[1]) && literal(m[2])) at(f, m.index, `${m[1]} is a plain-text vars entry: use \`wrangler secret put\``, bad);
    for (const m of text.matchAll(/^\s*["']?workers_dev["']?\s*[=:]\s*true/gm)) if (/^\s*(?:routes?|route)\s*=|"routes?"\s*:/m.test(text)) at(f, m.index, 'workers_dev = true keeps a *.workers.dev URL live next to your custom domain (it skips your zone\'s WAF and rate limits)', soft);
  }
  for (const f of d.fly) {
    tomlEnv(f, 'env', 'is set in plain text in fly.toml [env]: use `fly secrets set`');
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/^\s*force_https\s*=\s*false/gm)) at(f, m.index, 'force_https = false serves the app over plain HTTP', bad);
  }
  for (const f of d.render) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/-\s*key\s*:\s*["']?([A-Za-z_][\w-]*)["']?\s*\n\s*value\s*:\s*["']?([^"'\n]+)/g)) if (secretish(m[1]) && literal(m[2])) at(f, m.index, `${m[1]} has a literal value in render.yaml: use sync: false or generateValue`, bad);
  }
  for (const f of [...d.gae, ...d.serverless]) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/^\s+([A-Z][A-Z0-9_]*)\s*:\s*["']?([^"'\n#]+?)["']?\s*$/gm)) if (secretish(m[1]) && literal(m[2])) at(f, m.index, `${m[1]} has a literal value in ${f.name}`, bad);
  }
  for (const f of d.docker) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/^\s*(ENV|ARG)\s+([A-Za-z_][\w]*)(?:\s*=\s*|\s+)["']?([^"'\s\\]+)/gm)) {
      if (secretish(m[2]) && literal(m[3])) at(f, m.index, m[1] === 'ENV' ? `${m[2]} is baked into the image (anyone who pulls it can read it)` : `build arg ${m[2]} has a secret default (it is stored in the image history)`, m[1] === 'ENV' ? bad : soft);
    }
    if (!/^\s*USER\s+(?!root\b|0\b)\S+/m.test(text) && !/distroless|chainguard|:nonroot/.test(text)) soft.push(ev(f.rel, 1, 'the container runs as root (no USER instruction)'));
  }
  for (const f of d.terraform) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/ingress\s*\{([\s\S]*?)\}/g)) {
      const port = /from_port\s*=\s*(\d+)/.exec(m[1]);
      if (/0\.0\.0\.0\/0/.test(m[1]) && port && ['22', '3306', '5432', '27017', '6379', '3389', '9200'].includes(port[1])) at(f, m.index, `security group opens port ${port[1]} to the whole internet (0.0.0.0/0)`, soft);
    }
  }
  if (bad.length) return fail('INFRA-01', [...bad, ...soft]);
  if (soft.length) return warn('INFRA-01', soft);
  if (!d.hostNames.length && !d.docker.length && !d.terraform.length) return na('INFRA-01', 'no deployment config found (vercel.json, netlify.toml, wrangler, fly.toml, render.yaml, firebase.json, Dockerfile, Terraform…)');
  const q = {
    vercel: 'Vercel: is Deployment Protection on for preview deployments, are production env vars scoped to Production only, and do previews use a separate database?',
    netlify: 'Netlify: are deploy previews password-protected, and are env vars scoped per context (production vs. deploy-preview)?',
    cloudflare: 'Cloudflare: are secrets set with `wrangler secret put` (not [vars]), and is workers.dev disabled if you serve from a custom domain?',
    fly: 'Fly.io: are all secrets set with `fly secrets set`, and is only 80/443 exposed?',
    render: 'Render: do preview environments use separate databases, and are secret env vars marked sync: false?',
    firebase: 'Firebase: are API key restrictions and App Check enabled for the web app?',
    gae: 'App Engine: are secrets in Secret Manager rather than app.yaml?',
    railway: 'Railway: are PR environments isolated from the production database?',
  };
  const questions = d.hostNames.map((h) => q[h]).filter(Boolean);
  return manual('INFRA-01', [`Deployment config found: ${[...d.hostNames, ...(d.docker.length ? ['Docker'] : []), ...(d.terraform.length ? ['Terraform'] : [])].join(', ')}. No plaintext secrets, forced-HTTP or root-container issues in it.`], { question: questions.length ? questions.join(' ') : getQuestion() });
}

function getQuestion() {
  return 'In your hosting dashboard: are preview deployments protected, are production secrets scoped to production only, and is HTTPS enforced on every domain?';
}

// ── INFRA-02 ───────────────────────────────────────────────────────────────

function spendCaps(repo, d) {
  const notes = ['Manual: set spend caps in the provider dashboard, alerts do not stop usage.'];
  const add = (cond, text) => cond && notes.push(text);
  add(d.vercel.length, 'Vercel: Settings → Billing → Spend Management. Set an amount you can afford; on Pro, "pause production deployments" is on by default when it is reached. Hobby pauses at the free limits instead of billing.');
  add(d.netlify.length, 'Netlify: credit-based plans pause sites when credits run out. Keep auto-recharge off (the default) or capped. Legacy plans bill bandwidth overages.');
  add(d.cloudflare.length, 'Cloudflare Workers Paid has no hard spend cap: set usage notifications and keep request-heavy routes behind rate limiting rules.');
  add(d.fly.length, 'Fly.io has no spending limit: cap machine counts and autoscaling, and watch the usage dashboard.');
  add(d.render.length, 'Render: set autoscaling max instances and check bandwidth overage pricing for your plan.');
  add(d.firebase.length || repo.hasDep('firebase') || repo.hasDep('firebase-admin'), 'Firebase (Blaze): budget alerts only notify. Use spend-cap budgets where offered (Cloud Functions, App Hosting, AI Logic, Extensions), and wire a budget alert to disable billing for the rest.');
  add(d.supabase, 'Supabase: keep the Spend Cap on (the Pro default) under Organization → Billing. It blocks usage past your quota instead of billing it.');
  add(d.aws, 'AWS: Budgets only alert. Add Budget Actions (stop instances or apply an IAM deny policy) for a real cap.');
  add(d.gcp, 'Google Cloud: budgets don\'t cap spend. Connect a budget Pub/Sub notification to a function that disables billing.');
  add(repo.hasDep('openai'), 'OpenAI: use prepaid credits with auto-recharge off (or capped), and set per-project budgets and rate limits in the dashboard.');
  add(repo.hasDep('@anthropic-ai/sdk') || repo.hasDep('@ai-sdk/anthropic'), 'Anthropic: set a monthly spend limit under Console → Settings → Limits.');
  add(repo.hasDep('@google/generative-ai') || repo.hasDep('@google/genai') || repo.hasDep('@ai-sdk/google'), 'Google AI / Vertex: set quota limits on the API key\'s Google Cloud project.');
  add(repo.hasDep('twilio'), 'Twilio: add usage triggers (Console → Monitor → Usage triggers), turn on SMS Pumping Protection, and limit Messaging Geo Permissions to the countries you serve.');

  const gaps = [];
  const tfText = d.terraform.map((f) => repo.code(f) || '').join('\n');
  if (d.terraform.length && /resource\s+"aws_/.test(tfText) && !/resource\s+"aws_budgets_budget"/.test(tfText)) gaps.push(ev(d.terraform[0].rel, null, 'Terraform manages AWS resources but defines no aws_budgets_budget'));
  if (d.terraform.length && /resource\s+"google_/.test(tfText) && !/resource\s+"google_billing_budget"/.test(tfText)) gaps.push(ev(d.terraform[0].rel, null, 'Terraform manages Google Cloud resources but defines no google_billing_budget'));
  if (d.cdk && !repo.files.some((f) => !f.build && f.kind === 'code' && /CfnBudget|aws-budgets/.test(repo.code(f) || ''))) gaps.push('aws-cdk-lib is used but no CfnBudget is defined');
  if (notes.length === 1) notes.push('No hosting provider or usage-billed SDK detected from the repo. Whoever bills you per request, GB or token needs a hard cap set in their dashboard.');
  if (gaps.length) return warn('INFRA-02', [...gaps, ...notes]);
  return manual('INFRA-02', notes);
}

// ── INFRA-03 ───────────────────────────────────────────────────────────────

function serverless(repo, d) {
  const soft = [];
  const info = [];
  for (const f of d.vercel) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/"maxDuration"\s*:\s*(\d+)/g)) {
      const n = Number(m[1]);
      const line = repo.lineOf(f, m.index);
      (n >= 300 ? soft : info).push(ev(f.rel, line, n >= 300 ? `maxDuration ${n}s: every slow or abusive request can bill up to ${Math.round(n / 60)} minutes of compute` : `maxDuration ${n}s`, repo.snippet(f, line)));
    }
    for (const m of text.matchAll(/"regions"\s*:\s*\[([^\]]*)\]/g)) info.push(ev(f.rel, repo.lineOf(f, m.index), `function regions: ${m[1].replace(/\s+/g, '')} (keep them next to your database)`));
  }
  for (const f of repo.sources({ kinds: ['code'], tests: false })) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/\bexport\s+const\s+maxDuration\s*=\s*(\d+)/g)) {
      const n = Number(m[1]);
      if (n >= 300) soft.push(ev(f.rel, repo.lineOf(f, m.index), `route maxDuration ${n}s`, repo.snippet(f, repo.lineOf(f, m.index))));
    }
    for (const m of text.matchAll(/\b(?:setGlobalOptions|runWith)\(\s*\{([^}]*)\}/g)) info.push(ev(f.rel, repo.lineOf(f, m.index), `Firebase function options: ${m[1].replace(/\s+/g, ' ').trim().slice(0, 80)}`));
  }
  for (const f of d.serverless) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/^\s*timeout\s*:\s*(\d+)/gm)) if (Number(m[1]) >= 300) soft.push(ev(f.rel, repo.lineOf(f, m.index), `function timeout ${m[1]}s`));
  }
  for (const f of d.fly) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/^\s*auto_stop_machines\s*=\s*(?:false|["']off["'])/gm)) soft.push(ev(f.rel, repo.lineOf(f, m.index), 'auto_stop_machines is off: machines run (and bill) 24/7'));
    for (const m of text.matchAll(/^\s*min_machines_running\s*=\s*(\d+)/gm)) if (Number(m[1]) > 1) info.push(ev(f.rel, repo.lineOf(f, m.index), `min_machines_running = ${m[1]}`));
  }
  for (const f of d.cloudflare) {
    const text = repo.code(f) || '';
    const lim = /\[limits\][\s\S]*?cpu_ms\s*=\s*(\d+)|"limits"\s*:\s*\{[^}]*"cpu_ms"\s*:\s*(\d+)/.exec(text);
    info.push(lim ? ev(f.rel, repo.lineOf(f, lim.index), `CPU limit ${lim[1] || lim[2]} ms per request`) : ev(f.rel, null, 'no [limits] cpu_ms set: Workers Paid allows long CPU time per request'));
  }
  if (soft.length) return warn('INFRA-03', [...soft, ...info]);
  const serverlessHost = d.vercel.length || d.netlify.length || d.cloudflare.length || d.firebase.length || d.serverless.length || d.fly.length || d.render.length || repo.hasDep('next') || repo.files.some((f) => /(?:^|\/)(?:netlify|supabase)\/functions\//.test(f.rel));
  if (!serverlessHost) return na('INFRA-03', 'no serverless or autoscaling platform detected');
  return manual('INFRA-03', info.length ? info : ['No function duration, concurrency or instance limits are set in the repo, so platform defaults apply.']);
}

// ── INFRA-04 ───────────────────────────────────────────────────────────────

function rateLimiting(repo) {
  const { routes, nextMiddleware } = getRoutes(repo);
  if (!routes.length) return na('INFRA-04', 'no server routes found (if the browser calls Supabase/Firebase directly, their built-in limits apply; add rate limits to any functions you add)');
  const found = [];
  for (const f of repo.files) {
    if (f.build || repo.isTest(f) || !['code', 'config'].includes(f.kind) || f.name === 'package.json') continue;
    if (f.kind === 'code' && repo.side(f) === 'client') continue;
    const text = repo.code(f) || '';
    const m = RATE_LIMIT_RE.exec(text) || (/^wrangler\./.test(f.name) && /\[\[?(?:unsafe\.bindings|ratelimits)\]\]?[\s\S]*?(?:ratelimit|limit\s*=)/.exec(text)) || (/netlify/.test(f.rel) && /\brateLimit\s*:\s*\{/.exec(text));
    if (m) found.push({ f, line: repo.lineOf(f, m.index) });
  }
  if (!found.length) {
    return fail('INFRA-04', [`${routes.length} server route(s) and no rate limiting anywhere (no express-rate-limit, @upstash/ratelimit, rate-limiter-flexible, Arcjet, @vercel/firewall, @fastify/rate-limit, Cloudflare ratelimit binding…):`, ...routes.slice(0, 12).map((r) => ev(r.file.rel, r.line, `${r.method} ${r.path}`))]);
  }
  const chainHas = (r) => RATE_LIMIT_RE.test(`${r.mountMiddleware || ''}\n${r.text}`) || /\blimiter\b|\bratelimit\b|\brateLimiter\b/i.test(r.mountMiddleware || '');
  const globalLimiter = found.some(({ f }) => /\b(?:app|server|router)\.use\(\s*(?:['"`]\/?\*?['"`]\s*,\s*)?(?:rateLimit|limiter|rateLimiter|slowDown)\b/.test(repo.code(f) || '')) || (nextMiddleware && RATE_LIMIT_RE.test(repo.code(nextMiddleware.file) || ''));
  const uncovered = globalLimiter ? [] : routes.filter((r) => SENSITIVE_ROUTE_RE.test(r.path) && !chainHas(r));
  const where = found.slice(0, 5).map(({ f, line }) => ev(f.rel, line, 'rate limiting'));
  if (uncovered.length) return warn('INFRA-04', [...where, ...uncovered.slice(0, 10).map((r) => ev(r.file.rel, r.line, `${r.method} ${r.path} is a sensitive route with no limiter in its chain`))], { question: 'Do these login/AI/SMS/upload routes get rate limited somewhere the scanner cannot see (e.g. a WAF rule)?' });
  return pass('INFRA-04', where);
}

// ── INFRA-05 ───────────────────────────────────────────────────────────────

function bandwidth(repo, d) {
  const webApp = d.hostNames.length || repo.files.some((f) => !f.build && f.ext === '.html') || ['next', 'vite', 'express', '@sveltejs/kit', 'nuxt', 'astro', 'react-scripts'].some((x) => repo.hasDep(x));
  if (!webApp) return na('INFRA-05', 'no web app or hosting config found');
  const notes = [];
  const add = (cond, text) => cond && notes.push(text);
  add(d.vercel.length, 'Vercel: Hobby pauses projects at the free limits (no bill). Pro bills overages beyond included usage unless Spend Management pauses production first. Turn on Attack Challenge Mode in the Firewall tab during an attack. Cara\'s viral week in 2024 cost about $96K.');
  add(d.netlify.length, 'Netlify: credit-based plans pause sites when credits run out. Legacy plans bill bandwidth overages: in 2024 a DDoS on a free static site produced a $104,500 bill at $55 per 100 GB before it was waived.');
  add(d.cloudflare.length, 'Cloudflare: static asset bandwidth isn\'t billed, but Workers requests are (Paid plan, no hard cap). Use WAF rate limiting rules and bot protection.');
  add(d.fly.length, 'Fly.io: outbound bandwidth is billed per GB with no cap (about $0.02/GB in North America and Europe, more in other regions).');
  add(d.render.length, 'Render: bandwidth beyond your plan\'s included amount is billed. Cache static assets on a CDN.');
  add(d.firebase.length, 'Firebase Hosting (Blaze): bandwidth over the free quota is billed with no hard cap.');
  if (!notes.length) notes.push('Hosting provider not detected from the repo: before launch, check whether your plan pauses or bills when traffic spikes.');
  const big = repo.files.filter((f) => f.size > 2 * 1024 * 1024 && (f.build || /(?:^|\/)(?:public|static|assets|media)\//.test(f.rel))).sort((a, b) => b.size - a.size);
  for (const f of big.slice(0, 8)) notes.push(ev(f.rel, null, `${(f.size / 1048576).toFixed(1)} MB public asset; a bot downloading it in a loop multiplies your bandwidth bill (serve it from a CDN or object storage with caching)`));
  return manual('INFRA-05', notes);
}

module.exports = { name: 'infra', ids: IDS, run, detectProviders };
