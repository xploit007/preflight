'use strict';

const { entropy } = require('./util');

/**
 * High-confidence secret formats. Each regex keys on a provider-specific prefix and shape,
 * so a hit is almost always a real credential (or a deliberately fake one in a fixture).
 *
 *   ai         AI-provider key (also reported by AI-03)
 *   lowImpact  test-mode key: reported, but alone it only produces a warn
 *   google     AIza… keys are public by design for Firebase/Maps; callers decide by context
 *   group      capture group holding the secret, when the match includes a label
 */
const SECRET_PATTERNS = [
  // AWS access key id: 4-char prefix + 16 base32 chars (AWS's documented example key is skipped).
  { id: 'aws-access-key-id', label: 'AWS access key ID', re: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b/g },
  // AWS secret access key: 40 base64 chars, only when labelled (unlabelled 40-char strings are too noisy).
  { id: 'aws-secret-access-key', label: 'AWS secret access key', re: /\baws_?secret_?access_?key\b["'`]?\s*[:=]\s*["'`]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi, group: 1 },
  // Stripe secret and restricted keys (Clerk secret keys share the sk_live_/sk_test_ prefix).
  { id: 'stripe-live-secret', label: 'Stripe live secret key', re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,247}\b/g },
  { id: 'stripe-test-secret', label: 'Stripe test secret key', re: /\b(?:sk|rk)_test_[0-9a-zA-Z]{20,247}\b/g, lowImpact: true },
  // Stripe webhook signing secret.
  { id: 'stripe-webhook-secret', label: 'Stripe webhook signing secret', re: /\bwhsec_[0-9a-zA-Z]{24,}\b/g },
  // GitHub classic/OAuth/app tokens and fine-grained PATs; GitLab PATs.
  { id: 'github-token', label: 'GitHub token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b/g },
  { id: 'github-fine-grained', label: 'GitHub fine-grained token', re: /\bgithub_pat_[A-Za-z0-9_]{60,255}\b/g },
  { id: 'gitlab-token', label: 'GitLab token', re: /\bglpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g },
  // Anthropic: sk-ant-api03-… and admin keys.
  { id: 'anthropic-key', label: 'Anthropic API key', re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g, ai: 'Anthropic' },
  // OpenRouter (checked before the generic sk- shapes).
  { id: 'openrouter-key', label: 'OpenRouter API key', re: /\bsk-or-v1-[a-f0-9]{64}\b/g, ai: 'OpenRouter' },
  // OpenAI: project / service-account / admin keys, legacy keys with the T3BlbkFJ marker, legacy 48-char keys.
  { id: 'openai-key', label: 'OpenAI API key', re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b|\bsk-[A-Za-z0-9]{48}\b/g, ai: 'OpenAI' },
  // sk- + 32 hex: DeepSeek and other OpenAI-compatible providers.
  { id: 'sk-hex-key', label: 'API key (sk-<32 hex>, e.g. DeepSeek)', re: /\bsk-[a-f0-9]{32}\b/g, ai: 'OpenAI-compatible provider' },
  { id: 'groq-key', label: 'Groq API key', re: /\bgsk_[A-Za-z0-9]{48,}\b/g, ai: 'Groq' },
  { id: 'replicate-key', label: 'Replicate API token', re: /\br8_[A-Za-z0-9]{37,}\b/g, ai: 'Replicate' },
  { id: 'huggingface-token', label: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{34,}\b/g, ai: 'Hugging Face' },
  { id: 'xai-key', label: 'xAI API key', re: /\bxai-[A-Za-z0-9]{60,}\b/g, ai: 'xAI' },
  { id: 'perplexity-key', label: 'Perplexity API key', re: /\bpplx-[A-Za-z0-9]{40,}\b/g, ai: 'Perplexity' },
  // Google API keys: public by design for Firebase/Maps, secret for Gemini. Callers decide by context.
  { id: 'google-api-key', label: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g, google: true },
  // Chat and email providers.
  { id: 'slack-token', label: 'Slack token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,250}/g },
  { id: 'slack-webhook', label: 'Slack webhook URL', re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{20,}/g },
  { id: 'discord-webhook', label: 'Discord webhook URL', re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{15,}\/[A-Za-z0-9_-]{60,}/g },
  { id: 'telegram-bot-token', label: 'Telegram bot token', re: /\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b/g },
  { id: 'twilio-api-key', label: 'Twilio API key SID', re: /\bSK[0-9a-f]{32}\b/g },
  { id: 'sendgrid-key', label: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { id: 'mailgun-key', label: 'Mailgun API key', re: /\bkey-[0-9a-f]{32}\b/g },
  // Package registries and dev platforms.
  { id: 'npm-token', label: 'npm access token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'npmrc-auth', label: '.npmrc auth token', re: /_authToken\s*=\s*(?!\$\{)([^\s'"]{16,})/g, group: 1 },
  { id: 'shopify-token', label: 'Shopify access token', re: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g },
  { id: 'linear-key', label: 'Linear API key', re: /\blin_api_[A-Za-z0-9]{40}\b/g },
  { id: 'doppler-token', label: 'Doppler token', re: /\bdp\.(?:pt|st|sa|ct)\.[A-Za-z0-9]{40,44}\b/g },
  { id: 'planetscale-token', label: 'PlanetScale token', re: /\bpscale_(?:tkn|pw|oauth)_[A-Za-z0-9_-]{32,64}\b/g },
  { id: 'mapbox-secret', label: 'Mapbox secret token', re: /\bsk\.eyJ[A-Za-z0-9_-]{20,4096}\.[A-Za-z0-9_-]{20,1024}/g },
  // Supabase new-style secret keys and personal access tokens (service_role JWTs are decoded separately).
  { id: 'supabase-secret-key', label: 'Supabase secret API key', re: /\bsb_secret_[A-Za-z0-9_-]{20,}/g, supabaseSecret: true },
  { id: 'supabase-pat', label: 'Supabase access token', re: /\bsbp_[a-f0-9]{40}\b/g },
  // PEM private keys (also covers the private_key field of Google service-account JSON files).
  { id: 'private-key', label: 'Private key block', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g },
];

/** Documentation example values that are public on purpose. */
const KNOWN_EXAMPLES = new Set(['AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY']);

/** Three base64url segments starting with eyJ = a JWT (Supabase anon and service_role keys are JWTs). */
const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,512}\.eyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,1024}/g;

/**
 * scheme://user:password@host. Group 1 scheme, 2 user, 3 password, 4 host.
 * The user part may be empty (redis://:password@host).
 */
const DB_URL_RE = /\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|cockroachdb|clickhouse)(?:\+[a-z0-9]+)?:\/\/([^:\s'"`/@]{0,128}):([^@\s'"`/]{1,256})@([^\s'"`/:?#,;)]+)/gi;

/** Hosts that only make sense on a developer machine or inside docker-compose. */
const LOCAL_HOST_RE = /^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|\[::1\]|host\.docker\.internal|db|database|postgres|postgresql|mysql|mariadb|mongo|mongodb|redis|rabbitmq|cache|[\w-]+\.local|[\w-]+\.internal|[\w.-]+\.svc(?:\.cluster\.local)?)$/i;

/**
 * Generic `name = "value"` / `name: "value"` assignment where the name looks like a credential.
 * Group 1 name, 2 quote, 3 value (8–256 non-space chars).
 */
// The name prefix is bounded ({0,40}) so long dotted/word runs in minified code can't make this quadratic.
const GENERIC_ASSIGN_RE = /\b([A-Za-z_$][\w$.-]{0,40}?(?:api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?key|password|passwd|signing[_-]?key|encryption[_-]?key|webhook[_-]?secret|bearer[_-]?token))\b["']?\s*(?::|=|:=|=>)\s*(["'`])([^"'`\s]{8,256})\2/gi;

/** Names that look secret but are public by design. */
const PUBLIC_NAME_RE = /(public|publishable|anon|site[_-]?key|client[_-]?id|recaptcha|measurement|pk_)/i;

const PLACEHOLDER_RE = /^(?:\$\{|\{\{|<|\[|%|\*+$|x{3,}|\.{3})|process\.env|import\.meta|your[_-]|example|sample|placeholder|changeme|change[_-]?me|replace|dummy|todo|xxxx|redacted|insert[_-]|enter[_-]|lorem|undefined|^null$|^none$|^true$|^false$/i;

/** Values that are public tokens by format (publishable keys, anon JWTs are checked separately). */
const PUBLIC_VALUE_RE = /^(?:pk_(?:live|test)_|pk\.eyJ|sb_publishable_|phc_|G-[A-Z0-9]{6,}$|UA-\d|AIza)/;

function isPlaceholder(value) {
  return PLACEHOLDER_RE.test(value) || /^(.)\1+$/.test(value);
}

/** Heuristic for "this literal is a real secret, not a word": length + character mix or entropy. */
function looksSecret(value) {
  if (value.length < 8) return false;
  if (/^[A-Z][A-Z0-9_]{2,}$/.test(value)) return false; // an ENV_VAR_NAME, not a value
  if (/^https?:\/\//i.test(value) && !/@/.test(value)) return false;
  if (/^[./~]/.test(value)) return false; // a path
  if (value.length >= 16 && entropy(value) >= 3.2) return true;
  const lower = /[a-z]/.test(value);
  const upper = /[A-Z]/.test(value);
  const digit = /[0-9]/.test(value);
  const symbol = /[!-/:-@[-`{-~]/.test(value);
  const classes = [lower, upper, digit, symbol].filter(Boolean).length;
  return classes >= 3 || (digit && (lower || upper));
}

/** Decode a JWT payload without verifying it. */
function decodeJwt(token) {
  const parts = String(token).split('.');
  if (parts.length < 2) return null;
  try {
    const json = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const payload = JSON.parse(json);
    return payload && typeof payload === 'object' ? payload : null;
  } catch {
    return null;
  }
}

/** Supabase JWT role, if the token is a Supabase key ('anon', 'service_role', …). */
function supabaseRole(token) {
  const p = decodeJwt(token);
  if (!p || typeof p.role !== 'string') return null;
  if (p.iss && !/supabase/i.test(String(p.iss)) && !p.ref) return null;
  return p.role;
}

/**
 * All high-confidence secrets in `text`: provider patterns plus Supabase service_role JWTs.
 * Returns [{ index, value, id, label, ai?, lowImpact?, google? }], sorted by index.
 */
function findSecrets(text) {
  const hits = [];
  for (const p of SECRET_PATTERNS) {
    for (const m of text.matchAll(p.re)) {
      const value = p.group ? m[p.group] : m[0];
      if (!value || KNOWN_EXAMPLES.has(value)) continue;
      if (p.id === 'npmrc-auth' && isPlaceholder(value)) continue;
      const index = p.group ? m.index + m[0].indexOf(value) : m.index;
      hits.push({ index, value, id: p.id, label: p.label, ai: p.ai, lowImpact: p.lowImpact, google: p.google, supabaseSecret: p.supabaseSecret });
    }
  }
  for (const m of text.matchAll(JWT_RE)) {
    if (supabaseRole(m[0]) === 'service_role') {
      hits.push({ index: m.index, value: m[0], id: 'supabase-service-role', label: 'Supabase service_role key (JWT)', supabaseSecret: true });
    }
  }
  // The generic sk-<32 hex> shape can be a substring of nothing else; keep the earliest hit per index.
  hits.sort((a, b) => a.index - b.index);
  const out = [];
  for (const h of hits) {
    const prev = out[out.length - 1];
    if (prev && h.index < prev.index + prev.value.length) continue; // overlapping, keep the first
    out.push(h);
  }
  return out;
}

/** Database URLs with inline passwords. Returns [{ index, scheme, user, password, host, local, placeholder }]. */
function findDbUrls(text) {
  const out = [];
  for (const m of text.matchAll(DB_URL_RE)) {
    const [, scheme, user, password, host] = m;
    const placeholderHost = /^(?:host|hostname|server|your[-_.]?[\w-]*|[\w.-]*example\.(?:com|org|net)|<.*>|\[.*\]|\{.*\}|x+)$/i.test(host);
    const placeholder = placeholderHost || isPlaceholder(password) || /^(?:password|pass|pwd|passwd|secret|user|username|\*+|<.*>|\[.*\])$/i.test(password);
    out.push({ index: m.index, match: m[0], scheme: scheme.toLowerCase(), user, password, host, local: LOCAL_HOST_RE.test(host), placeholder });
  }
  return out;
}

// ── Redaction: evidence must never carry a usable secret ──────────────────

const KNOWN_PREFIX_RE = /^(sk_live_|sk_test_|rk_live_|rk_test_|sk-ant-(?:api|admin)\d{2}-|sk-or-v1-|sk-proj-|sk-svcacct-|sk-admin-|sk-|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|xox[baprs]-|AKIA|ASIA|AIza|gsk_|r8_|hf_|xai-|pplx-|SG\.|key-|npm_|sb_secret_|sbp_|whsec_|eyJ|shpat_|lin_api_|dp\.pt\.|pscale_tkn_)/;

/** Keep a recognizable prefix and two chars at each end: sk_live_51…7Q. */
function mask(value) {
  const v = String(value);
  if (v.length <= 6) return `${v.slice(0, 1)}…`;
  const m = KNOWN_PREFIX_RE.exec(v);
  const prefix = m ? m[1] : '';
  const rest = v.slice(prefix.length);
  if (rest.length <= 6) return `${prefix}${rest.slice(0, 1)}…`;
  return `${prefix}${rest.slice(0, 2)}…${rest.slice(-2)}`;
}

/** Mask every secret-looking token in a line of source before it goes into evidence. */
function redact(line) {
  const masked = (v) => String(v).includes('…');
  let out = String(line);
  for (const p of SECRET_PATTERNS) {
    out = out.replace(p.re, (m, ...groups) => {
      if (p.group) {
        const g = groups[p.group - 1];
        return typeof g === 'string' ? m.replace(g, mask(g)) : mask(m);
      }
      return mask(m);
    });
  }
  out = out.replace(JWT_RE, (m) => mask(m));
  out = out.replace(DB_URL_RE, (m, scheme, user, password) => (masked(password) ? m : m.replace(`:${password}@`, `:${mask(password)}@`)));
  out = out.replace(GENERIC_ASSIGN_RE, (m, name, quote, value) => (masked(value) ? m : m.replace(value, mask(value))));
  // Quoted high-entropy blobs that don't match a known shape.
  out = out.replace(/(["'`])([A-Za-z0-9+/=_-]{24,})\1/g, (m, q, v) => (entropy(v) > 3.5 ? `${q}${mask(v)}${q}` : m));
  // KEY=value lines (env files, shell) with secret-ish names.
  out = out.replace(/\b([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE|_KEY|APIKEY)[A-Z0-9_]*)\s*=\s*(["']?)([^\s"'#]{4,})\2/g, (m, name, q, v) => (masked(v) ? m : m.replace(v, mask(v))));
  return out;
}

// ── Env var name classification ──────────────────────────────────────────

/** Prefixes that bundlers inline into browser code, keyed by the framework that does it. */
const PUBLIC_PREFIXES = [
  { prefix: 'NEXT_PUBLIC_', framework: 'Next.js' },
  { prefix: 'VITE_', framework: 'Vite' },
  { prefix: 'REACT_APP_', framework: 'Create React App' },
  { prefix: 'EXPO_PUBLIC_', framework: 'Expo' },
  { prefix: 'NUXT_PUBLIC_', framework: 'Nuxt' },
  { prefix: 'GATSBY_', framework: 'Gatsby' },
  { prefix: 'VUE_APP_', framework: 'Vue CLI' },
  { prefix: 'NG_APP_', framework: 'Angular (@ngx-env)' },
  { prefix: 'PUBLIC_', framework: 'SvelteKit/Astro', needs: ['@sveltejs/kit', 'astro'] },
];

/** Names (after the public prefix) that mean "secret". */
const SECRET_ENV_NAME_RE = /(SECRET|PRIVATE|PASSWORD|PASSWD|PWD\b|DATABASE_URL|DB_URL|DB_PASS|CONNECTION_STRING|ADMIN_KEY|MASTER_KEY|SIGNING|ENCRYPTION_KEY|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|BOT_TOKEN|API_TOKEN|SENDGRID|RESEND_API|MAILGUN|POSTMARK|TWILIO_AUTH|AWS_ACCESS|PLAID_SECRET|ALGOLIA_ADMIN|ALGOLIA_WRITE|UPSTASH_REDIS_REST_TOKEN|MONGODB_URI|MONGO_URI|REDIS_URL|SENTRY_AUTH|VERCEL_TOKEN|NETLIFY_AUTH|CLOUDFLARE_API|GITHUB_TOKEN|SLACK_TOKEN|DISCORD_TOKEN|PINECONE|SERVICE_ACCOUNT|FIREBASE_ADMIN|STRIPE_SK|SK_LIVE)/;

/** Supabase service-role style names (reported by DATA-02, not SEC-08). */
const SERVICE_ROLE_NAME_RE = /(SERVICE_?ROLE|SERVICE_?KEY|SUPABASE_SECRET|SB_SECRET)/;

/** AI-provider key names (reported by AI-03, not SEC-08). */
const AI_ENV_NAME_RE = /(OPENAI|ANTHROPIC|CLAUDE|GROQ|MISTRAL|COHERE|REPLICATE|HUGGING_?FACE|(?:^|_)HF_|GEMINI|GOOGLE_AI|GOOGLE_GENERATIVE|GENAI|(?:^|_)PALM_|DEEPSEEK|(?:^|_)XAI_|GROK|PERPLEXITY|PPLX|TOGETHER_|FIREWORKS|OPENROUTER|ELEVENLABS|ASSEMBLYAI|DEEPGRAM|STABILITY_|AI21|VOYAGE|AZURE_OPENAI|BEDROCK|CEREBRAS|(?:^|_)LLM_)/;

const KEYISH_NAME_RE = /(KEY|TOKEN|SECRET)/;

/** Public names by design (anon/publishable keys, ids, URLs). */
const PUBLIC_ENV_OK_RE = /(ANON|PUBLISHABLE|PUBLIC_KEY|CLIENT_ID|APP_ID|PROJECT_ID|MEASUREMENT_ID|SITE_KEY|DSN|_URL$|HOST|DOMAIN|REGION|BUCKET|SENDER_ID|AUTH_DOMAIN)/;

/** Names that stay secret even when they also match PUBLIC_ENV_OK_RE (e.g. DATABASE_URL). */
const ALWAYS_SECRET_NAME_RE = /(SECRET|PRIVATE|PASSWORD|PASSWD|DATABASE_URL|DB_URL|CONNECTION_STRING|MONGODB_URI|MONGO_URI|REDIS_URL)/;

/** Split NAME into { prefix, rest, framework } when it carries a public prefix. */
function publicPrefix(name, deps) {
  for (const p of PUBLIC_PREFIXES) {
    if (!name.startsWith(p.prefix)) continue;
    if (p.needs && !(deps && p.needs.some((d) => deps.has(d)))) continue;
    return { prefix: p.prefix, rest: name.slice(p.prefix.length), framework: p.framework };
  }
  return null;
}

/** Classify a public-prefixed env var: 'secret' | 'service-role' | 'ai' | null (fine). */
function classifyPublicEnv(name, value) {
  const upper = name.toUpperCase();
  if (SERVICE_ROLE_NAME_RE.test(upper)) return 'service-role';
  if (value && /^sb_secret_/.test(value)) return 'service-role';
  if (value && supabaseRole(value) === 'service_role') return 'service-role';
  if (AI_ENV_NAME_RE.test(upper) && KEYISH_NAME_RE.test(upper)) return 'ai';
  if (value) {
    const hit = findSecrets(value)[0];
    if (hit && !hit.google) return hit.ai ? 'ai' : 'secret';
    if (findDbUrls(value).some((d) => !d.placeholder)) return 'secret';
  }
  if (PUBLIC_ENV_OK_RE.test(upper) && !ALWAYS_SECRET_NAME_RE.test(upper)) return null;
  if (SECRET_ENV_NAME_RE.test(upper)) return 'secret';
  return null;
}

module.exports = {
  SECRET_PATTERNS,
  JWT_RE,
  DB_URL_RE,
  LOCAL_HOST_RE,
  GENERIC_ASSIGN_RE,
  PUBLIC_NAME_RE,
  PUBLIC_VALUE_RE,
  PUBLIC_PREFIXES,
  AI_ENV_NAME_RE,
  SERVICE_ROLE_NAME_RE,
  SECRET_ENV_NAME_RE,
  isPlaceholder,
  looksSecret,
  decodeJwt,
  supabaseRole,
  findSecrets,
  findDbUrls,
  mask,
  redact,
  publicPrefix,
  classifyPublicEnv,
};
