'use strict';

/**
 * Legal pages, consent and data rights: LEGAL-04 privacy/terms/refund pages, LEGAL-05 trackers
 * without cookie consent, LEGAL-06 marketing email without unsubscribe, and the manual reviews
 * LEGAL-07 dark patterns, LEGAL-08 data deletion, LEGAL-09 children's data, LEGAL-10 font and
 * image licenses, LEGAL-11 third-party SDK data sharing. Static only: no network, nothing run.
 */

const { loadRepo } = require('../lib/repo');
const { getRoutes, resolveModule } = require('../lib/routes');
const { authImplementation } = require('./auth');
const { tagAt } = require('./a11y');
const { pass, fail, warn, manual, na, ev } = require('../lib/result');

const IDS = ['LEGAL-04', 'LEGAL-05', 'LEGAL-06', 'LEGAL-07', 'LEGAL-08', 'LEGAL-09', 'LEGAL-10', 'LEGAL-11'];

async function run(root, opts = {}) {
  const repo = loadRepo(root, opts);
  const { routes } = getRoutes(repo);
  const files = repo.sources({ kinds: ['code', 'markup'], tests: false });
  const ctx = { repo, routes, files, app: files.filter((f) => !repo.isTooling(f)) };
  ctx.trackers = findTrackers(ctx);
  ctx.data = dataCollection(ctx);
  return [legalPages(ctx), cookieConsent(ctx), unsubscribe(ctx), darkPatterns(ctx), dataDeletion(ctx), childrensData(ctx), assetLicenses(ctx), sdkAudit(ctx)];
}

/** First match of `re` in each file, as { f, line, m }. */
function* hits(repo, files, re, { all = false } = {}) {
  for (const f of files) {
    const text = repo.code(f) || '';
    const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
    for (const m of text.matchAll(g)) {
      const line = repo.lineOf(f, m.index);
      if (repo.suppressed(f, line)) continue;
      yield { f, line, m, index: m.index, text };
      if (!all) break;
    }
  }
}

// ── Shared: trackers and data collection ─────────────────────────────────────

// Browser trackers that set cookies or identifiers. Cookieless analytics (Plausible, Fathom,
// Simple Analytics, Umami, Vercel Analytics, Cloudflare Web Analytics) are deliberately absent.
const TRACKERS = [
  { name: 'Google Analytics / Tag Manager', cat: 'analytics', re: /googletagmanager\.com\/(?:gtag\/js|gtm\.js|ns\.html)|google-analytics\.com\/(?:analytics|ga)\.js|\bgtag\(\s*['"]config['"]|\bga\(\s*['"]create['"]|['"](?:react-ga4?|react-gtm-module|vue-gtag|ngx-google-analytics)['"]|import\s*\{[^}]*\bGoogle(?:Analytics|TagManager)\b[^}]*\}\s*from\s*['"]@next\/third-parties\/google['"]/ },
  { name: 'Meta Pixel', cat: 'ads', re: /connect\.facebook\.net\/[\w-]+\/fbevents\.js|\bfbq\(\s*['"](?:init|track|trackCustom)['"]|['"]react-facebook-pixel['"]/ },
  { name: 'Hotjar', cat: 'session replay', re: /static\.hotjar\.com|['"]@hotjar\/browser['"]|\b_hjSettings\b/ },
  { name: 'Segment', cat: 'analytics', re: /cdn\.segment\.com|['"]@segment\/analytics-next['"]/ },
  { name: 'Mixpanel', cat: 'analytics', re: /['"]mixpanel-browser['"]|cdn\.mxpnl\.com/ },
  { name: 'Amplitude', cat: 'analytics', re: /['"](?:@amplitude\/analytics-browser|amplitude-js)['"]|cdn\.amplitude\.com/ },
  { name: 'PostHog', cat: 'analytics', re: /['"]posthog-js['"]|\bposthog\.init\s*\(/, cookieless: /\bpersistence\s*:\s*['"]memory['"]|\bdisable_persistence\s*:\s*true|\bcookieless_mode\s*:/ },
  { name: 'Heap', cat: 'analytics', re: /cdn\.heapanalytics\.com|\bheap\.load\s*\(/ },
  { name: 'FullStory', cat: 'session replay', re: /['"]@fullstory\/browser['"]|edge\.fullstory\.com|fullstory\.com\/s\/fs\.js/ },
  { name: 'LogRocket', cat: 'session replay', re: /['"]logrocket['"]|\bLogRocket\.init\s*\(/ },
  { name: 'TikTok Pixel', cat: 'ads', re: /analytics\.tiktok\.com|\bttq\.(?:load|page|track)\s*\(/ },
  { name: 'LinkedIn Insight Tag', cat: 'ads', re: /snap\.licdn\.com|\b_linkedin_partner_id\b/ },
  { name: 'Microsoft Clarity', cat: 'session replay', re: /www\.clarity\.ms\/tag|['"]@microsoft\/clarity['"]/ },
  { name: 'X (Twitter) Pixel', cat: 'ads', re: /static\.ads-twitter\.com\/uwt\.js|\btwq\(\s*['"]/ },
  { name: 'Pinterest Tag', cat: 'ads', re: /s\.pinimg\.com\/ct\/core\.js|\bpintrk\(\s*['"]/ },
  { name: 'Reddit Pixel', cat: 'ads', re: /redditstatic\.com\/ads\/pixel\.js|\brdt\(\s*['"]init['"]/ },
  { name: 'Snap Pixel', cat: 'ads', re: /sc-static\.net\/scevent\.min\.js|\bsnaptr\(\s*['"]/ },
];

const trackerCache = new WeakMap();

/** Every tracker that loads in the app: { name, cat, f, line }, one per tracker per file. */
function findTrackers({ repo, app }) {
  if (trackerCache.has(repo)) return trackerCache.get(repo);
  const out = [];
  for (const t of TRACKERS) {
    for (const h of hits(repo, app, t.re)) {
      if (t.cookieless && t.cookieless.test(h.text)) continue;
      out.push({ name: t.name, cat: t.cat, f: h.f, line: h.line });
    }
  }
  trackerCache.set(repo, out);
  return out;
}

const PAYMENTS = [
  { name: 'Stripe', re: /['"](?:stripe|@stripe\/stripe-js|@stripe\/react-stripe-js)['"]|js\.stripe\.com|\bcheckout\.sessions\.create\s*\(|\bpaymentIntents\.create\s*\(/ },
  { name: 'Paddle', re: /['"]@paddle\/[\w-]+['"]|cdn\.paddle\.com/ },
  { name: 'Lemon Squeezy', re: /['"]@lemonsqueezy\/[\w.-]+['"]|app\.lemonsqueezy\.com/ },
  { name: 'PayPal', re: /['"]@paypal\/[\w-]+['"]|paypal\.com\/sdk\/js/ },
  { name: 'Razorpay', re: /['"]razorpay['"]|checkout\.razorpay\.com/ },
  { name: 'Braintree', re: /['"]braintree(?:-web)?['"]/ },
];
const PERSONAL_INPUT_RE = /<input\b[^>]*\b(?:type|name)\s*=\s*\{?\s*["'`](?:email|password|tel|phone)["'`]/i;

/** What personal data the app takes in: { accounts, inputs, payments, tracking } evidence lines. */
function dataCollection(ctx) {
  const { repo, routes, app } = ctx;
  const impl = authImplementation(repo, routes);
  const accounts = impl ? [ev(impl.f.rel, impl.line, `user accounts (${impl.label})`)] : [];
  const inputs = [...hits(repo, app, PERSONAL_INPUT_RE)].slice(0, 2).map((h) => ev(h.f.rel, h.line, 'form collects email, phone or password'));
  const payments = [];
  for (const p of PAYMENTS) {
    const h = hits(repo, app, p.re).next().value;
    if (h) payments.push(ev(h.f.rel, h.line, `payments (${p.name})`));
  }
  const tracking = ctx.trackers.slice(0, 2).map((t) => ev(t.f.rel, t.line, `${t.name} tracking`));
  return { accounts, inputs, payments, tracking, personal: accounts.length + inputs.length + tracking.length > 0 };
}

// ── LEGAL-04 ───────────────────────────────────────────────────────────────

const LEGAL_PAGES = {
  privacy: { label: 'privacy policy', re: /^(?:privacy(?:[-_]?policy|[-_]?notice)?|datenschutz|data[-_]?protection)$/i },
  terms: { label: 'terms of service', re: /^(?:terms(?:[-_]?(?:of[-_]?(?:service|use)|and[-_]?conditions|conditions))?|tos|conditions[-_]?of[-_]?use|eula|user[-_]?agreement|legal)$/i },
  refund: { label: 'refund policy', re: /^(?:refunds?(?:[-_]?policy)?|returns?(?:[-_]?policy)?|cancellation(?:[-_]?policy)?)$/i },
  cookies: { label: 'cookie policy', re: /^(?:cookies?(?:[-_]?policy)?)$/i },
};
const PAGE_EXT_RE = /\.(?:html?|md|mdx|jsx|tsx|vue|svelte|astro|ejs|hbs|njk|liquid|erb|pug)$/;
const LINK_RE = /(?:\b(?:href|to|path)\s*[=:]\s*\{?\s*|\]\()["'`]?([^"'`\s)>]{1,200})/g;
// Any other quoted URL or path, such as a policy URL constant: env.TERMS_URL || "https://cal.com/terms".
const QUOTED_URL_RE = /["'`]((?:https?:\/\/|\/)[^"'`\s<>]{1,200})["'`]/g;
// Settings that hold a policy URL, often filled from env at deploy time: PRIVACY_POLICY_URL, termsUrl.
const POLICY_SETTING_RE = /\b[\w$]*?(privacy|terms|refunds?)(?:[-_]?(?:policy|notice|of[-_]?(?:service|use)|and[-_]?conditions|conditions))?[-_]?(?:url|link|href|page)s?\b/gi;
const HOSTED_POLICY_RE = /(?:app\.termly\.io\/(?:document|policy-viewer)|termly\.io\/[\w/-]*(?:privacy|terms)|iubenda\.com\/(?:privacy-policy|terms-and-conditions)|getterms\.io|termsfeed\.com|privacypolicies\.com|termageddon\.com)[^"'`\s)]*/gi;
// Files that render pages; a repo with none is an API whose policies live on another site.
const UI_FILE_RE = /\.(?:jsx|tsx|vue|svelte|astro)$/;

/** Which legal page kinds exist: kind -> evidence line (files, routes and links). */
function legalPagesFound({ repo, routes, files }) {
  const found = {};
  const note = (kind, line) => {
    if (!found[kind]) found[kind] = line;
  };
  const kindsOf = (segments) => Object.keys(LEGAL_PAGES).filter((k) => segments.some((s) => LEGAL_PAGES[k].re.test(s)));
  for (const f of repo.files) {
    if (f.build || !PAGE_EXT_RE.test(f.name) || repo.isTest(f)) continue;
    const segs = f.rel.replace(PAGE_EXT_RE, '').split('/').map((s) => s.replace(/^\+|^\[|\]$|^\(|\)$/g, ''));
    for (const k of kindsOf(segs)) {
      note(k, ev(f.rel, null, `${LEGAL_PAGES[k].label} page`));
      // Terms of service often carry the refund and cancellation policy.
      if (k === 'terms' && /\brefunds?\b|\bcancell?ation polic(?:y|ies)\b/i.test(repo.read(f) || '')) note('refund', ev(f.rel, null, 'refund terms inside the terms of service'));
    }
  }
  for (const r of routes) for (const k of kindsOf(String(r.path).split('/'))) note(k, ev(r.file.rel, r.line, `${LEGAL_PAGES[k].label} route ${r.path}`));
  for (const f of files) {
    const text = repo.code(f) || '';
    for (const [re, what] of [[LINK_RE, 'link to the'], [QUOTED_URL_RE, 'URL of the']]) {
      for (const m of text.matchAll(re)) {
        const url = m[1].split(/[?#]/)[0];
        if (!url.includes('/')) continue;
        const segs = url.split('/').map((s) => s.replace(/\.html?$/, ''));
        for (const k of kindsOf(segs)) note(k, ev(f.rel, repo.lineOf(f, m.index), `${what} ${LEGAL_PAGES[k].label} (${url})`));
      }
    }
    for (const m of text.matchAll(POLICY_SETTING_RE)) {
      const kind = /^privacy/i.test(m[1]) ? 'privacy' : /^terms/i.test(m[1]) ? 'terms' : 'refund';
      note(kind, ev(f.rel, repo.lineOf(f, m.index), `${LEGAL_PAGES[kind].label} URL setting (${m[0]})`));
    }
    for (const m of text.matchAll(HOSTED_POLICY_RE)) {
      const kind = /terms/i.test(m[0]) ? 'terms' : 'privacy';
      note(kind, ev(f.rel, repo.lineOf(f, m.index), `hosted ${LEGAL_PAGES[kind].label} (${m[0].slice(0, 60)})`));
    }
  }
  return found;
}

function legalPages(ctx) {
  const { accounts, inputs, payments, tracking } = ctx.data;
  const needs = new Set();
  if (accounts.length || inputs.length || tracking.length || payments.length) needs.add('privacy');
  if (accounts.length || payments.length) needs.add('terms');
  if (payments.length) needs.add('refund');
  if (!needs.size) return na('LEGAL-04', 'no signup, accounts, email collection, analytics or payments found');
  const found = legalPagesFound(ctx);
  const missing = [...needs].filter((k) => !found[k]);
  const signals = [...accounts, ...payments, ...inputs, ...tracking].slice(0, 4);
  if (missing.length) {
    const names = missing.map((k) => LEGAL_PAGES[k].label);
    const join = (word) => (names.length > 1 ? `${names.slice(0, -1).join(', ')} ${word} ${names[names.length - 1]}` : names[0]);
    const { repo } = ctx;
    const ui = repo.files.some((f) => !f.build && !repo.isTest(f) && (f.kind === 'markup' || UI_FILE_RE.test(f.name)));
    if (!ui) {
      return manual('LEGAL-04', [...signals, `No ${join('or')} found, and this repo has no pages of its own (it looks like an API), so they would live on the site or app in front of it.`], {
        question: `This repo is an API with no pages. Does the site or app in front of it publish a ${join('and')} and link them where users sign up${payments.length ? ' and pay' : ''}?`,
      });
    }
    return fail('LEGAL-04', [...signals, `No ${join('or')} found (looked for pages, routes, links and URLs named privacy, terms, refund or cookies, and hosted policies).`]);
  }
  return pass('LEGAL-04', [...needs].map((k) => found[k]));
}

// ── LEGAL-05 ───────────────────────────────────────────────────────────────

const CONSENT_RE = /consent\.cookiebot\.com|\bCookiebot\b|cdn\.cookielaw\.org|\bOneTrust\b|\bOptanon\w*|cmp\.osano\.com|\bosano\b|cdn-cookieyes\.com|\bcookieyes\b|app\.termly\.io\/(?:embed|resource-blocker)|iubenda\.com\/cs|\bUsercentrics\b|\bdidomi\b|\bklaro\b|vanilla-cookieconsent|['"]cookieconsent['"]|react-cookie-consent|cookiehub|cookie-script\.com|consentmanager\.net|cookiefirst|\bgtag\(\s*['"]consent['"]\s*,\s*['"](?:default|update)['"]|\b(?:Cookie|Consent)(?:Banner|Consent|Notice|Popup|Modal|Bar|Manager|Dialog|Prompt)\b|\bcookie[-_]?(?:banner|consent|notice)\b|\bconsent[-_]?(?:banner|manager)\b/i;

function cookieConsent(ctx) {
  const { repo, files, trackers } = ctx;
  if (!trackers.length) return pass('LEGAL-05', ['No analytics or ad trackers that need cookie consent found (cookieless analytics such as Plausible or Vercel Analytics are fine).']);
  const consent = hits(repo, files, CONSENT_RE).next().value;
  if (consent) {
    return pass('LEGAL-05', [ev(consent.f.rel, consent.line, `consent mechanism (${consent.m[0]}) for ${[...new Set(trackers.map((t) => t.name))].join(', ')}`, repo.snippet(consent.f, consent.line))]);
  }
  return warn('LEGAL-05', trackers.map((t) => ev(t.f.rel, t.line, `${t.name} loads with no cookie consent banner or CMP`, repo.snippet(t.f, t.line))));
}

// ── LEGAL-06 ───────────────────────────────────────────────────────────────

const EMAIL_SENDERS = [
  { name: 'Resend', module: /['"]resend['"]/, call: () => /\.emails\.send\s*\(|\.batch\.send\s*\(|\.broadcasts\.(?:create|send)\s*\(/g, bulk: /\.batch\.send|\.broadcasts\./ },
  { name: 'SendGrid', module: /['"]@sendgrid\/mail['"]/, call: (text) => new RegExp(`\\b(?:${importedNames(text, '@sendgrid/mail').join('|') || 'sgMail'})\\.send(?:Multiple)?\\s*\\(`, 'g'), bulk: /sendMultiple|isMultiple\s*:\s*true/ },
  { name: 'Nodemailer', module: /['"]nodemailer['"]/, call: () => /\.sendMail\s*\(/g },
  { name: 'Postmark', module: /['"]postmark['"]/, call: () => /\.send(?:Email|EmailWithTemplate|EmailBatch|EmailBatchWithTemplates)\s*\(/g, bulk: /Batch/ },
  { name: 'AWS SES', module: /['"](?:@aws-sdk\/client-sesv?2?|aws-sdk)['"]/, call: () => /\bnew\s+Send(?:Bulk)?(?:Templated)?EmailCommand\s*\(|\.send(?:Raw|Templated|BulkTemplated)?Email\s*\(/g, bulk: /Bulk/ },
  { name: 'Mailgun', module: /['"](?:mailgun\.js|mailgun-js)['"]/, call: () => /\.messages\.create\s*\(/g },
  { name: 'Brevo', module: /['"](?:@getbrevo\/brevo|sib-api-v3-sdk|@sendinblue\/client)['"]/, call: () => /\bsendTransacEmail\s*\(|\bcreateEmailCampaign\s*\(/g, bulk: /createEmailCampaign/ },
  { name: 'Mailchimp Transactional', module: /['"](?:@mailchimp\/mailchimp_transactional|mandrill-api)['"]/, call: () => /\.messages\.send(?:Template)?\s*\(/g },
];
const MARKETING_RE = /\b(?:newsletters?|digests?|weekly|monthly|announce(?:ment|ments|ing)?|promo(?:s|tion|tions|tional)?|offers?|sale|discounts?|\d+%\s*off|launch(?:ing|es)?|what'?s new|product updates?|campaigns?|marketing|broadcasts?|re-?engage(?:ment)?|win-?back|we miss you|upgrade to)\b/i;
const TRANSACTIONAL_RE = /\b(?:reset (?:your )?password|password reset|verify (?:your )?email|verification code|confirm (?:your )?(?:email|account)|magic link|sign[- ]?in link|log ?in link|receipt|invoice|order (?:confirmation|#)|your code|one-time code|security alert)\b/i;
const AUDIENCE_LOOP_RE = /\bfor\s*\(\s*(?:const|let|var)\s+\w+\s+of\s+[\w.$]{0,60}?\b(?:users|subscribers|customers|members|contacts|recipients|emails|audience|rows|leads|list)\b|\b(?:users|subscribers|customers|members|contacts|recipients|emails|audience|rows|leads)\s*\.\s*(?:forEach|map)\s*\(/i;
const UNSUBSCRIBE_RE = /unsubscribe|list-unsubscribe|\{\{\{?\s*(?:unsub\w*|RESEND_UNSUBSCRIBE_URL)\s*\}?\}\}|<%asm_group_unsubscribe_raw_url%>|%unsubscribe_url%|\*\|UNSUB\|\*|\bopt[-_ ]?out\b|manage (?:your )?(?:email )?preferences|email[-_]?preferences/i;

/** Local names bound to a module: const x = require('m'), import x from 'm'. */
function importedNames(text, mod) {
  const esc = mod.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  const names = [];
  for (const m of text.matchAll(new RegExp(`\\b(?:const|let|var)\\s+(\\w+)\\s*=\\s*require\\(\\s*['"]${esc}['"]\\s*\\)|\\bimport\\s+(\\w+)\\s+from\\s+['"]${esc}['"]`, 'g'))) names.push(m[1] || m[2]);
  return names;
}

/** The function a call sits in (for its name), approximated by the nearest preceding declaration. */
function enclosingName(text, index) {
  const before = text.slice(Math.max(0, index - 2000), index);
  const all = [...before.matchAll(/\b(?:async\s+)?function\s+(\w+)|\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>/g)];
  const last = all[all.length - 1];
  return last ? last[1] || last[2] : '';
}

/** Text of the email templates a file imports (relative modules under emails/templates). */
function templateText(repo, f, text) {
  let out = '';
  for (const m of text.matchAll(/(?:from\s+|require\(\s*)['"](\.[^'"]+)['"]/g)) {
    if (!/email|mail|template|newsletter|digest/i.test(m[1])) continue;
    const target = resolveModule(repo, f.rel, m[1]);
    const file = target && repo.get(target);
    if (file) out += `\n${repo.code(file) || ''}`;
  }
  return out;
}

function unsubscribe(ctx) {
  const { repo, files } = ctx;
  const bad = [];
  let sends = 0;
  let marketing = 0;
  for (const f of files) {
    const text = repo.code(f) || '';
    for (const s of EMAIL_SENDERS) {
      if (!s.module.test(text)) continue;
      for (const m of text.matchAll(s.call(text))) {
        sends += 1;
        const args = text.slice(m.index, m.index + 1200);
        const before = text.slice(Math.max(0, m.index - 400), m.index);
        const fn = enclosingName(text, m.index);
        const reasons = [];
        if (s.bulk && s.bulk.test(m[0])) reasons.push('batch or broadcast API');
        if (AUDIENCE_LOOP_RE.test(before)) reasons.push('loops over a list of users');
        const word = MARKETING_RE.exec(`${args.slice(0, 700)} ${fn}`);
        if (word) reasons.push(`"${word[0]}" wording`);
        if (!reasons.length || TRANSACTIONAL_RE.test(args.slice(0, 700))) continue;
        marketing += 1;
        if (UNSUBSCRIBE_RE.test(args) || UNSUBSCRIBE_RE.test(text) || UNSUBSCRIBE_RE.test(templateText(repo, f, text))) continue;
        const line = repo.lineOf(f, m.index);
        if (!repo.suppressed(f, line)) bad.push(ev(f.rel, line, `${s.name} sends marketing email (${reasons.join(', ')}) with no unsubscribe link or List-Unsubscribe header`, repo.snippet(f, line)));
      }
    }
  }
  if (!sends) return na('LEGAL-06', 'no email-sending code found');
  if (bad.length) return fail('LEGAL-06', bad);
  if (!marketing) return pass('LEGAL-06', [`${sends} email send call(s), all transactional by the look of them (resets, receipts, sign-in links), which don't need an unsubscribe link.`]);
  const rest = sends > marketing ? '; the rest look transactional (resets, receipts, sign-in links)' : '';
  return pass('LEGAL-06', [`${sends} email send call(s): ${marketing} marketing, each with an unsubscribe option${rest}.`]);
}

// ── LEGAL-07 ───────────────────────────────────────────────────────────────

const FLOW_PATH_RE = /(?:checkout|pricing|billing|subscribe|subscription|plans?\b|upgrade|cancel|signup|sign-up|register|onboarding|cart|payment|paywall|trial)/i;
const PRECHECK_WORDS_RE = /newsletter|marketing|updates|offers?|promo|partners?|third[- ]part(?:y|ies)|share my|consent|subscribe|add-?on|insurance|protection|donat|tip\b|upsell|auto-?renew|recurring/i;
const URGENCY_RE = /\b(?:countdown|only \d+ (?:left|remaining)|limited time|offer ends|expires in|hurry|selling fast)\b/i;

function darkPatterns(ctx) {
  const { repo, app } = ctx;
  const flows = app.filter((f) => FLOW_PATH_RE.test(f.rel));
  const found = [];
  for (const f of app) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(/<input(?=[\s/>])/g)) {
      const tag = tagAt(text, m.index);
      if (!/\btype\s*=\s*\{?\s*["'`]checkbox["'`]/.test(tag)) continue;
      if (!/\b(?:defaultChecked|checked)\b(?!\s*=\s*\{?\s*false)/.test(tag)) continue;
      const near = text.slice(m.index, m.index + tag.length + 240);
      const word = PRECHECK_WORDS_RE.exec(near);
      if (!word) continue;
      const line = repo.lineOf(f, m.index);
      if (!repo.suppressed(f, line)) found.push(ev(f.rel, line, `checkbox is checked by default ("${word[0]}")`, repo.snippet(f, line)));
    }
  }
  for (const f of flows) {
    const text = repo.code(f) || '';
    const u = URGENCY_RE.exec(text);
    if (u) found.push(ev(f.rel, repo.lineOf(f, u.index), `urgency wording ("${u[0]}")`, repo.snippet(f, repo.lineOf(f, u.index))));
  }
  if (!flows.length && !found.length) return na('LEGAL-07', 'no checkout, pricing, signup or cancellation flows found');
  return manual('LEGAL-07', [...found, ...flows.slice(0, 8).map((f) => ev(f.rel, null, 'checkout, signup or subscription flow to review'))]);
}

// ── LEGAL-08 ───────────────────────────────────────────────────────────────

const SELF_PATH_RE = /(?:^|\/)(?:account|accounts|me|user|users|profile|profiles|self)(?:\/:[\w-]+)?\/?$/i;
const DELETE_PATH_RE = /(?:delete|close|remove|deactivate|erase)[-_]?(?:my[-_]?)?(?:account|me|user|profile|data)/i;
const ADMIN_RE = /(?:^|\/)(?:admin|internal|staff|backoffice|moderation)(?:\/|$)/i;
const DELETE_CODE_RE = /\b(?:deleteAccount|deleteMyAccount|deleteMe|closeAccount|removeAccount|destroyAccount|deleteUserData|eraseUser|deleteMyData)\s*\(|\.auth\.admin\.deleteUser\s*\(|\bcurrentUser\.delete\s*\(|\bdeleteUser\s*\(\s*(?:auth\.currentUser|user\b)|\busers\.deleteUser\s*\(/;
const DELETE_UI_RE = /delete (?:my |your )?account|close (?:my |your )?account|delete (?:all )?(?:my |your )?data|erase my data/i;

function dataDeletion(ctx) {
  const { repo, routes, app, data } = ctx;
  if (!data.accounts.length && !data.inputs.length) return na('LEGAL-08', 'no user accounts or personal data collection found');
  const found = [];
  for (const r of routes) {
    if (ADMIN_RE.test(r.path) || ADMIN_RE.test(r.file.rel)) continue;
    if ((r.method === 'DELETE' && SELF_PATH_RE.test(r.path)) || DELETE_PATH_RE.test(r.path)) found.push(ev(r.file.rel, r.line, `${r.method} ${r.path} deletes an account`));
  }
  for (const h of hits(repo, app.filter((f) => !ADMIN_RE.test(f.rel)), DELETE_CODE_RE)) found.push(ev(h.f.rel, h.line, 'account deletion code', repo.snippet(h.f, h.line)));
  for (const h of hits(repo, app.filter((f) => !ADMIN_RE.test(f.rel)), DELETE_UI_RE)) found.push(ev(h.f.rel, h.line, `"${h.m[0]}" offered in the UI or policy text`));
  if (!found.length) found.push('No self-service account deletion found: no DELETE route on account/me/user, deleteAccount handler or "Delete account" UI outside admin code.');
  return manual('LEGAL-08', [...data.accounts, ...found]);
}

// ── LEGAL-09 ───────────────────────────────────────────────────────────────

// An age or birthdate the app stores, not just the word: form fields, validator and model keys,
// SQL and Prisma columns, and request-body reads. A "birthday" holiday keyword doesn't count.
const AGE = String.raw`(?:date[-_]?of[-_]?birth|birth[-_]?date|birthday|dob|age)`;
const AGE_FIELD_RE = new RegExp([
  String.raw`\b(?:name|id|htmlFor|for)\s*=\s*\{?\s*["'\`]${AGE}["'\`]`,
  String.raw`\bauto[cC]omplete\s*=\s*\{?\s*["'\`]bday(?:-day|-month|-year)?["'\`]`,
  String.raw`\b(?:register|formData\.get|getFieldProps|useField)\(\s*["'\`]${AGE}["'\`]`,
  String.raw`\b${AGE}\s*\??\s*:\s*(?:z|yup|Joi|v|t)\.`,
  String.raw`\b${AGE}\s*:\s*\{?\s*(?:type\s*:\s*)?(?:Date|Number|DataTypes\.\w+|Sequelize\.\w+)\b(?!\s*\()`,
  String.raw`\b(?:date[-_]?of[-_]?birth|birth[-_]?date|dob)\s*\??\s*:\s*(?:Date|string)\b`,
  String.raw`\b${AGE}\s*=\s*(?:models\.\w+|db\.Column|Column|mapped_column|fields\.\w+)\(|\bt\.(?:date|datetime|integer)\s+:${AGE}\b`,
  String.raw`^\s*${AGE}\s+(?:DateTime|Int)\b`,
  String.raw`\b${AGE}\s+(?:date|timestamp\w*|int(?:eger)?|smallint)\b(?!\s*[=(])`,
  String.raw`\b(?:req|request|ctx\.request)\.body\.${AGE}\b|\bbody\.${AGE}\b`,
  String.raw`\{[^{}]{0,300}\b${AGE}\b[^{}]{0,300}\}\s*=\s*(?:await\s+)?(?:(?:req|request|ctx\.request|event)\.body|(?:req|request)\.json\(\)|body|input|values)\b`,
].join('|'), 'im');
const AGE_WORD_RE = new RegExp(String.raw`\b${AGE}\b|bday`, 'i');
const CHILD_CODE_RE = /\b(?:parentalConsent|parental_consent|coppa|isMinor|is_minor|childAccount|child_account|ageVerification|age_verification|ageGate|age_gate)\b/i;
const CHILD_WORDS = '(?:kids?|children|child\'s|students?|homework|classroom|teachers?|parents?|parental|under (?:the age of )?13|ages? \\d{1,2} ?(?:-|to|–) ?\\d{1,2}|coppa)';
// Visible copy only: the text after a tag's closing ">" (not an arrow's "=>" or a "->"), with no
// code characters in it, so "parent component" and `children?.length` in code don't count.
const CHILD_TEXT_RE = new RegExp(`(?<=[\\w"'}/]|^[ \\t]*)>[^<>{}=;&|()]{0,200}?\\b${CHILD_WORDS}\\b[^<>{}=;&|()]{0,200}<`, 'im');

function childrensData(ctx) {
  const { repo, app, data } = ctx;
  if (!data.personal) return na('LEGAL-09', 'no user accounts or personal data collection found');
  const found = [];
  for (const h of hits(repo, app, AGE_FIELD_RE)) found.push(ev(h.f.rel, h.line, `age or birthdate field ("${(AGE_WORD_RE.exec(h.m[0]) || h.m)[0]}")`, repo.snippet(h.f, h.line)));
  for (const h of hits(repo, app, CHILD_CODE_RE)) found.push(ev(h.f.rel, h.line, `child-related code ("${h.m[0]}")`, repo.snippet(h.f, h.line)));
  const ui = app.filter((f) => f.kind === 'markup' || /\.(?:jsx|tsx|vue|svelte|astro)$/.test(f.name));
  for (const h of hits(repo, ui, CHILD_TEXT_RE)) {
    const word = new RegExp(`\\b${CHILD_WORDS}\\b`, 'i').exec(h.m[0]);
    found.push(ev(h.f.rel, h.line, `child-directed wording ("${word ? word[0] : 'children'}")`, repo.snippet(h.f, h.line)));
  }
  if (!found.length) return pass('LEGAL-09', ['No age or birthdate fields and no child-directed wording found. If the app targets children under 13, COPPA requires verifiable parental consent before collecting their data.']);
  return manual('LEGAL-09', found);
}

// ── LEGAL-10 ───────────────────────────────────────────────────────────────

const FONT_FILE_RE = /\.(?:woff2?|ttf|otf|eot)$/i;
const PHOTO_FILE_RE = /\.(?:jpe?g|webp|avif)$/i;
const STOCK_NAME_RE = /shutterstock|istock|gettyimages|getty|adobestock|adobe[-_]stock|stock[-_]?photo|unsplash|pexels|pixabay|depositphotos|dreamstime|123rf|freepik|alamy|envato|storyblocks/i;
const OPEN_FONTS_RE = /fonts\.googleapis\.com|['"]next\/font\/google['"]|['"]@fontsource(?:-variable)?\/[\w-]+['"]/;

function assetLicenses(ctx) {
  const { repo, files } = ctx;
  const own = repo.files.filter((f) => !f.build && !repo.isTest(f));
  const fonts = own.filter((f) => FONT_FILE_RE.test(f.name));
  const photos = own.filter((f) => PHOTO_FILE_RE.test(f.name));
  const stock = photos.filter((f) => STOCK_NAME_RE.test(f.rel));
  const open = hits(repo, files, OPEN_FONTS_RE).next().value;
  if (!fonts.length && !photos.length) {
    return pass('LEGAL-10', [`No self-hosted font files or photos found${open ? '; fonts load from Google Fonts or open-license packages' : ''}.`]);
  }
  const evidence = [
    ...fonts.slice(0, 8).map((f) => ev(f.rel, null, 'self-hosted font file')),
    ...stock.slice(0, 8).map((f) => ev(f.rel, null, 'photo named after a stock site')),
  ];
  const other = photos.filter((f) => !STOCK_NAME_RE.test(f.rel));
  if (other.length) evidence.push(`${other.length} other photo(s), e.g. ${other.slice(0, 3).map((f) => f.rel).join(', ')}`);
  if (fonts.length > 8) evidence.push(`…and ${fonts.length - 8} more font file(s)`);
  return manual('LEGAL-10', evidence);
}

// ── LEGAL-11 ───────────────────────────────────────────────────────────────

const SDKS = [
  { re: /^posthog-js$|^posthog-node$/, cat: 'analytics' },
  { re: /^mixpanel-browser$|^mixpanel$/, cat: 'analytics' },
  { re: /^@amplitude\//, cat: 'analytics' },
  { re: /^@segment\//, cat: 'analytics' },
  { re: /^react-ga4?$|^vue-gtag$|^react-gtm-module$|^ngx-google-analytics$|^@next\/third-parties$/, cat: 'analytics' },
  { re: /^@vercel\/analytics$|^@vercel\/speed-insights$/, cat: 'cookieless analytics' },
  { re: /^@hotjar\/browser$|^@fullstory\/|^logrocket$|^@microsoft\/clarity$|^@highlight-run\//, cat: 'session replay' },
  { re: /^@sentry\/|^@bugsnag\/|^rollbar$|^@honeybadger-io\//, cat: 'error tracking' },
  { re: /^@datadog\/browser-|^dd-trace$|^newrelic$|^@newrelic\//, cat: 'monitoring' },
  { re: /^react-facebook-pixel$/, cat: 'ads' },
  { re: /^@intercom\/|^react-use-intercom$|^crisp-sdk-web$|^@zendesk\//, cat: 'support chat' },
  { re: /^@clerk\/|^@auth0\/|^@kinde-oss\/|^@workos-inc\/|^@stackframe\/|^@descope\/|^@stytch\//, cat: 'hosted auth' },
  { re: /^next-auth$|^@auth\/core$|^@react-oauth\/google$|^passport-google-oauth20$|^passport-facebook$|^passport-github2?$/, cat: 'social login' },
  { re: /^firebase$|^firebase-admin$|^@supabase\/supabase-js$|^@supabase\/ssr$/, cat: 'hosted backend' },
  { re: /^openai$|^@anthropic-ai\/sdk$|^@google\/generative-ai$|^@google\/genai$|^@ai-sdk\/(?:openai|anthropic|google|google-vertex|mistral|groq|xai|amazon-bedrock|azure|cohere|deepseek|fireworks|togetherai|perplexity|replicate|cerebras|deepinfra|gateway|vercel|openai-compatible|huggingface|elevenlabs|deepgram|assemblyai|fal)$|^groq-sdk$|^cohere-ai$|^replicate$|^@mistralai\//, cat: 'AI' },
  { re: /^resend$|^@sendgrid\/mail$|^postmark$|^mailgun\.js$|^@getbrevo\/brevo$|^@mailchimp\//, cat: 'email' },
  { re: /^twilio$|^@vonage\/|^plivo$|^telnyx$|^messagebird$/, cat: 'SMS' },
  { re: /^stripe$|^@stripe\/|^@paddle\/|^@lemonsqueezy\/|^@paypal\/|^razorpay$|^braintree$/, cat: 'payments' },
];
const DATA_BY_CATEGORY = {
  analytics: 'page views, device and location data, user IDs and events',
  'cookieless analytics': 'page views and device data, without cookies',
  'session replay': 'recordings of what users see and type, unmasked inputs included',
  'error tracking': 'stack traces and request data, which can include form fields, emails and tokens',
  monitoring: 'request traces and logs, which can include personal data',
  ads: 'page views and conversions tied to the visitor, shared with the ad network',
  'support chat': 'names, emails and conversation history',
  'hosted auth': 'names, emails, sign-in history and devices',
  'social login': 'profile name, email and avatar from the identity provider',
  'hosted backend': 'everything the app stores about its users',
  AI: 'prompts, including whatever user data the app puts in them',
  email: 'email addresses and message content',
  SMS: 'phone numbers and message content',
  payments: 'names, emails, billing addresses and payment details',
};

function depLine(pkg, name) {
  const idx = pkg.text.split('\n').findIndex((l) => l.includes(`"${name}"`));
  return idx === -1 ? null : idx + 1;
}

function sdkAudit(ctx) {
  const { repo, trackers } = ctx;
  const evidence = [];
  const seen = new Set();
  for (const p of repo.packages) {
    for (const [name, v] of Object.entries(p.versions)) {
      if (v.section === 'devDependencies' || seen.has(name)) continue;
      const sdk = SDKS.find((s) => s.re.test(name));
      if (!sdk) continue;
      seen.add(name);
      evidence.push(ev(p.rel, depLine(p, name), `${name} (${sdk.cat}): ${DATA_BY_CATEGORY[sdk.cat]}`));
    }
  }
  for (const t of trackers) {
    if (seen.has(t.name)) continue;
    seen.add(t.name);
    evidence.push(ev(t.f.rel, t.line, `${t.name} (${t.cat} script): ${DATA_BY_CATEGORY[t.cat] || DATA_BY_CATEGORY.analytics}`));
  }
  if (!evidence.length) return pass('LEGAL-11', ['No third-party SDKs that receive user data found in package.json or script tags.']);
  return manual('LEGAL-11', evidence);
}

module.exports = { name: 'legal', ids: IDS, run, findTrackers, legalPagesFound };

