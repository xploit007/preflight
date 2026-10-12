'use strict';

/**
 * Messaging & payments: LEGAL-01 SMS sends without verifiable opt-in (TCPA), LEGAL-03
 * payment amounts decided by the browser, APP-12 webhook receivers that skip signature checks.
 * LEGAL-01 and LEGAL-03 are always manual: the code shows where to look, a person decides.
 */

const { loadRepo } = require('../lib/repo');
const { getRoutes, routeBody } = require('../lib/routes');
const { taintedNames, isTainted } = require('../lib/taint');
const { pass, fail, manual, na, ev } = require('../lib/result');
const { splitArgs, objectAt } = require('../lib/util');

const IDS = ['LEGAL-01', 'LEGAL-03', 'APP-12'];

const SMS_PROVIDERS = [
  { name: 'Twilio', file: /require\(\s*['"]twilio['"]\s*\)|from\s+['"]twilio['"]|from\s+twilio\.rest|import\s+twilio/, call: /\.messages\.create\s*\(/g },
  { name: 'Twilio Verify (OTP)', file: /twilio/i, call: /\.verifications\.create\s*\(/g, otp: true },
  { name: 'Vonage/Nexmo', file: /@vonage\/|['"]nexmo['"]|vonage/i, call: /\b(?:vonage|nexmo)\.(?:sms\.send|messages\.send|message\.sendSms)\s*\(|\.sms\.send\s*\(/g },
  { name: 'Plivo', file: /plivo/i, call: /\.messages\.create\s*\(/g },
  { name: 'Telnyx', file: /telnyx/i, call: /\.messages\.create\s*\(/g },
  { name: 'MessageBird', file: /messagebird/i, call: /\.messages\.create\s*\(/g },
  { name: 'Sinch', file: /@sinch\//, call: /\.batches\.send\s*\(/g },
  { name: 'AWS SNS', file: /@aws-sdk\/client-sns|aws-sdk/, call: /\bnew\s+PublishCommand\s*\(\s*\{[^}]*PhoneNumber|\.publish\(\s*\{[^}]*PhoneNumber/g },
  { name: 'Bandwidth', file: /@bandwidth\//, call: /\.createMessage\s*\(/g },
  { name: 'SMS helper', file: /./, call: /textbelt\.com\/text|(?<![.\w])send(?:Sms|SMS|_sms)\s*\(/g },
];
const CONSENT_RE = /\b(?:sms_?consent|smsConsent|consent(?:ed)?_?at|consentedAt|opt_?in|optIn|opted_?in|optedIn|tcpa|marketing_?consent|sms_?opt)\b/i;
const OPTOUT_RE = /['"`](?:STOP|UNSUBSCRIBE|STOPALL|CANCEL|QUIT)['"`]|\bopt_?out\b|\boptOut\b|\bopted_?out\b|\bunsubscribed\b/i;
const VERIFY_RE = /constructEvent(?:Async)?\s*\(|\bwebhooks\.(?:constructEvent|verify|unwrap|verifySignature)\s*\(|validateRequest(?:WithBody)?\s*\(|\btwilio\.webhook\s*\(|\bnew\s+Webhook\s*\(|\bwh\.verify\s*\(|verifyWebhook\s*\(|verifySignature\s*\(|validateSignature\s*\(|isValidSignature|checkSignature|verify_signature|timingSafeEqual\s*\(|crypto\.subtle\.verify\s*\(|paddle\.webhooks\.unmarshal|validateWebhookSignature|shopify\.webhooks\.validate|@octokit\/webhooks|verifyAndReceive|standardwebhooks|from\s+['"]svix['"]|require\(\s*['"]svix['"]\s*\)/;

async function run(root, opts = {}) {
  const repo = loadRepo(root, opts);
  const code = repo.sources({ kinds: ['code'], tests: false }).filter((f) => !repo.isTooling(f));
  return [sms(repo, code), payments(repo, code), webhooks(repo)];
}

// ── LEGAL-01 ───────────────────────────────────────────────────────────────

function sms(repo, code) {
  const sends = [];
  for (const f of code) {
    const text = repo.code(f) || '';
    const names = taintedNames(text);
    for (const p of SMS_PROVIDERS) {
      if (!p.file.test(text)) continue;
      for (const m of text.matchAll(p.call)) {
        const line = repo.lineOf(f, m.index);
        if (repo.suppressed(f, line)) continue;
        const call = splitArgs(text, text.indexOf('(', m.index));
        const args = call ? call.args.map((a) => a.text).join(', ') : '';
        const to = /\b(?:to|PhoneNumber|recipient|recipients|destination)\s*:\s*([^,}\n]+)/.exec(args);
        const fromRequest = to ? isTainted(to[1], names) : isTainted(args, names);
        const note = `${p.name} send${p.otp ? ' (transactional OTP: consent comes from the user requesting it, but rate-limit it against SMS pumping)' : ''}${fromRequest ? '; the recipient number comes straight from the request' : ''}`;
        sends.push(ev(f.rel, line, note, repo.snippet(f, line)));
      }
    }
  }
  if (!sends.length) return na('LEGAL-01', 'no SMS sending code found');
  const consent = [];
  const optout = [];
  for (const f of repo.files.filter((x) => !x.build && (x.kind === 'code' || x.ext === '.sql' || x.ext === '.prisma'))) {
    const text = repo.code(f) || '';
    const c = CONSENT_RE.exec(text);
    if (c) consent.push(`${f.rel}:${repo.lineOf(f, c.index)}`);
    const o = OPTOUT_RE.exec(text);
    if (o) optout.push(`${f.rel}:${repo.lineOf(f, o.index)}`);
  }
  const evidence = [
    ...sends,
    consent.length ? `Consent-related code found at ${consent.slice(0, 3).join(', ')}: check that it gates every send above.` : 'No consent capture (sms_consent, opt_in, consented_at…) found anywhere in the repo.',
    optout.length ? `Opt-out handling found at ${optout.slice(0, 3).join(', ')}.` : 'No STOP/opt-out handling found.',
    'TCPA: $500 per unsolicited text, up to $1,500 if willful.',
  ];
  return manual('LEGAL-01', evidence);
}

// ── LEGAL-03 ───────────────────────────────────────────────────────────────

/**
 * The part of an amount expression the client controls directly. A lookup keyed by request
 * data (PRICES[plan], priceFor(plan)) is decided by the server, so index expressions and the
 * arguments of non-coercing calls are dropped; Number()/Math.round()/parseInt() keep theirs.
 */
function clientDecided(expr) {
  let out = String(expr);
  for (let i = 0; i < 3; i++) out = out.replace(/\[[^[\]]*\]/g, '');
  return out.replace(/\b(?!(?:Number|parseInt|parseFloat|BigInt|String|Math\.\w+)\b)([A-Za-z_$][\w$.]*)\s*\(([^()]*)\)/g, '$1()');
}

function payments(repo, code) {
  const usesPayments = repo.hasDepMatching(/^(?:stripe|@stripe\/|@paypal\/|razorpay|@lemonsqueezy\/|@paddle\/|square|braintree|mollie|@mollie\/)/);
  const flags = [];
  const fine = [];
  let calls = 0;
  for (const f of code) {
    const text = repo.code(f) || '';
    const side = repo.side(f);
    if (side !== 'client') {
      const names = taintedNames(text);
      for (const m of text.matchAll(/\b(?:paymentIntents|checkout\.sessions|charges|invoiceItems|orders|subscriptions|prices|paymentLinks|transactions)\.create\s*\(/g)) {
        calls++;
        const open = text.indexOf('(', m.index);
        const obj = objectAt(text, text.indexOf('{', open));
        if (!obj) continue;
        const line = repo.lineOf(f, m.index);
        const amount = /\b(amount|unit_amount|unit_amount_decimal|value|price|total)\s*:\s*([^,}\n]+)/g;
        let flagged = false;
        for (const a of obj.matchAll(amount)) {
          if (a[1] === 'price' && /^\s*['"`]price_/.test(a[2])) continue;
          if (isTainted(clientDecided(a[2]), names)) {
            flagged = true;
            const at = repo.lineOf(f, text.indexOf('{', open) + a.index);
            flags.push(ev(f.rel, at, `${m[0].replace(/\s*\($/, '')}: ${a[1]} comes from the request, so the browser decides what gets charged`, repo.snippet(f, at)));
          }
        }
        if (/\bline_items\s*:\s*(?:req\.body|body)\.\w+/.test(obj)) {
          flagged = true;
          flags.push(ev(f.rel, line, 'line_items are taken from the request body (price_data could be set by the client)'));
        }
        if (!flagged) fine.push(ev(f.rel, line, `${m[0].replace(/\s*\($/, '')} with server-side amounts/price IDs`));
      }
    } else {
      for (const m of text.matchAll(/\bfetch\(\s*['"`][^'"`]*(?:checkout|payment|pay|order|purchase|stripe|charge|subscribe)[^'"`]*['"`]\s*,\s*\{/gi)) {
        const obj = objectAt(text, text.indexOf('{', m.index + m[0].length - 1));
        if (/JSON\.stringify\(\s*\{[^}]*\b(?:amount|price|total|cost|unit_amount)\s*:/.test(obj)) {
          const line = repo.lineOf(f, m.index + m[0].length + obj.search(/\b(?:amount|price|total|cost|unit_amount)\s*:/));
          flags.push(ev(f.rel, line, 'the browser sends the amount/price to the checkout endpoint', repo.snippet(f, line)));
        }
      }
      for (const m of text.matchAll(/\b(?:coupon|promo|discount|voucher)\w*\s*===?\s*['"`][A-Z0-9_-]{3,}['"`]/gi)) {
        const line = repo.lineOf(f, m.index);
        flags.push(ev(f.rel, line, 'a discount code is checked in browser code (anyone can read it, or skip the check)', repo.snippet(f, line)));
      }
    }
  }
  if (flags.length) return manual('LEGAL-03', [...flags, ...fine]);
  if (!calls && !usesPayments) return na('LEGAL-03', 'no payment code found');
  return pass('LEGAL-03', fine.length ? fine : ['Payment SDK present; no charges built from request amounts and no client-side price or coupon logic found.']);
}

// ── APP-12 ─────────────────────────────────────────────────────────────────

function webhooks(repo) {
  const { routes } = getRoutes(repo);
  const candidates = new Map();
  for (const r of routes) {
    if (/webhook/i.test(r.path) || /webhook/i.test(r.file.rel) || (r.handler && /webhook/i.test(r.handler.file.rel))) candidates.set(`${r.file.rel}:${r.line}`, r);
  }
  if (!candidates.size) {
    const files = repo.sources({ kinds: ['code'], tests: false }).filter((f) => repo.side(f) !== 'client' && /webhook/i.test(f.rel) && !repo.isTooling(f));
    if (!files.length) return na('APP-12', 'no webhook receivers found');
    const bad = files.filter((f) => !VERIFY_RE.test(repo.code(f) || '')).map((f) => ev(f.rel, 1, 'webhook handler file with no signature verification'));
    return bad.length ? fail('APP-12', bad) : pass('APP-12', files.map((f) => ev(f.rel, null, 'webhook signature verified')));
  }
  const bad = [];
  const ok = [];
  for (const r of candidates.values()) {
    const texts = [routeBody(r), repo.code(r.file) || ''];
    if (r.handler) texts.push(repo.code(r.handler.file) || '');
    const verified = texts.some((t) => VERIFY_RE.test(t)) || VERIFY_RE.test(r.mountMiddleware || '');
    const where = r.handler && r.handler.file !== r.file ? ` (handler in ${r.handler.file.rel}:${repo.lineOf(r.handler.file, r.handler.start)})` : '';
    if (verified) ok.push(ev(r.file.rel, r.line, `${r.method} ${r.path} verifies the signature`));
    else bad.push(ev(r.file.rel, r.line, `${r.method} ${r.path} accepts webhook events without verifying the provider's signature${where}`, repo.snippet(r.file, r.line)));
  }
  if (bad.length) return fail('APP-12', [...bad, ...ok]);
  return pass('APP-12', ok);
}

module.exports = { name: 'comms', ids: IDS, run };
