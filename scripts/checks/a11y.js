'use strict';

/**
 * LEGAL-02 ADA accessibility smoke test: a static count of basic signals across UI source
 * (JSX/TSX/Vue/Svelte/Astro/HTML templates). It is not an audit; it catches the cheap misses
 * that show up in demand letters: images without alt, unlabeled buttons and inputs, clickable
 * divs, no h1, no lang, disabled zoom, and near-zero ARIA.
 */

const { loadRepo } = require('../lib/repo');
const { pass, warn, na, ev } = require('../lib/result');

const IDS = ['LEGAL-02'];
const UI_FILE_RE = /\.(?:jsx|tsx|vue|svelte|astro|html?|ejs|hbs|handlebars|erb|njk|liquid)$/;

async function run(root, opts = {}) {
  const repo = loadRepo(root, opts);
  return [smokeTest(repo)];
}

/** Full text of the opening tag starting at i ("<"), skipping {…} expressions and quoted values. */
function tagAt(text, i) {
  let depth = 0;
  let quote = null;
  for (let j = i + 1; j < Math.min(text.length, i + 3000); j++) {
    const ch = text[j];
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (depth === 0 && (ch === '"' || ch === "'")) quote = ch;
    else if (ch === '{') depth++;
    else if (ch === '}') depth = Math.max(0, depth - 1);
    else if (ch === '>' && depth === 0) return text.slice(i, j + 1);
  }
  return text.slice(i, i + 300);
}

function* tags(text, names) {
  const re = new RegExp(`<(${names})(?=[\\s/>])`, 'g');
  for (const m of text.matchAll(re)) yield { index: m.index, name: m[1], tag: tagAt(text, m.index) };
}

/** Inner content of an element whose open tag ends at `end`, up to its closing tag. */
function inner(text, end, name) {
  const close = text.indexOf(`</${name}>`, end);
  return close === -1 ? '' : text.slice(end, close);
}

/** The {…} expression of a JSX attribute (onClick={…}), or ''. */
function attrExpr(tag, name) {
  const m = new RegExp(`\\b${name}\\s*=\\s*\\{`).exec(tag);
  if (!m) return '';
  let depth = 0;
  for (let i = m.index + m[0].length - 1; i < tag.length; i++) {
    if (tag[i] === '{') depth++;
    else if (tag[i] === '}' && --depth === 0) return tag.slice(m.index + m[0].length, i);
  }
  return '';
}

/** onClick={(e) => e.stopPropagation()}: a wrapper that stops bubbling, not a control. */
function onlyStopsEvents(tag) {
  const expr = attrExpr(tag, 'onClick');
  if (!/\b(?:stopPropagation|preventDefault)\s*\(/.test(expr)) return false;
  return [...expr.matchAll(/([\w$.]+)\s*\(/g)].every((m) => /(?:^|\.)(?:stopPropagation|preventDefault)$/.test(m[1]));
}

const has = (tag, re) => re.test(tag);
const PER_FILE = 5;
const ARIA_NAME_RE = /\baria-label(?:ledby)?\s*=|\btitle\s*=|\{\s*\.\.\./;

function smokeTest(repo) {
  const component = (f) => /\.(?:jsx|tsx|vue|svelte|astro)$/.test(f.name);
  const framework = repo.files.some((f) => !f.build && component(f));
  // Vendored or generated HTML (public/pdfjs/viewer.html, coverage and docs output) is not the app's UI.
  const vendored = (f) => /\.html?$/.test(f.name) && (/(?:^|\/)(?:coverage|docs?|storybook-static|playwright-report|test-results|_site|site)\//.test(f.rel) || (framework && /(?:^|\/)(?:public|static)\/[^/]+\//.test(f.rel)) || /(?:^|\/)(?:vendor|third[_-]?party|lib\/vendor)\//.test(f.rel));
  const files = repo.files.filter((f) => !f.build && UI_FILE_RE.test(f.name) && !repo.isTest(f) && !/(?:^|\/)(?:emails?|mail)\//.test(f.rel) && !vendored(f));
  if (!files.length) return na('LEGAL-02', 'no UI files (JSX/TSX/Vue/Svelte/HTML templates) found');
  const counts = { ariaLabel: 0, role: 0, aria: 0, h1: 0, img: 0, imgNoAlt: 0, button: 0, buttonNoName: 0, link: 0, linkNoName: 0, clickable: 0, inputs: 0, inputNoLabel: 0 };
  const issues = [];
  const perFile = new Map();
  const add = (f, index, note) => {
    const line = repo.lineOf(f, index);
    if (repo.suppressed(f, line)) return;
    const n = (perFile.get(f.rel) || 0) + 1;
    perFile.set(f.rel, n);
    if (n <= PER_FILE) issues.push(ev(f.rel, line, note, repo.snippet(f, line)));
  };
  let pages = 0;
  for (const f of files) {
    const text = repo.code(f);
    if (!text) continue;
    counts.ariaLabel += (text.match(/\baria-label(?:ledby)?\s*=/g) || []).length;
    counts.role += (text.match(/\brole\s*=\s*["'{]/g) || []).length;
    counts.aria += (text.match(/\baria-[a-z]+\s*=/g) || []).length;
    counts.h1 += (text.match(/<h1[\s>]|aria-level\s*=\s*["'{]?1\b/gi) || []).length;
    if (/\.html?$/.test(f.name) || /(?:^|\/)(?:pages|app|routes|views)\//.test(f.rel)) pages++;

    for (const t of tags(text, 'img|Image')) {
      counts.img++;
      if (!has(t.tag, /\balt\s*=/) && !has(t.tag, /aria-hidden\s*=\s*["'{]?true|role\s*=\s*["']presentation|\{\s*\.\.\./)) {
        counts.imgNoAlt++;
        add(f, t.index, `<${t.name}> has no alt text`);
      }
    }
    for (const t of tags(text, 'button|IconButton|a')) {
      const isLink = t.name === 'a';
      if (isLink) counts.link++;
      else counts.button++;
      if (ARIA_NAME_RE.test(t.tag)) continue;
      const body = t.tag.endsWith('/>') ? '' : inner(text, t.index + t.tag.length, t.name);
      const textContent = body.replace(/<svg[\s\S]*?<\/svg>/g, '').replace(/<[^>]+>/g, '').replace(/\{\s*\/\*[\s\S]*?\*\/\s*\}/g, '').trim();
      const namedChild = /<img[^>]*\balt\s*=\s*["'{][^"'}]/.test(body) || /<title>/.test(body) || /aria-label\s*=/.test(body) || /\bsr-only\b|visually-hidden|VisuallyHidden/.test(body);
      if (!textContent && !namedChild && !(isLink && !body)) {
        if (isLink) counts.linkNoName++;
        else counts.buttonNoName++;
        add(f, t.index, `${isLink ? 'link' : 'button'} has no accessible name (icon-only, no aria-label)`);
      }
    }
    for (const t of tags(text, 'div|span|li|p|section|article|td|tr|i|svg|img')) {
      if (!/\b(?:onClick|@click|on:click|v-on:click|\(click\))\s*=/.test(t.tag) || onlyStopsEvents(t.tag)) continue;
      counts.clickable++;
      const role = /\brole\s*=/.test(t.tag);
      const focusable = /\btab[iI]ndex\s*=/.test(t.tag);
      const keys = /\b(?:onKey(?:Down|Up|Press)|@keydown|@keyup|on:keydown|on:keyup|\(keydown\)|\(keyup\))\s*=/.test(t.tag);
      if (!role || !focusable || !keys) add(f, t.index, `clickable <${t.name}> is not keyboard-accessible (needs role, tabIndex and a key handler, or use <button>)`);
    }
    for (const t of tags(text, 'input|select|textarea')) {
      if (/\btype\s*=\s*["'](?:hidden|submit|button|reset|image)["']/.test(t.tag)) continue;
      if (/\s(?:hidden|aria-hidden\s*=\s*["'{]?true)(?=[\s/>={])/.test(t.tag) && !/\bhidden\s*=\s*\{?\s*false/.test(t.tag)) continue;
      counts.inputs++;
      if (ARIA_NAME_RE.test(t.tag)) continue;
      const id = (/\bid\s*=\s*["']([^"']+)["']/.exec(t.tag) || [])[1];
      const labelled = id && new RegExp(`(?:htmlFor|for)\\s*=\\s*["']${id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']`).test(text);
      const before = text.slice(Math.max(0, t.index - 400), t.index);
      const wrapped = before.lastIndexOf('<label') > before.lastIndexOf('</label>');
      if (!labelled && !wrapped) {
        counts.inputNoLabel++;
        add(f, t.index, `<${t.name}> has no label (add <label htmlFor>, wrap it in <label>, or aria-label)`);
      }
    }
    if (/\.html?$/.test(f.name)) {
      for (const m of text.matchAll(/<html(?=[\s>])[^>]*>/gi)) if (!/\blang\s*=/.test(m[0])) add(f, m.index, '<html> has no lang attribute');
    }
    for (const m of text.matchAll(/user-scalable\s*=\s*(?:no|0)|maximum-scale\s*=\s*1(?:\.0)?(?![\d.])/gi)) add(f, m.index, 'the viewport disables zoom (WCAG 1.4.4)');
    for (const m of text.matchAll(/\btab[iI]ndex\s*=\s*(?:["']|\{\s*)([1-9]\d*)/g)) add(f, m.index, `positive tabIndex (${m[1]}) breaks the natural focus order`);
  }
  for (const [rel, n] of perFile) if (n > PER_FILE) issues.push(ev(rel, null, `${n - PER_FILE} more issue(s) in this file, not listed`));
  const interactive = counts.button + counts.link + counts.inputs + counts.clickable;
  const summary = `Counts across ${files.length} UI file(s): ${counts.ariaLabel} aria-label/labelledby, ${counts.role} role=, ${counts.aria} aria-* total, ${counts.h1} <h1>, ${counts.img} <img> (${counts.imgNoAlt} without alt), ${counts.button} buttons (${counts.buttonNoName} unnamed), ${counts.link} links (${counts.linkNoName} unnamed), ${counts.inputs} form fields (${counts.inputNoLabel} unlabeled), ${counts.clickable} clickable non-buttons.`;
  const extra = [];
  if (counts.aria + counts.role <= 1 && interactive >= 5) extra.push(`Near-zero ARIA: ${counts.aria + counts.role} ARIA attributes for ${interactive} interactive elements.`);
  if (!counts.h1 && pages) extra.push('No <h1> anywhere in the UI: every page needs one main heading.');
  if (issues.length || extra.length) return warn('LEGAL-02', [summary, ...extra, ...issues, 'Context: 4,000+ ADA digital-accessibility lawsuits were filed in the US in 2024 (UsableNet), mostly against small businesses.']);
  return pass('LEGAL-02', [summary, 'Static smoke test only: run axe DevTools or Lighthouse and a keyboard-only pass before launch.']);
}

module.exports = { name: 'a11y', ids: IDS, run, tagAt };
