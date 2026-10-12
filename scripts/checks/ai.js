'use strict';

/**
 * AI-specific: AI-01 prompt injection, AI-02 unpermissioned tool access, AI-03 AI API keys in
 * client code / bundles / git, AI-04 uncapped LLM spend.
 */

const { loadRepo } = require('../lib/repo');
const { RATE_LIMIT_RE } = require('../lib/primitives');
const { taintedNames, isTainted } = require('../lib/taint');
const P = require('../lib/patterns');
const { pass, fail, warn, manual, na, ev } = require('../lib/result');
const { splitArgs, objectAt } = require('../lib/util');
const { historyFindings, historyEvidence, AI_CONTEXT_RE } = require('./secrets');

const IDS = ['AI-01', 'AI-02', 'AI-03', 'AI-04'];

const AI_SDK_RE = /['"](?:openai|@anthropic-ai\/sdk|ai|@ai-sdk\/[\w-]+|@google\/genai|@google\/generative-ai|groq-sdk|@mistralai\/mistralai|cohere-ai|langchain|@langchain\/[\w-]+|ollama|replicate|together-ai|@openrouter\/[\w-]+|@modelcontextprotocol\/sdk|@anthropic-ai\/claude-agent-sdk|@anthropic-ai\/claude-code)(?:\/[\w-]+)*['"]|from\s+openai\s+import|import\s+anthropic|from\s+anthropic\s+import/;
const LLM_CALL_RE = /\.chat\.completions\.create\s*\(|\.responses\.create\s*\(|(?<!sms)\.completions\.create\s*\(|\.messages\.(?:create|stream)\s*\(|\b(?:generateText|streamText|generateObject|streamObject)\s*\(|\.generateContent(?:Stream)?\s*\(|\.models\.generateContent\s*\(|\bollama\.(?:chat|generate)\s*\(/g;
const MAX_TOKENS_RE = /\b(?:max_tokens|maxTokens|max_output_tokens|maxOutputTokens|max_completion_tokens|maxCompletionTokens|max_new_tokens|maxNewTokens|num_predict|maxOutputTokenCount)\b/;
const DANGEROUS_RE = /(?<![\w.])(?:exec|execSync|spawn)\s*\(|child_process|\bfs\.(?:writeFile|writeFileSync|unlink|unlinkSync|rm|rmSync|rename)\s*\(|\.(?:delete|deleteMany|deleteOne|destroy|remove|drop|truncate)\s*\(|\bDELETE\s+FROM\b|\bDROP\s+TABLE\b|\.(?:update|upsert|insert)\s*\(|\b(?:refunds|transfers|payouts|charges|paymentIntents)\.create\s*\(|\bsendMail\s*\(|\bsendEmail\s*\(|\bmessages\.create\s*\(|\bfetch\s*\(\s*(?:url|args\.url|input\.url|params\.url|\w+\.url)\b/;
const APPROVAL_RE = /\bneedsApproval\b|\brequireApproval\b|\brequiresApproval\b|\bhuman_in_the_loop\b|\bhumanInTheLoop\b|\binterrupt\s*\(|\bcanUseTool\b|\bconfirmationRequired\b|\brequireConfirmation\b|\baskUser(?:Confirmation)?\b|\bapproval\s*:/;
const BYPASS_RE = /permissionMode\s*:\s*['"]bypassPermissions['"]|allowDangerouslySkipPermissions|--dangerously-skip-permissions|dangerouslySkipPermissions\s*:\s*true/;

async function run(root, opts = {}) {
  const repo = loadRepo(root, opts);
  const code = repo.sources({ kinds: ['code'], tests: false }).filter((f) => !repo.isTooling(f));
  const aiFiles = code.filter((f) => AI_SDK_RE.test(repo.code(f) || ''));
  const ctx = { repo, code, aiFiles, opts };
  return [promptInjection(ctx), toolAccess(ctx), await aiKeys(ctx), spend(ctx)];
}

/** Template literal interpolations: [{ expr, before, after, offset }]. */
function interpolations(template) {
  const out = [];
  let i = 0;
  while ((i = template.indexOf('${', i)) !== -1) {
    let depth = 0;
    let j = i + 2;
    for (; j < template.length; j++) {
      if (template[j] === '{') depth++;
      else if (template[j] === '}') {
        if (depth === 0) break;
        depth--;
      }
    }
    out.push({ expr: template.slice(i + 2, j), before: template.slice(Math.max(0, i - 40), i), after: template.slice(j + 1, j + 41), offset: i });
    i = j + 1;
  }
  return out;
}

const delimited = (x) => (/<[\w-]+>\s*$/.test(x.before) && /^\s*<\/[\w-]+>/.test(x.after)) || (/(?:"""|```|'''|\[\[|<<<|-{3,}|={3,})\s*$/.test(x.before) && /^\s*(?:"""|```|'''|\]\]|>>>|-{3,}|={3,})/.test(x.after));

// ── AI-01 ──────────────────────────────────────────────────────────────────

function promptInjection({ repo, aiFiles }) {
  if (!aiFiles.length) return na('AI-01', 'no LLM SDK usage found');
  const hits = [];
  const patterns = [
    { re: /\brole\s*:\s*['"`]system['"`]\s*,\s*content\s*:\s*`/g, what: 'system message' },
    { re: /\b(?:system|instructions|systemInstruction|system_prompt|systemPrompt|preamble)\s*:\s*`/g, what: 'system prompt' },
    { re: /\bnew\s+SystemMessage\(\s*`/g, what: 'SystemMessage' },
    { re: /\[\s*['"`]system['"`]\s*,\s*`/g, what: 'system prompt template' },
    { re: /\bprompt\s*:\s*`/g, what: 'prompt', instructionsOnly: true },
  ];
  for (const f of aiFiles) {
    const text = repo.code(f) || '';
    const names = repo.side(f) === 'client' ? new Set() : taintedNames(text);
    for (const p of patterns) {
      for (const m of text.matchAll(p.re)) {
        const start = m.index + m[0].length - 1;
        let end = start + 1;
        for (; end < text.length; end++) {
          if (text[end] === '\\') {
            end++;
            continue;
          }
          if (text[end] === '`') break;
        }
        const tpl = text.slice(start + 1, end);
        if (p.instructionsOnly && !/\b(?:you are|you're|act as|instructions?|rules?|system:|never|always|do not|don't|respond only)\b/i.test(tpl)) continue;
        for (const x of interpolations(tpl)) {
          if (!isTainted(x.expr, names) || delimited(x)) continue;
          const line = repo.lineOf(f, start + 1 + x.offset);
          if (repo.suppressed(f, line)) continue;
          hits.push(ev(f.rel, line, `request data (${x.expr.trim().slice(0, 30)}) is interpolated into the ${p.what} with no delimiters`, repo.snippet(f, line)));
        }
      }
    }
  }
  if (hits.length) return warn('AI-01', [...new Set(hits)]);
  return pass('AI-01', ['No request data interpolated into system prompts or instruction text without delimiters.']);
}

// ── AI-02 ──────────────────────────────────────────────────────────────────

function toolAccess({ repo, code }) {
  const hits = [];
  const fine = [];
  let tools = 0;
  for (const f of code) {
    const text = repo.code(f) || '';
    for (const m of text.matchAll(new RegExp(BYPASS_RE.source, 'g'))) {
      const line = repo.lineOf(f, m.index);
      hits.push(ev(f.rel, line, 'agent runs with permission checks bypassed', repo.snippet(f, line)));
    }
    const toolDefs = [...text.matchAll(/\btool\s*\(\s*\{|\btools\s*:\s*\[|\bnew\s+(?:Dynamic(?:Structured)?Tool|Tool)\s*\(|\bserver\.(?:tool|registerTool)\s*\(|\bfunctionDeclarations\s*:|\bfunction_declarations\s*:|@tool\b/g)];
    if (!toolDefs.length || !AI_SDK_RE.test(text)) continue;
    tools += toolDefs.length;
    const first = repo.lineOf(f, toolDefs[0].index);
    const danger = DANGEROUS_RE.exec(text);
    if (danger && !APPROVAL_RE.test(text)) {
      const line = repo.lineOf(f, danger.index);
      hits.push(ev(f.rel, line, `the model can trigger a side effect (${danger[0].trim().slice(0, 30)}) through a tool with no approval step`, repo.snippet(f, line)));
    } else fine.push(ev(f.rel, first, danger ? 'tools with side effects, gated by an approval step' : 'read-only tools'));
  }
  for (const f of repo.files.filter((x) => !x.build && (x.kind === 'config' || x.kind === 'doc') && /package\.json$|\.ya?ml$|\.sh$/.test(x.name))) {
    const text = repo.code(f) || '';
    const m = /--dangerously-skip-permissions/.exec(text);
    if (m) hits.push(ev(f.rel, repo.lineOf(f, m.index), 'an agent is launched with --dangerously-skip-permissions', repo.snippet(f, repo.lineOf(f, m.index))));
  }
  if (hits.length) return warn('AI-02', hits);
  if (!tools) return na('AI-02', 'no LLM tool/function definitions or agent configs found');
  return pass('AI-02', fine);
}

// ── AI-03 ──────────────────────────────────────────────────────────────────

async function aiKeys({ repo, opts }) {
  const hits = [];
  const seen = new Set();
  const add = (key, e) => {
    if (seen.has(key)) return;
    seen.add(key);
    hits.push(e);
  };
  const files = repo.files.filter((f) => ['code', 'markup', 'config', 'map', 'doc'].includes(f.kind));
  for (const f of files) {
    const text = repo.read(f);
    if (!text) continue;
    const side = f.build ? 'build' : repo.side(f);
    const tracked = repo.git.isTracked(f.rel);
    const exposed = side === 'client' || side === 'build' || tracked === true || (tracked === null && f.kind !== 'doc');
    const aiFile = AI_CONTEXT_RE.test(text);
    if (exposed) {
      for (const s of P.findSecrets(text)) {
        if (!(s.ai || (s.google && aiFile))) continue;
        const line = repo.lineOf(f, s.index);
        if (repo.suppressed(f, line)) continue;
        const where = side === 'build' ? 'build output' : side === 'client' ? 'browser code' : 'a committed file';
        add(`${s.value}|${f.rel}`, ev(f.rel, line, `${s.ai || 'Google AI'} key ${P.mask(s.value)} in ${where}`));
      }
    }
    if (f.kind === 'code' && !f.build) {
      for (const m of (repo.code(f) || '').matchAll(/\bdangerouslyAllowBrowser\s*:\s*true\b/g)) {
        const line = repo.lineOf(f, m.index);
        if (!repo.suppressed(f, line)) add(`dab|${f.rel}|${line}`, ev(f.rel, line, 'the AI SDK runs in the browser (dangerouslyAllowBrowser: true), so the key ships to every visitor', repo.snippet(f, line)));
      }
    }
  }
  const publicName = (name, f, line, snippet) => {
    const pp = P.publicPrefix(name, repo.depsFor(f.rel));
    if (pp && P.classifyPublicEnv(name, '') === 'ai') add(`env|${name}|${f.rel}`, ev(f.rel, line, `${name} puts an AI key behind the ${pp.prefix} prefix, so ${pp.framework} inlines it into the browser bundle`, snippet));
  };
  for (const f of repo.envFiles()) {
    (repo.read(f) || '').split('\n').forEach((raw, i) => {
      const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S*)/.exec(raw);
      if (m && (m[2] || repo.isEnvExample(f))) publicName(m[1], f, i + 1, P.redact(raw.trim()).slice(0, 120));
    });
  }
  for (const { f, m, line } of repo.matches(repo.sources({ kinds: ['code', 'markup'], tests: false }), /\b(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]*)/g)) publicName(m[1], f, line, repo.snippet(f, line));

  const h = await historyFindings(repo, opts);
  if (h.found) for (const x of h.found.values()) if (x.ai) add(`${x.value}|${x.file}|hist`, historyEvidence(repo, x).replace(' — ', ' — in git history: '));

  if (hits.length) return fail('AI-03', hits);
  const anyAi = repo.hasDepMatching(/^(?:openai|@anthropic-ai\/|ai$|@ai-sdk\/|@google\/genai|@google\/generative-ai|groq-sdk|@mistralai\/|cohere-ai|langchain|@langchain\/|replicate)/);
  if (!anyAi && !h.found) return na('AI-03', 'no AI SDKs or AI keys found');
  return pass('AI-03', ['No AI provider keys in browser code, public env vars, build output, committed files or recent git history.']);
}

// ── AI-04 ──────────────────────────────────────────────────────────────────

function spend({ repo, aiFiles }) {
  const server = aiFiles.filter((f) => repo.side(f) !== 'client');
  const calls = [];
  for (const f of aiFiles) {
    const text = repo.code(f) || '';
    const names = repo.side(f) === 'client' ? new Set() : taintedNames(text);
    for (const m of text.matchAll(LLM_CALL_RE)) {
      if (/\.messages\.(?:create|stream)/.test(m[0]) && /twilio/i.test(text) && !/anthropic/i.test(text)) continue;
      const call = splitArgs(text, m.index + m[0].length - 1);
      const args = call ? call.args.map((a) => (a.text.startsWith('{') ? objectAt(text, a.start + a.text.length - a.text.trimStart().length) || a.text : a.text)).join(', ') : '';
      calls.push({ f, index: m.index, args, names });
    }
  }
  if (!calls.length) return na('AI-04', 'no LLM API calls found');
  const hits = [];
  for (const c of calls) {
    const line = repo.lineOf(c.f, c.index);
    if (repo.suppressed(c.f, line)) continue;
    if (!MAX_TOKENS_RE.test(c.args)) hits.push(ev(c.f.rel, line, 'LLM call sets no output-token cap (max_tokens / maxOutputTokens)', repo.snippet(c.f, line)));
    const model = /\bmodel\s*:\s*([^,}\n]+)/.exec(c.args);
    if (model && isTainted(model[1], c.names)) hits.push(ev(c.f.rel, line, `the model is chosen by the request (${model[1].trim().slice(0, 30)}): callers can pick the most expensive one`));
  }
  const limited = repo.files.some((f) => !f.build && f.name !== 'package.json' && ['code', 'config'].includes(f.kind) && RATE_LIMIT_RE.test(repo.code(f) || ''));
  if (server.length && !limited) hits.push('LLM calls run on the server and nothing in the repo rate-limits them (see INFRA-04): anyone can run up your bill.');
  if (hits.length) return warn('AI-04', hits);
  return manual('AI-04', [`${calls.length} LLM call(s) cap output tokens, fix the model server-side and sit behind rate limiting.`, 'Provider-side limits are not visible from the repo: set a monthly budget/spend limit in the OpenAI, Anthropic or Google console.']);
}

module.exports = { name: 'ai', ids: IDS, run };
