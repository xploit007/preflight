# preflight

Pre-launch security and cost-risk scanner for vibe-coded web apps. It ships as a Claude Code plugin (`/scan`) and an agent skill: deterministic scripts find the problems, and the agent judges the uncertain ones and writes `preflight-report.md`.

Cloudflare's `security-audit-skill` does deep, adversarial vulnerability hunting in code. preflight is different and complementary: a fast, deterministic pre-launch checklist that catches the cheap, common, script-detectable mistakes that bankrupt vibe-coded apps or get them sued. Think leaked keys, Supabase tables with RLS off, API routes with no rate limit, cloud accounts with no spend cap, SMS sent without consent, and inaccessible markup. Most checks here need grep and APIs, not agents. The scan of a typical app finishes in seconds, and the agent only steps in to verify the heuristic hits and to turn dashboard-only questions into a to-do list.

## Install

**Claude Code plugin** (adds the `/scan` command and the `preflight` skill):

```text
/plugin marketplace add xploit007/preflight
/plugin install preflight@preflight
```

Or from your shell: `claude plugin marketplace add xploit007/preflight` then `claude plugin install preflight@preflight`.

**Agent skill via [skills.sh](https://skills.sh)** (Claude Code, Codex, Cursor and other agents):

```bash
npx skills add https://github.com/xploit007/preflight --skill preflight
```

Add `-a claude-code` to install it only for Claude Code, or `-g` to install it for every project. The skill folder (`skills/preflight/`) carries its own single-file copy of the scanner, so it works without the rest of this repo.

**CLI only** (no agent, no install step, Node 18+):

```bash
git clone https://github.com/xploit007/preflight
node preflight/scripts/scan.js /path/to/your-app
```

## Usage

In Claude Code, from your app's repo:

```text
/scan
/scan --url https://your-app.com
/scan --supabase-url https://<project-ref>.supabase.co --supabase-key <anon-key>
```

If another plugin also defines `/scan`, use `/preflight:scan`. With the skills.sh install there is no `/scan` command: type `/preflight`, or just ask Claude to "run preflight on this repo".

What `/scan` does:

1. Runs `node scripts/scan.js <repo> --json`: 59 checks, one result each, exit code 1 if any critical check fails.
2. For every `warn` and `manual` result, reads the code at the evidence lines and answers that result's precise question (confirmed, not an issue, or needs the owner). It doesn't re-scan the repo by eye.
3. Writes `preflight-report.md` in the scanned repo: findings ordered by severity, each with `file:line` evidence and a concrete fix, plus a to-do list for dashboard-only items such as spend caps.

It reports first and never fixes without asking. It doesn't run destructive or active tests: the only network calls are `npm audit` and, when you pass the flags, one read-only GET per live check.

### CLI options

```text
node scripts/scan.js [path] [options]

  --json                   machine-readable output (what /scan uses)
  --url <url>              check the deployed site's security headers, CORS and cookies
  --supabase-url <url>     Supabase project URL for the live RLS read test
  --supabase-key <key>     the anon/publishable key (service-role keys are refused)
  --offline                skip npm audit and live checks
  --no-history             skip the git history secret scan
  --history-depth <n>      commits of history to scan (default 200)
  --only <groups|ids>      e.g. --only secrets,env or --only DATA-01
  --fail-on <severity>     exit 1 on fails at or above this severity (default critical)
  --verbose                list passing checks and full fix text
```

Exit codes: `0` no failing check at or above `--fail-on`, `1` at least one, `2` usage error or crash. It writes nothing into the scanned repo.

With `--supabase-url` and `--supabase-key`, preflight sends one `GET /rest/v1/<table>?select=*&limit=1` per table name it finds in your migrations and queries. If rows come back, the table is readable by anyone with your anon key, and DATA-01 fails as critical. Pass the anon key, never the service-role key.

### Output

Every check emits exactly one result:

```json
{
  "id": "DATA-01",
  "title": "Supabase RLS disabled or permissive",
  "severity": "critical",
  "status": "fail",
  "evidence": ["supabase/migrations/20250101000000_init.sql:10 — public.notes is created without \"enable row level security\": anyone with your anon key can read and write it"],
  "fix": "Run `alter table public.<t> enable row level security;` for every table, then add explicit policies…"
}
```

`severity` is `critical | high | medium | low` and `status` is `pass | fail | warn | manual`. `warn` and `manual` results also carry a `question`: the precise thing the agent (or you) has to decide. Secrets in evidence are always masked (`sk_live_51…7Q`). The JSON envelope adds `summary`, `detected` (frameworks and services), `notes` and per-group timings.

Suppress a finding with a `preflight-ignore` comment on the line (or the line above), or list paths in a `.preflightignore` file (gitignore syntax) at the repo root.

## The 59 checks

`auto` means the script decides. `auto + agent` means the script flags candidates and the agent verifies them. `manual` means the script gathers context and the agent or you decide (usually in a provider dashboard). Full detection logic and fix guidance for each check are in [`skills/preflight/references/checklist.md`](skills/preflight/references/checklist.md).

<!-- checklist:start (generated by tools/gen-docs.js, do not edit by hand) -->

| ID | Check | Group | Severity | Auto/manual |
| :- | :- | :- | :- | :- |
| SEC-01 | Exposed database credentials | Secrets & credentials | critical | auto |
| SEC-02 | Committed or public .env files | Secrets & credentials | critical | auto |
| SEC-03 | Hardcoded secrets in source | Secrets & credentials | critical | auto |
| SEC-04 | Secrets in git history | Secrets & credentials | critical | auto |
| SEC-05 | Secrets in built JS bundles | Secrets & credentials | critical | auto |
| SEC-06 | Hardcoded JWT / session secrets | Secrets & credentials | critical | auto |
| SEC-07 | Default credentials | Secrets & credentials | high | auto + agent |
| SEC-08 | Secrets behind public env prefixes | Secrets & credentials | critical | auto |
| AUTH-01 | Weak authentication | Auth & access | high | auto + agent |
| AUTH-02 | Missing authorization checks | Auth & access | critical | auto + agent |
| AUTH-03 | Cross-user data access | Auth & access | high | auto + agent |
| AUTH-04 | Unprotected admin routes | Auth & access | critical | auto + agent |
| AUTH-05 | Broken password reset | Auth & access | high | auto + agent |
| AUTH-06 | Weak session management | Auth & access | high | auto + agent |
| AUTH-07 | IDOR / BOLA | Auth & access | high | auto + agent |
| AUTH-08 | Mass assignment | Auth & access | high | auto + agent |
| AUTH-09 | Misconfigured OAuth | Auth & access | high | auto + agent |
| AUTH-10 | Insecure cookie settings | Auth & access | medium | auto + agent |
| DATA-01 | Supabase RLS disabled or permissive | Data & database | critical | auto |
| DATA-02 | Supabase service_role key in client code | Data & database | critical | auto |
| DATA-03 | Open database & storage rules | Data & database | critical | auto |
| DATA-04 | Excessive database privileges | Data & database | high | auto + agent |
| DATA-05 | Unencrypted sensitive data | Data & database | high | auto + agent |
| DATA-06 | Poor tenant isolation | Data & database | high | manual |
| DATA-07 | Missing backups / restore plan | Data & database | high | manual |
| INFRA-01 | Cloud service misconfiguration | Infra & cost | high | auto + agent |
| INFRA-02 | Spend caps & budget alerts | Infra & cost | high | manual |
| INFRA-03 | Unbounded serverless execution | Infra & cost | medium | auto + agent |
| INFRA-04 | No rate limiting on API routes | Infra & cost | high | auto |
| INFRA-05 | DDoS & bandwidth bill exposure | Infra & cost | high | manual |
| APP-01 | XSS sinks | AppSec | high | auto + agent |
| APP-02 | SQL injection | AppSec | critical | auto + agent |
| APP-03 | NoSQL injection | AppSec | high | auto + agent |
| APP-04 | CSRF | AppSec | medium | auto + agent |
| APP-05 | SSRF | AppSec | high | auto + agent |
| APP-06 | Path traversal | AppSec | high | auto + agent |
| APP-07 | Insecure file uploads | AppSec | high | auto + agent |
| APP-08 | Command injection | AppSec | critical | auto + agent |
| APP-09 | Code injection (eval) | AppSec | critical | auto + agent |
| APP-10 | Insecure deserialization | AppSec | high | auto + agent |
| APP-11 | Input validation gaps | AppSec | medium | auto + agent |
| APP-12 | Unsigned webhooks | AppSec | high | auto |
| APP-13 | Permissive CORS | AppSec | high | auto |
| APP-14 | Open redirects | AppSec | medium | auto + agent |
| APP-15 | Missing security headers | AppSec | medium | auto |
| APP-16 | Exposed environments & debug tools in production | AppSec | high | auto + agent |
| APP-17 | Verbose production errors | AppSec | medium | auto + agent |
| APP-18 | Exposed logs | AppSec | medium | auto |
| APP-19 | Exposed source maps | AppSec | medium | auto |
| LEGAL-01 | SMS without opt-in consent (TCPA) | Legal & compliance | critical | manual |
| LEGAL-02 | ADA accessibility smoke test | Legal & compliance | high | auto + agent |
| LEGAL-03 | Client-side-only payment validation | Legal & compliance | critical | manual |
| DEP-01 | Known-vulnerable dependencies | Dependencies & supply chain | high | auto |
| DEP-02 | Missing lockfile | Dependencies & supply chain | medium | auto |
| DEP-03 | Malicious & typosquatted packages | Dependencies & supply chain | critical | auto + agent |
| AI-01 | Prompt injection | AI-specific | high | auto + agent |
| AI-02 | Unpermissioned AI tool access | AI-specific | high | auto + agent |
| AI-03 | AI API keys in client code or git | AI-specific | critical | auto |
| AI-04 | Uncapped LLM spend | AI-specific | high | auto + agent |

<!-- checklist:end -->

## How it differs from Cloudflare's security-audit-skill

Cloudflare's [security-audit-skill](https://github.com/cloudflare/security-audit-skill) turns a coding agent into a security auditor. Isolated agents work through six phases (reconnaissance, coverage-led hunting, candidate validation, structured output, independent record verification and reporting), and a fresh verifier tries to disprove every candidate before it counts. That makes it deep and adversarial: the right tool for the exploitable bug that no pattern would catch, at the cost of a long, token-heavy run. preflight makes the opposite trade-off. The scan itself is deterministic, takes seconds and needs no model. It targets the common, cheap mistakes that sink launches, and it adds launch checks that aren't code vulnerabilities at all: whether spend caps are set in provider dashboards, how your host bills a traffic flood, TCPA consent for SMS, ADA basics. Run preflight on every repo before launch, and reach for security-audit-skill when you need depth. They work well together.

## Design

- **Scripts find, the agent judges.** Regexes and small parsers do the detection. The agent only verifies `warn` results and answers `manual` questions, so it never eyeballs a whole repo for secrets.
- **Zero runtime dependencies.** Node builtins only (`fs`, `path`, `child_process`, `http`/`https`). `node scripts/scan.js` works in a fresh checkout with no `npm install`.
- **Read-only.** git commands run with optional locks off; live checks are single GETs that run only when you pass `--url` or `--supabase-url`.
- **Never leaks what it finds.** Every evidence line is redacted before it's printed.

Limits worth knowing: the heuristics are pattern-based, not a parser or a taint engine, so they miss vulnerabilities that span files in unusual ways and occasionally flag safe code (which is what the agent step is for). Dashboard settings (spend caps, backups, Supabase RLS created in the UI) can't be seen from a repo, so those checks are manual by design. Secrets in bundles are only found if build output exists locally.

## Contributing

Issues and pull requests are welcome.

- **Add or change a check:** update its entry in `scripts/lib/catalog.js` (id, severity, what, why, detection, fix, question) and its logic in the matching `scripts/checks/*.js` file. Plant the issue in `fixtures/vulnerable/` and record it in `test/planted.json`, and keep `fixtures/clean/` passing.
- **Rebuild generated files:** `npm run build` regenerates the checklist reference, the README table, `commands/scan.md`, `skills/preflight/SKILL.md` and the bundled skill scanner. `npm run check` fails if any of them is stale.
- **Test:** `npm run verify` runs the acceptance tests. `npm test` runs the scanner against the vulnerable fixture and exits 1 by design.
- The fixtures contain fake secrets on purpose. `.github/secret_scanning.yml` keeps GitHub secret scanning and push protection away from `fixtures/`.

## License

MIT. See [LICENSE](LICENSE).
