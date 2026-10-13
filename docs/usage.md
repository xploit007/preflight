# Using preflight

## In Claude Code

From your app's repo:

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

It reports first and never fixes without asking. It doesn't run destructive or active tests. The only network calls are `npm audit` and, when you pass `--url` or `--supabase-url`, a handful of read-only GET requests: the page itself, one CORS probe, the http→https redirect check, and one `?limit=1` read per table.

## CLI options

```text
node scripts/scan.js [path] [options]

  --json                   machine-readable output (what /scan uses)
  --url <url>              check the deployed site's security headers, CORS and cookies
  --supabase-url <url>     Supabase project URL for the live RLS read test
  --supabase-key <key>     the anon/publishable key (service-role keys are refused)
  --offline                skip npm audit and live checks
  --no-audit               skip npm audit only
  --no-history             skip the git history secret scan
  --history-depth <n>      commits of history to scan (default 200)
  --only <groups|ids>      e.g. --only secrets,env or --only DATA-01
  --fail-on <severity>     exit 1 on fails at or above this severity (default critical)
  --verbose                list passing checks and full fix text
```

Exit codes: `0` no failing check at or above `--fail-on`, `1` at least one, `2` usage error or crash. It writes nothing into the scanned repo.

With `--supabase-url` and `--supabase-key`, preflight sends one `GET /rest/v1/<table>?select=*&limit=1` per table name it finds in your migrations and queries. If rows come back, the table is readable by anyone with your anon key, and DATA-01 fails as critical. Pass the anon key, never the service-role key.

## Output

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

## Suppressing findings

Add a `preflight-ignore` comment on the line (or the line above), or list paths in a `.preflightignore` file (gitignore syntax) at the repo root.

## Design and limits

- **Scripts find, the agent judges.** Regexes and small parsers do the detection. The agent only verifies `warn` results and answers `manual` questions, so it never eyeballs a whole repo for secrets.
- **Zero runtime dependencies.** Node builtins only (`fs`, `path`, `child_process`, `http`/`https`). `node scripts/scan.js` works in a fresh checkout with no `npm install`.
- **Read-only.** git commands run with optional locks off; live checks are single GETs that run only when you pass `--url` or `--supabase-url`.
- **Never leaks what it finds.** Every evidence line is redacted before it's printed.

The heuristics are pattern-based, not a parser or a taint engine, so they miss vulnerabilities that span files in unusual ways and occasionally flag safe code (which is what the agent step is for). Dashboard settings (spend caps, backups, Supabase RLS created in the UI) can't be seen from a repo, so those checks are manual by design. Secrets in bundles are only found if build output exists locally.
