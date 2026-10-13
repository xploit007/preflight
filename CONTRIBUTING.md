# Contributing

Issues and pull requests are welcome.

- **Add or change a check:** update its entry in `scripts/lib/catalog.js` (id, severity, what, why, detection, fix, question) and its logic in the matching `scripts/checks/*.js` file. Plant the issue in `fixtures/vulnerable/` and record it in `test/planted.json`, and keep `fixtures/clean/` passing.
- **Rebuild generated files:** `npm run build` regenerates the checklist reference, `commands/scan.md`, `skills/preflight/SKILL.md` and the bundled skill scanner. `npm run check` fails if any of them is stale.
- **Test:** `npm run verify` runs the acceptance tests. `npm test` runs the scanner against the vulnerable fixture and exits 1 by design.
- **Fake secrets:** the fixtures contain fake secrets on purpose. `.github/secret_scanning.yml` keeps them out of GitHub secret-scanning alerts, but push protection still blocks a push that adds a new provider-format key; open the link it prints and allow the value as "used in tests".
