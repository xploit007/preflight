'use strict';

// Consistency of everything that ships: versions, manifests, generated docs, the skill bundle.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { ROOT, scan } = require('./helpers');

const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

test('versions agree: package.json, plugin.json, scripts/lib/version.js', () => {
  const pkg = JSON.parse(read('package.json'));
  const plugin = JSON.parse(read('.claude-plugin/plugin.json'));
  const market = JSON.parse(read('.claude-plugin/marketplace.json'));
  assert.equal(require('../scripts/lib/version'), pkg.version);
  assert.equal(plugin.version, pkg.version);
  // The marketplace entry leaves version to plugin.json (setting both makes `claude plugin validate` warn).
  assert.equal(market.plugins[0].version, undefined);
});

test('plugin.json carries the fields from the spec', () => {
  const plugin = JSON.parse(read('.claude-plugin/plugin.json'));
  assert.equal(plugin.name, 'preflight');
  assert.equal(plugin.description, 'Pre-launch security and cost-risk scanner for vibe-coded web apps');
  assert.equal(plugin.version, '0.1.0');
});

test('package.json test script runs the scanner on the vulnerable fixture', () => {
  assert.equal(JSON.parse(read('package.json')).scripts.test, 'node scripts/scan.js ./fixtures/vulnerable');
});

test('generated files are up to date (checklist, command, skill, bundle)', () => {
  for (const tool of ['tools/gen-docs.js', 'tools/build-skill.js']) {
    const res = spawnSync(process.execPath, [path.join(ROOT, tool), '--check'], { cwd: ROOT, encoding: 'utf8' });
    assert.equal(res.status, 0, `${tool} --check: ${res.stderr}`);
  }
});

test('the check count is the same everywhere it is stated', () => {
  const { CHECKS } = require('../scripts/lib/catalog');
  for (const doc of ['README.md', 'docs/usage.md', 'skills/preflight/SKILL.md', 'skills/preflight/references/checklist.md', 'commands/scan.md']) {
    const counts = [...read(doc).matchAll(/\b(\d+) checks\b/g)].map((m) => Number(m[1]));
    for (const n of counts) assert.equal(n, CHECKS.length, `${doc} says ${n} checks`);
  }
  const bundled = scan(['fixtures/clean', '--json', '--offline'], { script: path.join(ROOT, 'skills', 'preflight', 'scripts', 'scan.js') });
  assert.equal(bundled.json.results.length, CHECKS.length, 'the bundled scanner reports every check');
});

test('the bundled skill scanner gives exactly the same results as scripts/scan.js', () => {
  for (const target of ['fixtures/vulnerable', 'fixtures/clean']) {
    const a = scan([target, '--json', '--offline']);
    const b = scan([target, '--json', '--offline'], { script: path.join(ROOT, 'skills', 'preflight', 'scripts', 'scan.js') });
    assert.equal(a.status, b.status);
    assert.deepEqual(b.json.results, a.json.results);
  }
});

test('SKILL.md frontmatter: name and the auto-invoke description from the spec', () => {
  const skill = read('skills/preflight/SKILL.md');
  const fm = /^---\n([\s\S]*?)\n---\n/.exec(skill)[1];
  assert.match(fm, /^name: preflight$/m);
  assert.ok(fm.includes('Use when the user asks to audit, scan, or harden a web app before launch, or mentions preflight, /scan, or pre-launch security review.'));
  assert.ok(skill.includes('${CLAUDE_SKILL_DIR}/scripts/scan.js'));
  assert.ok(fs.existsSync(path.join(ROOT, 'skills', 'preflight', 'scripts', 'scan.js')));
});

test('/scan command: description frontmatter, the three steps and the safety rules', () => {
  const cmd = read('commands/scan.md');
  assert.match(cmd, /^---\ndescription: .+\n/);
  assert.ok(cmd.includes('node "${CLAUDE_PLUGIN_ROOT}/scripts/scan.js"'));
  for (const s of ['## Step 1: run the scanner', '## Step 2: judge the warn and manual results', '## Step 3: write preflight-report.md', 'Report first, never fix', 'No destructive or active testing', 'production URLs']) assert.ok(cmd.includes(s), `missing: ${s}`);
});

test('claude plugin validate passes (skipped when the claude CLI is not installed)', (t) => {
  const which = spawnSync(process.platform === 'win32' ? 'where' : 'which', ['claude'], { encoding: 'utf8' });
  if (which.status !== 0) return t.skip('claude CLI not found');
  const res = spawnSync('claude', ['plugin', 'validate', ROOT], { encoding: 'utf8', timeout: 60000 });
  if (res.error) return t.skip(`claude plugin validate could not run: ${res.error.message}`);
  assert.equal(res.status, 0, res.stdout + res.stderr);
  assert.match(res.stdout, /Validation passed/);
});
