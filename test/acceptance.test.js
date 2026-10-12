'use strict';

// The acceptance criteria from the build spec, one test each.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { ROOT, scan, isTracked, pointsAt, schemaProblems, tempCopy, byId } = require('./helpers');
const planted = require('./planted.json');
const { CHECKS } = require('../scripts/lib/catalog');

const VULN = 'fixtures/vulnerable';
const CLEAN = 'fixtures/clean';
const committed = isTracked(`${VULN}/.env`);

function expectedStatuses(p) {
  if (!committed && p.statusWithoutGit) return p.statusWithoutGit;
  return p.status;
}

test('node scripts/scan.js ./fixtures/vulnerable exits non-zero', () => {
  const res = scan(['./fixtures/vulnerable']);
  assert.equal(res.status, 1, res.stderr);
  assert.match(res.stdout, /Exit 1: at least one critical check failed/);
});

test('vulnerable fixture: at least 10 of the 12 headline planted issues are reported at the right file:line', () => {
  const { status, json } = scan(['./fixtures/vulnerable', '--json']);
  assert.equal(status, 1);
  const results = byId(json);
  const misses = [];
  for (const p of planted.headline) {
    const r = results.get(p.check);
    const ok = r && expectedStatuses(p).includes(r.status) && pointsAt(r, p.file, p.line);
    if (!ok) misses.push(`${p.check} ${p.file}:${p.line} (${p.what}) → ${r ? `${r.status}: ${r.evidence.slice(0, 3).join(' | ')}` : 'missing'}`);
  }
  assert.equal(planted.headline.length, 12);
  assert.ok(planted.headline.length - misses.length >= 10, `only ${planted.headline.length - misses.length}/12 found:\n${misses.join('\n')}`);
  assert.deepEqual(misses, [], 'every headline planted issue should be found');
});

test('vulnerable fixture: every other planted issue is reported at the right file:line', () => {
  const { json } = scan(['./fixtures/vulnerable', '--json']);
  const results = byId(json);
  const misses = [];
  for (const p of planted.more) {
    if (p.requiresGit && !committed) continue;
    const r = results.get(p.check);
    if (!r || !expectedStatuses(p).includes(r.status) || !pointsAt(r, p.file, p.line)) {
      misses.push(`${p.check} ${p.file}:${p.line} (${p.what}) → ${r ? `${r.status}: ${r.evidence.slice(0, 3).join(' | ')}` : 'missing'}`);
    }
  }
  assert.deepEqual(misses, []);
});

test('node scripts/scan.js ./fixtures/clean exits zero', () => {
  const res = scan(['./fixtures/clean']);
  assert.equal(res.status, 0, res.stdout + res.stderr);
});

test('clean fixture: no critical or high failures (and no warnings)', () => {
  const { status, json } = scan(['./fixtures/clean', '--json', '--no-audit']);
  assert.equal(status, 0);
  const bad = json.results.filter((r) => r.status === 'fail' && (r.severity === 'critical' || r.severity === 'high'));
  assert.deepEqual(bad.map((r) => `${r.id}: ${r.evidence[0]}`), []);
  assert.equal(json.summary.fail, 0, 'no failures of any severity');
  assert.deepEqual(json.results.filter((r) => r.status === 'warn').map((r) => `${r.id}: ${r.evidence[0]}`), []);
});

test('--json outputs valid JSON matching the result schema', () => {
  for (const target of [VULN, CLEAN]) {
    const { stdout, json } = scan([target, '--json', '--offline']);
    assert.doesNotThrow(() => JSON.parse(stdout));
    assert.equal(json.tool, 'preflight');
    assert.equal(json.results.length, CHECKS.length);
    assert.deepEqual(json.results.map((r) => r.id), CHECKS.map((c) => c.id), 'one result per check, in catalog order');
    for (const r of json.results) assert.deepEqual(schemaProblems(r), [], `${target} ${r.id}`);
    for (const k of ['total', 'fail', 'warn', 'manual', 'pass', 'criticalFails', 'exitCode']) assert.equal(typeof json.summary[k], 'number');
  }
  // --json with no path scans the current directory
  const here = scan(['--json', '--offline'], { cwd: path.join(ROOT, CLEAN) });
  assert.equal(here.json.target, path.join(ROOT, CLEAN));
});

test('no runtime dependencies: runs from a bare copy of scripts/ with no node_modules', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  for (const k of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) assert.equal(pkg[k], undefined, `package.json has ${k}`);
  const builtins = new Set(require('module').builtinModules);
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));
  for (const file of walk(path.join(ROOT, 'scripts')).filter((f) => f.endsWith('.js'))) {
    const code = require('../scripts/lib/util').blankComments(fs.readFileSync(file, 'utf8'), '.js');
    for (const m of code.matchAll(/require\(\s*['"]([^'"]+)['"]\s*\)/g)) {
      const spec = m[1].replace(/^node:/, '');
      assert.ok(spec.startsWith('.') || builtins.has(spec), `${path.relative(ROOT, file)} requires "${m[1]}"`);
    }
  }
  const bare = tempCopy(path.join(ROOT, 'scripts'), 'preflight-bare-');
  const res = scan([path.join(ROOT, VULN), '--json', '--offline'], { cwd: bare, script: path.join(bare, 'scan.js') });
  assert.equal(res.status, 1, res.stderr);
  assert.equal(res.json.results.length, CHECKS.length);
  // The skill folder alone (what `npx skills add` installs) also runs.
  const skill = tempCopy(path.join(ROOT, 'skills', 'preflight'), 'preflight-skill-');
  const res2 = scan([path.join(ROOT, VULN), '--json', '--offline'], { cwd: skill, script: path.join(skill, 'scripts', 'scan.js') });
  assert.equal(res2.status, 1, res2.stderr);
  assert.equal(res2.json.results.length, CHECKS.length);
});

test('scan of the vulnerable fixture completes in under 60 seconds', () => {
  const res = scan(['./fixtures/vulnerable', '--json']);
  assert.ok(res.ms < 60000, `took ${res.ms}ms`);
});

test('README install commands match the repo layout', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const market = JSON.parse(fs.readFileSync(path.join(ROOT, '.claude-plugin', 'marketplace.json'), 'utf8'));
  const plugin = JSON.parse(fs.readFileSync(path.join(ROOT, '.claude-plugin', 'plugin.json'), 'utf8'));
  // /plugin marketplace add <owner>/<repo> then /plugin install <plugin>@<marketplace>
  const install = /\/plugin install ([\w.-]+)@([\w.-]+)/.exec(readme);
  assert.ok(/\/plugin marketplace add xploit007\/preflight/.test(readme));
  assert.ok(install, 'README has a /plugin install command');
  assert.equal(install[1], market.plugins[0].name);
  assert.equal(install[2], market.name);
  assert.equal(plugin.name, market.plugins[0].name);
  assert.equal(market.plugins[0].source, './');
  // npx skills add … --skill preflight → skills/preflight/SKILL.md with name: preflight
  assert.ok(readme.includes('npx skills add https://github.com/xploit007/preflight --skill preflight'));
  const skill = fs.readFileSync(path.join(ROOT, 'skills', 'preflight', 'SKILL.md'), 'utf8');
  assert.match(skill, /^---\nname: preflight\n/);
  // Every repo path the README links or names exists.
  for (const rel of ['skills/preflight/references/checklist.md', 'skills/preflight/SKILL.md', 'scripts/scan.js', 'commands/scan.md', 'LICENSE', 'scripts/lib/catalog.js', 'test/planted.json', 'fixtures/vulnerable', 'fixtures/clean', '.github/secret_scanning.yml']) {
    assert.ok(fs.existsSync(path.join(ROOT, rel)), `${rel} is referenced but missing`);
  }
  assert.ok(readme.includes('node preflight/scripts/scan.js'), 'CLI usage points at scripts/scan.js');
  // The /scan command exists where the plugin loader looks for commands.
  assert.ok(fs.existsSync(path.join(ROOT, 'commands', 'scan.md')));
});

test('every one of the 59 checks appears in references/checklist.md and the README table', () => {
  assert.equal(CHECKS.length, 59);
  const checklist = fs.readFileSync(path.join(ROOT, 'skills', 'preflight', 'references', 'checklist.md'), 'utf8');
  const headings = [...checklist.matchAll(/^### ([A-Z]+-\d+): /gm)].map((m) => m[1]);
  assert.deepEqual(headings, CHECKS.map((c) => c.id));
  for (const c of CHECKS) {
    const section = checklist.slice(checklist.indexOf(`### ${c.id}: `)).split('\n### ')[0];
    for (const label of ['**What:**', '**Why it matters:**', "**How it's detected:**", '**Fix:**']) assert.ok(section.includes(label), `${c.id} missing ${label}`);
  }
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const rows = [...readme.matchAll(/^\| ([A-Z]+-\d+) \| (.+?) \| .+? \| (critical|high|medium|low) \| (auto|auto \+ agent|manual) \|$/gm)].map((m) => m[1]);
  assert.deepEqual(rows, CHECKS.map((c) => c.id));
});
