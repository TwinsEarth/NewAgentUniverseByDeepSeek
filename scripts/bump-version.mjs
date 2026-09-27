#!/usr/bin/env node
// Bumps the project version everywhere it is written down.
//
// WHY THIS EXISTS
// ---------------
// Upstream `agent-universe` managed its version with `scripts/bump-version.sh`,
// a pile of `sed -i` rules keyed to a hand-maintained table
// (`docs/version-checklist.md`). The audit found that approach had already
// drifted: six files still declared `2.3.6`/`v2.3.4` because the table never
// registered them, and `sed` exits 0 whether or not it matched, so every rule
// that stopped matching failed *silently*.
//
// This script inverts that: it declares every target explicitly, and it FAILS
// LOUDLY if any of them cannot be updated. A version bump that quietly did
// nothing is the failure mode being designed out.
//
// Usage:
//   node scripts/bump-version.mjs 1.1.1
//   node scripts/bump-version.mjs 1.1.1 --check   # verify, change nothing

import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..');

const args = process.argv.slice(2);
const check = args.includes('--check');
const next = args.find((a) => !a.startsWith('--'));

if (!next) {
  console.error('usage: node scripts/bump-version.mjs <MAJOR.MINOR.PATCH> [--check]');
  process.exit(2);
}
if (!/^\d+\.\d+\.\d+$/.test(next)) {
  console.error(`error: "${next}" is not MAJOR.MINOR.PATCH`);
  process.exit(2);
}

const current = fs.readFileSync(path.join(ROOT, 'VERSION'), 'utf8').trim();
if (current === next) {
  console.log(`already at ${next}; nothing to do`);
  process.exit(0);
}
console.log(`bumping ${current} -> ${next}${check ? '  (check only)' : ''}\n`);

/** Each target: a file, a regex with a capture group for the version, and a label. */
const targets = [
  {
    file: 'VERSION',
    label: 'repository version (the single source of truth)',
    pattern: /^(\d+\.\d+\.\d+)\s*$/m,
    template: (v) => `${v}\n`,
    wholeFile: true,
  },
  {
    file: 'contracts/VERSION',
    label: 'contracts mirror (CI diffs this against VERSION)',
    pattern: /^(\d+\.\d+\.\d+)\s*$/m,
    template: (v) => `${v}\n`,
    wholeFile: true,
  },
  {
    file: 'contracts/deploy.config.example.json',
    label: 'deploy config example (asserted against VERSION by contracts/verify_static.py)',
    pattern: /("version"\s*:\s*")(\d+\.\d+\.\d+)(")/,
  },
  {
    file: 'Cargo.toml',
    label: '[workspace.package] version',
    pattern: /(\[workspace\.package\][\s\S]*?^version\s*=\s*")(\d+\.\d+\.\d+)(")/m,
  },
  {
    file: 'Cargo.toml',
    label: '[workspace.dependencies] path-dependency versions',
    pattern: /(nau-[a-z]+\s*=\s*\{\s*path\s*=\s*"crates\/nau-[a-z]+",\s*version\s*=\s*")(\d+\.\d+\.\d+)(")/g,
    expectMultiple: true,
  },
  {
    file: 'crates/nau-core/tests/version_consistency.rs',
    label: 'the assertion that pins the release version',
    pattern: /(assert_eq!\(\s*v,\s*")(\d+\.\d+\.\d+)(",)/,
  },
];

let failures = 0;
let edits = 0;

for (const t of targets) {
  const full = path.join(ROOT, t.file);
  if (!fs.existsSync(full)) {
    console.error(`FAIL  ${t.file}: file does not exist`);
    failures += 1;
    continue;
  }
  let text = fs.readFileSync(full, 'utf8');

  // Build a count of matches so a rule that no longer applies is loud.
  const probe = new RegExp(t.pattern.source, t.pattern.flags.replace('g', ''));
  const globalCount = (text.match(new RegExp(t.pattern.source, t.pattern.flags.includes('g') ? t.pattern.flags : t.pattern.flags + 'g')) || []).length;

  if (globalCount === 0) {
    console.error(`FAIL  ${t.file}: ${t.label} — pattern did not match (nothing to update)`);
    failures += 1;
    continue;
  }
  if (t.expectMultiple && globalCount < 2) {
    console.error(`FAIL  ${t.file}: ${t.label} — expected several matches, found ${globalCount}`);
    failures += 1;
    continue;
  }

  let updated;
  if (t.wholeFile) {
    updated = t.template(next);
  } else if (t.pattern.flags.includes('g')) {
    updated = text.replace(t.pattern, (_m, pre, _old, post) => `${pre}${next}${post}`);
  } else {
    updated = text.replace(t.pattern, (_m, pre, _old, post) => `${pre}${next}${post}`);
  }

  if (updated === text) {
    console.error(`FAIL  ${t.file}: ${t.label} — matched but produced no change`);
    failures += 1;
    continue;
  }
  // Sanity: the old version must be gone from the places we touched.
  const stillOld = t.wholeFile ? false : probe.exec(updated) !== null && probe.exec(updated)?.[2] === current;
  if (stillOld) {
    console.error(`FAIL  ${t.file}: ${t.label} — ${current} still present after the edit`);
    failures += 1;
    continue;
  }

  edits += 1;
  console.log(`ok    ${t.file.padEnd(46)} ${t.label}  (${globalCount} match${globalCount === 1 ? '' : 'es'})`);
  if (!check) fs.writeFileSync(full, updated, 'utf8');
}

console.log('');
if (failures > 0) {
  console.error(`${failures} target(s) could not be updated; refusing to leave a half-bumped tree.`);
  process.exit(1);
}
console.log(check ? `${edits} target(s) would be updated.` : `${edits} target(s) updated. Now run:`);
if (!check) {
  console.log('  node conformance/generate.mjs && git diff --exit-code conformance/vectors.json');
  console.log('  cargo test --workspace');
}
