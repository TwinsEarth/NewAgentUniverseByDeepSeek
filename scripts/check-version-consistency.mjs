#!/usr/bin/env node
// Gate: VERSION is the only place the release version is written down.
//
// This mirrors the `version` job in .github/workflows/ci.yml. It exists locally
// because the version bump is exactly the kind of change that is easy to do
// half-way: `scripts/bump-version.mjs` updates the declarations it knows about, but
// nothing checked that the SDKs and the contract tree still agree, and CI is too
// late to find out. (The 1.1.1 -> 1.2.3 bump in this repo was carried out by a
// script whose own pattern silently missed a target -- see docs/SELF-AUDIT.md --
// which is the argument for having this gate rather than trusting the tool.)
//
// Checks, in the same order and with the same intent as CI:
//   1. VERSION is non-empty and equals [workspace.package] version;
//   2. every crates/*/Cargo.toml either declares no version or declares VERSION;
//   3. sdks/js/package.json does NOT restate the version (npm needs it at publish
//      time and the publish step injects it, so a copy here would drift);
//   4. sdks/python/pyproject.toml derives it (attr = ...) instead of declaring it;
//   5. no shipping SDK source restates the version string;
//   6. contracts/VERSION mirrors VERSION.
//
// Usage: node scripts/check-version-consistency.mjs [--list]

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const ROOT = path.resolve(
  path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')),
  '..',
);
const listOnly = process.argv.includes('--list');
const problems = [];
const notes = [];
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

// 1) VERSION vs [workspace.package] version.
const version = read('VERSION').replace(/\s+/g, '');
if (!version) problems.push('VERSION is empty');
const manifest = read('Cargo.toml');
const wpMatch = /\[workspace\.package\]([\s\S]*?)(?=\n\[|$)/.exec(manifest);
const wpVersion = wpMatch ? (/^\s*version\s*=\s*"([^"]+)"/m.exec(wpMatch[1]) || [])[1] : undefined;
if (!wpVersion) problems.push('Cargo.toml has no [workspace.package] version');
else if (wpVersion !== version) {
  problems.push('VERSION (' + version + ') != [workspace.package] version (' + wpVersion + ')');
}

// 2) Every crate manifest either declares nothing or declares VERSION.
const cratesDir = path.join(ROOT, 'crates');
for (const name of fs.readdirSync(cratesDir)) {
  const p = path.join(cratesDir, name, 'Cargo.toml');
  if (!fs.existsSync(p)) continue;
  const t = fs.readFileSync(p, 'utf8');
  if (!/^\[package\]/m.test(t)) continue;
  const m = /^\s*version\s*=\s*"([^"]+)"/m.exec(t);
  if (m && m[1] !== version) {
    problems.push('crates/' + name + '/Cargo.toml declares ' + m[1] + ', expected ' + version);
  }
}

// 3) The npm manifest must not restate the version.
const jsManifest = 'sdks/js/package.json';
if (fs.existsSync(path.join(ROOT, jsManifest))) {
  const t = read(jsManifest);
  if (/"version"\s*:/.test(t)) {
    problems.push(jsManifest + ' declares a version; keep it only in VERSION and inject it at publish time');
  }
}

// 4) The Python manifest must derive, not declare.
const pyManifest = 'sdks/python/pyproject.toml';
if (fs.existsSync(path.join(ROOT, pyManifest))) {
  const t = read(pyManifest);
  if (/^version\s*=\s*"/m.test(t)) {
    problems.push(pyManifest + ' declares a literal version; use attr = nau_sdk.version.VERSION');
  }
}

// 5) No shipping SDK source restates the version string.
const escaped = version.replace(/\./g, '\\.');
const restates = new RegExp('"' + escaped + '"|\'' + escaped + '\'');
const scanDirs = ['sdks/python/nau_sdk', 'sdks/js/lib'];
const scanFiles = ['sdks/js/index.js', 'sdks/js/index.d.ts'];
function walk(dir, out) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '__pycache__') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}
const toCheck = [];
for (const d of scanDirs) {
  const abs = path.join(ROOT, d);
  if (!fs.existsSync(abs)) continue;
  for (const f of walk(abs, [])) {
    if (/\.(py|js|mjs|cjs|ts)$/.test(f)) toCheck.push(f);
  }
}
for (const f of scanFiles) {
  const abs = path.join(ROOT, f);
  if (fs.existsSync(abs)) toCheck.push(abs);
}
for (const f of toCheck) {
  if (restates.test(fs.readFileSync(f, 'utf8'))) {
    problems.push(path.relative(ROOT, f).replace(/\\/g, '/') + ' restates the version ' + version + '; read VERSION instead');
  }
}

// 7) No Rust source restates the release version as a literal.
//
// This check exists because a duplicated constant already went stale once:
// `crates/nau-libp2p/src/lib.rs` asserted `VERSION == "1.1.1"` while the workspace
// had moved to 1.2.3. `scripts/bump-version.mjs` did not know about that site, and
// the first revision of THIS gate only looked at manifests and SDK sources -- so the
// only thing that noticed was `cargo test -p nau-libp2p`, hours later. A version
// literal outside the one pinning file is a duplicated failure mode, so it is
// refused here instead.
const RUST_ALLOW = new Map([
  [
    'crates/nau-core/tests/version_consistency.rs',
    'the single pinning site: asserting the release version is this file\'s whole job',
  ],
  [
    'crates/nau-migrate/src/amount.rs',
    'a version-shaped string used as a deliberately invalid amount input, not a version claim',
  ],
]);
let rustScanned = 0;
for (const f of walk(path.join(ROOT, 'crates'), []).filter((p) => p.endsWith('.rs'))) {
  const r = path.relative(ROOT, f).replace(/\\/g, '/');
  if (RUST_ALLOW.has(r)) continue;
  rustScanned += 1;
  const text = fs.readFileSync(f, 'utf8');
  if (text.includes('"' + version + '"') || text.includes("'" + version + "'")) {
    problems.push(
      r + ' restates the release version ' + version + '; use env!("CARGO_PKG_VERSION") or read VERSION',
    );
  }
}

// 6) contracts/VERSION mirrors VERSION.
if (fs.existsSync(path.join(ROOT, 'contracts/VERSION'))) {
  const cv = read('contracts/VERSION').replace(/\s+/g, '');
  if (cv !== version) problems.push('contracts/VERSION (' + cv + ') != VERSION (' + version + ')');
}

notes.push('VERSION = ' + version + '  ([workspace.package] = ' + (wpVersion || 'MISSING') + ')');
notes.push('crate manifests checked: ' + fs.readdirSync(cratesDir).filter((n) => fs.existsSync(path.join(cratesDir, n, 'Cargo.toml'))).length);
notes.push('SDK sources scanned for a restated version: ' + toCheck.length);
notes.push('Rust sources scanned for a restated version: ' + rustScanned + ' (' + RUST_ALLOW.size + ' documented exception(s))');

for (const n of notes) console.log('  ' + n);
if (problems.length === 0) {
  console.log('\nOK: VERSION is the only place the release version is written down.');
  process.exit(0);
}
console.log('\n' + problems.length + ' version-consistency problem(s):');
for (const p of problems) console.log('  ' + p);
process.exit(listOnly ? 0 : 1);
