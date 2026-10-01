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
// Comment stripping, for the same reason `check-no-panics.mjs` needs it: a naive
// match over the raw text counts this project's own prose. On its first run after the
// plugin kernel landed, this check flagged `nau-plugin/src/registry.rs` for
// `parse_semver("1.2.3")` in a test -- an arbitrary input to a parser, not a version
// claim -- and for a doc line reading "the V1.2.3 work". Both are false positives of
// exactly the class the no-panics gate's header describes.
function stripComments(text) {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const two = text.slice(i, i + 2);
    if (two === '//') {
      const nl = text.indexOf('\n', i);
      i = nl === -1 ? text.length : nl;
    } else if (two === '/*') {
      const close = text.indexOf('*/', i + 2);
      const end = close === -1 ? text.length : close + 2;
      out += text.slice(i, end).replace(/[^\n]/g, ' ');
      i = end;
    } else {
      out += text[i];
      i += 1;
    }
  }
  return out;
}

// A quoted version in TEST code is only a restated release version if the same line is
// actually making a claim about one. Skipping test modules outright would blind this
// check to its own motivating defect -- `crates/nau-libp2p/src/lib.rs` asserted
// `VERSION == "1.1.1"`, and that assertion lived in a test. `parse_semver("1.2.3")` is
// a parser input; `VERSION == "1.2.3"` is a claim.
const VERSION_CLAIM = /\b(VERSION|CARGO_PKG_VERSION|version|abi)\b/;

// Files under a `tests/` directory are test code whatever their shape, and this check
// used to treat them as production because it looked only for an inline
// `#[cfg(test)]`. The no-panics gate has excluded these all along, so the two gates
// disagreed about what "production" means -- which is how a fixture version inside
// `crates/nau-node/tests/plugin_cli.rs` came to be reported as a production restatement.
// The single pinning site, `crates/nau-core/tests/version_consistency.rs`, is still
// covered: it is in RUST_ALLOW with its reason.
const isTestFile = (r) =>
  r.includes('/tests/') || /(^|\/)(tests|testutil)\.rs$/.test(r) || /_test\.rs$/.test(r);

let rustScanned = 0;
for (const f of walk(path.join(ROOT, 'crates'), []).filter((p) => p.endsWith('.rs'))) {
  const r = path.relative(ROOT, f).replace(/\\/g, '/');
  if (RUST_ALLOW.has(r)) continue;
  rustScanned += 1;

  const lines = fs.readFileSync(f, 'utf8').split('\n');
  const testAt = lines.findIndex((l) => l.trim().startsWith('#[cfg(test)]'));
  const inTestFile = isTestFile(r);
  const prodText = inTestFile || testAt === -1 ? '' : lines.slice(0, testAt).join('\n');
  const testText = inTestFile
    ? lines.join('\n')
    : testAt === -1
      ? ''
      : lines.slice(testAt).join('\n');
  const prod = stripComments(prodText);
  const test = stripComments(testText);
  const testOffset = inTestFile ? 0 : testAt;
  const where = inTestFile ? 'integration test' : 'test claim';

  const quoted = (l) => l.includes('"' + version + '"') || l.includes("'" + version + "'");
  const hits = [];
  // In production a quoted release version is always wrong: it is a duplicated
  // constant that `bump-version.mjs` cannot see.
  prod.split('\n').forEach((l, i) => {
    if (quoted(l)) hits.push('line ' + (i + 1) + ' (production)');
  });
  test.split('\n').forEach((l, i) => {
    if (quoted(l) && VERSION_CLAIM.test(l)) {
      hits.push('line ' + (testOffset + i + 1) + ' (' + where + ')');
    }
  });

  if (hits.length) {
    problems.push(
      r +
        ' restates the release version ' +
        version +
        ' at ' +
        hits.join(', ') +
        '; use env!("CARGO_PKG_VERSION") or read VERSION',
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
