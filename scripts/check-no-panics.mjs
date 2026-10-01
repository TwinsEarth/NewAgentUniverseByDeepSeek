#!/usr/bin/env node
// Gate: production Rust code contains no unwrap() / expect( / panic!( /
// unreachable!( / todo!( / unimplemented!( outside #[cfg(test)].
//
// WHY THIS IS A GATE AND NOT A GREP
// ---------------------------------
// The rule is stated in this repository's own module docs and README, and a
// self-audit found it violated in 6 production sites -- which nobody noticed
// because nothing failed. A documented rule that no gate enforces is the exact
// "documented but unenforced" defect this project criticises upstream for, so the
// rule now has a gate.
//
// The naive version of this check is wrong in a way I proved on myself: a plain
// grep count of "unwrap(" over crates/ reported 312 hits, of which 6 were
// production code. The other 306 were my own module docs QUOTING upstream's
// unwrap() to explain what was fixed. So this scanner:
//
//   1. strips line and block comments before matching (doc comments included),
//   2. splits each file at its first top-level #[cfg(test)],
//   3. skips tests/, tests.rs and testutil.rs (test code is expected to unwrap),
//   4. requires any exception to be written down in ALLOW with a reason.
//
// Usage:
//   node scripts/check-no-panics.mjs            report and exit non-zero on any hit
//   node scripts/check-no-panics.mjs --list     report only, always exit 0

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const ROOT = path.resolve(
  path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')),
  '..',
);
const listOnly = process.argv.includes('--list');

// Justified exceptions: key "relative/path.rs:LINE" -> written reason.
// The point of the list is that a reader can check the REASON, not trust a silence.
const ALLOW = new Map();

const PATTERNS = [
  ['unwrap()', /\.unwrap\(\)/],
  ['expect(', /\.expect\(/],
  ['panic!(', /panic!\(/],
  ['unreachable!(', /unreachable!\(/],
  ['todo!(', /todo!\(/],
  ['unimplemented!(', /unimplemented!\(/],
];

const BACKTICK = String.fromCharCode(96);
const SLASH_SLASH = '/' + '/';
const SLASH_STAR = '/' + '*';
const STAR_SLASH = '*' + '/';

// Strip comments, preserving line count so reported line numbers stay true.
function stripComments(text) {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const two = text.slice(i, i + 2);
    if (two === SLASH_SLASH) {
      const nl = text.indexOf('\n', i);
      i = nl === -1 ? text.length : nl;
    } else if (two === SLASH_STAR) {
      const close = text.indexOf(STAR_SLASH, i + 2);
      const end = close === -1 ? text.length : close + 2;
      out += text.slice(i, end).replace(/[^\n]/g, ' ');
      i = end;
    } else if (text[i] === '"' || text[i] === "'") {
      const quote = text[i];
      let j = i + 1;
      while (j < text.length && text[j] !== quote) {
        if (text[j] === '\\') j += 1;
        if (text[j] === '\n') break;
        j += 1;
      }
      out += text.slice(i, Math.min(j + 1, text.length));
      i = Math.min(j + 1, text.length);
    } else {
      out += text[i];
      i += 1;
    }
  }
  return out;
}

function walk(dir, out) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'target' || e.name === 'node_modules' || e.name === '.git') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

const rel = (p) => path.relative(ROOT, p).replace(/\\/g, '/');
const isTestFile = (p) => {
  const r = rel(p);
  return (
    r.includes('/tests/') ||
    /(^|\/)(tests|testutil)\.rs$/.test(r) ||
    /_test\.rs$/.test(r)
  );
};

const files = walk(path.join(ROOT, 'crates'), [])
  .filter((f) => f.endsWith('.rs'))
  .filter((f) => !isTestFile(f));

const violations = [];
const allowed = [];

for (const f of files) {
  const text = fs.readFileSync(f, 'utf8');
  const lines = text.split('\n');
  const testAt = lines.findIndex((l) => l.trim().startsWith('#[cfg(test)]'));
  const prodLines = testAt === -1 ? lines : lines.slice(0, testAt);
  const prod = stripComments(prodLines.join('\n')).split('\n');

  for (let idx = 0; idx < prod.length; idx += 1) {
    for (const pair of PATTERNS) {
      const name = pair[0];
      const re = pair[1];
      if (!re.test(prod[idx])) continue;
      const n = idx + 1;
      const entry = {
        file: rel(f),
        line: n,
        kind: name,
        text: lines[idx].trim().slice(0, 120),
      };
      const key = entry.file + ':' + n;
      if (ALLOW.has(key)) allowed.push(Object.assign({ reason: ALLOW.get(key) }, entry));
      else violations.push(entry);
    }
  }
}

console.log(
  'checked ' + files.length + ' production .rs files ' +
    '(tests/, tests.rs, testutil.rs excluded; comments and string literals stripped)',
);

if (allowed.length) {
  console.log('\n' + allowed.length + ' justified exception(s):');
  for (const a of allowed) {
    console.log('  ' + a.file + ':' + a.line + '  [' + a.kind + ']  ' + a.reason);
  }
}

if (violations.length === 0) {
  console.log('\nOK: no panic path in production code.');
  process.exit(0);
}

console.log('\n' + violations.length + ' production panic path(s):');
for (const v of violations) {
  console.log('  ' + v.file + ':' + v.line + '  [' + v.kind + ']  ' + v.text);
}
console.log(
  '\nProduction code must return a typed error instead. If a site is genuinely\n' +
    'unreachable, that is not by itself a reason to keep it: an upstream\n' +
    'expect("cannot happen") is exactly the kind of unverifiable claim this project\n' +
    'refuses. Replace it, or add it to ALLOW in this script WITH a written reason so\n' +
    'that a reader can check the reason rather than trust the exemption.',
);
process.exit(listOnly ? 0 : 1);
