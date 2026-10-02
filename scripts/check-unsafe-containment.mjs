#!/usr/bin/env node
// Gate: unsafe code is contained, not merely discouraged.
//
// The repository claims a structural property in README and in every crate's
// module docs: `#![forbid(unsafe_code)]` crate-wide, with at most one explicitly
// documented exception. A claim like that decays the moment someone adds an
// `unsafe` block in a new crate, because nothing fails. So this checks the three
// parts of the claim that can be checked mechanically:
//
//   1. every crate root declares forbid(unsafe_code) or deny(unsafe_code);
//   2. any file containing an `unsafe` block sits inside a module tree whose root
//      file opts in with an inner allow(unsafe_code) attribute;
//   3. every `unsafe` block carries a `// SAFETY:` comment in that file.
//
// Rule 2 is the one that matters. "unsafe is only in one crate" is not a boundary;
// "unsafe is only in a file that had to say so, whose parent module had to say so"
// is, because adding a second one means editing an attribute a reviewer can see.
//
// Usage:
//   node scripts/check-unsafe-containment.mjs           fail on any violation
//   node scripts/check-unsafe-containment.mjs --list    report only, exit 0

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const ROOT = path.resolve(
  path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')),
  '..',
);
const listOnly = process.argv.includes('--list');

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
const UNSAFE_BLOCK = /unsafe\s*\{|unsafe\s+fn/g;
const SAFETY_COMMENT = /\/\/\s*SAFETY:/g;

const cratesDir = path.join(ROOT, 'crates');
const crates = fs
  .readdirSync(cratesDir, { withFileTypes: true })
  .filter((e) => e.isDirectory())
  .map((e) => path.join(cratesDir, e.name));

const problems = [];
const exceptions = [];
let cratesChecked = 0;

for (const crate of crates) {
  const src = path.join(crate, 'src');
  if (!fs.existsSync(src)) continue;
  const name = path.basename(crate);
  const files = walk(src, []).filter((f) => f.endsWith('.rs'));

  // Rule 1: the crate root must forbid or deny unsafe.
  const roots = files.filter((f) => /(^|[\\/])(lib|main)\.rs$/.test(f));
  const rootOk = roots.some((f) => /#!\[(forbid|deny)\(unsafe_code\)\]/.test(fs.readFileSync(f, 'utf8')));
  if (!rootOk) {
    problems.push(name + ': crate root does not declare #![forbid(unsafe_code)] or #![deny(unsafe_code)]');
  }
  cratesChecked += 1;

  for (const f of files) {
    const text = fs.readFileSync(f, 'utf8');
    const blocks = (text.match(UNSAFE_BLOCK) || []).length;
    if (blocks === 0) continue;

    // Rule 2: the file, or its parent module file in the same directory chain,
    // must opt in with an inner attribute.
    const dir = path.dirname(f);
    const candidates = [f, path.join(dir, path.basename(dir) + '.rs')];
    // also allow any ancestor module file, e.g. src/platform/windows.rs -> src/platform.rs
    let cursor = dir;
    while (cursor.startsWith(src) && cursor !== path.dirname(src)) {
      candidates.push(path.join(path.dirname(cursor), path.basename(cursor) + '.rs'));
      cursor = path.dirname(cursor);
    }
    const optIn = candidates.find(
      (c) => fs.existsSync(c) && /#!\[allow\(unsafe_code\)\]/.test(fs.readFileSync(c, 'utf8')),
    );
    if (!optIn) {
      problems.push(
        rel(f) + ': contains ' + blocks + ' unsafe block(s) but no enclosing module declares #![allow(unsafe_code)]',
      );
      continue;
    }

    // Rule 3: one written SAFETY justification per block.
    const safety = (text.match(SAFETY_COMMENT) || []).length;
    if (safety < blocks) {
      problems.push(
        rel(f) + ': ' + blocks + ' unsafe block(s) but only ' + safety + ' "// SAFETY:" comment(s)',
      );
    }
    exceptions.push({
      file: rel(f),
      blocks,
      safety,
      optedInBy: rel(optIn),
    });
  }
}

console.log('checked ' + cratesChecked + ' crate root(s) for unsafe containment');
if (exceptions.length) {
  console.log('\nunsafe is present in exactly these files:');
  for (const e of exceptions) {
    console.log('  ' + e.file + '  (' + e.blocks + ' block(s), ' + e.safety + ' SAFETY comment(s), opted in by ' + e.optedInBy + ')');
  }
} else {
  console.log('  no unsafe code anywhere in the workspace');
}

if (problems.length === 0) {
  console.log('\nOK: unsafe is contained and every block carries a written justification.');
  process.exit(0);
}

console.log('\n' + problems.length + ' containment violation(s):');
for (const p of problems) console.log('  ' + p);
console.log(
  '\nAn unsafe block is not forbidden -- it is required to be visible. Put it behind a\n' +
    'module that declares #![allow(unsafe_code)], keep the surface minimal, and write a\n' +
    '// SAFETY: comment stating the invariant that makes the block sound.',
);
process.exit(listOnly ? 0 : 1);
