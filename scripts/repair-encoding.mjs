#!/usr/bin/env node
// Repairs source files that are not valid UTF-8.
//
// WHY THIS EXISTS: a file written during this project ended up with a truncated
// multi-byte sequence (a U+2014 em dash stored as `E2 80` with the third byte
// missing), so `rustc` refused the crate with "stream did not contain valid UTF-8".
// Rather than hand-editing, this scans the tree, reports every file that fails
// strict UTF-8 validation, decodes it lossily (invalid sequences become U+FFFD) and
// replaces the replacement characters with an ASCII hyphen, then rewrites the file.
//
// Usage:
//   node scripts/repair-encoding.mjs            # report and fix
//   node scripts/repair-encoding.mjs --dry-run  # report only

import fs from 'node:fs';
import path from 'node:path';

const TEXT_EXT = new Set([
  '.rs', '.toml', '.md', '.txt', '.js', '.mjs', '.cjs', '.ts', '.json',
  '.py', '.yml', '.yaml', '.sol', '.sh', '.html', '.css', '.lock', '.cfg',
]);
const SKIP_DIRS = new Set(['.git', 'target', 'node_modules', '__pycache__', '.pytest_cache']);

const dryRun = process.argv.includes('--dry-run');
const root = path.resolve(process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : '.');

const strict = new TextDecoder('utf-8', { fatal: true });
const lossy = new TextDecoder('utf-8', { fatal: false });

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      out.push(...walk(full));
    } else if (entry.isFile()) {
      if (TEXT_EXT.has(path.extname(entry.name).toLowerCase())) out.push(full);
    }
  }
  return out;
}

let checked = 0;
let broken = 0;
for (const file of walk(root)) {
  const buf = fs.readFileSync(file);
  checked++;
  try {
    strict.decode(buf);
    continue;
  } catch {
    // Invalid UTF-8 — report, then repair.
    const decoded = lossy.decode(buf);
    const replacements = (decoded.match(/\uFFFD/g) || []).length;
    // Locate the first offending byte offset for the report.
    let offset = 0;
    for (let i = 0; i < buf.length; i++) {
      try {
        strict.decode(buf.subarray(i));
        offset = i;
        break;
      } catch {
        /* keep advancing */
      }
    }
    broken++;
    const rel = path.relative(root, file);
    const ctx = buf.subarray(Math.max(0, offset - 24), offset + 8);
    console.log(
      `INVALID UTF-8  ${rel}\n` +
        `    replacement chars: ${replacements}\n` +
        `    near byte: ${JSON.stringify(ctx.toString('latin1'))}`,
    );
    if (!dryRun) {
      const repaired = decoded.replace(/\uFFFD/g, '-');
      fs.writeFileSync(file, repaired, 'utf8');
      console.log(`    repaired -> wrote ${Buffer.byteLength(repaired)} bytes of valid UTF-8`);
    }
  }
}

console.log(`\nchecked ${checked} text files; ${broken} needed repair${dryRun ? ' (dry run, nothing written)' : ''}`);
process.exit(broken > 0 && dryRun ? 1 : 0);
