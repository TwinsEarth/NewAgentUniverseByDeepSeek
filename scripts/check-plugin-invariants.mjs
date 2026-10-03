#!/usr/bin/env node
// Gate: the plugin kernel's architectural invariants, checked at the source level.
//
// WHY THESE ARE NOT RUST TESTS
// ----------------------------
// A Rust test can prove that `Lifecycle::transition` refuses an illegal edge. It
// cannot prove that `transition` is the ONLY place the state is assigned -- a test
// observes behaviour, and a second assignment site is only visible in the text. The
// V1.2.3 market work found exactly this: upstream added a transition table and then
// kept `task.state = TaskState::Disputed;` in `open_dispute`, walking around it,
// including out of a terminal state. A table one function can bypass is decoration.
//
// The same class of question applies to four more things here:
//
//   * starting a plugin must have ONE entry point (the arbiter), or isolating the
//     policy becomes a matter of every caller remembering it;
//   * minting a capability token must have ONE production site, or "which
//     capabilities does this plugin hold" stops having a single answer;
//   * the kernel must not depend on the host crates, or "everything is a plugin"
//     quietly becomes "the kernel knows about its plugins";
//   * the security vocabulary in the architecture document must be the vocabulary in
//     the code, or the document describes a system that is not this one.
//
// Every check below fails the gate. Each one prints what it found, not just a count.
//
// Usage:
//   node scripts/check-plugin-invariants.mjs           report and exit non-zero on any hit
//   node scripts/check-plugin-invariants.mjs --list    report only, always exit 0

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const ROOT = path.resolve(
  path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')),
  '..',
);
const listOnly = process.argv.includes('--list');
const KERNEL = path.join(ROOT, 'crates', 'nau-plugin');
// The plugin implementations live in a separate crate. Checked as a whole: the wiring
// invariant spans both, because the kernel declares the trait and the plugins crate
// supplies the implementations and the list the host builds from.
const KERNEL_PLUGINS = path.join(ROOT, 'crates', 'nau-plugins');

/** Files under `dir` ending in `.rs`, excluding `#[cfg(test)]` bodies. */
function rustFiles(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (e.name === 'target' || e.name === 'node_modules') continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.rs')) out.push(p);
    }
  };
  walk(dir);
  return out;
}

const rel = (p) => path.relative(ROOT, p).replace(/\\/g, '/');

/**
 * Strip line and block comments, preserving line count so reported line numbers stay
 * true. Without this the lifecycle check counts the module doc that *says* there is
 * one assignment site -- a false positive this gate produced on its first run, which
 * is worth stating because the alternative reading (a second assignment site) is a
 * real defect and the two must not be confused.
 */
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

/**
 * Split a file into its production text and its test text at the first top-level
 * `#[cfg(test)]`. Inline `mod tests` is placed last by convention in this codebase,
 * so this is the same boundary the no-panics gate uses. Comments are stripped from
 * the production part.
 */
function splitTests(text) {
  const lines = text.split('\n');
  const at = lines.findIndex((l) => l.trim().startsWith('#[cfg(test)]'));
  if (at === -1) return { prod: stripComments(text), test: '' };
  return {
    prod: stripComments(lines.slice(0, at).join('\n')),
    test: lines.slice(at).join('\n'),
  };
}

const findings = [];
const notes = [];
const fail = (check, detail) => findings.push({ check, detail });

// --- 1. one assignment site for the lifecycle state --------------------------
{
  const file = path.join(KERNEL, 'src', 'lifecycle.rs');
  const { prod } = splitTests(fs.readFileSync(file, 'utf8'));
  const hits = prod
    .split('\n')
    .map((l, i) => ({ l, n: i + 1 }))
    .filter(({ l }) => /self\.state\s*=/.test(l));
  if (hits.length !== 1) {
    fail(
      'lifecycle-single-assignment-site',
      `${rel(file)} assigns \`self.state\` ${hits.length} time(s) in production code; ` +
        `exactly 1 is required, inside \`transition\`.` +
        hits.map((h) => `\n      line ${h.n}: ${h.l.trim()}`).join(''),
    );
  } else {
    notes.push(`lifecycle state has exactly one assignment site (line ${hits[0].n})`);
  }
}

// --- 2. one entry point for starting a plugin --------------------------------
{
  const offenders = [];
  for (const f of rustFiles(path.join(KERNEL, 'src'))) {
    const { prod } = splitTests(fs.readFileSync(f, 'utf8'));
    prod.split('\n').forEach((l, i) => {
      // `runtime.start(` is the port call; `Self::start`/`fn start` definitions are fine.
      if (/\.start\(&|\.start\(&self\.|runtime\.start\(|runtimes\[.*\]\.start\(/.test(l)) {
        offenders.push(`${rel(f)}:${i + 1}  ${l.trim()}`);
      }
    });
  }
  const onlyArbiter = offenders.filter((o) => !o.startsWith('crates/nau-plugin/src/arbiter.rs'));
  if (onlyArbiter.length) {
    fail(
      'one-start-entry-point',
      'a plugin may only be started by the arbiter, so the policy has a single choke ' +
        'point; these sites start one elsewhere:\n' +
        onlyArbiter.map((o) => `      ${o}`).join('\n'),
    );
  } else {
    notes.push(`plugin start has one entry point (${offenders.length} site(s), all in arbiter.rs)`);
  }
}

// --- 3. one production site that mints a capability token --------------------
{
  const offenders = [];
  for (const f of rustFiles(path.join(KERNEL, 'src'))) {
    const base = path.basename(f);
    if (base === 'capability.rs') continue; // the definition itself
    const { prod } = splitTests(fs.readFileSync(f, 'utf8'));
    prod.split('\n').forEach((l, i) => {
      if (/CapabilityToken::issue\(/.test(l)) offenders.push(`${rel(f)}:${i + 1}  ${l.trim()}`);
    });
  }
  const outsideManifest = offenders.filter((o) => !o.includes('/manifest.rs:'));
  if (outsideManifest.length) {
    fail(
      'one-token-issuer',
      'only the manifest verification path may mint a capability token, because the ' +
        'token must be bound to a digest that was actually verified; these sites mint ' +
        'one without that:\n' +
        outsideManifest.map((o) => `      ${o}`).join('\n'),
    );
  } else {
    notes.push(`capability tokens are minted in one place (${offenders.length} site(s))`);
  }
}

// --- 4. the kernel does not depend on the host -------------------------------
{
  const manifest = fs.readFileSync(path.join(KERNEL, 'Cargo.toml'), 'utf8');
  const depSection = manifest.split('[dependencies]')[1] || '';
  // `nau-image` is in this list for a different reason from the others. The host crates are
  // forbidden because a kernel that knows about its plugins is not a plugin kernel;
  // `nau-image` is forbidden because resolving a chunk means fetching one, and a kernel that
  // can fetch is a kernel with I/O in it. The crate was created in A-05 precisely so the
  // manifest vocabulary (in `nau-core`, no I/O) and the fetch machinery (in `nau-image`) do
  // not have to live together.
  const forbidden = ['nau-node', 'nau-http', 'nau-libp2p', 'nau-market', 'nau-mcp', 'nau-image'];
  const found = forbidden.filter((d) => new RegExp(`^\\s*${d}[.\\s=]`, 'm').test(depSection));
  if (found.length) {
    fail(
      'kernel-layering',
      `the kernel must not depend on the host crates (found: ${found.join(', ')}); ` +
        'a kernel that knows about its plugins is not a plugin kernel, and one that can ' +
        'fetch image chunks has I/O in it',
    );
  } else {
    notes.push(
      'kernel does not depend on nau-node/nau-http/nau-libp2p/nau-market/nau-mcp/nau-image',
    );
  }
}

// --- 5. a name can never classify as the blacklist verdict -------------------
{
  const file = path.join(KERNEL, 'src', 'tier.rs');
  const { prod } = splitTests(fs.readFileSync(file, 'utf8'));
  // Scoped to `from_name`'s body rather than to the whole file. The first version of
  // this check scanned the file, and it fired as a false positive the moment
  // `Tier::from_label` was added -- parsing a *label* may legitimately yield the
  // blacklist verdict, because a label is a stated fact while a name is a claim. A gate
  // that fires on a correct change is a gate people weaken; the invariant is about
  // derivation from a name, so that is what is checked.
  const body = /pub fn from_name\(.*?\)\s*->\s*Result<Tier>\s*\{(.*?)\n    \}/s.exec(prod);
  if (!body) {
    fail(
      'blacklist-is-a-verdict-not-a-name',
      `${rel(file)}: could not locate \`from_name\` to check. This is a failure rather than a ` +
        'skip: a rename that silently disables the check is how an invariant stops being ' +
        'enforced without anyone noticing.',
    );
  } else if (/Ok\(\s*Tier::Blacklisted\s*\)/.test(body[1])) {
    fail(
      'blacklist-is-a-verdict-not-a-name',
      `${rel(file)}::from_name can return \`Tier::Blacklisted\`; the verdict must come from ` +
        'the blacklist store, so that a manifest cannot declare itself into a tier and a ' +
        'squatting name cannot resolve to one',
    );
  } else {
    // Self-test. Narrowing a check to one function is exactly the change that can turn it
    // into a no-op, and a no-op check reports "ok" -- which is worse than no check,
    // because it is believed. So the violation is planted inside the extracted body and
    // the same regex must report it. If this ever stops working, the "ok" below would
    // mean nothing.
    const planted = body[1].replace('Ok(Tier::ThirdParty)', 'Ok(Tier::Blacklisted)');
    if (planted === body[1] || !/Ok\(\s*Tier::Blacklisted\s*\)/.test(planted)) {
      fail(
        'blacklist-is-a-verdict-not-a-name',
        'the scoped check failed its own self-test: a violation planted inside `from_name` ' +
          'was not detected, so its "ok" verdict would be meaningless',
      );
    } else {
      notes.push('no code path derives the blacklist verdict from a plugin name (self-tested)');
    }
  }
}

// --- 6. the document and the code use the same security vocabulary -----------
{
  const docPath = path.join(ROOT, 'docs', 'PLUGIN-ARCHITECTURE.md');
  if (!fs.existsSync(docPath)) {
    fail('doc-code-vocabulary', 'docs/PLUGIN-ARCHITECTURE.md is missing');
  } else {
    const doc = fs.readFileSync(docPath, 'utf8');

    // 6a. the tier prefixes
    const tierSrc = fs.readFileSync(path.join(KERNEL, 'src', 'tier.rs'), 'utf8');
    const prefixes = [...tierSrc.matchAll(/pub const \w+_PREFIX: &str = "([^"]+)"/g)].map((m) => m[1]);
    const missingPrefixes = prefixes.filter((p) => !doc.includes(p));
    if (missingPrefixes.length) {
      fail(
        'doc-code-vocabulary',
        `these tier prefixes exist in code but not in the architecture document: ` +
          missingPrefixes.join(', '),
      );
    }

    // 6b. every capability wire name. The document is allowed to shorten a group
    //     (`net:dht:read/write`), so a name counts as documented if it appears
    //     literally or its last two segments appear joined after the group prefix.
    const capSrc = fs.readFileSync(path.join(KERNEL, 'src', 'capability.rs'), 'utf8');
    const names = [...capSrc.matchAll(/=> "([a-z]+:[a-z:_]+)"/g)].map((m) => m[1]);
    const undocumented = names.filter((n) => {
      if (doc.includes(n)) return false;
      const [group, ...rest] = n.split(':');
      const tail = rest.join(':');
      return !doc.includes(`${group}:`) || !doc.includes(tail.split(':').pop());
    });
    if (undocumented.length) {
      fail(
        'doc-code-vocabulary',
        `these capability wire names are enforced in code but absent from the ` +
          `architecture document, so the document understates the permission model: ` +
          undocumented.join(', '),
      );
    }
    notes.push(
      `document vocabulary matches the code (${prefixes.length} prefixes, ${names.length} capabilities)`,
    );

    // 6c. the hot-swap claim must match the constant, so the document cannot promise
    //     a capability this build reports as absent.
    const libSrc = fs.readFileSync(path.join(KERNEL, 'src', 'lib.rs'), 'utf8');
    const hotSwap = /HOT_SWAP_SUPPORTED: bool = (\w+)/.exec(libSrc);
    if (hotSwap && hotSwap[1] === 'false' && !/V3\.0\.0/.test(doc)) {
      fail(
        'doc-code-vocabulary',
        'this build reports HOT_SWAP_SUPPORTED = false, but the architecture document ' +
          'does not mention V3.0.0 as the version that adds it',
      );
    }
  }
}

// --- 7. every SystemPlugin implementation is actually constructed -------------
//
// The defect this exists for is the one this project keeps finding in its own work: a
// plugin written, tested in isolation, and never added to the list the host builds from.
// It compiles, its tests pass, and it does nothing — "written but not wired", which the
// objective for this version names explicitly as something not to do.
//
// The check is source-level because nothing else can see it: a Rust test can only test a
// plugin it can name, and a plugin nobody constructs is a plugin no test can reach.
{
  const pluginsDir = path.join(KERNEL_PLUGINS, 'src', 'plugins');
  if (!fs.existsSync(pluginsDir)) {
    // The plugins crate is separate from the kernel; if it is not checked out, say so
    // rather than passing silently.
    notes.push('plugins crate not present; the wiring check did not run');
  } else {
    const implemented = new Map(); // type name -> file
    for (const f of fs.readdirSync(pluginsDir).filter((n) => n.endsWith('.rs'))) {
      if (f === 'mod.rs') continue;
      const { prod } = splitTests(fs.readFileSync(path.join(pluginsDir, f), 'utf8'));
      for (const m of prod.matchAll(/impl\s+SystemPlugin\s+for\s+(\w+)/g)) {
        implemented.set(m[1], f);
      }
    }

    const hostSrc = fs.readFileSync(path.join(KERNEL_PLUGINS, 'src', 'host.rs'), 'utf8');
    const stdFns = /pub fn standard_plugins\(.*?\n\}/s.exec(hostSrc);
    const declFns = /pub fn standard_declarations\(.*?\n\}/s.exec(hostSrc);
    if (!stdFns || !declFns) {
      fail(
        'every-system-plugin-is-wired',
        'could not locate `standard_plugins` / `standard_declarations` in host.rs. This is a ' +
          'failure rather than a skip: a rename that disables the check is how wiring stops ' +
          'being verified without anyone noticing.',
      );
    } else {
      const unwired = [...implemented.entries()]
        .filter(([ty]) => !new RegExp(`\\b${ty}\\b`).test(stdFns[0]))
        .map(([ty, f]) => `${ty} (${f})`);
      const undeclared = [...implemented.entries()]
        .filter(([ty]) => !new RegExp(`\\b${ty}\\b`).test(declFns[0]))
        .map(([ty, f]) => `${ty} (${f})`);

      if (unwired.length) {
        fail(
          'every-system-plugin-is-wired',
          `${unwired.length} SystemPlugin implementation(s) are never constructed by ` +
            '`standard_plugins()`, so the host cannot load them and no test that goes through ' +
            'the host can reach them:\n' +
            unwired.map((u) => `      ${u}`).join('\n'),
        );
      }
      if (undeclared.length) {
        fail(
          'every-system-plugin-is-wired',
          `${undeclared.length} SystemPlugin implementation(s) are missing from ` +
            '`standard_declarations()`, so no manifest is built for them and they cannot be ' +
            'registered:\n' +
            undeclared.map((u) => `      ${u}`).join('\n'),
        );
      }
      if (!unwired.length && !undeclared.length) {
        notes.push(
          `every SystemPlugin implementation is wired (${implemented.size} found, ` +
            `${implemented.size} constructed and declared)`,
        );
      }
    }
  }
}

// --- 7. the migration document's "runnable" rows match the shipped binaries -----
//
// WHY THIS IS A SOURCE-LEVEL CHECK AND NOT A REVIEW HABIT
// -------------------------------------------------------
// `docs/PLUGIN-MIGRATION.md` states, in a table and again in a sentence, which official
// plugins can actually be run. Both statements went stale **in the same session that made
// them false**: the table was updated to four runnable plugins while the sentence at the end
// of the section still said "1 项可运行", and `docs/VERIFICATION.md` still claimed the
// cross-target gate covered seven crates after it was measured at sixteen. Nothing caught
// either, because a prose claim is not compared to anything.
//
// A document that describes a system is part of the system's correctness here -- the whole
// premise of this repository's "written is not wired" discipline. So the claim is mechanised:
// every `nau-plugin-*.rs` under `src/bin/` is either the fixture or is named by a row the
// document marks runnable, and every file the document names must exist. Deleting a binary,
// renaming one, or adding one without saying so all fail.
{
  const docPath = path.join(ROOT, 'docs', 'PLUGIN-MIGRATION.md');
  const binDir = path.join(KERNEL_PLUGINS, 'src', 'bin');
  // The echo plugin is a test fixture rather than a shipped plugin, and is named here so that
  // the exemption is a decision in the open rather than an accident of a naming convention.
  const FIXTURES = new Set(['nau-plugin-echo.rs']);

  let doc = '';
  try {
    doc = fs.readFileSync(docPath, 'utf8');
  } catch {
    fail(
      'migration-document-matches-binaries',
      `${rel(docPath)} is missing. It is the document that says which plugins run, so its ` +
        'absence is a failure rather than a skip.',
    );
  }

  const binaries = fs
    .readdirSync(binDir)
    .filter((f) => f.startsWith('nau-plugin-') && f.endsWith('.rs'))
    .filter((f) => !FIXTURES.has(f));

  // The rows the document marks runnable, and the `.rs` file each names.
  const claimed = new Set();
  for (const line of doc.split('\n')) {
    if (!line.includes('|') || !line.includes('可运行')) continue;
    for (const m of line.matchAll(/([\w.-]+\.rs)/g)) claimed.add(m[1]);
  }

  const missingFile = [...claimed].filter((f) => !fs.existsSync(path.join(binDir, f)));
  const unclaimed = binaries.filter((f) => !claimed.has(f));

  if (missingFile.length) {
    fail(
      'migration-document-matches-binaries',
      `${rel(docPath)} marks a plugin runnable whose binary does not exist: ` +
        `${missingFile.join(', ')}. The document is the only place an operator learns what can ` +
        'be run, so a claim with no artefact behind it is worse than an omission.',
    );
  }
  if (unclaimed.length) {
    fail(
      'migration-document-matches-binaries',
      `${unclaimed.length} shipped plugin binar(y|ies) are not named by any runnable row in ` +
        `${rel(docPath)}: ${unclaimed.join(', ')}. A plugin that runs and is not documented as ` +
        'running is the same defect as one documented and absent.',
    );
  }
  if (!missingFile.length && !unclaimed.length) {
    notes.push(
      `the migration document names every shipped plugin binary (${binaries.length} runnable, ` +
        `${FIXTURES.size} fixture(s) exempt) and every name it gives exists`,
    );
  }
}

console.log(`plugin-invariant checks over ${rel(KERNEL)}`);

if (findings.length === 0) {
  for (const n of notes) console.log(`  ok   ${n}`);
  console.log('\nOK: the kernel keeps its architectural invariants.');
  process.exit(0);
}

console.log(`\n${findings.length} invariant(s) violated:`);
for (const f of findings) console.log(`  [${f.check}] ${f.detail}`);
process.exit(listOnly ? 0 : 1);
