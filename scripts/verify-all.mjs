#!/usr/bin/env node
// Runs every verification gate this project has, in one place, and prints a table
// that distinguishes PASS from SKIPPED-with-a-reason.
//
// WHY THIS EXISTS
// ---------------
// The upstream audit's recurring finding was not "the code is broken" but "nobody
// could tell": CI greps that a file of comments satisfies, Python tests that skip
// themselves when a dependency is missing, and a README that promised more than
// the code did. `cargo test` passing in one directory and `forge test` never
// having been run at all is the same class of problem.
//
// So this script treats a missing tool as a REPORTED OUTCOME, not a silent skip:
// every gate prints PASS, FAIL, or SKIP + the exact command that would enable it,
// and any SKIP makes the exit code non-zero unless you pass --allow-missing-tools.
// That is the difference between "we verified this" and "we did not look".
//
// Usage:
//   node scripts/verify-all.mjs                     # everything available; SKIPs fail
//   node scripts/verify-all.mjs --allow-missing-tools
//   node scripts/verify-all.mjs --only rust,contracts
//   node scripts/verify-all.mjs --quick             # skip the slow Rust suites

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..');
const argv = process.argv.slice(2);
const allowMissing = argv.includes('--allow-missing-tools');
const quick = argv.includes('--quick');
const onlyArg = argv.find((a) => a.startsWith('--only'));
const only = onlyArg ? (onlyArg.split('=')[1] || argv[argv.indexOf(onlyArg) + 1] || '').split(',').filter(Boolean) : null;

// --- environment ------------------------------------------------------------
// Pinned to the MSRV CI verifies, so a local run and CI run the same compiler.
const RUST = process.env.NAU_RUST || '1.85.0';
const PY = process.env.NAU_PYTHON || process.env.PYTHON || 'python';
const NODE = process.execPath;
const FORGE = process.env.FORGE_BIN || 'forge';
const SOLC = process.env.SOLC_BIN || '';

const env = { ...process.env, CARGO_BUILD_JOBS: process.env.CARGO_BUILD_JOBS || '2' };

function have(cmd) {
  const r = spawnSync(cmd, ['--version'], { encoding: 'utf8', shell: process.platform === 'win32' });
  return r.status === 0;
}

function run(cmd, args, opts = {}) {
  const started = Date.now();
  const r = spawnSync(cmd, args, {
    cwd: opts.cwd ? path.join(ROOT, opts.cwd) : ROOT,
    encoding: 'utf8',
    env,
    shell: process.platform === 'win32',
    maxBuffer: 64 * 1024 * 1024,
  });
  return {
    code: r.status === null ? 1 : r.status,
    out: `${r.stdout || ''}${r.stderr || ''}`,
    ms: Date.now() - started,
  };
}

/** Pull the most useful one-line summary out of a command's output. */
function summarise(text) {
  const lines = text.split('\n').map((l) => l.trim()).filter(Boolean);
  const patterns = [
    /Compiler run successful.*$/,
    /^test result:.*$/,
    /tests? passed.*$/i,
    /^\d+ passed.*$/,
    /Ran \d+ test suites.*$/,
    /all \d+ .*checks passed$/i,
    /every resolved call site.*$/i,
    /byte-identical|reproduc/i,
    /^Finished/,
  ];
  for (const p of patterns) {
    const hit = lines.filter((l) => p.test(l));
    if (hit.length) return hit[hit.length - 1].slice(0, 120);
  }
  return lines.length ? lines[lines.length - 1].slice(0, 120) : '(no output)';
}

const gates = [];
function gate(id, title, fn) {
  gates.push({ id, title, fn });
}

// --- Rust -------------------------------------------------------------------
gate('rust-fmt', 'Rust formatting (cargo fmt --check)', () => {
  const r = run('cargo', [`+${RUST}`, 'fmt', '--all', '--check']);
  return { state: r.code === 0 ? 'PASS' : 'FAIL', detail: r.code === 0 ? 'no diffs' : summarise(r.out), ms: r.ms };
});

gate('rust-lock', 'Cargo.lock agrees with the manifests (--locked)', () => {
  const r = run('cargo', [`+${RUST}`, 'metadata', '--locked', '--format-version', '1']);
  return { state: r.code === 0 ? 'PASS' : 'FAIL', detail: r.code === 0 ? `resolved with ${RUST}` : summarise(r.out), ms: r.ms };
});

gate('rust-test', `Rust workspace tests (cargo test --workspace, rust ${RUST})`, () => {
  const r = run('cargo', [`+${RUST}`, 'test', '--workspace', '--locked']);
  const passed = [...r.out.matchAll(/test result: ok\. (\d+) passed/g)].reduce((a, m) => a + Number(m[1]), 0);
  const failed = [...r.out.matchAll(/(\d+) failed/g)].reduce((a, m) => a + Number(m[1]), 0);
  const failing = [...r.out.matchAll(/^---- (\S+) stdout ----/gm)].map((m) => m[1]).slice(0, 6);
  return {
    state: r.code === 0 ? 'PASS' : 'FAIL',
    detail: `${passed} passed, ${failed} failed${failing.length ? ' :: ' + failing.join(', ') : ''}`,
    ms: r.ms,
  };
});

gate('rust-clippy', 'Rust lints (cargo clippy -D warnings)', () => {
  const r = run('cargo', [`+${RUST}`, 'clippy', '--workspace', '--all-targets', '--', '-D', 'warnings']);
  const warnings = (r.out.match(/^warning:/gm) || []).length;
  return { state: r.code === 0 ? 'PASS' : 'FAIL', detail: r.code === 0 ? '0 warnings' : `${warnings} warning(s)`, ms: r.ms };
});

// The libp2p stack is behind a DEFAULT-OFF feature so the default workspace build
// stays pure Rust. That means `cargo test --workspace` above does NOT run it: 88
// tests, including the real multi-node GossipSub/Kademlia/relay tests, would go
// unrun and unnoticed. A verification list that silently omits a whole component
// is the failure mode this file exists to prevent, so it gets its own gate.
gate('libp2p', 'libp2p stack (--features libp2p: real two-node swarm)', () => {
  const build = run('cargo', [`+${RUST}`, 'build', '-p', 'nau-libp2p', '--features', 'libp2p', '--locked']);
  if (build.code !== 0) {
    return { state: 'FAIL', detail: `build: ${summarise(build.out)}`, ms: build.ms };
  }
  // Serialised: these tests start real swarms on loopback, and running them in
  // parallel makes port contention look like a code failure.
  const test = run('cargo', [
    `+${RUST}`, 'test', '-p', 'nau-libp2p', '--features', 'libp2p', '--locked', '--', '--test-threads=1',
  ]);
  const passed = [...test.out.matchAll(/test result: ok\. (\d+) passed/g)].reduce((a, m) => a + Number(m[1]), 0);
  const failed = [...test.out.matchAll(/(\d+) failed/g)].reduce((a, m) => a + Number(m[1]), 0);
  return {
    state: test.code === 0 ? 'PASS' : 'FAIL',
    detail: `${passed} passed, ${failed} failed (feature only; the default build skips these)`,
    ms: build.ms + test.ms,
  };
});

// --- Conformance vectors ----------------------------------------------------
gate('conformance', 'Conformance vectors regenerate byte-identically', () => {
  const before = fs.readFileSync(path.join(ROOT, 'conformance/vectors.json'), 'utf8');
  const r = run(NODE, ['conformance/generate.mjs']);
  if (r.code !== 0) return { state: 'FAIL', detail: summarise(r.out), ms: r.ms };
  const after = fs.readFileSync(path.join(ROOT, 'conformance/vectors.json'), 'utf8');
  const same = before === after;
  return { state: same ? 'PASS' : 'FAIL', detail: same ? 'byte-identical' : 'regeneration CHANGED the file', ms: r.ms };
});

// --- Python SDK -------------------------------------------------------------
gate('python', 'Python SDK tests', () => {
  if (!have(`${PY}`)) return { state: 'SKIP', detail: `python not found; set NAU_PYTHON`, ms: 0 };
  const r = run(PY, ['sdks/python/run_tests.py']);
  return { state: r.code === 0 ? 'PASS' : 'FAIL', detail: summarise(r.out), ms: r.ms };
});

// --- JavaScript SDK ---------------------------------------------------------
gate('javascript', 'JavaScript SDK tests', () => {
  const r = run(NODE, ['sdks/js/test/run.js']);
  return { state: r.code === 0 ? 'PASS' : 'FAIL', detail: summarise(r.out), ms: r.ms };
});

// --- GUI client end-to-end --------------------------------------------------
gate('client', 'Browser client end-to-end against the real daemon', () => {
  const r = run(NODE, ['client/test/e2e.mjs']);
  return { state: r.code === 0 ? 'PASS' : 'FAIL', detail: summarise(r.out), ms: r.ms };
});

// --- Deployment -------------------------------------------------------------
// Not a unit test: this installs the release binaries into a prefix, runs the
// daemon against a PERSISTENT data directory, drives real HTTP, checks that the
// CLI reads what the daemon wrote, then RESTARTS the daemon and asserts the state
// survived. It is the only gate that covers persistence across a restart, and it
// is how the journal-duplication bug (a restart that minted money) was found:
// every other gate uses an ephemeral store and never persists twice.
gate('deploy', 'Local deployment: install, run, restart, state survives', () => {
  const r = run(NODE, ['scripts/deploy-local.mjs', '--prefix', path.join(ROOT, '..', 'nau-deploy')]);
  const m = r.out.match(/(\d+) passed, (\d+) failed/);
  return {
    state: r.code === 0 ? 'PASS' : 'FAIL',
    detail: m ? `${m[1]} deployment checks passed, ${m[2]} failed` : summarise(r.out),
    ms: r.ms,
  };
});

// --- Solidity ---------------------------------------------------------------
gate('contracts-static', 'Contract static checks (no toolchain needed)', () => {
  const a = run(PY, ['contracts/verify_static.py']);
  if (a.code !== 0) return { state: 'FAIL', detail: summarise(a.out), ms: a.ms };
  const b = run(PY, ['contracts/verify_api.py']);
  return { state: b.code === 0 ? 'PASS' : 'FAIL', detail: summarise(b.out), ms: a.ms + b.ms };
});

gate('contracts-build', 'Contracts compile (forge build --sizes)', () => {
  if (!have(FORGE)) {
    return {
      state: 'SKIP',
      detail: 'forge not on PATH; install Foundry or set FORGE_BIN (e.g. FORGE_BIN=E:\\path\\forge.exe)',
      ms: 0,
    };
  }
  const args = ['build', '--sizes'];
  if (SOLC) args.push('--use', SOLC);
  const r = run(FORGE, args, { cwd: 'contracts' });
  // Report the linter's findings rather than a summary line: Foundry's linter
  // flags real things (unsafe casts, arbitrary ETH sends), and a verification
  // table that hides them would be the same "green but uninformative" failure
  // this project keeps running into. They do not fail the build (see
  // foundry.toml's `deny`), so the count is the honest signal.
  const lint = (r.out.match(/^warning\[/gm) || []).length;
  return {
    state: r.code === 0 ? 'PASS' : 'FAIL',
    detail: r.code === 0 ? `compiled; ${lint} forge-lint warning(s)` : summarise(r.out),
    ms: r.ms,
  };
});

gate('contracts-test', 'Contract tests (forge test, excluding the dependency suite)', () => {
  if (!have(FORGE)) {
    return { state: 'SKIP', detail: 'forge not on PATH; see the row above', ms: 0 };
  }
  const args = ['test', '--no-match-path', '*lib/forge-std*'];
  if (SOLC) args.push('--use', SOLC);
  const r = run(FORGE, args, { cwd: 'contracts' });
  const m = r.out.match(/Ran \d+ test suites[^\n]*/);
  return { state: r.code === 0 ? 'PASS' : 'FAIL', detail: m ? m[0].trim().slice(0, 120) : summarise(r.out), ms: r.ms };
});

// --- run --------------------------------------------------------------------
const selected = gates.filter((g) => !only || only.includes(g.id));
if (quick) {
  const slow = new Set([
    'rust-test',
    'rust-clippy',
    'contracts-test',
    'contracts-build',
    'deploy',
    'libp2p',
  ]);
  for (const g of selected) if (slow.has(g.id)) g.fn = () => ({ state: 'SKIP', detail: '--quick', ms: 0 });
}

console.log(`verify-all  root=${ROOT}`);
console.log(`rust=${RUST}  quick=${quick}  allow-missing-tools=${allowMissing}\n`);

const results = [];
for (const g of selected) {
  process.stdout.write(`  ${g.title.padEnd(62)} `);
  let res;
  try {
    res = g.fn();
  } catch (e) {
    res = { state: 'FAIL', detail: `threw: ${e.message}`, ms: 0 };
  }
  results.push({ ...g, ...res });
  const secs = res.ms > 0 ? `  (${(res.ms / 1000).toFixed(1)}s)` : '';
  console.log(`${res.state.padEnd(5)} ${res.detail}${secs}`);
}

const failed = results.filter((r) => r.state === 'FAIL');
const skipped = results.filter((r) => r.state === 'SKIP');
const passed = results.filter((r) => r.state === 'PASS');

console.log(`\n${passed.length} passed, ${failed.length} failed, ${skipped.length} skipped`);
if (skipped.length) {
  console.log('\nNOT VERIFIED (this is a finding, not a pass):');
  for (const s of skipped) console.log(`  - ${s.title}: ${s.detail}`);
}
if (failed.length) {
  console.log('\nFAILED:');
  for (const f of failed) console.log(`  - ${f.title}: ${f.detail}`);
}

const skipsAreFatal = skipped.length > 0 && !allowMissing;
process.exit(failed.length > 0 || skipsAreFatal ? 1 : 0);
