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
// Interpreter resolution. Assuming the name `python` made two gates report
// "python not found" on machines where a perfectly good interpreter is installed
// under another name -- Windows ships a `py` launcher, many Linux images ship only
// `python3`. NAU_PYTHON still wins, so an unusual layout stays overridable.
function resolvePython() {
  if (process.env.NAU_PYTHON) return process.env.NAU_PYTHON;
  if (process.env.PYTHON) return process.env.PYTHON;
  for (const candidate of ['python3', 'python', 'py']) {
    if (have(candidate)) return candidate;
  }
  return 'python'; // keeps the historical default, so the SKIP message is unchanged
}
const PY = resolvePython();
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

// --- Production code has no panic path --------------------------------------
// The rule "no unwrap()/expect()/panic!() outside #[cfg(test)]" is stated in this
// repository's own module docs and README, and docs/SELF-AUDIT.md found it violated
// in 6 production sites -- which nothing noticed, because no gate checked it. A rule
// that only lives in prose is the "documented but unenforced" defect this project
// criticises upstream for, so it now has a gate. The checker strips comments first:
// a naive grep reported 312 hits where 6 were real, the rest being this project's own
// docs quoting upstream's unwrap() to explain what was fixed.
gate('no-panics', 'Production code has no panic path (no unwrap/expect/panic! outside tests)', () => {
  const r = run(NODE, ['scripts/check-no-panics.mjs']);
  if (r.code === 0) return { state: 'PASS', detail: 'no panic path in production code', ms: r.ms };
  const sites = r.out
    .split('\n')
    .filter((l) => /^\s+crates\//.test(l))
    .map((l) => l.trim());
  return {
    state: 'FAIL',
    detail: `${sites.length} site(s): ` + sites.slice(0, 3).join(' | '),
    ms: r.ms,
  };
});

// --- VERSION is the single source of truth ----------------------------------
// CI has a `version` job for this; the local harness did not, so a half-finished
// version bump could only be caught after a push. That is too late for the step
// that names the release: scripts/bump-version.mjs updates the declarations it knows
// about, and its pattern silently missed a target during the 1.2.3 bump (a crate
// name containing a digit), which is precisely why this is checked rather than
// trusted.
gate('version-consistency', 'VERSION is the only place the release version is written down', () => {
  const r = run(NODE, ['scripts/check-version-consistency.mjs']);
  if (r.code === 0) {
    const first = r.out.split('\n').find((l) => l.includes('VERSION =')) || '';
    return { state: 'PASS', detail: first.trim(), ms: r.ms };
  }
  const sites = r.out
    .split('\n')
    .filter((l) => /^\s{2}\S/.test(l) && !l.includes('VERSION ='))
    .map((l) => l.trim());
  return { state: 'FAIL', detail: sites.slice(0, 2).join(' | ') || summarise(r.out), ms: r.ms };
});

// --- unsafe is contained, not merely discouraged ----------------------------
// Every crate claims `#![forbid(unsafe_code)]` crate-wide with at most one documented
// exception (nau-sandbox's platform module, which needs Job Objects on Windows and
// setrlimit on Unix to actually enforce limits). That claim decays silently the moment
// someone adds an unsafe block in a new crate, because no gate notices. This one checks
// that the crate roots forbid it, that any file with unsafe sits inside a module that
// opted in with #![allow(unsafe_code)], and that every block carries a written
// justification -- so a second exception means editing an attribute a reviewer sees.
gate('unsafe-containment', 'unsafe code is contained in opted-in modules, each with a written justification', () => {
  const r = run(NODE, ['scripts/check-unsafe-containment.mjs']);
  if (r.code === 0) {
    const files = r.out.split('\n').filter((l) => /^\s+crates\//.test(l)).length;
    return { state: 'PASS', detail: `${files} file(s) with unsafe, all opted in`, ms: r.ms };
  }
  const sites = r.out
    .split('\n')
    .filter((l) => /^\s+crates\//.test(l))
    .map((l) => l.trim());
  return {
    state: 'FAIL',
    detail: `${sites.length} violation(s): ` + sites.slice(0, 2).join(' | '),
    ms: r.ms,
  };
});

// --- the plugin kernel keeps its architectural invariants ---------------------
// A Rust test observes behaviour; it cannot see a second assignment site, a second
// entry point, or a document whose vocabulary has drifted from the code. Those are
// exactly the ways the plugin architecture can decay into the thing it replaced --
// upstream's transition table that `open_dispute` walked around is the precedent this
// gate exists to prevent repeating.
gate('plugin-invariants', 'The plugin kernel keeps one assignment site, one start entry point, one token issuer, no host dependency, and a document that matches its code', () => {
  const r = run(NODE, ['scripts/check-plugin-invariants.mjs']);
  if (r.code === 0) {
    const oks = r.out.split('\n').filter((l) => l.trim().startsWith('ok ')).length;
    return { state: 'PASS', detail: `${oks} invariant(s) hold`, ms: r.ms };
  }
  const sites = r.out
    .split('\n')
    .filter((l) => /^\s{2}\[/.test(l))
    .map((l) => l.trim());
  return {
    state: 'FAIL',
    detail: `${sites.length} violated: ` + sites.slice(0, 2).join(' | '),
    ms: r.ms,
  };
});

// --- the OTHER platforms compile ----------------------------------------------
// This gate exists because of a specific failure. `crates/nau-sandbox/src/component.rs`
// imported `std::path::Path` under `#[cfg(any(windows, test))]` while using it in a
// method that is NOT platform-gated. The crate therefore compiled on Windows and under
// `cargo test` (cfg(test)) and failed to compile at all on Linux and macOS under a plain
// `cargo build` -- which is the first step CI runs, on two of its three runners. Every
// local gate was green, and structurally could not have been otherwise: a Windows machine
// never compiles the Unix-only branches. `cargo check --target` does not link, so it can
// type-check those branches from here.
gate('cross-target', 'The workspace type-checks for the other CI platforms, not just this one', () => {
  const TARGETS = [
    { triple: 'x86_64-unknown-linux-gnu', label: 'linux' },
    { triple: 'x86_64-apple-darwin', label: 'macos' },
  ];
  const done = [];
  const missing = [];
  const partialChecks = [];
  for (const t of TARGETS) {
    const installed = run('rustup', ['target', 'list', '--installed', '--toolchain', RUST]);
    if (installed.code !== 0 || !installed.out.includes(t.triple)) {
      missing.push(t.triple);
      continue;
    }
    const r = run('cargo', [
      `+${RUST}`, 'check', '--workspace', '--all-targets', '--target', t.triple, '--locked',
    ]);
    if (r.code !== 0) {
      // "the C cross-toolchain is absent" and "the code does not compile" are
      // different facts and must not share a verdict. `ring` (pulled in through
      // nau-libp2p) builds C, so cross-checking this workspace from a Windows host
      // needs `x86_64-linux-gnu-gcc`; without it the run dies inside a build script
      // and says nothing about the Rust code. Reporting that as FAIL would be a gate
      // that can never be satisfied locally, which is a gate people learn to ignore.
      //
      // So it is a SKIP -- and the header of this file is explicit that a SKIP makes
      // the exit code non-zero. It is not a quiet pass: the run still reports that
      // this platform's code was NOT verified here. On a Linux or macOS runner the
      // triple equals the host, no cross-compiler is involved, and CI runs it for
      // real; that is where this gate has teeth.
      const toolAbsent = /ToolNotFound|failed to find tool|program not found|linker .*not found|cannot find -l/i.test(
        r.out,
      );
      if (toolAbsent) {
        const tool =
          (r.out.match(/failed to find tool "([^"]+)"/) || [])[1] ||
          (r.out.match(/linker `?([\w.-]+)`? not found/) || [])[1] ||
          'a C cross-compiler';
        // Falling back is worth it: the crates that do not pull `ring` type-check for the
        // other platforms perfectly well from here, and "seven crates verified, ten not,
        // and here is why" is a far more useful answer than "nothing was checked". The
        // verdict stays SKIP -- the workspace as a whole was still not verified -- but the
        // detail now says exactly which part was.
        const CHECKABLE = [
          'nau-plugin',
          'nau-plugins',
          'nau-core',
          'nau-store',
          'nau-sandbox',
          'nau-erasure',
          'nau-consensus',
        ];
        const partial = run('cargo', [
          `+${RUST}`,
          'check',
          '--all-targets',
          '--target',
          t.triple,
          '--locked',
          ...CHECKABLE.flatMap((p) => ['-p', p]),
        ]);
        if (partial.code === 0) {
          partialChecks.push(`${t.label}: ${CHECKABLE.length} crates ok (needs ${tool} for the rest)`);
        } else {
          const first =
            partial.out.split('\n').find((l) => /^error/.test(l.trim())) || summarise(partial.out);
          return { state: 'FAIL', detail: `${t.label} (partial): ${first.trim()}`, ms: partial.ms };
        }
        missing.push(`${t.triple} (needs ${tool})`);
        continue;
      }
      const first = r.out
        .split('\n')
        .find((l) => /^error/.test(l.trim())) || summarise(r.out);
      return { state: 'FAIL', detail: `${t.label}: ${first.trim()}`, ms: r.ms };
    }
    done.push(`${t.label} ok (${Math.round(r.ms / 1000)}s)`);
  }
  if (done.length === 0) {
    const stdMissing = missing.filter((m) => !m.includes('needs '));
    const toolMissing = missing.filter((m) => m.includes('needs '));
    return {
      state: 'SKIP',
      detail:
        (stdMissing.length
          ? `no cross-target std installed; run: rustup target add ${stdMissing.join(' ')} --toolchain ${RUST}`
          : '') +
        (stdMissing.length && toolMissing.length ? '; ' : '') +
        (toolMissing.length
          ? `missing cross C toolchain: ${toolMissing.join(', ')} -- the code was NOT type-checked for these platforms here; CI runs it natively`
          : '') +
        (partialChecks.length ? `; PARTIALLY covered -- ${partialChecks.join('; ')}` : ''),
      ms: 0,
    };
  }
  return {
    state: missing.length === 0 ? 'PASS' : 'SKIP',
    detail: done.join(', ') + (missing.length ? `; not installed: ${missing.join(', ')}` : ''),
    ms: 0,
  };
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
  // Labelled "no toolchain needed" because it must not require Foundry -- but it
  // does need an interpreter. It used to run PY unconditionally, so with no python
  // available it FAILED with the Windows shell's unhelpful "operable program or
  // batch file" instead of reporting a missing tool the way every other gate does.
  // A harness whose whole point is "a missing tool is a reported SKIP, never an
  // opaque failure" cannot make an exception for itself.
  if (!have(PY)) {
    return { state: 'SKIP', detail: 'python not found; set NAU_PYTHON', ms: 0 };
  }
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
  // forge-std is the only external dependency and it is deliberately NOT
  // vendored (contracts/lib is skipped when publishing). Without this check a
  // missing dependency surfaces as a wall of solc parser errors --
  // `Source "forge-std/Test.sol" not found` -- instead of the one line that says
  // what to do about it. CI clones the pinned tag; a local clone has to as well.
  if (!fs.existsSync(path.join(ROOT, 'contracts/lib/forge-std/src/Test.sol'))) {
    return {
      state: 'SKIP',
      detail:
        'contracts/lib/forge-std is absent (the only external dependency, not vendored); fetch it with: ' +
        'git clone --depth 1 --branch v1.9.4 https://github.com/foundry-rs/forge-std.git contracts/lib/forge-std',
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
  if (!fs.existsSync(path.join(ROOT, 'contracts/lib/forge-std/src/Test.sol'))) {
    return { state: 'SKIP', detail: 'contracts/lib/forge-std is absent; see the row above', ms: 0 };
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
console.log(
  `rust=${RUST}  python=${PY}  quick=${quick}  allow-missing-tools=${allowMissing}\n`,
);

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
