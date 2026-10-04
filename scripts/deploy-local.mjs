#!/usr/bin/env node
// Deploys the release build onto this machine and verifies it AS A DEPLOYMENT.
//
// The test suites answer "does the code work". This answers the different
// questions that only appear once something is actually installed and running:
//
//   * do the release binaries build and install to a prefix?
//   * does the daemon come up against a PERSISTENT data directory (not
//     --ephemeral), and does the state it writes SURVIVE A RESTART?
//   * do the CLI and the daemon agree about the on-disk format, i.e. can
//     `nau inspect` read what the daemon wrote?
//   * does the running daemon report the version the repository declares?
//
// Restart survival is the property nothing else covers: every other test in this
// repo uses --ephemeral, so a store that silently failed to persist would pass all
// of them. It is also the property a filesystem-store rewrite is most likely to
// get wrong.
//
// Usage:
//   node scripts/deploy-local.mjs [--prefix DIR] [--port N] [--keep-running]

import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { setTimeout as sleep } from 'node:timers/promises';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..');
const argv = process.argv.slice(2);
const argVal = (name, dflt) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
};
const PREFIX = path.resolve(argVal('--prefix', path.join(ROOT, '..', 'nau-deploy')));
const PORT = Number(argVal('--port', '4713'));
const KEEP = argv.includes('--keep-running');
const BASE = `http://127.0.0.1:${PORT}`;

// The API is fail-closed: every mutating route requires a credential, and a daemon
// with nothing configured refuses to serve at all. So this harness mints one and uses
// it, and one check deliberately omits it -- a gate that is never tested in the CLOSED
// direction is indistinguishable from no gate, which is the whole subject of this
// project's audit of upstream.
//
// Format is `id:token[:did][:scope,scope]`, colon-separated
// (crates/nau-node/src/auth.rs `Authenticator::from_env`). Note the DOUBLE colon for a
// token with no DID: `local:tok::write`. A DID written in its usual `did:nau:<id>` form
// cannot be expressed in this table at all, because its own colons are read as field
// separators -- recorded as a limit in docs/VERIFICATION.md rather than papered over.
const TOKEN = 'deploy-local-token';
const TOKENS = `local:${TOKEN}::read,write,admin`;

const BIN = path.join(PREFIX, 'bin');
const DATA = path.join(PREFIX, 'data');
const LOGS = path.join(PREFIX, 'logs');
const LOG = [];
const findings = [];

function say(line) {
  LOG.push(line);
  console.log(line);
}
function head(t) {
  say(`\n${'='.repeat(72)}\n${t}\n${'='.repeat(72)}`);
}
function finding(title, detail) {
  findings.push({ title, detail });
  say(`  !! FINDING: ${title}\n     ${detail}`);
}

const results = [];
async function check(title, fn) {
  process.stdout.write(`  ${title.padEnd(58)} `);
  try {
    const detail = await fn();
    results.push({ title, state: 'PASS', detail: detail || '' });
    console.log(`PASS ${detail || ''}`);
  } catch (e) {
    const detail = e && e.message ? e.message : String(e);
    results.push({ title, state: 'FAIL', detail });
    console.log(`FAIL ${detail}`);
  }
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const exe = (n) => path.join(BIN, process.platform === 'win32' ? `${n}.exe` : n);

// Which build profile is being deployed. Release is what you would actually
// ship, but it is a full recompile of every dependency and this box has already
// died mid-build for want of memory while other cargo builds were running
// (`rustc-LLVM ERROR: out of memory` / a silent exit, see .cargo/config.toml).
// Falling back to the debug profile keeps the DEPLOYMENT questions answerable
// without pretending the artefact is something it is not: the profile is printed
// and carried into the summary.
const PROFILE = process.env.NAU_PROFILE || (fs.existsSync(cargoBinAt('release', 'nau')) ? 'release' : 'debug');
function cargoBinAt(profile, n) {
  return path.join(ROOT, 'target', profile, process.platform === 'win32' ? `${n}.exe` : n);
}
const cargoBin = (n) => cargoBinAt(PROFILE, n);

let daemon = null;

/// How many plugins the running daemon reported at boot, so the shutdown check can compare against
/// what this daemon actually started rather than against a number written here.
///
/// The shutdown check used to assert `stopped === 17` literally, and it is skipped on Windows
/// (`child.kill()` is `TerminateProcess`, so no graceful stop line appears). Adding an eighteenth
/// system plugin therefore passed every local run on Windows and failed the Linux and macOS jobs --
/// which is the shape of defect a deployment check exists to catch, and the reason the number is
/// no longer written down: "a daemon stops every plugin it started" cannot go stale.
let bootedPluginCount = null;
function startDaemon(tag) {
  const logStream = fs.createWriteStream(path.join(LOGS, `daemon-${tag}.log`), { flags: 'a' });
  // A write error must be reported, not thrown.
  //
  // An unhandled `error` event on a WriteStream **ends the process**, and this stream carries a
  // child's output: a full disk or a closed handle would have failed the deployment checks with a
  // message about a stream rather than about the daemon or the disk.
  logStream.on('error', (err) => say(`  [daemon/${tag}] log stream error: ${err.message}`));
  const p = spawn(exe('nau-daemon'), ['--data-dir', DATA, '--api-port', String(PORT)], {
    cwd: PREFIX,
    env: {
      ...process.env,
      RUST_LOG: process.env.RUST_LOG || 'info',
      NAU_API_TOKENS: TOKENS,
      // Deliberately NOT set: NAU_API_ALLOW_ANONYMOUS_WRITES. The deployment checks
      // must exercise the authenticated path, not the loopback escape hatch.
      NAU_API_ALLOW_ANONYMOUS_WRITES: undefined,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // `{ end: false }` on **both**, and one explicit end when the process exits.
  //
  // Two readable streams piped to one writable is the bug this replaces: `pipe` calls
  // `dest.end()` when *its* source ends, so whichever of stdout and stderr reached EOF first
  // ended the shared file and the other stream's next write was a write after end --
  // `ERR_STREAM_WRITE_AFTER_END`, which ended the whole deployment run. Which stream EOFs first
  // depends on buffering and platform, so it presented as an intermittent CI failure on one
  // platform while the same job passed on the other two.
  p.stdout.pipe(logStream, { end: false });
  p.stderr.pipe(logStream, { end: false });
  p.on('exit', (code, sig) => {
    say(`  [daemon/${tag}] exited code=${code} signal=${sig}`);
  });
  // The log stream is ended on `close`, **not** on `exit`, and that distinction is a real bug
  // that took three CI failures to find.
  //
  // `exit` fires when the process terminates. The pipe may still be carrying its last writes --
  // stdio is closed separately, and `close` is the event that fires after it has. Ending the
  // stream on `exit` therefore **discards the daemon's final stderr**, which is where
  // `stopped N plugin(s); M could not be stopped` is written, as the last thing a graceful
  // shutdown does.
  //
  // The symptom was the shape a race always has: the shutdown check passed on the Release
  // workflow's ubuntu job and failed on the Client workflow's ubuntu job, for the same commit.
  // Green, green, red, green. The message was never missing from the daemon -- it was missing
  // from the file.
  //
  // `closed` is a promise a caller can await, and `stopDaemon` does: waiting for `exitCode` is
  // not enough, because that is set at `exit`.
  p.closed = new Promise((resolve) => {
    p.on('close', () => {
      logStream.end();
      resolve();
    });
  });
  return p;
}
async function stopDaemon(p) {
  if (!p || p.exitCode !== null) return;
  p.kill();
  for (let i = 0; i < 60 && p.exitCode === null; i++) await sleep(100);
  if (p.exitCode === null) p.kill('SIGKILL');
  // After the kill, wait for stdio to actually close -- otherwise the caller polls a file the
  // daemon's last write has not reached yet, which is the same race one level up.
  if (p.closed) await Promise.race([p.closed, sleep(5000)]);
}
async function waitHealthy(timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  let lastErr = 'no attempt';
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${BASE}/health`, { signal: AbortSignal.timeout(2000) });
      if (r.ok) return await r.json();
      lastErr = `HTTP ${r.status}`;
    } catch (e) {
      lastErr = e.message || String(e);
    }
    await sleep(250);
  }
  throw new Error(`daemon never became healthy: ${lastErr}`);
}
async function api(method, p, body, credential = TOKEN) {
  const r = await fetch(`${BASE}${p}`, {
    method,
    headers: {
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      ...(credential === null ? {} : { authorization: `Bearer ${credential}` }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(5000),
  });
  const text = await r.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON error page */
  }
  return { status: r.status, json, text };
}
function cli(args, { allowFail = false } = {}) {
  const r = spawnSync(exe('nau'), args, { cwd: PREFIX, encoding: 'utf8', shell: false });
  const out = `${r.stdout || ''}${r.stderr || ''}`.trim();
  if (!allowFail && r.status !== 0) throw new Error(`nau ${args.join(' ')} -> exit ${r.status}: ${out.slice(0, 200)}`);
  return { code: r.status, out };
}

// ---------------------------------------------------------------------------
async function main() {
  head('1. Deploy: build and install the release binaries');
  say(`  prefix:  ${PREFIX}`);
  say(`  port:    ${PORT}`);
  say(`  profile: ${PROFILE}${PROFILE === 'debug' ? '  (debug: unoptimised; release build was not available)' : ''}`);

  for (const d of [BIN, DATA, LOGS]) fs.mkdirSync(d, { recursive: true });

  await check('release binaries exist (cargo build --release)', () => {
    const missing = ['nau', 'nau-daemon'].filter((n) => !fs.existsSync(cargoBin(n)));
    assert(
      missing.length === 0,
      `missing ${PROFILE} binaries: ${missing.join(', ')}; run: cargo build --release -p nau-node --locked`,
    );
    return `${PROFILE} profile: nau, nau-daemon present`;
  });

  await check('install binaries into the deploy prefix', () => {
    for (const n of ['nau', 'nau-daemon']) {
      fs.copyFileSync(cargoBin(n), exe(n));
    }
    const sizes = ['nau', 'nau-daemon'].map((n) => `${n}=${(fs.statSync(exe(n)).size / 1048576).toFixed(1)}MB`);
    return sizes.join(' ');
  });

  const declaredVersion = fs.readFileSync(path.join(ROOT, 'VERSION'), 'utf8').trim();
  await check('binary reports the repository version', () => {
    const { out } = cli(['version']);
    assert(out.includes(declaredVersion), `VERSION is ${declaredVersion} but the binary said: ${out.split('\n')[0]}`);
    return out.split('\n')[0];
  });

  head('2. Start the daemon against a PERSISTENT data directory');
  daemon = startDaemon('boot1');
  let health = null;
  await check('daemon becomes healthy on a persistent store', async () => {
    health = await waitHealthy();
    assert(!/ephemeral/i.test(JSON.stringify(health)), 'daemon reported ephemeral mode');
    return `version ${health.version ?? '?'} protocol ${health.protocol ?? '?'}`;
  });

  // The daemon's own functionality is plugins, so whether it booted them is a health
  // question about the deployment rather than a detail about a subsystem.
  //
  // This check exists because the answer used to be "no". `boot_system_plugins` was called
  // by its own unit tests and by `nau plugin system`, and **the daemon never called it**:
  // seventeen plugins were registered, tested and documented, and not one of them ran in the
  // running node. A green unit suite could not see it, because every unit test booted the
  // host itself -- which is exactly the shape of defect a deployment check is for.
  await check('the daemon hosts its compiled-in system plugins', async () => {
    const r = await api('GET', '/plugins');
    assert(r.status === 200, `/plugins -> HTTP ${r.status}`);
    const count = Number(r.json && r.json.count);
    assert(count > 0, `the daemon booted ${count} plugins`);
    // Remembered for the shutdown check, which asserts that every one of these is stopped.
    bootedPluginCount = count;
    const plugins = (r.json && r.json.plugins) || [];
    assert(plugins.length === count, `count ${count} disagrees with ${plugins.length} entries`);
    const notRunning = plugins.filter((p) => p.state !== 'running');
    assert(notRunning.length === 0, `not running: ${notRunning.map((p) => p.id + '=' + p.state).join(', ')}`);
    // A host key, so a later report can be compared against this one: the plugins are
    // registered against manifests signed at boot, and the key changing across a restart is
    // how an operator knows the registration was redone rather than reused.
    assert(
      typeof r.json.host_key === 'string' && r.json.host_key.length === 64,
      `host_key should be a 32-byte key in hex, got ${JSON.stringify(r.json.host_key)}`,
    );
    // Every plugin reports a pending-outbox count, which must be zero at boot.
    //
    // The count is not decoration. Nothing in the running node drains an outbox -- the
    // daemon holds no Bus and the host holds no Registry for `Bus::send` to resolve
    // recipients against -- so a plugin that queues a bus message has it wait forever, and
    // a queue nobody reads looks exactly like a queue that is always empty. Asserting the
    // field is present and zero means the difference is visible from a deployment rather
    // than discovered later.
    const missing = plugins.filter((p) => typeof p.outbox_pending !== 'number');
    assert(missing.length === 0, `plugins without an outbox count: ${missing.map((p) => p.id).join(', ')}`);
    const queued = plugins.filter((p) => p.outbox_pending > 0);
    assert(
      queued.length === 0,
      `plugins queued bus messages at boot with nothing to carry them: ` +
        queued.map((p) => `${p.id}=${p.outbox_pending}`).join(', '),
    );
    return `${count} plugin(s), all running, no queued bus messages`;
  });

  // And the node *using* one. Booting seventeen plugins and reporting their state makes
  // them observable; it does not make them do anything, and until this route existed the
  // daemon started its own functionality and never invoked it.
  //
  // `sys.policy`'s `matrix` op is the one `nau plugin system` already calls, so the answer
  // is checkable against a second, independent caller rather than against this script's
  // expectation of what a policy matrix looks like.
  // AUSec's plugin answers in the running node, not only in its unit tests.
  //
  // A-13's deployment half. v3.5.0 added `com.twinsearth.sys.ausec` to `standard_plugins()`
  // and the host's unit tests saw it constructed and declared; what they could not see is
  // whether the **daemon** boots it. That is the same shape of gap the "daemon hosts its
  // compiled-in system plugins" check exists for -- seventeen plugins were once registered,
  // tested and documented while not one of them ran -- so this is a call through the daemon's
  // HTTP surface rather than a look at a registration list.
  // C-01's third criterion: the six security organisations are assembled into the running node.
  //
  // The AUSec check above proves the daemon boots its compiled-in plugins. This one proves the
  // security namespace specifically, and it asks a question the registration list cannot answer:
  // each body reports the authority it holds **and the authority it does not**. A body that had
  // quietly gained a kernel capability would show it here, in the running daemon, rather than in
  // a manifest a reviewer read once.
  await check('the six security organisations are booted with the right authorities', async () => {
    const EXPECTED = {
      police: { may: ['kernel:plugin:manage'], mayNot: ['kernel:policy:write'] },
      surveillance: { may: [], mayNot: [] },
      audit: { may: [], mayNot: [] },
      registry: { may: ['kernel:plugin:manage'], mayNot: ['chain:evm:write'] },
      report: { may: ['chain:evm:write'], mayNot: ['kernel:plugin:manage'] },
      tribunal: { may: ['kernel:policy:write'], mayNot: ['kernel:plugin:manage'] },
    };
    const seen = [];
    for (const [body, expectation] of Object.entries(EXPECTED)) {
      const r = await api('POST', `/plugins/com.twinsearth.sys.security.${body}/call`, {
        capability: 'plugin:lifecycle:read',
        op: 'capabilities',
      });
      assert(
        r.status >= 200 && r.status < 300,
        `security.${body} -> HTTP ${r.status}: ${r.text.slice(0, 160)}`,
      );
      const declares = r.json && Array.isArray(r.json.declares) ? r.json.declares : [];
      assert(declares.length > 0, `security.${body} declares nothing`);
      for (const cap of expectation.may) {
        assert(
          declares.includes(cap),
          `security.${body} must hold ${cap}, it declares ${JSON.stringify(declares)}`,
        );
      }
      for (const cap of expectation.mayNot) {
        assert(
          !declares.includes(cap),
          `security.${body} must NOT hold ${cap}; the split between the bodies is the reason \
           they are six rather than one`,
        );
      }
      // The two observers hold no kernel authority at all. Asserted from the running node rather
      // than from the source, because a body that gained one at assembly time would not show up
      // in a source read.
      if (body === 'surveillance' || body === 'audit') {
        const kernel = declares.filter((c) => c.startsWith('kernel:'));
        assert(
          kernel.length === 0,
          `security.${body} must watch and not act, but the running node reports ${JSON.stringify(kernel)}`,
        );
      }
      seen.push(body);
    }
    return `${seen.length} bodies booted with the expected authorities: ${seen.join(', ')}`;
  });

  // C-03's enforcement, end to end in the running node.
  //
  // Two violations must leave the plugin running and the third must quarantine it, and the count
  // is asserted at each step because "it quarantined" alone would also be true of a rule that
  // quarantined on the first.
  //
  // The victim is `security.tribunal`, chosen because **no check after this one calls it**. A
  // quarantine is not undoable -- `Quarantined` is terminal in this repository -- so a check that
  // quarantined a plugin a later check needed would break the suite in a way that looked like the
  // later check's fault.
  // C-05's two criteria, in the running node.
  //
  // The first is answered by reading the assessment back: it must carry factors and a band and no
  // bare score. The second is answered by ATTACKING it -- the check sends an observation about the
  // subject in the request and requires a refusal. A check that only read a clean answer would pass
  // against a plugin that accepted self-reports and ignored them.
  await check('an assessment explains itself and refuses to be told what to think', async () => {
    const subject = 'com.twinsearth.sys.security.police';
    const good = await api('POST', '/plugins/com.twinsearth.sys.security.audit/assess', {
      subject,
    });
    assert(
      good.status >= 200 && good.status < 300,
      `assess -> HTTP ${good.status}: ${good.text.slice(0, 200)}`,
    );
    const a = good.json && good.json.assessment;
    assert(a, `the route must return an assessment, got ${good.text.slice(0, 160)}`);
    assert(
      Array.isArray(a.factors) && a.factors.length > 0,
      `an assessment must carry factors, not only a verdict: ${JSON.stringify(a).slice(0, 200)}`,
    );
    for (const f of a.factors) {
      assert(
        typeof f.name === 'string' && f.name.length > 0 && typeof f.observed === 'string' && f.observed.length > 0,
        `every factor must name what it looked at and what it found: ${JSON.stringify(f)}`,
      );
      assert(typeof f.weight === 'number', `every factor must carry its weight: ${JSON.stringify(f)}`);
    }
    assert(
      typeof a.band === 'string' && ['low', 'elevated', 'high'].includes(a.band),
      `an assessment must band, got ${a.band}`,
    );
    assert(
      a.score === undefined,
      `there must be no score field to return; the answer carried one: ${JSON.stringify(a).slice(0, 200)}`,
    );
    assert(
      Array.isArray(a.unobserved) && a.unobserved.length > 0,
      'an assessment must say what it could not look at',
    );

    // Criterion two, as an attack rather than an observation.
    for (const key of ['violations', 'state', 'score']) {
      const bad = await api('POST', '/plugins/com.twinsearth.sys.security.audit/assess', {
        subject,
        [key]: key === 'state' ? 'running' : 0,
      });
      assert(
        bad.status === 400,
        `a request carrying \`${key}\` must be refused, got HTTP ${bad.status}: ${bad.text.slice(0, 160)}`,
      );
      assert(
        bad.text.includes('self_reported_observation'),
        `the refusal must name the rule, got: ${bad.text.slice(0, 200)}`,
      );
    }
    return `${a.factors.length} factor(s), band ${a.band}, and 3 self-reporting keys refused`;
  });

  // C-07's two rules, attacked rather than read.
  //
  // The reporting desk refuses a grade the workspace cannot award, and refuses a verified report
  // that names nothing to re-check. Both refusals are checked here, in the running node, because a
  // check that only recorded a well-formed report would pass against a plugin that accepted
  // anything.
  await check('a report must be re-checkable, and cannot claim a grade nothing here awards', async () => {
    const report = async (body) =>
      api('POST', '/plugins/com.twinsearth.sys.security.report/call', {
        capability: 'chain:evm:write',
        ...body,
      });

    const good = await report({
      op: 'record',
      evidence: {
        // The SERDE name, which is not the label. `#[serde(rename_all = "snake_case")]` renders
        // `SignatureVerified` as `signature_verified` with an underscore, while the crate's
        // published `label` is `signature-verified` with a hyphen. One is a name for a person and
        // the other is the wire form, and the first version of this check used the wrong one --
        // which the running node caught with `malformed_evidence` rather than accepting a grade it
        // did not recognise.
        grade: 'signature_verified',
        subject: 'com.twinsearth.sys.security.police',
        artifact: 'sha256:' + 'c'.repeat(64),
        digest: 'c'.repeat(64),
      },
    });
    assert(
      good.status >= 200 && good.status < 300,
      `a well-formed report must record: HTTP ${good.status}: ${good.text.slice(0, 200)}`,
    );
    assert(good.json && good.json.recorded === true, `expected a record, got ${good.text.slice(0, 160)}`);
    assert(
      good.json.anchored === false,
      'recording is not anchoring, and the answer must say so rather than let a reader assume it',
    );

    // Rule one: a verified report with nothing to re-check.
    const unbacked = await report({
      op: 'record',
      evidence: {
        grade: 'signature_verified',
        subject: 'com.twinsearth.sys.security.police',
        digest: 'd'.repeat(64),
      },
    });
    assert(
      unbacked.status === 400,
      `a verified report with no artifact must be refused, got HTTP ${unbacked.status}`,
    );
    assert(
      unbacked.text.includes('evidence_not_recheckable'),
      `the refusal must name the rule, got: ${unbacked.text.slice(0, 200)}`,
    );

    // Rule two: a grade above the ceiling this workspace can award.
    const unreachable = await report({
      op: 'record',
      evidence: {
        grade: 'hardware_attested',
        subject: 'com.twinsearth.sys.security.police',
        artifact: 'sha256:' + 'e'.repeat(64),
        digest: 'e'.repeat(64),
      },
    });
    assert(
      unreachable.status === 400,
      `a grade above the ceiling must be refused, got HTTP ${unreachable.status}`,
    );
    assert(
      unreachable.text.includes('grade_not_achievable'),
      `the refusal must name the rule, got: ${unreachable.text.slice(0, 200)}`,
    );

    // And the ceiling is the one the grading crate publishes, read from the plugin rather than
    // restated in this script.
    const grades = await api('POST', '/plugins/com.twinsearth.sys.security.report/call', {
      capability: 'plugin:lifecycle:read',
      op: 'grades',
    });
    assert(
      grades.json && grades.json.ceiling === 'signature-verified',
      `the ceiling must be signature-verified, got ${grades.json && grades.json.ceiling}`,
    );

    return `recorded a re-checkable report; refused an unbacked one and an unreachable grade; ceiling ${grades.json.ceiling}`;
  });

  // C-08's three criteria, attacked rather than read.
  await check('a penalty is the rule\'s, the field names are the struct\'s, and the tribunal cannot pardon itself', async () => {
    const tribunal = async (body) =>
      api('POST', '/plugins/com.twinsearth.sys.security.tribunal/call', {
        capability: 'kernel:policy:write',
        ...body,
      });

    // Criterion one, as an ATTEMPT TO BE LET OFF. The request asks for a reprimand for malware;
    // the rule says the name is condemned, and the answer says it was overruled.
    const lenient = await tribunal({
      op: 'rule',
      reason: 'malware',
      violations: 0,
      penalty: 'reprimand',
    });
    assert(
      lenient.status >= 200 && lenient.status < 300,
      `rule -> HTTP ${lenient.status}: ${lenient.text.slice(0, 200)}`,
    );
    assert(
      lenient.json && lenient.json.penalty === 'condemn-name',
      `a request may not choose its own punishment; the rule gives condemn-name for malware, got ${lenient.json && lenient.json.penalty}`,
    );
    assert(
      lenient.json.overruled === true,
      'the answer must say the request was overruled rather than leaving a caller to diff two fields',
    );
    assert(
      String(lenient.json.decided_by).includes('not the request'),
      `the answer must say who decided, got ${lenient.json.decided_by}`,
    );

    // And a policy violation reaches a build condemnation only on the kernel's own threshold.
    const early = await tribunal({ op: 'rule', reason: 'policy_violation', violations: 2 });
    const atThreshold = await tribunal({ op: 'rule', reason: 'policy_violation', violations: 3 });
    assert(
      early.json.penalty === 'reprimand' && atThreshold.json.penalty === 'condemn-build',
      `the third violation must be the one that condemns: ${early.json.penalty} then ${atThreshold.json.penalty}`,
    );

    // Criterion two: the field names are this repository's, and the design's are not.
    //
    // Called with the READ capability rather than the write one, because asking what the fields are
    // is not writing policy. The first version of this used the same helper as the rulings and got
    // `undefined` for the list -- the plugin refused a write authority it does not need for a
    // question, which is the capability model working rather than getting in the way.
    const fields = await api('POST', '/plugins/com.twinsearth.sys.security.tribunal/call', {
      capability: 'plugin:lifecycle:read',
      op: 'penalties',
    });
    assert(
      fields.status === 200,
      `penalties -> HTTP ${fields.status}: ${fields.text.slice(0, 160)}`,
    );
    const listed = fields.json.blacklist_fields;
    assert(
      Array.isArray(listed) && listed.includes('module_sha256'),
      `the real field is module_sha256: ${JSON.stringify(listed)}`,
    );
    assert(
      !listed.includes('wasm_sha256') && !listed.includes('evidence_hash'),
      `the original design's names exist nowhere and must not appear as fields: ${JSON.stringify(listed)}`,
    );

    // Criterion three: the tribunal cannot pardon on its own authority.
    const selfPardon = await tribunal({
      op: 'unseal',
      plugin_name: 'com.twinsearth.sys.security.police',
      approval: 'host',
    });
    assert(
      selfPardon.status === 400,
      `the host is this node and this node condemned, so its own approval must be refused: HTTP ${selfPardon.status}`,
    );
    assert(
      selfPardon.text.includes('self_approval'),
      `the refusal must name the rule, got: ${selfPardon.text.slice(0, 200)}`,
    );

    const granted = await tribunal({
      op: 'unseal',
      plugin_name: 'com.twinsearth.sys.security.police',
      approval: 'operator',
      module_sha256: 'f'.repeat(64),
    });
    assert(
      granted.status >= 200 && granted.status < 300,
      `an operator approval must be accepted: HTTP ${granted.status}: ${granted.text.slice(0, 200)}`,
    );
    assert(
      granted.json && granted.json.approved_by === 'operator',
      `the record must say WHO approved, not merely that it was allowed: ${JSON.stringify(granted.json).slice(0, 160)}`,
    );

    // And a missing approval is a refusal rather than a default.
    const noApproval = await tribunal({
      op: 'unseal',
      plugin_name: 'com.twinsearth.sys.security.police',
    });
    assert(
      noApproval.status === 400 && noApproval.text.includes('missing_approval'),
      `unsealing without an approval must be refused, got HTTP ${noApproval.status}: ${noApproval.text.slice(0, 160)}`,
    );

    return `overruled a lenient request, named the real fields, refused a self-pardon and a missing one`;
  });

  // C-10's second criterion: an over-reach attempt, and the chain that stops it.
  //
  // The design names `XFS_IOC_SWAPEXT` -- an ioctl that swaps file extents and has been used to
  // modify a file the caller was not permitted to write. It is an over-reach of the FIRST layer's
  // kind: the sandbox asking to do something it does not hold the authority for. So the attempt
  // here is the same shape, and what is asserted is the chain rather than the ioctl: the request is
  // refused BY NAME, at the first layer, and the refusal reaches the caller.
  //
  // WHAT THIS DOES NOT SHOW, and the boundary document says so: a kernel vulnerability that only
  // corrupts kernel memory does not need an authority the caller lacks, so no layer here intercepts
  // it. This check is about the permission-shaped over-reach and nothing else.
  await check('an over-reach is stopped at the first layer, by name', async () => {
    // A sandbox asking for kernel authority it does not hold. `sandbox:create` is a real capability
    // and the sandbox plugin is a real holder of part of the pair -- so this is an asked-for
    // authority rather than a made-up string.
    const overreach = await api('POST', '/plugins/com.twinsearth.sys.ausec/call', {
      capability: 'kernel:policy:write',
      op: 'backends',
    });
    assert(
      overreach.status === 400,
      `an undeclared capability must be refused: HTTP ${overreach.status}: ${overreach.text.slice(0, 200)}`,
    );
    assert(
      /capability/i.test(overreach.text),
      `the refusal must be the capability check rather than something downstream, got: ${overreach.text.slice(0, 200)}`,
    );
    assert(
      overreach.text.includes('kernel:policy:write'),
      `the refusal must NAME the capability it refused, which is what makes it diagnosable: ${overreach.text.slice(0, 220)}`,
    );

    // And the same over-reach through the plugin whose job is confinement: asking it to configure
    // isolation under a capability it does not declare.
    const wrongDoor = await api('POST', '/plugins/com.twinsearth.sys.security.audit/call', {
      capability: 'kernel:plugin:manage',
      op: 'capabilities',
    });
    assert(
      wrongDoor.status === 400,
      `a body asked to act outside its authority must refuse: HTTP ${wrongDoor.status}`,
    );

    // The layer is not merely refusing everything: a capability the plugin DOES declare is served,
    // so the refusal above is the capability check and not a broken endpoint.
    //
    // The capability here is the one AUSec's `backends` op actually requires. The first version
    // used the read capability and was refused -- correctly, since asking which backends exist is
    // done under the sandbox authority in that plugin -- which made the control fail while the
    // thing it was controlling for was working.
    const allowed = await api('POST', '/plugins/com.twinsearth.sys.ausec/call', {
      capability: 'sandbox:create',
      op: 'backends',
    });
    assert(
      allowed.status >= 200 && allowed.status < 300,
      `a declared capability must be served, or the refusal above proves nothing: HTTP ${allowed.status}: ${allowed.text.slice(0, 200)}`,
    );

    return 'refused by name at layer one, and a declared capability still served';
  });

  // D-01's third and fourth criteria, and D-02's: the resource vocabulary is booted, the six kinds
  // carry six distinct units, and the ten capabilities this workspace does not have are refused BY
  // NAME rather than described in a document.
  await check('the resource vocabulary is booted, with its units and its refusals', async () => {
    const kinds = await api('POST', '/plugins/com.twinsearth.sys.resource/call', {
      capability: 'plugin:lifecycle:read',
      op: 'kinds',
    });
    assert(
      kinds.status >= 200 && kinds.status < 300,
      `kinds -> HTTP ${kinds.status}: ${kinds.text.slice(0, 200)}`,
    );
    assert(
      kinds.json && kinds.json.count === 6,
      `six kinds of resource, got ${kinds.json && kinds.json.count}`,
    );
    const units = kinds.json.kinds.map((k) => k.unit);
    assert(
      new Set(units).size === units.length,
      `two kinds share a unit, which would make a unit unable to say which kind a number is: ${JSON.stringify(units)}`,
    );
    // The rate-like kinds say so, because a price that ignored the clock for them would be selling
    // something other than what it delivers.
    const rates = kinds.json.kinds.filter((k) => k.rate_like).map((k) => k.kind);
    assert(
      rates.length === 2 && rates.includes('memory') && rates.includes('storage'),
      `memory and storage are the kinds held over time, got ${JSON.stringify(rates)}`,
    );
    assert(
      String(kinds.json.quota_is_not_an_amount).includes('no conversion'),
      'the answer must say that a quota and an amount are different things with no bridge',
    );

    // D-02: the refusal is something a caller can QUERY, which a document is not.
    const refused = await api('POST', '/plugins/com.twinsearth.sys.resource/call', {
      capability: 'plugin:lifecycle:read',
      op: 'refused',
    });
    assert(
      refused.json && refused.json.count === 10,
      `ten named refusals, got ${refused.json && refused.json.count}`,
    );
    const names = refused.json.refused.map((r) => r.name);
    for (const expected of ['ERC-8004', 'x402', 'L402', 'USDC']) {
      assert(
        names.includes(expected),
        `\`${expected}\` has zero hits in this repository and must be refused by name: ${JSON.stringify(names)}`,
      );
    }
    for (const entry of refused.json.refused) {
      assert(
        typeof entry.why === 'string' && entry.why.length > 20,
        `\`${entry.name}\` is refused with a reason too short to be one: ${entry.why}`,
      );
    }

    return `6 kinds with 6 distinct units, and ${names.length} capabilities refused by name`;
  });

  // D-03's three criteria, in the running node: a stake below the market's own minimum is refused,
  // and a caller's claimed penalty does not decide the penalty.
  await check('a provider below the market minimum cannot offer, and cannot name its own penalty', async () => {
    const resource = async (body) =>
      api('POST', '/plugins/com.twinsearth.sys.resource/call', body);

    const offer = {
      provider: 'did:example:deploy-check',
      amount: { kind: 'cpu', quantity: 100 },
      // Money is #[serde(transparent)] over an i64, so a price is a JSON INTEGER and not an
      // object. The first version of this check sent { minor: 500 } and the plugin refused it
      // with invalid type: map, expected i64 -- the wire form is the crate's, not this script's.
      price: 500,
      expires_in: 60,
      // Added by D-04: an offer now says what latency it can serve and how long it promises to
      // take, because a matcher that had to guess would guess permissive -- and guessing permissive
      // is the direction that puts an interactive task on a batch node.
      latency: 'standard',
      eta_secs: 30,
    };

    // Below the minimum. The threshold is the MARKET's, read through the plugin rather than
    // restated here -- so this script cannot disagree with the configuration about what it is.
    const low = await resource({
      capability: 'plugin:storage:own',
      op: 'register',
      registration: {
        provider: 'did:example:poor',
        offer,
        stake: 1,
        registered_at: 1,
      },
    });
    assert(
      low.status === 400,
      `a stake below the minimum must be refused: HTTP ${low.status}: ${low.text.slice(0, 200)}`,
    );
    assert(
      low.text.includes('below the minimum'),
      `the refusal must say which rule: ${low.text.slice(0, 200)}`,
    );

    const notAdmitted = await resource({
      capability: 'plugin:lifecycle:read',
      op: 'admitted',
      provider: 'did:example:poor',
    });
    assert(
      notAdmitted.json && notAdmitted.json.admitted === false,
      'a refused registration must not leave an admitted provider',
    );
    const minimum = Number(notAdmitted.json.min_stake.replace(/[^0-9]/g, '')) || 0;
    assert(minimum > 0, `the plugin must publish the minimum it is using, got ${notAdmitted.json.min_stake}`);

    // At the minimum, admitted. The number comes from the plugin rather than being assumed.
    const ok = await resource({
      capability: 'plugin:storage:own',
      op: 'register',
      registration: {
        provider: 'did:example:deploy-check',
        offer,
        stake: 100_000_000,
        registered_at: 1,
      },
    });
    assert(
      ok.status >= 200 && ok.status < 300,
      `the market's own minimum stake must be enough: HTTP ${ok.status}: ${ok.text.slice(0, 220)}`,
    );

    // The penalty is computed. The caller asks for one minor unit and gets the rule's answer.
    const lenient = await resource({
      capability: 'plugin:storage:own',
      op: 'slash',
      provider: 'did:example:deploy-check',
      bonded_minor: 1_000_000,
      claimed_minor: 1,
    });
    assert(
      lenient.status >= 200 && lenient.status < 300,
      `slash -> HTTP ${lenient.status}: ${lenient.text.slice(0, 200)}`,
    );
    assert(
      lenient.json.slashed_minor > 1,
      `the caller's claim must not decide the penalty; it asked for 1 and got ${lenient.json.slashed_minor}`,
    );
    assert(
      lenient.json.claim_decided_it === false,
      'the answer must say plainly that the claim did not decide it',
    );

    // A zero claim is malformed rather than lenient: silence must not be the lightest sentence.
    const zero = await resource({
      capability: 'plugin:storage:own',
      op: 'slash',
      provider: 'did:example:deploy-check',
      bonded_minor: 1_000_000,
      claimed_minor: 0,
    });
    assert(
      zero.status === 400,
      `a zero claim must be refused as malformed, got HTTP ${zero.status}: ${zero.text.slice(0, 160)}`,
    );

    // And writing the registry needs the storage capability, not merely a read: the first version
    // of this check used the read and was refused, which is the capability model working.
    const wrongCap = await resource({
      capability: 'plugin:lifecycle:read',
      op: 'register',
      registration: { provider: 'did:example:x', offer, stake: 100_000_000, registered_at: 1 },
    });
    assert(
      wrongCap.status === 400,
      `writing the registry under a read capability must be refused: HTTP ${wrongCap.status}`,
    );

    return `refused below-minimum and a zero claim, and the rule decided the penalty`;
  });

  // D-04's first criterion, attacked: an interactive task must NOT be matched to a tolerant node,
  // and the exclusion must be REPORTED rather than silent.
  //
  // The difference from the bid path is the point. `rank_bids` DISFAVOURS a slow bid and lets it win
  // anyway if it is cheap enough -- right for a market where everything is a trade-off. "Must not be
  // matched" is a filter, so the tolerant node is set at a TWENTIETH of the price to make the two
  // distinguishable: a penalty would still have let it win.
  await check('an interactive task is not matched to a tolerant node, and says who was excluded', async () => {
    const resource = async (body) =>
      api('POST', '/plugins/com.twinsearth.sys.resource/call', body);

    const offerOf = (provider, latency, price, eta) => ({
      provider,
      amount: { kind: 'cpu', quantity: 100 },
      price,
      expires_in: 60,
      latency,
      eta_secs: eta,
    });

    for (const [provider, latency, price, eta] of [
      ['did:example:cheap-slow', 'tolerant', 10, 600],
      ['did:example:dear-fast', 'interactive', 200, 5],
    ]) {
      const r = await resource({
        capability: 'plugin:storage:own',
        op: 'register',
        registration: {
          provider,
          offer: offerOf(provider, latency, price, eta),
          stake: 100_000_000,
          registered_at: 1,
        },
      });
      assert(
        r.status >= 200 && r.status < 300,
        `registering ${provider} -> HTTP ${r.status}: ${r.text.slice(0, 200)}`,
      );
    }

    const matched = await resource({
      capability: 'plugin:lifecycle:read',
      op: 'match',
      demand: { amount: { kind: 'cpu', quantity: 10 }, latency: 'interactive' },
      target_secs: 30,
    });
    assert(
      matched.status >= 200 && matched.status < 300,
      `match -> HTTP ${matched.status}: ${matched.text.slice(0, 220)}`,
    );
    assert(
      matched.json.winner && matched.json.winner.provider === 'did:example:dear-fast',
      `an interactive task must go to the interactive node, got ${JSON.stringify(matched.json.winner)}`,
    );
    const excluded = matched.json.excluded.map((e) => e.provider);
    assert(
      excluded.includes('did:example:cheap-slow'),
      `the tolerant node must be EXCLUDED, not merely outscored -- it is twenty times cheaper and a penalty would have let it win: ${JSON.stringify(matched.json.excluded)}`,
    );
    const why = matched.json.excluded.find((e) => e.provider === 'did:example:cheap-slow').why;
    assert(
      why.includes('tolerant') && why.includes('interactive'),
      `the exclusion must name both classes, got: ${why}`,
    );

    // The other direction, so the rule is not simply refusing everything: a tolerant task may be
    // served by the interactive node.
    //
    // Asserted as a PROPERTY rather than a count. The first version required exactly two ranked
    // offers, which is true only if this check runs against a fresh registry -- and the D-03 check
    // above registers a third provider in the same node, so the count was three. That is the
    // deployment-check equivalent of a test that depends on the order it runs in, and the same
    // mistake the C-06 trust checks made.
    const batch = await resource({
      capability: 'plugin:lifecycle:read',
      op: 'match',
      demand: { amount: { kind: 'cpu', quantity: 10 }, latency: 'tolerant' },
      target_secs: 30,
    });
    const batchRanked = batch.json.ranked.map((r) => r.provider);
    assert(
      batchRanked.includes('did:example:dear-fast'),
      `a tolerant task may use the interactive node: ${JSON.stringify(batchRanked)}`,
    );
    assert(
      batchRanked.includes('did:example:cheap-slow'),
      `and the tolerant node, which was excluded for the interactive task: ${JSON.stringify(batchRanked)}`,
    );
    assert(
      batch.json.excluded.length === 0,
      `nothing should be excluded for a tolerant task, got ${JSON.stringify(batch.json.excluded)}`,
    );

    return `excluded the twenty-times-cheaper tolerant node and named why; a tolerant task saw both`;
  });

  // D-05's two criteria: a price carries its terms rather than a bare number, and every term is an
  // exact integer number of basis points.
  await check('a price carries its terms, and every term is an exact integer', async () => {
    const resource = async (body) =>
      api('POST', '/plugins/com.twinsearth.sys.resource/call', body);

    const priced = await resource({
      capability: 'plugin:lifecycle:read',
      op: 'price',
      input: {
        base_minor: 10_000,
        scarcity_bps: 2_500,
        reputation_bps: 9_000,
        reputation_floor_bps: 1_000,
        latency: 'interactive',
        snapshot_reuses: 3,
      },
    });
    assert(
      priced.status >= 200 && priced.status < 300,
      `price -> HTTP ${priced.status}: ${priced.text.slice(0, 220)}`,
    );
    const adjustments = priced.json.adjustments;
    assert(
      Array.isArray(adjustments) && adjustments.length === 4,
      `the four tracks the plan names, got ${JSON.stringify(adjustments)}`,
    );
    assert(
      adjustments.map((a) => a.track).join(',') ===
        'scarcity,reputation,latency,snapshot-royalty',
      `the tracks must be the four, in order: ${JSON.stringify(adjustments.map((a) => a.track))}`,
    );
    for (const a of adjustments) {
      assert(
        typeof a.because === 'string' && a.because.length > 20,
        `every term must say WHY, in words: ${JSON.stringify(a)}`,
      );
      // The contribution is an exact integer, and it is the truncation of the basis-point product
      // rather than a rounded figure.
      const exact = Math.trunc((priced.json.base_minor * a.bps) / 10_000);
      assert(
        a.delta_minor === exact,
        `term ${a.track}: ${a.delta_minor} must be the truncated product ${exact}`,
      );
    }
    assert(
      Array.isArray(priced.json.explain) && priced.json.explain.length === 5,
      `four terms and a total: ${JSON.stringify(priced.json.explain)}`,
    );

    // The total is DERIVED: it is the base plus the terms, and this script computes it that way
    // rather than trusting the answer's own arithmetic.
    const sum = priced.json.base_minor + adjustments.reduce((n, a) => n + a.delta_minor, 0);
    assert(
      priced.json.total_minor === Math.max(0, sum),
      `the total must be the terms added up: ${priced.json.total_minor} vs ${sum}`,
    );

    // The direction that makes idle capacity worth selling: a task that can wait is cheaper.
    const cheaper = await resource({
      capability: 'plugin:lifecycle:read',
      op: 'price',
      input: { base_minor: 10_000, latency: 'tolerant' },
    });
    const dearer = await resource({
      capability: 'plugin:lifecycle:read',
      op: 'price',
      input: { base_minor: 10_000, latency: 'interactive' },
    });
    assert(
      cheaper.json.total_minor < 10_000 && dearer.json.total_minor > 10_000,
      `tolerant ${cheaper.json.total_minor} < base < interactive ${dearer.json.total_minor}`,
    );

    // A price from nothing is refused, because every adjustment of zero is zero and the answer
    // would explain nothing while looking computed.
    const fromNothing = await resource({
      capability: 'plugin:lifecycle:read',
      op: 'price',
      input: { base_minor: 0 },
    });
    assert(
      fromNothing.status === 400,
      `a price from a zero base must be refused, got HTTP ${fromNothing.status}`,
    );

    return `4 terms each with a reason, the total re-derived here, and a zero base refused`;
  });

  // D-06's first criterion, and its LIMIT stated as a check rather than left in a document.
  //
  // The record is built from the typed variant, so its capability name is the canonical one. What
  // this check asserts is exactly what is true: the record and its capability are PRODUCED, and the
  // body reports that it cannot FILE them, because `SystemPlugin::handle` receives no
  // `&mut HostContext` and so has no way to call `request_send`. Asserting "filed" when the record
  // is produced would be the written-but-not-wired shape this project keeps finding.
  await check('a snapshot asset names the canonical restore capability, and says it cannot file it', async () => {
    const resource = async (body) =>
      api('POST', '/plugins/com.twinsearth.sys.resource/call', body);

    const good = await resource({
      capability: 'plugin:lifecycle:read',
      op: 'asset',
      asset: {
        snapshot: 'sha256:deploy-check-snapshot',
        author: 'did:example:author',
        seller: 'did:example:seller',
        royalty_bps: 250,
      },
    });
    assert(
      good.status >= 200 && good.status < 300,
      `asset -> HTTP ${good.status}: ${good.text.slice(0, 220)}`,
    );
    // The canonical name, taken from the typed variant rather than chosen at the call site.
    assert(
      good.json.restore_capability === 'sandbox:restore',
      `the restore capability must be the canonical one, got ${JSON.stringify(good.json.restore_capability)}`,
    );
    // And the honest limit, asserted so that a change which DID start filing would fail this check
    // and force someone to update it rather than leaving a stale disclaimer behind.
    assert(
      good.json.record_filed === false,
      'the body cannot file from `handle`, and the answer must say so',
    );
    assert(
      String(good.json.why_not_filed).includes('request_send'),
      `the reason must name the missing call: ${good.json.why_not_filed}`,
    );

    // A royalty above the whole price would pay out more than it took in.
    const greedy = await resource({
      capability: 'plugin:lifecycle:read',
      op: 'asset',
      asset: {
        snapshot: 'sha256:x',
        author: 'did:example:a',
        seller: 'did:example:s',
        royalty_bps: 10_001,
      },
    });
    assert(
      greedy.status === 400,
      `a royalty above 100% must be refused: HTTP ${greedy.status}: ${greedy.text.slice(0, 160)}`,
    );

    // An asset with no address has nothing that says what a buyer gets.
    const nowhere = await resource({
      capability: 'plugin:lifecycle:read',
      op: 'asset',
      asset: { snapshot: '', author: 'did:example:a', seller: 'did:example:s', royalty_bps: 0 },
    });
    assert(nowhere.status === 400, `an asset with no address must be refused, got ${nowhere.status}`);

    return `canonical sandbox:restore, and record_filed:false reported rather than glossed`;
  });

  // D-07's three criteria. The second is the one worth attacking directly: a bound must be REFUSED
  // rather than saturated, because a saturated figure is a silently wrong one and a conservation
  // check over silently wrong numbers reports success.
  await check('six kinds are conserved separately, and a bound is refused rather than saturated', async () => {
    const resource = async (body) =>
      api('POST', '/plugins/com.twinsearth.sys.resource/call', body);

    // Two kinds, so that "reported BY KIND" is distinguishable from "reported once".
    for (const [holder, kind, quantity] of [
      ['did:example:ledger-a', 'cpu', 100],
      ['did:example:ledger-a', 'network', 4096],
      ['did:example:ledger-b', 'cpu', 50],
    ]) {
      const r = await resource({
        capability: 'plugin:storage:own',
        op: 'issue',
        holder,
        amount: { kind, quantity },
      });
      assert(
        r.status >= 200 && r.status < 300,
        `issue ${quantity} ${kind} -> HTTP ${r.status}: ${r.text.slice(0, 200)}`,
      );
      // Each answer is about ONE kind.
      assert(r.json.kind === kind, `the answer must name the kind, got ${r.json.kind}`);
      assert(typeof r.json.unit === 'string' && r.json.unit.length > 0, 'and its unit');
    }

    const consumed = await resource({
      capability: 'plugin:storage:own',
      op: 'consume',
      holder: 'did:example:ledger-a',
      amount: { kind: 'cpu', quantity: 40 },
    });
    assert(consumed.status < 300, `consume -> ${consumed.status}: ${consumed.text.slice(0, 200)}`);
    assert(consumed.json.held === 60, `100 issued less 40 consumed, got ${consumed.json.held}`);

    const audit = await resource({
      capability: 'plugin:lifecycle:read',
      op: 'resource-audit',
    });
    assert(audit.json.conserved === true, `the books must be conserved: ${audit.text.slice(0, 220)}`);
    assert(audit.json.unbalanced.length === 0, JSON.stringify(audit.json.unbalanced));
    // Per-kind books, and each carries its own unit -- so two rows cannot be added up by accident.
    const byKind = Object.fromEntries(audit.json.books.map((b) => [b.kind, b]));
    assert(byKind.cpu && byKind.network, `cpu and network each have a book: ${JSON.stringify(Object.keys(byKind))}`);
    assert(byKind.cpu.issued === 150, `cpu issued 100 + 50, got ${byKind.cpu.issued}`);
    assert(byKind.cpu.consumed === 40);
    assert(byKind.network.issued === 4096, 'network is a separate book, untouched by the cpu one');
    assert(byKind.network.consumed === 0);
    assert(
      byKind.cpu.unit !== byKind.network.unit,
      'the units differ, which is why a grand total would be meaningless',
    );
    // And the answer says so rather than leaving it to a reader.
    assert(
      String(audit.json.no_grand_total).includes('BY KIND'),
      'the report must state that there is no total across kinds',
    );

    // Consuming more than is held is refused rather than going negative.
    const overdraw = await resource({
      capability: 'plugin:storage:own',
      op: 'consume',
      holder: 'did:example:ledger-a',
      amount: { kind: 'cpu', quantity: 61 },
    });
    assert(overdraw.status === 400, `an overdraw must be refused, got HTTP ${overdraw.status}`);
    assert(
      overdraw.text.includes('cannot consume'),
      `and must say so: ${overdraw.text.slice(0, 160)}`,
    );

    // Holding one kind does not permit spending another: the balance is per (holder, kind).
    const wrongKind = await resource({
      capability: 'plugin:storage:own',
      op: 'consume',
      holder: 'did:example:ledger-a',
      amount: { kind: 'storage', quantity: 1 },
    });
    assert(
      wrongKind.status === 400,
      `holding cpu must not permit spending storage, got HTTP ${wrongKind.status}`,
    );

    // A zero quantity is refused by the amount's own constructor, on the wire as in code.
    const zero = await resource({
      capability: 'plugin:storage:own',
      op: 'issue',
      holder: 'did:example:ledger-a',
      amount: { kind: 'cpu', quantity: 0 },
    });
    assert(zero.status === 400, `a zero amount must be refused, got HTTP ${zero.status}`);

    // Nothing the refusals did may have unbalanced a book.
    const after = await resource({ capability: 'plugin:lifecycle:read', op: 'resource-audit' });
    assert(after.json.conserved === true, `refusals must not unbalance anything: ${after.text.slice(0, 220)}`);
    assert(after.json.unbalanced.length === 0);

    return `cpu and network conserved separately, refusals carried nothing, no total across kinds`;
  });

  // D-08's first criterion, both halves, and the honest split between them.
  //
  // The sample must not be predictable, and that has two parts: the seed unknown before the fact,
  // and the draw reproducible after it. This module provides the second and says plainly that the
  // first is the caller's obligation -- so the check asserts the REPRODUCIBILITY and asserts that
  // the body does NOT claim unpredictability.
  await check('a sample is reproducible from its seed, and the body does not claim unpredictability', async () => {
    const resource = async (body) =>
      api('POST', '/plugins/com.twinsearth.sys.resource/call', body);

    const candidates = Array.from({ length: 400 }, (_, i) => `sample-delivery-${i}`);

    const first = await resource({
      capability: 'plugin:lifecycle:read',
      op: 'sample',
      rate_bps: 2_000,
      seed: 'deploy-check-seed-a',
      candidates,
    });
    assert(
      first.status >= 200 && first.status < 300,
      `sample -> HTTP ${first.status}: ${first.text.slice(0, 220)}`,
    );
    assert(first.json.candidates === 400, `400 candidates, got ${first.json.candidates}`);
    assert(first.json.drawn > 0, 'a 20% sample of 400 must not be empty');
    assert(
      first.json.drawn < 400,
      `and must not be all of them, got ${first.json.drawn}`,
    );

    // Same seed, same candidates: the same sample, every time. This is what a provider disputing a
    // finding needs and what an auditor re-running the sample needs.
    for (let i = 0; i < 3; i += 1) {
      const again = await resource({
        capability: 'plugin:lifecycle:read',
        op: 'sample',
        rate_bps: 2_000,
        seed: 'deploy-check-seed-a',
        candidates,
      });
      assert(
        JSON.stringify(again.json.findings) === JSON.stringify(first.json.findings),
        `run ${i}: the sample must be reproducible`,
      );
    }

    // A different seed draws a different sample: the seed is not decoration.
    const other = await resource({
      capability: 'plugin:lifecycle:read',
      op: 'sample',
      rate_bps: 2_000,
      seed: 'deploy-check-seed-b',
      candidates,
    });
    assert(
      JSON.stringify(other.json.findings) !== JSON.stringify(first.json.findings),
      'two seeds must not draw the same sample',
    );

    // The honest limit, asserted so that a change which DID start generating seeds would fail this
    // check and force someone to update it.
    assert(
      String(first.json.unpredictability).startsWith('NOT provided here'),
      `the body must not claim unpredictability: ${first.json.unpredictability}`,
    );
    assert(
      String(first.json.dispute_not_filed).includes('PUBLIC KEY'),
      `and must say why it cannot file the dispute: ${first.json.dispute_not_filed}`,
    );

    // A fault produces a claim carrying the sample, so a responder can re-derive the draw.
    const delivered = first.json.findings[0].delivery;
    const withFault = await resource({
      capability: 'plugin:lifecycle:read',
      op: 'sample',
      rate_bps: 10_000,
      seed: 'deploy-check-seed-c',
      candidates: [delivered],
      verdicts: { [delivered]: 'sha256:not-what-was-promised' },
    });
    assert(withFault.json.drawn === 1, 'a 100% sample of one');
    const finding = withFault.json.findings[0];
    assert(finding.faulty === true, JSON.stringify(finding));
    assert(finding.claim, 'a fault must produce a claim');
    assert(
      finding.claim.evidence_digest.includes('deploy-check-seed-c'),
      `the claim must carry the seed: ${finding.claim.evidence_digest}`,
    );
    assert(
      finding.claim.reason.includes('did not match'),
      `and say what was wrong: ${finding.claim.reason}`,
    );

    // A zero rate and a blank seed are both refused: a sample that checks nothing looks like
    // oversight while finding nothing, and a seed that cannot be reproduced makes a finding
    // unappealable.
    for (const [body, why] of [
      [{ rate_bps: 0, seed: 'x' }, 'a zero rate'],
      [{ rate_bps: 1_000, seed: '   ' }, 'a blank seed'],
    ]) {
      const refused = await resource({
        capability: 'plugin:lifecycle:read',
        op: 'sample',
        candidates: [],
        ...body,
      });
      assert(refused.status === 400, `${why} must be refused, got HTTP ${refused.status}`);
    }

    return `reproducible from the seed, a different seed differs, and unpredictability NOT claimed`;
  });

  // D-09's first criterion, attacked: a reputation must not be self-reportable.
  //
  // There is no operation that takes a score from the provider. The only one that moves the
  // dimension takes an OBSERVATION, whose fields are what a checker advertised and measured -- so
  // the check asserts both that a claim moves it and that the shape of the call makes a
  // self-reported score impossible.
  await check('a resource reputation moves only through a measurement, never a self-report', async () => {
    const resource = async (body) =>
      api('POST', '/plugins/com.twinsearth.sys.resource/call', body);

    const observe = (advertised, measured) =>
      resource({
        capability: 'plugin:storage:own',
        op: 'observe',
        provider: 'did:nau:0011223344556677',
        checker: 'did:nau:8899aabbccddeeff',
        kind: 'cpu',
        advertised,
        measured,
        at: 1,
      });

    // Exactly what was advertised: the ratio is the whole, and the dimension converges upward.
    const honest = await observe(100, 100);
    assert(
      honest.status >= 200 && honest.status < 300,
      `observe -> HTTP ${honest.status}: ${honest.text.slice(0, 220)}`,
    );
    assert(honest.json.ratio_bps === 10_000, `ratio ${honest.json.ratio_bps}`);
    const before = honest.json.truthfulness_bps;
    for (let i = 0; i < 40; i += 1) await observe(100, 100);
    const after = (await observe(100, 100)).json;
    assert(
      after.truthfulness_bps > before,
      `matching measurements must raise it: ${before} -> ${after.truthfulness_bps}`,
    );
    assert(after.observed === true, 'and the type must say it has been observed');
    assert(after.observations >= 41, `observations counted: ${after.observations}`);

    // A half-truth sits AT NEUTRAL rather than below it, which is the design: `measured/advertised`
    // of 50% is 5,000 bps, and 5,000 is neutral. An agent that delivers half of what it claims is
    // not a known liar -- it is an agent whose claim is half-true.
    const half = await resource({
      capability: 'plugin:storage:own',
      op: 'observe',
      provider: 'did:nau:1111222233334444',
      checker: 'did:nau:8899aabbccddeeff',
      kind: 'cpu',
      advertised: 100,
      measured: 50,
      at: 1,
    });
    assert(half.json.ratio_bps === 5_000, `half-truth ratio ${half.json.ratio_bps}`);
    for (let i = 0; i < 200; i += 1) {
      await resource({
        capability: 'plugin:storage:own',
        op: 'observe',
        provider: 'did:nau:1111222233334444',
        checker: 'did:nau:8899aabbccddeeff',
        kind: 'cpu',
        advertised: 100,
        measured: 50,
        at: 1,
      });
    }
    const settled = await resource({
      capability: 'plugin:storage:own',
      op: 'observe',
      provider: 'did:nau:1111222233334444',
      checker: 'did:nau:8899aabbccddeeff',
      kind: 'cpu',
      advertised: 100,
      measured: 50,
      at: 1,
    });
    assert(
      settled.json.truthfulness_bps === 5_000,
      `a half-truth must sit exactly at neutral, got ${settled.json.truthfulness_bps}`,
    );

    // Over-delivery is not a credit beyond the whole: an agent that delivers more than it advertised
    // has not proved it is honest about anything.
    const surplus = await resource({
      capability: 'plugin:storage:own',
      op: 'observe',
      provider: 'did:nau:5555666677778888',
      checker: 'did:nau:8899aabbccddeeff',
      kind: 'cpu',
      advertised: 100,
      measured: 10_000,
      at: 1,
    });
    assert(
      surplus.json.ratio_bps === 10_000,
      `over-delivery must be capped at the whole, got ${surplus.json.ratio_bps}`,
    );

    // The shape of the call, asserted: it takes an observation and has no parameter for a score.
    const noScoreParameter = await resource({
      capability: 'plugin:storage:own',
      op: 'observe',
      provider: 'did:nau:0011223344556677',
      checker: 'did:nau:8899aabbccddeeff',
      kind: 'cpu',
      advertised: 100,
      measured: 100,
      at: 0, // a zero timestamp, which an observation refuses
    });
    assert(
      noScoreParameter.status === 400,
      `an observation must carry a real timestamp, got HTTP ${noScoreParameter.status}`,
    );
    const answer = await resource({
      capability: 'plugin:storage:own',
      op: 'observe',
      provider: 'did:nau:0011223344556677',
      checker: 'did:nau:8899aabbccddeeff',
      kind: 'cpu',
      advertised: 100,
      measured: 100,
      at: 1,
    });
    assert(
      String(answer.json.cannot_self_report).includes('no call that takes a score'),
      `the answer must state the criterion: ${answer.json.cannot_self_report}`,
    );

    // An unattributed measurement is one nobody can be asked about.
    const unattributed = await resource({
      capability: 'plugin:storage:own',
      op: 'observe',
      provider: 'did:nau:0011223344556677',
      checker: '   ',
      kind: 'cpu',
      advertised: 100,
      measured: 100,
      at: 1,
    });
    assert(
      unattributed.status === 400,
      `an observation must name its checker, got HTTP ${unattributed.status}`,
    );

    return `raised by measurement, a half-truth at neutral, and no call that takes a score`;
  });

  // D-10's three criteria. The first is attacked from the angle that matters: a provider that
  // arrives having declared its own perfection must be admitted on exactly the same terms as one
  // that declared nothing, because the assessment turns on a figure no provider can set.
  await check('cold start: a self-declared perfect provider is admitted on the starter cap only', async () => {
    const resource = async (body) =>
      api('POST', '/plugins/com.twinsearth.sys.resource/call', body);

    const assess = (provider, requested_bps) =>
      resource({
        capability: 'plugin:lifecycle:read',
        op: 'cold-start',
        provider,
        requested_bps,
      });

    // Never seen at all: on probation, capped, and admitted to SOMETHING -- a zero cap would be a
    // market that cannot start.
    const unseen = await assess('did:nau:aaaabbbbccccdddd', 10_000);
    assert(
      unseen.status >= 200 && unseen.status < 300,
      `cold-start -> HTTP ${unseen.status}: ${unseen.text.slice(0, 220)}`,
    );
    assert(unseen.json.full_admission === false, 'an unseen provider is on probation');
    assert(unseen.json.cap_bps > 0, `the starter cap must be positive, got ${unseen.json.cap_bps}`);
    assert(unseen.json.cap_bps < 10_000, `and below the full limit, got ${unseen.json.cap_bps}`);
    assert(unseen.json.past_probation === false);
    assert(
      unseen.json.admits_the_request === false,
      'a full-size task must not be admitted to an unseen provider',
    );
    assert(
      unseen.json.admits_the_request === false && unseen.json.cap_bps > 0,
      'while a small one would be',
    );

    // The starter cap admits a SMALL task, so probation is a limit rather than an exclusion.
    const small = await assess('did:nau:aaaabbbbccccdddd', 100);
    assert(
      small.json.admits_the_request === true,
      `a task inside the cap must be admitted: cap ${small.json.cap_bps}, requested 100`,
    );

    // And the criterion, stated by the answer itself.
    assert(
      String(unseen.json.cannot_be_self_reported).includes('cannot set'),
      `the answer must state the criterion: ${unseen.json.cannot_be_self_reported}`,
    );
    assert(
      String(unseen.json.reproducible).includes('no clock'),
      `and must say why it is reproducible: ${unseen.json.reproducible}`,
    );

    // The cap WIDENS with observations, and the same history gives the same conclusion.
    const observed = async (provider, advertised, measured, times) => {
      for (let i = 0; i < times; i += 1) {
        const r = await resource({
          capability: 'plugin:storage:own',
          op: 'observe',
          provider,
          checker: 'did:nau:8899aabbccddeeff',
          kind: 'cpu',
          advertised,
          measured,
          at: 1,
        });
        assert(r.status < 300, `observe -> HTTP ${r.status}: ${r.text.slice(0, 160)}`);
      }
    };

    // A DID no earlier check has touched, and that matters: the first version of this check reused
    // `did:nau:1111222233334444`, which the D-09 check above had already observed 200 times -- so
    // the provider was past probation before this check began and the cap was 10,000 at "one"
    // observation. The failure read "the cap must widen with observations: 10000 -> 10000".
    //
    // That is the third time in this project a deployment check assumed it ran against fresh state:
    // the C-06 trust checks, the D-04 tolerant-task count, and now this. A check that depends on
    // being first is one whose result depends on the order somebody else chose.
    const rising = 'did:nau:abcdabcdabcdabcd';
    await observed(rising, 100, 100, 1);
    const one = await assess(rising, 10_000);
    await observed(rising, 100, 100, 4);
    const five = await assess(rising, 10_000);
    assert(
      five.json.cap_bps > one.json.cap_bps,
      `the cap must widen with observations: ${one.json.cap_bps} -> ${five.json.cap_bps}`,
    );

    // Called twice, same answer: the property that makes an admission checkable.
    const again = await assess(rising, 10_000);
    assert(
      JSON.stringify(again.json) === JSON.stringify(five.json),
      'the assessment must be pure',
    );

    // A provider measured many times and found to deliver a TENTH of what it claims is past
    // probation by count and must still be held to the starter cap -- otherwise the observation
    // count becomes a way to launder a bad record.
    // Also its own DID, for the same reason.
    const dishonest = 'did:nau:efefefefefefefef';
    await observed(dishonest, 100, 10, 40);
    const held = await assess(dishonest, 10_000);
    assert(
      held.json.past_probation === true,
      `forty observations is past probation, got ${held.json.observations}`,
    );
    assert(
      held.json.full_admission === false,
      `and a found-wanting provider must not graduate by being measured often: ${held.json.because}`,
    );
    assert(
      String(held.json.because).includes('found wanting'),
      `the reason must say so: ${held.json.because}`,
    );

    return `starter cap for the unseen, widening with observations, and no graduation by frequency`;
  });

  // D-11's first criterion: every figure is DERIVED from the state it is about rather than
  // accumulated, so two calls agree and a node re-deriving from the same journals gets the same
  // answer. This check calls it twice and compares.
  await check('the market report is derived from state, and there is no total across kinds', async () => {
    const resource = async (body) =>
      api('POST', '/plugins/com.twinsearth.sys.resource/call', body);

    const first = await resource({ capability: 'plugin:lifecycle:read', op: 'metrics' });
    assert(
      first.status >= 200 && first.status < 300,
      `metrics -> HTTP ${first.status}: ${first.text.slice(0, 220)}`,
    );
    // Called twice on the same state, field for field.
    for (let i = 0; i < 3; i += 1) {
      const again = await resource({ capability: 'plugin:lifecycle:read', op: 'metrics' });
      assert(
        JSON.stringify(again.json) === JSON.stringify(first.json),
        `run ${i}: derived figures must be reproducible`,
      );
    }

    // Per kind, each naming its own unit -- so two rows cannot be added up by accident.
    assert(Array.isArray(first.json.by_kind) && first.json.by_kind.length > 0, 'at least one book');
    for (const row of first.json.by_kind) {
      assert(
        typeof row.unit === 'string' && row.unit.length > 0,
        `a row with no unit: ${JSON.stringify(row)}`,
      );
      assert(
        row.utilisation_bps >= 0 && row.utilisation_bps <= 10_000,
        `a ratio out of range: ${JSON.stringify(row)}`,
      );
      // The conservation identity, re-derived here rather than trusted.
      assert(
        row.held === row.issued - row.consumed,
        `${row.kind}: held ${row.held} must be issued ${row.issued} less consumed ${row.consumed}`,
      );
    }

    // Coverage can never exceed the whole, whatever has been observed.
    assert(
      first.json.observation_coverage_bps >= 0 && first.json.observation_coverage_bps <= 10_000,
      `coverage out of range: ${first.json.observation_coverage_bps}`,
    );
    assert(
      first.json.providers_observed <= first.json.providers,
      `observed ${first.json.providers_observed} cannot exceed registered ${first.json.providers}`,
    );

    // The absence, stated by the report itself.
    assert(
      String(first.json.no_total_across_kinds).includes('do not add up'),
      `the report must say why there is no total: ${first.json.no_total_across_kinds}`,
    );
    assert(
      String(first.json.reproducible).includes('DERIVED'),
      `and that the figures are derived: ${first.json.reproducible}`,
    );
    const lines = first.json.explain;
    assert(
      Array.isArray(lines) && lines.length >= 3,
      `an explanation per kind and then some: ${JSON.stringify(lines)}`,
    );
    assert(
      lines[lines.length - 1].includes('no total across kinds'),
      `the last line must be the absence: ${lines[lines.length - 1]}`,
    );

    // A figure CHANGES when the state does, so it is a measurement and not a constant.
    //
    // The capability is `storage:own`, because `issue` WRITES. This check's first version used the
    // read capability, the plugin refused it, and the failure surfaced three assertions later as
    // "issuing must move the figure: 150 -> 150" -- so the write's success is now asserted HERE,
    // where a capability mistake fails rather than somewhere downstream of it.
    const before = first.json.by_kind.find((r) => r.kind === 'cpu');
    const issued = await resource({
      capability: 'plugin:storage:own',
      op: 'issue',
      holder: 'did:nau:metricscheckcheck',
      amount: { kind: 'cpu', quantity: 7 },
    });
    assert(
      issued.status >= 200 && issued.status < 300,
      `issuing is a write and needs the write capability: HTTP ${issued.status}: ${issued.text.slice(0, 180)}`,
    );
    const after = (await resource({ capability: 'plugin:lifecycle:read', op: 'metrics' })).json;
    const afterCpu = after.by_kind.find((r) => r.kind === 'cpu');
    assert(
      afterCpu.issued === before.issued + 7,
      `issuing must move the figure: ${before.issued} -> ${afterCpu.issued}`,
    );

    return `${first.json.by_kind.length} per-kind books, reproducible, and no total across kinds`;
  });

  // E-01's three criteria, and this is the one release of the v3.9 family that can be verified on
  // every platform: the vocabulary is a value, not an integration.
  await check('every settlement rail answers, and the unavailable ones refuse by name', async () => {
    const settlement = async (body) =>
      api('POST', '/plugins/com.twinsearth.sys.settlement/call', body);

    const rails = await settlement({ capability: 'plugin:lifecycle:read', op: 'rails' });
    assert(
      rails.status >= 200 && rails.status < 300,
      `rails -> HTTP ${rails.status}: ${rails.text.slice(0, 220)}`,
    );
    assert(rails.json.total === 13, `thirteen rails, got ${rails.json.total}`);
    assert(
      rails.json.available === 2,
      `exactly the two this repository has: local-ledger and evm-contracts, got ${rails.json.available}`,
    );
    assert(rails.json.refused === 11, `and eleven refusals, got ${rails.json.refused}`);

    // EVERY rail answers, and the two answers are distinguishable: an available one says HOW, a
    // refused one says WHY. A third answer would be one a caller could not act on.
    for (const rail of rails.json.rails) {
      if (rail.available) {
        assert(
          typeof rail.via === 'string' && rail.via.length > 20,
          `${rail.rail} is available with no how: ${JSON.stringify(rail)}`,
        );
        assert(rail.refused_because === null || rail.refused_because === undefined, rail.rail);
      } else {
        assert(
          typeof rail.refused_because === 'string' && rail.refused_because.length > 30,
          `${rail.rail} refuses with a reason too short to act on: ${JSON.stringify(rail)}`,
        );
        assert(rail.via === null || rail.via === undefined, rail.rail);
      }
    }

    // The available set as a WHOLE, so a rail flipped to available without the work fails here.
    const available = rails.json.rails.filter((r) => r.available).map((r) => r.rail);
    assert(
      available.includes('local-ledger') && available.includes('evm-contracts'),
      `got ${JSON.stringify(available)}`,
    );
    // And the rails that need a network say so, rather than reporting themselves local.
    const local = rails.json.rails.filter((r) => r.local).map((r) => r.rail);
    assert(local.length === 2, `two local rails, got ${JSON.stringify(local)}`);

    // E-01's second criterion: the decision is explainable, and it names every rail it did not pick.
    const routed = await settlement({
      capability: 'plugin:lifecycle:read',
      op: 'route',
      amount_minor: 1000,
      tolerates_network: true,
      payee_accepts_local: true,
    });
    assert(routed.json.chosen === 'local-ledger', `got ${JSON.stringify(routed.json.chosen)}`);
    assert(
      routed.json.considered.length === 12,
      `every other rail must be explained: got ${routed.json.considered.length}`,
    );
    const lines = routed.json.explain;
    assert(
      lines.some((l) => l.startsWith('chosen: local-ledger')),
      JSON.stringify(lines),
    );
    assert(
      lines.some((l) => l.includes('lightning: not chosen because')),
      'and a refused rail must appear with its own reason',
    );
    // The refusal reason is the RAIL's, not a generic one.
    const lightning = routed.json.considered.find((c) => c.rail === 'lightning');
    assert(
      String(lightning.why_not).includes('Lightning node'),
      `the rail's own reason: ${lightning.why_not}`,
    );

    // A payer who will not wait and a payee who will not take the ledger unit: nothing is chosen,
    // rather than a rail they said they would not wait for.
    const stuck = await settlement({
      capability: 'plugin:lifecycle:read',
      op: 'route',
      amount_minor: 10_000,
      tolerates_network: false,
      payee_accepts_local: false,
    });
    assert(stuck.json.chosen === null, `nothing should be chosen: ${JSON.stringify(stuck.json.chosen)}`);
    // The same payee, a patient payer: the contracts are chosen.
    const patient = await settlement({
      capability: 'plugin:lifecycle:read',
      op: 'route',
      amount_minor: 10_000,
      tolerates_network: true,
      payee_accepts_local: false,
    });
    assert(patient.json.chosen === 'evm-contracts', JSON.stringify(patient.json.chosen));

    // E-02's first criterion: the nouns are named, and no count is quoted.
    const nouns = await settlement({ capability: 'plugin:lifecycle:read', op: 'nouns' });
    assert(nouns.json.nouns.length === 10, `ten nouns, got ${nouns.json.nouns.length}`);
    const names = nouns.json.nouns.map((n) => n.noun);
    for (const expected of ['ERC-8004', 'x402', 'L402', 'USDC', 'Paymaster']) {
      assert(names.includes(expected), `${expected} must be named: ${JSON.stringify(names)}`);
    }
    assert(
      String(nouns.json.why_no_count_here).includes('method'),
      `the answer must say why it carries no figure: ${nouns.json.why_no_count_here}`,
    );
    assert(
      String(nouns.json.the_plan_is_no_longer_right).includes('REFUSED'),
      'and must say what changed the number',
    );
    // E-02's second criterion: the four contracts, by path.
    assert(nouns.json.existing_contracts.length === 4, JSON.stringify(nouns.json.existing_contracts));
    assert(
      nouns.json.existing_contracts.every((p) => p.startsWith('contracts/src/')),
      'paths a reader can open, not names',
    );

    return `${rails.json.available} of ${rails.json.total} rails available, 11 refusals by name, and no invented counts`;
  });

  // E-03's three criteria. The third is the platform question, and it is checkable on EVERY platform
  // -- which is the point: a Linux-only mechanism that refuses elsewhere is verified everywhere,
  // while one that degrades silently is verified nowhere.
  await check('no Bitcoin capability is available, and the node answer is the platform\'s', async () => {
    const settlement = async (body) =>
      api('POST', '/plugins/com.twinsearth.sys.settlement/call', body);

    const bitcoin = await settlement({ capability: 'plugin:lifecycle:read', op: 'bitcoin' });
    assert(
      bitcoin.status >= 200 && bitcoin.status < 300,
      `bitcoin -> HTTP ${bitcoin.status}: ${bitcoin.text.slice(0, 220)}`,
    );
    assert(
      bitcoin.json.capabilities.length === 3,
      `three capabilities, got ${bitcoin.json.capabilities.length}`,
    );
    // E-03's second criterion, structurally: none is available, on any platform.
    assert(
      bitcoin.json.any_available === false,
      `no Bitcoin capability may be reported available: ${bitcoin.text.slice(0, 220)}`,
    );
    for (const cap of bitcoin.json.capabilities) {
      assert(cap.available === false, `${cap.capability} must not be available`);
      assert(
        typeof cap.refused_because === 'string' && cap.refused_because.length > 30,
        `${cap.capability} refuses with a reason too short to act on: ${JSON.stringify(cap)}`,
      );
      assert(
        cap.capability.startsWith('bitcoin:'),
        `the same colon shape as chain:evm:read: ${cap.capability}`,
      );
    }

    // E-03's third criterion: exactly one of them is a platform question, and its answer names which
    // question it answered. The runner's own platform decides which wording is correct, so this
    // assertion holds on ubuntu, macOS and Windows alike.
    const platformDependent = bitcoin.json.capabilities.filter((c) => c.platform_dependent);
    assert(
      platformDependent.length === 1 && platformDependent[0].capability === 'bitcoin:node:run',
      `only node running is a platform question: ${JSON.stringify(platformDependent)}`,
    );
    const node = platformDependent[0];
    if (bitcoin.json.target_os === 'linux') {
      assert(
        node.refused_because.includes('no Bitcoin node binary'),
        `on Linux the reason is what the BUILD lacks: ${node.refused_because}`,
      );
    } else {
      assert(
        node.refused_because.includes('not Linux'),
        `elsewhere the reason is the PLATFORM: ${node.refused_because}`,
      );
      assert(
        node.refused_because.includes('refused rather than degraded'),
        `and it must be a refusal rather than a downgrade: ${node.refused_because}`,
      );
    }

    // The names are not `Capability` variants, asserted through the answer: `chain:evm:write` IS one
    // and this plugin does not hold it, while none of these is one at all.
    const caps = await settlement({ capability: 'plugin:lifecycle:read', op: 'capabilities' });
    assert(
      caps.json.holds_no_value_authority === true,
      'the body still holds no authority to move value',
    );
    assert(
      !caps.json.declares.some((c) => c.startsWith('bitcoin:')),
      `a Bitcoin name must not be declared as held: ${JSON.stringify(caps.json.declares)}`,
    );
    assert(
      String(bitcoin.json.not_capability_variants).includes('HOLD'),
      `the answer must say why they are not capability variants: ${bitcoin.json.not_capability_variants}`,
    );

    // E-03's first criterion, with the premise corrected: the conclusion is that none may be claimed
    // supported, and the answer says the plan's zero-hit premise changed.
    assert(
      String(bitcoin.json.the_plan_premise_changed).includes('CONCLUSION survives'),
      `the answer must keep the conclusion and correct the premise: ${bitcoin.json.the_plan_premise_changed}`,
    );
    const rails = await settlement({ capability: 'plugin:lifecycle:read', op: 'rails' });
    for (const label of ['lightning', 'taproot', 'rgb']) {
      const rail = rails.json.rails.find((r) => r.rail === label);
      assert(rail && rail.available === false, `${label} must not be available`);
    }

    return `three capabilities, none available, and the platform question answered where it runs`;
  });

  await check('a plugin is quarantined on the third violation, not before', async () => {
    const victim = 'com.twinsearth.sys.security.tribunal';
    const threshold = 3;
    // Read through the list endpoint: there is no `GET /plugins/<id>` route, and adding one for a
    // check would be a route the node has for no reason but the test. `stateOf` below reads the
    // same list, so the before and after readings cannot disagree about where they looked.
    const stateOf = async (id) => {
      const r = await api('GET', '/plugins');
      assert(r.status === 200, `cannot list plugins: HTTP ${r.status}`);
      const entry = (r.json.plugins || []).find((p) => p.id === id);
      assert(entry, `${id} is not in the node's plugin list`);
      return entry.state;
    };
    const before = await stateOf(victim);
    assert(
      before === 'running',
      `${victim} should start running, it is ${before}`,
    );

    const reported = [];
    for (let n = 1; n < threshold; n++) {
      const r = await api('POST', '/plugins/com.twinsearth.sys.security.police/report', {
        subject: victim,
        what: `deployment check violation ${n}`,
      });
      assert(
        r.status >= 200 && r.status < 300,
        `report ${n} -> HTTP ${r.status}: ${r.text.slice(0, 200)}`,
      );
      assert(
        r.json && r.json.violations === n,
        `report ${n} should record ${n} violation(s), the node says ${r.json && r.json.violations}`,
      );
      assert(
        r.json.state === 'running',
        `violation ${n} of ${threshold} must not quarantine on its own, state is ${r.json.state}`,
      );
      reported.push(n);
    }

    const last = await api('POST', '/plugins/com.twinsearth.sys.security.police/report', {
      subject: victim,
      what: 'the violation that quarantines',
    });
    assert(
      last.status >= 200 && last.status < 300,
      `the third report -> HTTP ${last.status}: ${last.text.slice(0, 200)}`,
    );
    assert(
      last.json && last.json.state === 'quarantined',
      `the ${threshold}rd violation must quarantine ${victim}, state is ${last.json && last.json.state}`,
    );

    // And the node agrees, read back rather than taken from the report's own answer.
    const after = await stateOf(victim);
    assert(
      after === 'quarantined',
      `${victim} reports ${after} after the third violation`,
    );
    return `${threshold} violations -> quarantined, with ${reported.length} tolerated first`;
  });

  await check('the AUSec plugin answers in the running node', async () => {
    const r = await api('POST', '/plugins/com.twinsearth.sys.ausec/call', {
      capability: 'sandbox:create',
      op: 'backends',
    });
    assert(
      r.status >= 200 && r.status < 300,
      `/plugins/com.twinsearth.sys.ausec/call -> HTTP ${r.status}: ${r.text.slice(0, 160)}`,
    );
    const answer = r.json;
    assert(
      answer && typeof answer === 'object',
      `expected an object answer, got ${JSON.stringify(answer).slice(0, 160)}`,
    );
    // The shape the plugin actually answers with, read from its `backends` handler rather than
    // assumed: a **count**, a list of available runtimes, and a list of refusals carrying the
    // reason. The first version of this check treated `backends` as the array and looked for
    // `available`/`unavailability` on each entry, which is not what the plugin returns.
    const total = Number(answer.backends);
    assert(
      Number.isFinite(total) && total > 0,
      `AUSec must report how many runtimes it knows, got ${JSON.stringify(answer.backends)}`,
    );
    assert(Array.isArray(answer.available), `expected an available list, got ${JSON.stringify(answer.available)}`);
    assert(Array.isArray(answer.unavailable), `expected an unavailable list, got ${JSON.stringify(answer.unavailable)}`);
    assert(
      answer.available.length + answer.unavailable.length === total,
      `the two lists must account for all ${total} runtimes: ` +
        `${answer.available.length} available + ${answer.unavailable.length} unavailable`,
    );
    // Every refusal names why. On a non-Linux build the Linux-only runtimes are exactly this
    // case, and the whole AUSec vocabulary exists so that asking succeeds and the answer says
    // what cannot be provided instead of silently offering something weaker.
    for (const entry of answer.unavailable) {
      assert(
        typeof entry.why === 'string' && entry.why.trim().length > 0,
        `runtime ${entry.kind} is unavailable but gives no reason; a refusal without one is not actionable`,
      );
    }
    return (
      `${total} runtime(s): ${answer.available.length} available, ` +
      `${answer.unavailable.length} refused with a reason, in the running daemon`
    );
  });

  await check('the daemon can call a system plugin and read its answer', async () => {
    const r = await api('POST', '/plugins/com.twinsearth.sys.policy/call', {
      capability: 'plugin:message:send',
      op: 'matrix',
    });
    assert(r.status >= 200 && r.status < 300, `/plugins/.../call -> HTTP ${r.status}: ${r.text.slice(0, 160)}`);
    const answer = r.json;
    assert(answer && typeof answer === 'object', `expected an object answer, got ${JSON.stringify(answer).slice(0, 120)}`);
    const rows = Array.isArray(answer) ? answer.length : Object.keys(answer).length;
    assert(rows > 0, 'the policy matrix came back empty');
    // The route drains the plugin's bus outbox after the call and reports what happened.
    //
    // This field is the evidence that the internal messaging protocol has a **runtime**
    // carrier. Before it the daemon held no bus at all: `Bus::new` appeared in production only
    // inside the one-shot load pipelines, and a system plugin that queued a message had nothing
    // carry it. The kernel now asks `BusMembership` ("is this plugin running?"), which the T0
    // host answers for its own plugins, and the node owns the bus.
    assert(
      Array.isArray(answer.bus),
      `a plugin call must report its bus outbox drain, got ${JSON.stringify(answer.bus)}`,
    );
    return `policy.matrix answered (${rows} entr(ies)); bus outbox drained (${answer.bus.length} message(s))`;
  });

  // The plugin whose job is to answer "in what order should plugins start?" answers with
  // **every** plugin, not with an empty list.
  //
  // It answered `[]` for as long as the boot has existed. The boot created the registry it
  // hands to `sys.orchestrator` empty, with a comment saying it would be "filled as plugins
  // register" -- and nothing filled it, and nothing could have: `Arc<Registry>` is shared and
  // immutable while `host.register` writes to the host's own map. So the one plugin that
  // exists to report the start order reported nothing, while `/plugins` showed seventeen
  // plugins running. The boot now verifies every manifest first, fills the registry, and
  // computes the order with `HotPlug::start_order` -- which had no production caller at all.
  await check('the orchestrator reports the start order of every system plugin', async () => {
    // The expectation is read from the host rather than pinned to a literal: a number written
    // down here would have to be edited whenever a plugin is added, and the interesting fact is
    // the **agreement** between what the daemon runs and what its own orchestrator says it runs.
    const listed = Number((await api('GET', '/plugins')).json?.count);
    assert(listed > 0, `the daemon reports ${listed} plugins, so there is nothing to order`);
    const r = await api('POST', '/plugins/com.twinsearth.sys.orchestrator/call', {
      capability: 'kernel:plugin:manage',
      op: 'start_order',
    });
    assert(
      r.status >= 200 && r.status < 300,
      `/plugins/.../orchestrator/call -> HTTP ${r.status}: ${r.text.slice(0, 200)}`,
    );
    const answer = r.json;
    const order = answer?.payload?.order ?? answer?.order;
    const count = answer?.payload?.count ?? answer?.count;
    assert(
      Array.isArray(order),
      `the orchestrator must return an order array: ${r.text.slice(0, 200)}`,
    );
    assert(
      Number(count) === order.length,
      `the orchestrator's own count must match its list: count=${count}, len=${order.length}`,
    );
    assert(
      order.length === listed,
      `the orchestrator must name every plugin the daemon runs (${listed}), got ${order.length}: ${order.join(', ')}`,
    );
    return `start order names ${order.length} plugin(s), first is ${order[0]}`;
  });

  // PMB's **external** interface: what the internal protocol has carried, and what it is
  // allowed to carry.
  //
  // Until this route existed the bus was invisible from outside the kernel -- `Bus::audit()`
  // and `Bus::limits()` had no caller anywhere in `nau-node` -- so an operator could not see
  // what plugins had sent, to whom, or whether it was delivered. The objective names the
  // protocol AND its external interface, and only the first half was there.
  //
  // The absence of a send route is asserted too, because a missing capability and a forgotten
  // one look identical from outside: the payload has to say which it is.
  await check('the bus reports its own limits and audit over HTTP, and says why it cannot send', async () => {
    const r = await api('GET', '/bus');
    assert(r.status === 200, `GET /bus -> HTTP ${r.status}: ${r.text.slice(0, 160)}`);
    const b = r.json;
    assert(b && typeof b === 'object', `expected an object, got ${r.text.slice(0, 120)}`);
    const limits = b.limits || {};
    for (const field of ['max_message_bytes', 'max_messages_per_minute', 'max_audit_records']) {
      assert(
        typeof limits[field] === 'number' && limits[field] > 0,
        `/bus must report \`limits.${field}\`, got ${JSON.stringify(limits[field])}`,
      );
    }
    for (const field of ['records', 'carried', 'refused']) {
      assert(typeof b[field] === 'number', `/bus must report \`${field}\` as a number`);
    }
    assert(Array.isArray(b.audit), `/bus must report its audit as an array`);
    assert(
      b.carried + b.refused === b.records,
      `carried + refused must equal records: ${b.carried} + ${b.refused} != ${b.records}`,
    );
    assert(
      b.send_via_http === false && typeof b.why_not === 'string' && b.why_not.length > 20,
      `/bus must state that sending over HTTP is impossible and why: ${JSON.stringify({
        send_via_http: b.send_via_http,
        why_not: b.why_not,
      })}`,
    );
    return `${b.records} audit record(s), ${b.carried} carried, ${b.refused} refused; max ${limits.max_message_bytes} B`;
  });

  // A capability the plugin does not declare is refused by **the plugin**, not by the route.
  // The route keeps no second list of which capability each plugin takes -- that list would
  // be a second source of truth for the capability model, and the second one is the one that
  // goes stale.
  await check('a plugin call under a capability the plugin does not declare is refused', async () => {
    const r = await api('POST', '/plugins/com.twinsearth.sys.storage/call', {
      capability: 'chain:evm:write',
      op: 'anything',
    });
    assert(r.status >= 400, `expected a refusal, got HTTP ${r.status}: ${r.text.slice(0, 160)}`);
    assert(
      /capability|does not declare|refus/i.test(r.text),
      `the refusal should name the capability: ${r.text.slice(0, 200)}`,
    );
    return r.text.slice(0, 80).replace(/\s+/g, ' ');
  });
  if (health) {
    await check('running daemon agrees with the VERSION file', () => {
      assert(String(health.version) === declaredVersion, `daemon says ${health.version}, VERSION says ${declaredVersion}`);
      return String(health.version);
    });
    await check('daemon reports the upstream provenance it was audited from', () => {
      const up = String(health.upstream ?? '');
      assert(/agent-universe/.test(up), `upstream field missing or unexpected: ${JSON.stringify(health.upstream)}`);
      return up;
    });
  }

  head('3. Real HTTP usage against the running deployment');
  // The routes are `/accounts/:account/{balance,deposit}` -- the account is a
  // PATH segment and only the amount travels in the body. The first run of this
  // script guessed `/deposit` and `/balance/:id` and got four 404s, which is the
  // kind of thing only a real deployment surfaces: the tests exercise the router
  // as a pure function, so nothing tells an operator the actual URL shape.
  // The data directory PERSISTS between runs, so this asserts the DELTA rather
  // than an absolute balance. That keeps the verification re-runnable (the second
  // run of this script failed with 25.6 when it asserted "== 12.8") and is
  // strictly stronger: the delta must be exact, and it must still be there after
  // the restart.
  // --- authentication: proven in BOTH directions ------------------------------
  // The daemon was started with `NAU_API_TOKENS` and without the anonymous escape
  // hatch, so a refusal here is the real gate and not a configuration accident.
  await check('a mutating route refuses a request with no credential', async () => {
    const r = await api('POST', '/accounts/deploy-check/deposit', { amount: '1' }, null);
    assert(
      r.status === 401 || r.status === 403,
      `expected a refusal without a credential, got HTTP ${r.status}: ${r.text.slice(0, 120)}`,
    );
    return `HTTP ${r.status}`;
  });

  await check('a credential that authenticates nobody is refused, not downgraded', async () => {
    const r = await api('POST', '/accounts/deploy-check/deposit', { amount: '1' }, 'not-a-configured-token');
    assert(
      r.status === 401 || r.status === 403,
      `expected a refusal for an unknown credential, got HTTP ${r.status}`,
    );
    return `HTTP ${r.status} (never treated as anonymous)`;
  });

  await check('the same mutation succeeds with the deployment credential', async () => {
    const r = await api('POST', '/accounts/deploy-check/deposit', { amount: '1' });
    assert(
      r.status === 200 || r.status === 201,
      `expected 2xx with the credential, got HTTP ${r.status}: ${r.text.slice(0, 120)}`,
    );
    return `HTTP ${r.status}`;
  });

  let balanceBefore = null;
  await check('read the starting balance', async () => {
    const b = await api('GET', '/accounts/deploy-check/balance');
    assert(b.status === 200, `balance -> HTTP ${b.status}`);
    balanceBefore = Number(b.json && b.json.balance_minor);
    assert(Number.isFinite(balanceBefore), `no balance_minor in ${b.text.slice(0, 120)}`);
    return `minor=${balanceBefore}`;
  });

  // **The ledger plugin reports the node's own money.**
  //
  // This is the check that would have caught the defect it now guards: `standard_plugins` built
  // `sys.ledger` with `LedgerPlugin::new()` -- an **empty** ledger -- so the daemon hosted a
  // ledger plugin that had never seen a penny, answering `0 / known:false` to every balance
  // while `/accounts/.../balance` answered the real number. The two agreed only by accident, and
  // never once the node had money. The plugin's own module documentation predicted it
  // ("a host with real books must use `LedgerPlugin::sharing` at the wiring site") and nothing
  // compared the two answers until this check.
  await check('the ledger plugin reports the same balance the market does', async () => {
    const market = await api('GET', '/accounts/deploy-check/balance');
    assert(market.status === 200, `market balance -> HTTP ${market.status}`);
    const marketMinor = Number(market.json && market.json.balance_minor);

    const plugin = await api('POST', '/plugins/com.twinsearth.sys.ledger/call', {
      capability: 'plugin:message:send',
      op: 'balance',
      account: 'deploy-check',
    });
    assert(
      plugin.status >= 200 && plugin.status < 300,
      `ledger plugin call -> HTTP ${plugin.status}: ${plugin.text.slice(0, 160)}`,
    );
    const answer = plugin.json;
    const pluginMinor = Number(answer && answer.minor);
    assert(
      Number.isFinite(pluginMinor),
      `the ledger plugin must report \`minor\`, got ${plugin.text.slice(0, 160)}`,
    );
    assert(
      pluginMinor === marketMinor,
      `the ledger plugin and the market disagree about the same account: plugin=${pluginMinor}, ` +
        `market=${marketMinor}. Two records of one balance is the defect this asserts against.`,
    );
    assert(
      answer.known !== false,
      `the ledger plugin must know an account the market has been crediting: ${plugin.text.slice(0, 160)}`,
    );
    return `plugin=${pluginMinor} = market=${marketMinor}, known=${answer.known}`;
  });

  // **B1: the plugin's answer decides whether the market may move money.**
  //
  // Upstream calls this "the orchestrator takes over the data plane". Ours asks `sys.ledger`
  // whether it holds an escrow for the task before `settle` releases anything, and this check
  // proves the gate is **live in the daemon** rather than merely written: a task id nothing ever
  // published cannot settle, and the refusal has to name the plugin that answered.
  //
  // The **happy path** is covered a few gates away, by `client/test/e2e.mjs`, which drives
  // publish/bid/match/start/submit/verify/settle through this same route. That gate is what
  // caught the half-wiring when this was built: `Node::open` shared its ledger with the plugin
  // and `Node::ephemeral` did not, and the browser end-to-end runs `--ephemeral`. I had written
  // here that the happy path was argued "by construction" and not tested -- that was wrong, and
  // the gate said so before I could publish it.
  await check('a settlement the ledger never escrowed is refused, and the refusal names it', async () => {
    const r = await api('POST', '/tasks/deploy-check-never-published/settle', {});
    assert(
      r.status === 409,
      `expected the gate to refuse with 409, got HTTP ${r.status}: ${r.text.slice(0, 200)}`,
    );
    assert(
      /com\.twinsearth\.sys\.ledger/.test(r.text),
      `the refusal must name the plugin that answered: ${r.text.slice(0, 240)}`,
    );
    assert(
      /no escrow/.test(r.text),
      `the refusal must say what the ledger reported: ${r.text.slice(0, 240)}`,
    );
    return `HTTP ${r.status}, refusal names the ledger`;
  });

  await check('deposit exact decimal amounts and read them back', async () => {
    for (const amt of ['12.5', '0.2', '0.1']) {
      const r = await api('POST', '/accounts/deploy-check/deposit', { amount: amt });
      assert(r.status === 200 || r.status === 201, `deposit ${amt} -> HTTP ${r.status} ${r.text.slice(0, 120)}`);
    }
    const b = await api('GET', '/accounts/deploy-check/balance');
    assert(b.status === 200, `balance -> HTTP ${b.status}`);
    const after = Number(b.json && b.json.balance_minor);
    // 12.5 + 0.2 + 0.1 must be exactly 12.8 = 12_800_000 minor units. In f64 the
    // sum is 12.799999999999999, which is precisely why the ledger is integral.
    assert(
      after - balanceBefore === 12_800_000,
      `expected exactly +12800000 minor, got +${after - balanceBefore} (${b.text.slice(0, 120)})`,
    );
    return `+12.8 exactly (${balanceBefore} -> ${after} minor)`;
  });

  await check('a float amount is refused with 422, not coerced', async () => {
    const r = await api('POST', '/accounts/deploy-check/deposit', { amount: 12.5 });
    assert(r.status === 422, `expected 422 for a JSON float, got ${r.status}`);
    return 'HTTP 422';
  });

  await check('a malformed amount is refused with 422', async () => {
    const r = await api('POST', '/accounts/deploy-check/deposit', { amount: 'not-a-number' });
    assert(r.status === 422, `expected 422, got ${r.status}`);
    const r2 = await api('POST', '/accounts/deploy-check/deposit', { amount: '1.0000001' });
    assert(r2.status === 422, `expected 422 for sub-minor-unit precision, got ${r2.status}`);
    return 'HTTP 422 for both';
  });

  await check('read methods on a mutating route are refused (405)', async () => {
    const r = await api('GET', '/accounts/deploy-check/deposit');
    assert(r.status === 405, `expected 405, got ${r.status}`);
    return 'HTTP 405';
  });

  await check('unknown route is 404', async () => {
    const r = await api('GET', '/definitely-not-a-route');
    assert(r.status === 404, `expected 404, got ${r.status}`);
    return 'HTTP 404';
  });

  await check('conservation and audit agree with discrepancy 0', async () => {
    const c = await api('GET', '/conservation');
    const a = await api('GET', '/audit');
    assert(c.status === 200 && a.status === 200, `conservation ${c.status} / audit ${a.status}`);
    const blob = `${JSON.stringify(c.json)} ${JSON.stringify(a.json)}`;
    assert(/"discrepancy"\s*:\s*"?0"?/.test(blob), `no zero discrepancy in: ${blob.slice(0, 200)}`);
    return 'discrepancy 0 in both responses';
  });

  head('4. CLI and daemon agree about the on-disk format');
  // The CLI reads its subcommand from argv[1] and its options from anywhere
  // after that, so `nau inspect --data-dir X` is the accepted order. Passing the
  // option first makes argv[1] the option, which the CLI correctly reports as an
  // unknown command -- but nothing documents the order, which is why this is
  // asserted here rather than assumed.
  await check('nau inspect reads the store the daemon wrote', () => {
    const { out } = cli(['inspect', '--data-dir', DATA]);
    assert(/agents\s+\d+/.test(out), `unexpected inspect output: ${out.slice(0, 160)}`);
    const line = out.split('\n').find((l) => l.startsWith('agents')) || out.split('\n')[0];
    return line.trim().slice(0, 80);
  });

  await check('the CLI reports an option given before the subcommand', () => {
    const { code, out } = cli(['--data-dir', DATA, 'inspect'], { allowFail: true });
    assert(code !== 0, 'expected a non-zero exit when the subcommand is missing');
    assert(/unknown command/.test(out), `expected an 'unknown command' message, got: ${out.slice(0, 120)}`);
    return 'unknown command reported, exit ' + code;
  });

  // C-06's second criterion, first half: trust a key, so there is something a restart could lose.
  //
  // Placed BEFORE section 5 stops the daemon, and the first version of it was not. An earlier
  // attempt sat after `stopDaemon` and before the restart, so every request in it failed with
  // "fetch failed" and the check looked like a trust-store defect rather than a check running in a
  // window where no daemon existed. A test that runs while the thing under test is stopped is not
  // measuring the thing under test.
  //
  // A trust store in memory would re-verify every plugin at every boot, which is not forgetting a
  // decision so much as never recording one. The restart below is the one section 5 already
  // performs, which is why this is here: the event that proves the criterion is one the deployment
  // already does.
  const TRUSTED_KEY = 'aa'.repeat(32);
  await check('a key can be trusted and the store moves from nobody to somebody', async () => {
    const before = await api('POST', '/plugins/com.twinsearth.sys.security.registry/call', {
      capability: 'plugin:lifecycle:read',
      op: 'trust',
    });
    assert(before.status === 200, `trust -> HTTP ${before.status}: ${before.text.slice(0, 160)}`);
    assert(
      before.json && typeof before.json.trusted === 'number',
      `the store must report how many keys it holds: ${before.text.slice(0, 160)}`,
    );
    // The STARTING COUNT is read rather than assumed to be zero.
    //
    // The first version asserted `trusted === 0`, which is true of a fresh data directory and false
    // of one a previous run left behind -- so the check passed when run alone and failed inside
    // verify-all, where the prefix is reused. That is the deployment-check equivalent of a test
    // that depends on the order it runs in.
    //
    // What matters is the TRANSITION: trust a key and the count goes up by one, whatever it was.
    // That is the property C-06 needs, and it is independent of what the directory already held.
    const startedAt = before.json.trusted;

    // Self-healing rather than precondition-checking, and this is the third shape this check has
    // had. It started by asserting the store was empty, which is true of a fresh directory and
    // false of a reused one. It then refused to run if the key was already trusted, which is
    // correct and still leaves the suite failing on a directory an EARLIER FAILED RUN left behind
    // -- including the run that failed before reaching its own cleanup.
    //
    // So the key is revoked first if it is there. A check that can only run on a pristine directory
    // is a check that fails for reasons that have nothing to do with what it tests, and
    // verify-all's prefix is deliberately long-lived.
    if ((before.json.vendor || []).includes(TRUSTED_KEY)) {
      const cleared = await api('POST', '/plugins/com.twinsearth.sys.security.registry/call', {
        capability: 'kernel:plugin:manage',
        op: 'revoke',
        key: TRUSTED_KEY,
      });
      assert(
        cleared.status >= 200 && cleared.status < 300,
        `could not clear a leftover key: HTTP ${cleared.status}: ${cleared.text.slice(0, 160)}`,
      );
    }
    const from = await api('POST', '/plugins/com.twinsearth.sys.security.registry/call', {
      capability: 'plugin:lifecycle:read',
      op: 'trust',
    });
    const startedFrom = from.json.trusted;

    const added = await api('POST', '/plugins/com.twinsearth.sys.security.registry/call', {
      capability: 'kernel:plugin:manage',
      op: 'trust-add',
      key: TRUSTED_KEY,
      kind: 'vendor',
    });
    assert(
      added.status >= 200 && added.status < 300,
      `trust-add -> HTTP ${added.status}: ${added.text.slice(0, 200)}`,
    );
    assert(
      added.json && added.json.trusted === startedFrom + 1,
      `trusting one key must add exactly one, from ${startedFrom}: ${JSON.stringify(added.json).slice(0, 160)}`,
    );

    // The store now answers for that key, and still refuses a stranger -- the fail-closed direction
    // observed rather than merely described.
    const verified = await api('POST', '/plugins/com.twinsearth.sys.security.registry/call', {
      capability: 'plugin:lifecycle:read',
      op: 'verify',
      key: TRUSTED_KEY,
      kind: 'vendor',
    });
    assert(
      verified.json && verified.json.trusted === true,
      `the key just trusted must verify, got ${JSON.stringify(verified.json).slice(0, 160)}`,
    );
    const stranger = await api('POST', '/plugins/com.twinsearth.sys.security.registry/call', {
      capability: 'plugin:lifecycle:read',
      op: 'verify',
      key: 'bb'.repeat(32),
      kind: 'vendor',
    });
    assert(
      stranger.json && stranger.json.trusted === false,
      `a key nobody trusted must not verify, got ${JSON.stringify(stranger.json).slice(0, 160)}`,
    );
    return '0 -> 1 trusted key, and a stranger is still refused';
  });

  head('5. THE DEPLOYMENT PROPERTY: state survives a restart');
  await stopDaemon(daemon);
  say('  [deploy] daemon stopped; restarting against the same data directory');

  // The daemon stops its plugins when it is asked to stop.
  //
  // Until this round it did nothing of the kind: it had a signal handler, seventeen plugins ran
  // under it, and the process exited without stopping one of them.
  // `SystemPluginHost::shutdown` was called only from tests and `HotPlug::stop_plan` had no
  // caller anywhere in the repository.
  //
  // Platform-aware for a real reason rather than for convenience: Node's `child.kill()` on
  // Windows calls `TerminateProcess`, so **no handler runs** and the daemon never reaches its
  // shutdown path there. Asserting that on Windows -- rather than skipping the check -- is the
  // same choice `nau plugin run` makes on macOS: a skip would make the platform look like one
  // where the code was never tried.
  await check('the daemon stops its plugins when it is asked to stop', async () => {
    // The first daemon's log. Named here rather than derived, because the tag is the thing that
    // pairs a log with a run and getting it wrong would silently assert against an empty file.
    //
    // Polled rather than read once, and that is a fix rather than a precaution. The line is
    // written as part of the daemon's **graceful shutdown**, which begins after the signal is
    // delivered -- so a single read immediately after `stopDaemon` races the write, and on a
    // loaded CI runner it loses. It lost on the ubuntu job of v3.6.3's Client workflow while the
    // same check passed on that release's own ubuntu job, which is what a race looks like from
    // the outside: green, green, red, green.
    //
    // The bound is ten seconds and the failure message says the wait expired, so a genuine
    // regression (the daemon never stopping its plugins) still fails and fails distinguishably
    // from a slow write.
    const logPath = path.join(LOGS, 'daemon-boot1.log');
    const STOPPED = /stopped (\d+) plugin\(s\); (\d+) could not be stopped/;
    const deadline = Date.now() + 10_000;
    let log = '';
    for (;;) {
      log = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8') : '';
      if (STOPPED.test(log) || Date.now() >= deadline) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    const m = STOPPED.exec(log);
    if (process.platform === 'win32') {
      assert(
        m === null,
        `Windows cannot deliver a graceful stop through child.kill(), so this line should not ` +
          `appear here: ${m && m[0]}`,
      );
      return 'not exercised on Windows (child.kill() is TerminateProcess); the Linux and macOS jobs run it natively';
    }
    assert(
      m,
      `the daemon must report stopping its plugins within 10s of being signalled; the tail of ` +
        `its log is: ${JSON.stringify(log.slice(-400))}`,
    );
    // Compared against what this daemon booted, not a number in this file. The literal was 17 and
    // A-03 made it 18; because this branch never runs on Windows, the mismatch reached CI with a
    // green local run behind it.
    assert(
      bootedPluginCount !== null,
      'the boot check must have run first, or there is nothing to compare the shutdown against',
    );
    assert(
      Number(m[1]) === bootedPluginCount,
      `the daemon booted ${bootedPluginCount} plugin(s) and stopped ${m[1]}; every plugin it ` +
        `started must be stopped`,
    );
    // The count alone was not enough to diagnose this, and the failure that proved it is worth
    // recording: at v3.7.1 this line failed with "1 plugin(s) could not be stopped" on macOS and
    // ubuntu, and finding out WHICH plugin took reading the runner's log by hand. The daemon
    // already prints the name and the reason on the lines after the summary; the assertion was
    // throwing them away.
    if (Number(m[2]) !== 0) {
      const after = log
        .slice(log.indexOf(m[0]) + m[0].length)
        .split('\n')
        .slice(0, 4)
        .map((l) => l.trim())
        .filter(Boolean);
      assert(
        false,
        `${m[2]} plugin(s) could not be stopped: ${after.length ? after.join(' | ') : 'the daemon named none'}`,
      );
    }
    return `daemon stopped ${m[1]} of ${bootedPluginCount} plugin(s), none failed`;
  });

  await check('store files were actually written to disk', () => {
    const files = fs.existsSync(DATA) ? fs.readdirSync(DATA, { recursive: true }).map(String) : [];
    assert(files.length > 0, `no files under ${DATA} — the daemon persisted nothing`);
    return `${files.length} file(s): ${files.slice(0, 4).join(', ')}`;
  });

  daemon = startDaemon('boot2');
  await check('restarted daemon becomes healthy', async () => {
    await waitHealthy();
    return 'healthy';
  });

  // C-06's second criterion, second half: the trusted key is still trusted after the restart.
  //
  // The count alone would not be enough -- a store that came back holding some other key would pass
  // it -- so the key itself is asserted to be in the list. The count is compared with what the first
  // half ended at rather than with a literal, for the same reason that half reads its starting
  // value: a reused data directory is normal and the check must not depend on being first.
  await check('the trusted key survived the restart', async () => {
    const r = await api('POST', '/plugins/com.twinsearth.sys.security.registry/call', {
      capability: 'plugin:lifecycle:read',
      op: 'trust',
    });
    assert(r.status === 200, `trust -> HTTP ${r.status}: ${r.text.slice(0, 160)}`);
    assert(
      Array.isArray(r.json.vendor) && r.json.vendor.includes(TRUSTED_KEY),
      `the key itself must come back after the restart, not only a count: ${JSON.stringify(r.json.vendor)}`,
    );
    return `${r.json.trusted} key(s) trusted after the restart, including the one added before it, read from ${r.json.store}`;
  });

  // Put the store back the way it was found.
  //
  // Without this the suite is not idempotent: the first check needs a key that is NOT already
  // trusted, so a second run against the same data directory fails its own precondition and looks
  // like a trust-store defect. That is what happened -- the suite passed alone and failed inside
  // verify-all, which reuses the prefix.
  //
  // Revoking rather than trusting a different key each run, because a store that grows a key per
  // run is one whose size stops meaning anything, and the point of this pair of checks is the
  // transition, not the residue.
  await check('the key the checks added is revoked, so a second run starts where this one did', async () => {
    const r = await api('POST', '/plugins/com.twinsearth.sys.security.registry/call', {
      capability: 'kernel:plugin:manage',
      op: 'revoke',
      key: TRUSTED_KEY,
    });
    assert(r.status >= 200 && r.status < 300, `revoke -> HTTP ${r.status}: ${r.text.slice(0, 160)}`);
    assert(r.json && r.json.was_trusted === true, `it was trusted and must be revoked: ${JSON.stringify(r.json).slice(0, 160)}`);

    const after = await api('POST', '/plugins/com.twinsearth.sys.security.registry/call', {
      capability: 'plugin:lifecycle:read',
      op: 'trust',
    });
    assert(
      !(after.json.vendor || []).includes(TRUSTED_KEY),
      `the revoked key must be gone from the store: ${JSON.stringify(after.json.vendor)}`,
    );
    return `revoked; the store is back to what it held before these checks ran`;
  });

  await check('the deposited balance survived the restart', async () => {
    const b = await api('GET', '/accounts/deploy-check/balance');
    assert(b.status === 200, `balance -> HTTP ${b.status}`);
    const after = Number(b.json && b.json.balance_minor);
    const expected = balanceBefore + 12_800_000;
    // Equality, not "contains 12.8": the bug this catches added 25.2 on every
    // restart, and a substring check would have passed on a corrupt total that
    // merely happened to contain the digits.
    assert(
      after === expected,
      `balance did NOT survive the restart: ${b.text.slice(0, 160)} (expected ${expected} minor)`,
    );
    return `${after} minor still present`;
  });

  await check('conservation still holds after the restart', async () => {
    const c = await api('GET', '/conservation');
    assert(c.status === 200, `conservation -> HTTP ${c.status}`);
    const blob = JSON.stringify(c.json);
    assert(/"discrepancy"\s*:\s*"?0"?/.test(blob), `discrepancy non-zero after restart: ${blob.slice(0, 200)}`);
    return 'discrepancy 0';
  });

  if (!KEEP) {
    await stopDaemon(daemon);
    daemon = null;
    say('\n  [deploy] daemon stopped.');
  } else {
    say(`\n  [deploy] --keep-running: daemon left running on ${BASE} (pid ${daemon.pid})`);
  }

  head('Summary');
  const failed = results.filter((r) => r.state === 'FAIL');
  for (const r of results) console.log(`  ${r.state.padEnd(5)} ${r.title}${r.detail ? '  — ' + r.detail : ''}`);
  console.log(`\n  ${results.length - failed.length} passed, ${failed.length} failed, ${findings.length} finding(s)`);

  fs.writeFileSync(path.join(LOGS, 'deploy-local.log'), LOG.join('\n') + '\n', 'utf8');
  console.log(`  log: ${path.join(LOGS, 'deploy-local.log')}`);
  process.exit(failed.length ? 1 : 0);
}

process.on('SIGINT', async () => {
  await stopDaemon(daemon);
  process.exit(130);
});

main().catch(async (e) => {
  console.error(`\ndeploy-local aborted: ${e && e.stack ? e.stack : e}`);
  await stopDaemon(daemon);
  process.exit(1);
});
