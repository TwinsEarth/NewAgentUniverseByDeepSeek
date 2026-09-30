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
function startDaemon(tag) {
  const logStream = fs.createWriteStream(path.join(LOGS, `daemon-${tag}.log`), { flags: 'a' });
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
  p.stdout.pipe(logStream);
  p.stderr.pipe(logStream);
  p.on('exit', (code, sig) => say(`  [daemon/${tag}] exited code=${code} signal=${sig}`));
  return p;
}
async function stopDaemon(p) {
  if (!p || p.exitCode !== null) return;
  p.kill();
  for (let i = 0; i < 60 && p.exitCode === null; i++) await sleep(100);
  if (p.exitCode === null) p.kill('SIGKILL');
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

  head('5. THE DEPLOYMENT PROPERTY: state survives a restart');
  await stopDaemon(daemon);
  say('  [deploy] daemon stopped; restarting against the same data directory');
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
