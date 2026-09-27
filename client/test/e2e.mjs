#!/usr/bin/env node
/**
 * End-to-end test for the NewAgentUniverse browser client.
 *
 *     node client/test/e2e.mjs
 *
 * # What this proves, and what it does not
 *
 * This test drives **the real daemon HTTP API through the real proxy** used by
 * the UI, using the same imported modules (`client/lib/*.mjs`) that the browser
 * loads — the same Ed25519 key derivation, the same canonical serializer, the
 * same HTTP client, the same domain payload builders. It does not launch a
 * browser: it cannot, and this test does not claim to have done so. What it
 * shows is that every call the UI makes is accepted by a running daemon and that
 * the page's own signing and serialization code is byte-exact.
 *
 * Concretely it performs:
 *
 *   1. `cargo build -p nau-node --bin nau-daemon` (with `CARGO_BUILD_JOBS=2`)
 *      when the binary is missing, or reuses `target/debug/nau-daemon[.exe]`.
 *   2. starts the daemon on a random free port with `--ephemeral`;
 *   3. starts `client/serve.mjs` pointed at that daemon;
 *   4. drives the full market lifecycle over HTTP through the proxy:
 *      deposit → register (real signature) → discover → publish task → bid →
 *      match → start → submit result → verify (signed votes) → settle →
 *      conservation + audit with `discrepancy 0`;
 *   5. asserts a JSON-float deposit is refused with `422` and a mutating route
 *      rejects `GET` with `405`;
 *   6. asserts the browser-side canonical serializer reproduces the `canonical`
 *      bytes in `conformance/vectors.json`, and that a signature produced by the
 *      **Node SDK** verifies under the browser `crypto.subtle` code path (and that
 *      tampering with the payload makes it fail);
 *   7. shuts both servers down and exits non-zero on any failure.
 *
 * Node 20+ is required: `globalThis.crypto.subtle` gained Ed25519 in Node 18.4
 * and became available as a global in Node 19/20.
 */

import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';

import { startServer, API_PREFIX } from '../serve.mjs';
import {
  fakeDocumentFromHtml,
  fetchAgainst,
  registeredListeners,
  resetRegisteredListeners,
} from './dom-stub.mjs';
import {
  CanonicalError,
  Identity,
  NauApiError,
  NauClient,
  agentCardDraft,
  bidDraft,
  canonicalJson,
  describeError,
  nextNonce,
  nowSeconds,
  parseDecimalAmount,
  pathSegment,
  resultDraft,
  sha256,
  taskDraft,
  voteDraft,
} from '../lib/nau.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLIENT_DIR = resolve(HERE, '..');
const REPO_ROOT = resolve(CLIENT_DIR, '..');

// ------------------------------------------------------------------ reporting

let passed = 0;
let failed = 0;
const failures = [];

/**
 * Record one assertion.
 * @param {string} name
 * @param {boolean} condition
 * @param {string} [detail]
 */
function check(name, condition, detail = '') {
  if (condition) {
    passed += 1;
    console.log(`  ok   ${name}`);
  } else {
    failed += 1;
    failures.push(`${name}${detail ? ` — ${detail}` : ''}`);
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

/** @param {string} title */
function section(title) {
  console.log(`\n== ${title}`);
}

/**
 * Assert that an async call rejects, and hand the error to `inspect`.
 * @param {string} name
 * @param {() => Promise<unknown>} action
 * @param {(error: unknown) => boolean} [inspect]
 */
async function checkRejects(name, action, inspect) {
  try {
    const value = await action();
    check(name, false, `expected a rejection but resolved with ${JSON.stringify(value)}`);
  } catch (error) {
    if (inspect) {
      const ok = inspect(error);
      check(name, ok, ok ? '' : `unexpected error: ${describeError(error)}`);
    } else {
      check(name, true);
    }
  }
}

// -------------------------------------------------------------------- helpers

/**
 * @param {string} message
 * @returns {Promise<never>}
 */
function fatal(message) {
  throw new Error(message);
}

/** Ask the OS for a free TCP port, then release it. */
async function freePort() {
  return new Promise((resolvePort, rejectPort) => {
    const probe = createServer();
    probe.once('error', rejectPort);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      const port = typeof address === 'object' && address !== null ? address.port : 0;
      probe.close(() => resolvePort(port));
    });
  });
}

/** @param {number} ms */
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

/**
 * Resolve the daemon binary path and build it when it is missing.
 *
 * `CARGO_BUILD_JOBS=2` is set because a parallel `rustc` burst exhausts memory on
 * a 16 GB machine (`rustc-LLVM ERROR: out of memory`), which is the same bound
 * `.cargo/config.toml` and CI use.
 *
 * @returns {Promise<{binary: string, built: boolean}>}
 */
async function ensureDaemonBinary() {
  const exe = process.platform === 'win32' ? 'nau-daemon.exe' : 'nau-daemon';
  const binary = join(REPO_ROOT, 'target', 'debug', exe);
  if (existsSync(binary)) {
    console.log(`[e2e] reusing the existing daemon binary at ${binary}`);
    return { binary, built: false };
  }
  console.log('[e2e] target/debug daemon missing; running cargo build -p nau-node --bin nau-daemon');
  const started = Date.now();
  const child = spawn('cargo', ['build', '-p', 'nau-node', '--bin', 'nau-daemon'], {
    cwd: REPO_ROOT,
    env: { ...process.env, CARGO_BUILD_JOBS: '2' },
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
  const code = await new Promise((resolveCode, rejectCode) => {
    child.once('error', rejectCode);
    child.once('exit', (exitCode) => resolveCode(exitCode ?? 1));
  });
  if (code !== 0) fatal(`cargo build exited with ${code}`);
  if (!existsSync(binary)) fatal(`cargo build succeeded but ${binary} does not exist`);
  console.log(`[e2e] built the daemon in ${Math.round((Date.now() - started) / 1000)}s`);
  return { binary, built: true };
}

/**
 * Wait until `GET /health` answers, or fail after `timeoutMs`.
 * @param {string} baseUrl
 * @param {number} [timeoutMs]
 * @param {() => boolean} [stillAlive]
 */
async function waitForHealth(baseUrl, timeoutMs = 60_000, stillAlive) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    if (stillAlive && !stillAlive()) {
      fatal(`the process died before ${baseUrl}/health answered (last error: ${lastError})`);
    }
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) return await response.json();
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = describeError(error);
    }
    await sleep(200);
  }
  fatal(`${baseUrl}/health never became ready (last error: ${lastError})`);
}

/**
 * Start one ephemeral daemon on a free port and collect its log.
 *
 * `detached: true` puts the child in its own process group so a stray Ctrl-C
 * cannot take the test down before its `finally` block has shut the daemon down.
 *
 * @param {string} binary
 * @returns {Promise<{child: import('node:child_process').ChildProcess, port: number, base: string, log: () => string}>}
 */
async function startDaemonProcess(binary) {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  console.log(`[e2e] starting ${binary} --api-port ${port} --ephemeral`);
  const child = spawn(binary, ['--api-port', String(port), '--ephemeral'], {
    cwd: REPO_ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let buffer = '';
  child.stdout.on('data', (chunk) => {
    buffer += chunk.toString();
  });
  child.stderr.on('data', (chunk) => {
    buffer += chunk.toString();
  });
  const health = await waitForHealth(base, 30_000, () => child.exitCode === null);
  console.log(
    `[e2e] daemon ready on ${base}: v${health.version} protocol ${health.protocol} upstream ${health.upstream}`,
  );
  return { child, port, base, log: () => buffer };
}

/**
 * Stop a daemon started by {@link startDaemonProcess}.
 * @param {{child: import('node:child_process').ChildProcess}|null} daemon
 */
async function stopDaemonProcess(daemon) {
  if (!daemon || !daemon.child || daemon.child.exitCode !== null || daemon.child.killed) return;
  daemon.child.kill();
  await sleep(300);
}

/**
 * Start the client's static server on a free port, pointed at `daemonBase`.
 * @param {string} daemonBase
 * @returns {Promise<{url: string, close: () => Promise<void>}>}
 */
async function startClientServer(daemonBase) {
  const port = await freePort();
  const server = await startServer({
    port,
    host: '127.0.0.1',
    daemon: daemonBase,
    root: CLIENT_DIR,
    quiet: true,
  });
  console.log(`[e2e] client served at ${server.url} (proxying ${API_PREFIX}/* to ${daemonBase})`);
  return server;
}

// ------------------------------------------------------- canonical + signing

/**
 * Prove the browser canonicalizer against `conformance/vectors.json`.
 *
 * @returns {{checked: number, skipped: string[]}}
 */
function checkCanonicalVectors() {
  const vectorsPath = join(REPO_ROOT, 'conformance', 'vectors.json');
  if (!existsSync(vectorsPath)) fatal(`${vectorsPath} does not exist`);
  const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));
  const skipped = [];
  let checked = 0;

  for (const vector of vectors.payloads) {
    const input = JSON.parse(vector.input_json);
    if (vector.languages && vector.languages.javascript === 'unsupported-by-json-parse') {
      // 2^63-1 and 2^64-1 do not survive `JSON.parse`, which the vector itself
      // records. The JS side cannot reproduce them by construction, so they are
      // reported as skipped rather than silently treated as passing.
      skipped.push(vector.id);
      console.log(`  skip ${vector.id} (${vector.languages.javascript})`);
      continue;
    }
    const actual = canonicalJson(input);
    check(
      `canonical bytes: ${vector.id}`,
      actual === vector.canonical,
      actual === vector.canonical
        ? ''
        : `\n       expected ${JSON.stringify(vector.canonical)}\n       actual   ${JSON.stringify(actual)}`,
    );
    checked += 1;
  }

  for (const rejection of vectors.rejections) {
    const input = JSON.parse(rejection.input_json);
    // Two vectors cannot be refusals in JavaScript, and pinning that is better
    // than pretending otherwise. `{"amount":100.0}` and `{"amount":1e2}` are
    // refused by Rust and Python because `100`, `100.0` and `1e2` format
    // differently there. JavaScript has exactly one number type:
    // `JSON.parse('100.0')` is the integer 100 and `Number.isInteger` is true, so
    // there is nothing to distinguish. `sdks/js/test/conformance.test.js:187`
    // records the same deviation; this mirrors it.
    if (rejection.id === 'float-value' || rejection.id === 'exponent-notation') {
      const amount = input.amount;
      check(
        `canonical acceptance: ${rejection.id} — JavaScript parses this to the integer ${amount}`,
        Number.isInteger(amount) && canonicalJson(input) === `{"amount":${amount}}`,
        `canonicalJson produced ${canonicalJson(input)}`,
      );
      continue;
    }
    let threw = null;
    try {
      canonicalJson(input);
    } catch (error) {
      threw = error;
    }
    check(
      `canonical rejection: ${rejection.id}`,
      threw instanceof CanonicalError,
      threw === null ? 'it produced output instead of refusing' : `got ${describeError(threw)}`,
    );
  }

  return { checked, skipped };
}

/**
 * Prove the page's Ed25519 path against the Node SDK (and, transitively, against
 * the Rust implementation, which the same vectors pin).
 *
 * @returns {Promise<void>}
 */
async function checkSigningAgreement() {
  const vectorsPath = join(REPO_ROOT, 'conformance', 'vectors.json');
  const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));
  const seed = vectors.seed_hex;

  const browser = await Identity.fromSeed(seed);
  check(
    'browser-side DID matches conformance/vectors.json',
    browser.did === vectors.identity.did_nau,
    `got ${browser.did}, expected ${vectors.identity.did_nau}`,
  );
  check(
    'browser-side raw public key matches conformance/vectors.json',
    browser.publicKeyHex === vectors.identity.public_key_hex,
    `got ${browser.publicKeyHex}, expected ${vectors.identity.public_key_hex}`,
  );

  // 1. The browser-side signer must reproduce the pinned signature bytes.
  const compat = vectors.payloads.find((v) => v.id === 'upstream-v2.5.6-compat');
  const payload = JSON.parse(compat.input_json);
  const ours = await browser.signPayload(payload);
  check(
    'browser-side signature over the upstream vector is byte-identical',
    ours === compat.signature_hex,
    `got ${ours}, expected ${compat.signature_hex}`,
  );

  // 2. A signature the NODE SDK produced must verify under the browser-side
  //    verifier. `sdks/js` is ESM without a package.json `type`, so the modules
  //    are loaded by absolute file URL from an .mjs context.
  const sdkIdentityUrl = pathToFileURL(join(REPO_ROOT, 'sdks', 'js', 'lib', 'identity.js')).href;
  const sdkCanonicalUrl = pathToFileURL(join(REPO_ROOT, 'sdks', 'js', 'lib', 'canonical.js')).href;
  const { Keypair } = await import(sdkIdentityUrl);
  const { canonicalPayload } = await import(sdkCanonicalUrl);

  const nodeKeypair = Keypair.fromSeed(Buffer.from(seed, 'hex'));
  check(
    'the Node SDK derives the same public key as the browser path',
    nodeKeypair.exportPublicKeyHex() === browser.publicKeyHex,
    `node ${nodeKeypair.exportPublicKeyHex()} vs browser ${browser.publicKeyHex}`,
  );

  const sdkObject = {
    did: nodeKeypair.did,
    name: 'CrossLang',
    capabilities: ['text-generation', 'mcp'],
    stake: 100,
    nested: { inner: 7, signature: 'this must be dropped' },
    signature: '',
  };
  const sdkSignature = nodeKeypair.sign(canonicalPayload(sdkObject)).toString('hex');
  const verified = await browser.verifyPayload(sdkObject, sdkSignature);
  check('a Node-SDK-produced signature verifies under the browser crypto.subtle verifier', verified);

  // 3. Falsification: change one byte of the payload and the signature must fail.
  const tampered = { ...sdkObject, stake: 101 };
  const verifiedTampered = await browser.verifyPayload(tampered, sdkSignature);
  check('tampering with the payload makes that signature fail to verify', verifiedTampered === false);
}

// ------------------------------------------------------------------ lifecycle

/**
 * Drive the whole market over HTTP through the proxy, exactly as the UI does.
 *
 * @param {NauClient} api
 */
async function checkLifecycle(api) {
  const requester = await Identity.fromSeed(new Uint8Array(32).fill(0x11));
  const agent = await Identity.fromSeed(new Uint8Array(32).fill(0x22));
  const voters = await Promise.all(
    [0xa1, 0xa2, 0xa3].map((byte) => Identity.fromSeed(new Uint8Array(32).fill(byte))),
  );

  section('HTTP through the proxy: deposit and balance');
  const depositText = '1000.5';
  const deposit = await api.deposit(requester.did, depositText);
  check(
    'POST /accounts/{did}/deposit accepts a decimal string',
    deposit.amount_minor === parseDecimalAmount(depositText),
    `amount_minor=${deposit.amount_minor}, expected ${parseDecimalAmount(depositText)}`,
  );
  check(
    'the deposit response echoes an exact decimal balance',
    deposit.balance === '1000.5',
    `balance=${JSON.stringify(deposit.balance)}`,
  );
  const balance = await api.balance(requester.did);
  check(
    'GET /accounts/{did}/balance agrees with the deposit response',
    balance.balance_minor === deposit.balance_minor,
    `${balance.balance_minor} vs ${deposit.balance_minor}`,
  );
  await api.deposit(agent.did, '1000');

  section('Lifecycle: register an agent with a real signature');
  const card = await agent.signObject(
    agentCardDraft({
      identity: agent,
      name: 'Claude translator',
      skills: ['translation', 'text-generation'],
      stakeMinor: parseDecimalAmount('100'),
    }),
  );
  check('the card carries a 128-hex-character signature', /^[0-9a-f]{128}$/.test(card.signature));
  const registered = await api.registerAgent(card);
  check('POST /agents registers the signed card', registered.status === 'registered');

  section('Lifecycle: discover and search');
  const discovered = await api.agents({ skill: 'translation' });
  check(
    'GET /agents?skill=translation finds the new agent',
    discovered.count === 1 && discovered.agents[0].owner === agent.did,
    `count=${discovered.count}`,
  );
  const searched = await api.agents({ q: 'CLAUDE' });
  check('GET /agents?q= is case-insensitive', searched.count === 1, `count=${searched.count}`);
  const all = await api.agents();
  check('GET /agents lists the agent', all.count === 1, `count=${all.count}`);

  section('Lifecycle: publish, bid, match, start, submit');
  const taskId = `task-e2e-${Date.now()}`;
  const task = await requester.signObject(
    taskDraft({
      id: taskId,
      requester,
      goal: 'translate the daemon API reference',
      context: 'English to Chinese',
      done: ['every endpoint documented'],
      todo: ['read', 'translate'],
      requiredSkills: ['translation'],
      budgetMinor: parseDecimalAmount('50'),
      committee: { n: 3, f: 0 },
      deadline: nowSeconds() + 3_600,
    }),
  );
  const published = await api.publishTask(task);
  check('POST /tasks publishes the signed task', published.status === 'published');

  const bid = await agent.signObject(
    bidDraft({ taskId, bidder: agent, priceMinor: parseDecimalAmount('40') }),
  );
  const bidResult = await api.submitBid(taskId, bid);
  check('POST /tasks/{id}/bids records the signed bid', bidResult.status === 'bid recorded');

  const match = await api.matchTask(taskId);
  check(
    'POST /tasks/{id}/match selects the only bidder',
    match.status === 'matched' && match.agent_id === agent.did,
    `winner=${match.agent_id}`,
  );
  check(
    'the matched price is the bid, not the budget',
    match.price_minor === parseDecimalAmount('40'),
    `price_minor=${match.price_minor}`,
  );

  const started = await api.startTask(taskId, agent.did);
  check('POST /tasks/{id}/start moves the task to running', started.status === 'running');

  const envelope = await agent.signObject(
    await resultDraft({
      taskId,
      agent,
      summary: 'translated every endpoint',
      output: 'a real output payload, hashed with SHA-256',
      evidence: 'verified',
    }),
  );
  const digest = await sha256(new TextEncoder().encode('a real output payload, hashed with SHA-256'));
  check(
    'the result envelope carries the real SHA-256 of its output',
    envelope.output_digest === [...digest].map((b) => b.toString(16).padStart(2, '0')).join(''),
  );
  const submitted = await api.submitResult(taskId, envelope);
  check('POST /tasks/{id}/results accepts the signed envelope', submitted.status === 'submitted');

  section('Lifecycle: verify with signed committee votes');
  const signedAt = nowSeconds();
  const votes = [];
  for (const [index, voter] of voters.entries()) {
    const unsigned = await voteDraft({
      proposal: taskId,
      voter,
      decision: 'Accept',
      signedAt,
      nonce: nextNonce() + index,
    });
    votes.push(await voter.signObject(unsigned));
  }
  const verified = await api.verifyTask(
    taskId,
    voters.map((v) => v.did),
    votes,
  );
  check(
    'POST /tasks/{id}/verify accepts three signed votes',
    verified.status === 'Accepted',
    `status=${JSON.stringify(verified.status)}`,
  );

  section('Lifecycle: settle');
  const settled = await api.settleTask(taskId);
  check('POST /tasks/{id}/settle pays the escrowed budget', settled.status === 'settled');
  check(
    'the amount paid is the escrowed budget, not the bid',
    settled.paid_minor === parseDecimalAmount('50'),
    `paid_minor=${settled.paid_minor}`,
  );
  const afterSettle = await api.balance(agent.did);
  check(
    'the executor balance is deposit − stake + paid = 1000 − 100 + 50',
    afterSettle.balance_minor === parseDecimalAmount('950'),
    `balance=${afterSettle.balance}`,
  );

  section('The core invariant: conservation and audit agree');
  const conservation = await api.conservation();
  const audit = await api.audit();
  check('GET /conservation reports conserved', conservation.conserved === true);
  check(
    'GET /conservation reports discrepancy 0 (exact integers, no epsilon)',
    conservation.discrepancy === 0,
    `discrepancy=${conservation.discrepancy}`,
  );
  check('GET /audit reports conserved', audit.conserved === true);
  check('GET /audit reports discrepancy 0', audit.discrepancy === 0);
  check(
    'the O(1) counters and the O(N) recomputation agree on the balance sum',
    conservation.sum_of_balances === audit.sum_of_balances,
    `${conservation.sum_of_balances} vs ${audit.sum_of_balances}`,
  );
  check(
    // 1000.5 + 1000 deposited by the two identities, plus the 100 stake lock:
    // `register_agent` moves the stake with `withdraw` + `deposit`, so the
    // counter grows by the stake as well while the balance sum does not.
    'total deposited is 1000.5 + 1000 + the 100 stake lock = 2100.5 exactly',
    conservation.total_deposited === parseDecimalAmount('2100.5'),
    `total_deposited=${conservation.total_deposited} (minor), expected ${parseDecimalAmount('2100.5')}`,
  );
  check(
    'total withdrawn is exactly the 100 stake lock',
    conservation.total_withdrawn === parseDecimalAmount('100'),
    `total_withdrawn=${conservation.total_withdrawn}`,
  );
  check(
    'nothing remains escrowed after settlement',
    conservation.total_escrowed === 0,
    `total_escrowed=${conservation.total_escrowed}`,
  );
  // The field the upstream client read and printed as `undefined`.
  check(
    'the response has no `totalPaid` field (the upstream client read exactly that)',
    !('totalPaid' in conservation),
  );

  section('Reporting: stats and leaderboard');
  const stats = await api.stats();
  check('GET /stats counts one agent and one task', stats.agents === 1 && stats.tasks === 1, JSON.stringify(stats));
  const leaderboard = await api.leaderboard(10);
  check(
    'GET /leaderboard ranks the settled executor',
    leaderboard.count === 1 && leaderboard.leaderboard[0].agent_id === agent.did,
    JSON.stringify(leaderboard),
  );
  return { requester, agent, taskId, conservation };
}

/**
 * The two refusals the UI must surface rather than hide.
 *
 * @param {NauClient} api
 * @param {string} account
 */
async function checkRefusals(api, account) {
  section('Refusals are surfaced, not hidden');

  // 1. A JSON float is refused with 422 — the whole reason amounts are strings.
  await checkRejects(
    'POST /accounts/{account}/deposit with {"amount":12.5} is refused with 422',
    () => api.depositFloat(account, 12.5),
    (error) => {
      if (!(error instanceof NauApiError)) return false;
      if (error.status !== 422) return false;
      if (error.code !== 'unprocessable') return false;
      // The message must actually explain the rule.
      return /decimal string|floating-point/i.test(error.serverMessage);
    },
  );
  // And the same call with a decimal string succeeds, so the difference is the
  // encoding and nothing else.
  const ok = await api.deposit(account, '12.5');
  check(
    'the same amount as a decimal string is accepted',
    ok.amount_minor === parseDecimalAmount('12.5'),
    `amount_minor=${ok.amount_minor}`,
  );

  // 2. A mutating route rejects GET with 405 (upstream settled tasks on GET).
  await checkRejects(
    `GET ${API_PREFIX}/tasks/{id}/settle is refused with 405`,
    () => api.request('GET', '/tasks/task-does-not-exist/settle'),
    (error) =>
      error instanceof NauApiError &&
      error.status === 405 &&
      error.code === 'method_not_allowed' &&
      error.allow.includes('POST'),
  );

  // 3. An unknown amount encoding is a 422 as well.
  await checkRejects(
    'POST /accounts/{account}/deposit with {"amount_minor":"x"} is refused with 422',
    () => api.request('POST', `/accounts/${pathSegment(account, 'an account id')}/deposit`, { amount_minor: 'x' }),
    (error) => error instanceof NauApiError && error.status === 422,
  );

  // 4. A request path that is not URL-safe is refused client-side rather than
  //    sent as a percent-encoded DID the daemon would reject opaquely.
  checkRejects(
    'a path segment with unsafe characters is refused before it is sent',
    async () => api.agent('did:nau:../../../etc/passwd'),
    (error) => typeof error.message === 'string' && /not valid in a request path/.test(error.message),
  );

  // 4. A signed object with a forged signature is refused, not accepted.
  const impostor = await Identity.fromSeed(new Uint8Array(32).fill(0x99));
  const honest = await Identity.fromSeed(new Uint8Array(32).fill(0x98));
  const forged = agentCardDraft({
    identity: impostor,
    name: 'forged',
    skills: ['translation'],
    stakeMinor: parseDecimalAmount('100'),
  });
  forged.signature = await honest.signPayload(forged);
  await checkRejects(
    'POST /agents refuses a card whose signature was made by the wrong key',
    () => api.registerAgent(forged),
    (error) => error instanceof NauApiError && (error.status === 401 || error.status === 422),
  );
}

// -------------------------------------------------------------- the page itself

/**
 * Import `client/app.js` for real under a minimal DOM stub and click things.
 *
 * This is **not** a browser and the test does not claim to be one: there is no
 * layout, no CSS, no event bubbling and no `innerHTML`. What it does prove is
 * that the page's own module graph loads without throwing, that every id it
 * looks up exists in `index.html`, that every button has a listener, and that a
 * real click reaches the daemon through the page's own `NauClient`.
 *
 * @param {string} pageUrl the static server's origin
 */
async function checkPageUnderDomStub(pageUrl) {
  const html = readFileSync(join(CLIENT_DIR, 'index.html'), 'utf8');
  const { document: fakeDocument, ids, buttonIds } = fakeDocumentFromHtml(html);

  const previous = {
    document: globalThis.document,
    HTMLButtonElement: globalThis.HTMLButtonElement,
    fetch: globalThis.fetch,
  };
  resetRegisteredListeners();
  globalThis.document = fakeDocument;
  // `handle()` checks `instanceof HTMLButtonElement` before touching `.disabled`.
  globalThis.HTMLButtonElement = class HTMLButtonElement {};
  globalThis.fetch = fetchAgainst(pageUrl, previous.fetch);

  let importError = null;
  try {
    // A cache-busting query makes the import fresh even if another test imported
    // it earlier, so the module-level wiring runs exactly once, here.
    await import(`../app.js?e2e=${Date.now()}`);
  } catch (error) {
    importError = error;
  }

  check(
    'app.js imports without throwing under a DOM (module-level wiring is sound)',
    importError === null,
    importError === null ? '' : describeError(importError),
  );

  const lookedUp = [...readFileSync(join(CLIENT_DIR, 'app.js'), 'utf8').matchAll(/byId\('([^']+)'\)/g)]
    .map((match) => match[1]);
  const missing = [...new Set(lookedUp)].filter((id) => !ids.includes(id));
  check(
    'every id app.js looks up exists in index.html',
    missing.length === 0,
    missing.join(', '),
  );

  const wiredIds = new Set(registeredListeners.filter((l) => l.type === 'click').map((l) => l.id));
  const deadButtons = buttonIds.filter((id) => !wiredIds.has(id));
  check(
    'every button in index.html has a click listener (no dead button)',
    deadButtons.length === 0,
    deadButtons.join(', '),
  );

  // A stub that left every `value` empty would let a working button look broken,
  // so the defaults the page relies on are checked explicitly.
  const filled = ['deposit-amount', 'agent-name', 'agent-skills', 'agent-stake', 'task-id', 'task-budget', 'task-skills', 'task-bid-price'];
  const empty = filled.filter((id) => (fakeDocument.getElementById(id)?.value ?? '') === '');
  check(
    'the inputs the page reads have their defaults from index.html',
    empty.length === 0,
    empty.join(', '),
  );
  check(
    'the page generated a task id at startup',
    /^task-[0-9a-f]{8}-\d+$/.test(fakeDocument.getElementById('task-id')?.value ?? ''),
    JSON.stringify(fakeDocument.getElementById('task-id')?.value),
  );

  // Let the startup `GET /health` finish, then read what the page wrote.
  const healthText = () => fakeDocument.getElementById('health-daemon')?.allText ?? '';
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline && !healthText().includes('protocol')) await sleep(50);
  check(
    'the page contacted the daemon at startup and wrote the answer into the DOM as text',
    /protocol nau\/1/.test(healthText()),
    JSON.stringify(healthText()),
  );

  // Click the float-deposit button: the page must render the 422 rather than
  // silently doing nothing. The identity is loaded first so the call is possible.
  await fakeDocument.getElementById('identity-restore')?.dispatch('click');
  await fakeDocument.getElementById('deposit-float')?.dispatch('click');
  const bannerText = fakeDocument.created
    .filter((element) => element.className === 'error-banner')
    .map((element) => element.textContent)
    .join(' | ');
  check(
    'clicking "try a float" renders the daemon\'s 422 as visible text',
    /HTTP 422/.test(bannerText) && /unprocessable/.test(bannerText),
    bannerText === '' ? 'no error banner was created' : bannerText,
  );

  // And the decimal-string path must succeed through the same wiring.
  await fakeDocument.getElementById('deposit-submit')?.dispatch('click');
  const balanceText = fakeDocument.getElementById('account-balance')?.textContent ?? '';
  check(
    'clicking "deposit" credits the account and renders the new balance',
    /balance 1000/.test(balanceText),
    JSON.stringify(balanceText),
  );
  // Restore the real globals so nothing later runs under the stub.
  globalThis.document = previous.document;
  globalThis.HTMLButtonElement = previous.HTMLButtonElement;
  globalThis.fetch = previous.fetch;
}

// ----------------------------------------------------------------------- main

/** @type {{child: import('node:child_process').ChildProcess, log: () => string}|null} */
let daemon = null;
/** @type {{close: () => Promise<void>}|null} */
let staticServer = null;
/** Every daemon's captured stdout/stderr, for the failure tail. */
let daemonLogs = '';

/**
 * Retire a daemon, keeping its log for the failure report.
 * @param {{child: import('node:child_process').ChildProcess, log: () => string}|null} instance
 */
async function retireDaemon(instance) {
  if (!instance) return;
  daemonLogs += instance.log();
  await stopDaemonProcess(instance);
}

/** Shut everything down; safe to call more than once. */
async function shutdown() {
  if (staticServer) {
    try {
      await staticServer.close();
    } catch (error) {
      console.error(`[e2e] closing the static server failed: ${describeError(error)}`);
    }
    staticServer = null;
  }
  await retireDaemon(daemon);
  daemon = null;
}

async function main() {
  console.log('[e2e] NewAgentUniverse client end-to-end test');
  console.log(`[e2e] repo root:   ${REPO_ROOT}`);
  console.log(`[e2e] node:        ${process.version} (crypto.subtle Ed25519: ${
    typeof globalThis.crypto?.subtle === 'object' ? 'available' : 'MISSING'
  })`);

  if (typeof globalThis.crypto?.subtle !== 'object') {
    fatal('globalThis.crypto.subtle is missing; Node 20 or newer is required');
  }

  // 1. The daemon binary.
  const { binary } = await ensureDaemonBinary();

  // 2. The static server and the daemon the lifecycle runs against.
  //
  //    The page-level check further down gets its OWN daemon and server: sharing
  //    one would leave the page's deposits in the ledger the lifecycle
  //    assertions read, so an exact `total_deposited` check would depend on
  //    which test ran first. A second ephemeral daemon costs one process start
  //    and removes that coupling entirely.
  daemon = await startDaemonProcess(binary);
  staticServer = await startClientServer(daemon.base);
  const pageUrl = staticServer.url;

  // The proxy must serve the page and the ES modules with usable content types.
  const pageResponse = await fetch(`${pageUrl}/`);
  check('the static server serves index.html', pageResponse.status === 200);
  check(
    'index.html is served as text/html; charset=utf-8',
    (pageResponse.headers.get('content-type') ?? '').startsWith('text/html'),
    pageResponse.headers.get('content-type') ?? '(none)',
  );
  const moduleResponse = await fetch(`${pageUrl}/app.js`);
  check('the static server serves app.js', moduleResponse.status === 200);
  check(
    'app.js is served with a JavaScript content type (a browser refuses otherwise)',
    /javascript/.test(moduleResponse.headers.get('content-type') ?? ''),
    moduleResponse.headers.get('content-type') ?? '(none)',
  );
  const traverse = await fetch(`${pageUrl}/../../Cargo.toml`);
  check(
    'a path that escapes the served directory is refused',
    traverse.status === 400 || traverse.status === 404,
    `status ${traverse.status}`,
  );

  // Everything from here on speaks to the daemon only through the proxy — the
  // same origin, the same routes, the same client object the page uses.
  const api = new NauClient(`${pageUrl}${API_PREFIX}`);
  const health = await api.health();
  check(`GET ${API_PREFIX}/health is proxied to the daemon`, typeof health.version === 'string', JSON.stringify(health));

  section('Canonical JSON against conformance/vectors.json');
  const { checked, skipped } = checkCanonicalVectors();
  console.log(`  (${checked} payloads and 5 rejections checked; skipped: ${skipped.join(', ') || 'none'})`);

  section('Ed25519: the browser path against the Node SDK');
  await checkSigningAgreement();

  const { agent } = await checkLifecycle(api);
  await checkRefusals(api, agent.did);

  section('The core invariant again, after the refusals');
  // `checkRefusals` deliberately deposited another 12.5 as a decimal string, so
  // the invariant is re-checked here: a refusal must not have moved a counter.
  const finalConservation = await api.conservation();
  const finalAudit = await api.audit();
  check(
    'POSTing a refused float left the counters untouched: the only new credit is the 12.5 string',
    finalConservation.total_deposited === parseDecimalAmount('2113'),
    `total_deposited=${finalConservation.total_deposited} (minor), expected ${parseDecimalAmount('2113')}`,
  );
  check(
    'conservation and audit still agree with discrepancy 0 after the refusals',
    finalConservation.conserved === true &&
      finalAudit.conserved === true &&
      finalConservation.discrepancy === 0 &&
      finalAudit.discrepancy === 0 &&
      finalConservation.sum_of_balances === finalAudit.sum_of_balances,
    JSON.stringify({ finalConservation, finalAudit }),
  );

  // The lifecycle is finished, so its daemon is retired: the page-level check
  // gets a clean ledger and nothing above can be perturbed by what the page does.
  await staticServer.close();
  staticServer = null;
  await retireDaemon(daemon);
  daemon = null;

  section('The page itself: importing client/app.js under a DOM stub');
  daemon = await startDaemonProcess(binary);
  staticServer = await startClientServer(daemon.base);
  await checkPageUnderDomStub(staticServer.url);

  section('UI source rules');
  const appSource = readFileSync(join(CLIENT_DIR, 'app.js'), 'utf8');
  check(
    'app.js contains no innerHTML assignment (upstream built its log lines with innerHTML)',
    !/\.innerHTML\s*=/.test(appSource) && !/insertAdjacentHTML/.test(appSource),
  );
  const nauSource = readFileSync(join(CLIENT_DIR, 'lib', 'nau.mjs'), 'utf8');
  check(
    'app.js imports ./lib/nau.mjs, which re-exports the canonicalizer from ./lib/canonical.mjs',
    /from '\.\/lib\/nau\.mjs'/.test(appSource) &&
      /(import|export) \{[\s\S]*?canonicalJson[\s\S]*?\} from '\.\/canonical\.mjs'/.test(nauSource),
  );
  check(
    'app.js does not define a second canonical serializer of its own',
    !/function\s+canonicalJson/.test(appSource),
  );
  const htmlSource = readFileSync(join(CLIENT_DIR, 'index.html'), 'utf8');
  check(
    'index.html ships a Content-Security-Policy meta tag',
    htmlSource.includes('http-equiv="Content-Security-Policy"') &&
      /content="default-src 'none'/.test(htmlSource),
  );
  check(
    'index.html has no inline event handler (which the CSP would block anyway)',
    !/\son(click|load|error)\s*=/.test(htmlSource),
  );
  const serveSource = readFileSync(join(CLIENT_DIR, 'serve.mjs'), 'utf8');
  const bareImports = [...serveSource.matchAll(/from\s+'([^']+)'/g)]
    .map((match) => match[1])
    .filter((specifier) => !specifier.startsWith('node:') && !specifier.startsWith('.'));
  check(
    'serve.mjs imports only node: builtins and relative modules (zero npm dependencies)',
    bareImports.length === 0,
    bareImports.join(', '),
  );

  // The Tauri shell is source-only here and is NOT built: this is a static check
  // on its configuration, which is all that can honestly be claimed.
  const tauriConfigPath = join(CLIENT_DIR, 'src-tauri', 'tauri.conf.json');
  if (existsSync(tauriConfigPath)) {
    const tauri = JSON.parse(readFileSync(tauriConfigPath, 'utf8'));
    check(
      'src-tauri/tauri.conf.json sets a real CSP (upstream set "csp": null)',
      typeof tauri.app?.security?.csp === 'string' && tauri.app.security.csp.length > 0,
      JSON.stringify(tauri.app?.security?.csp),
    );
    const bundleConfig = JSON.stringify(tauri.bundle ?? {});
    check(
      'src-tauri/tauri.conf.json does not reference icon.icns / icon.ico, which upstream gitignored and never shipped',
      !bundleConfig.includes('icon.icns') && !bundleConfig.includes('icon.ico'),
    );
    // Every icon the config *does* reference must exist: upstream's build failed
    // precisely because that was not true.
    const referenced = (tauri.bundle?.icon ?? []).filter((entry) => !entry.includes('*'));
    const missingIcons = referenced.filter(
      (entry) => !existsSync(join(CLIENT_DIR, 'src-tauri', entry)),
    );
    check(
      'every icon file src-tauri/tauri.conf.json references exists on disk',
      missingIcons.length === 0,
      missingIcons.join(', '),
    );
    check(
      'src-tauri/Cargo.toml declares its own [workspace] so the root workspace never builds Tauri',
      /^\[workspace\]$/m.test(readFileSync(join(CLIENT_DIR, 'src-tauri', 'Cargo.toml'), 'utf8')),
    );
  }

  // A short daemon log tail helps diagnose a failure without re-running. It is
  // accumulated across every daemon the test started, because the failing
  // assertion may belong to either lifetime.
  if (failed > 0 && daemonLogs.trim().length > 0) {
    console.log('\n-- daemon log tail --');
    console.log(daemonLogs.trim().split('\n').slice(-25).join('\n'));
  }
}

try {
  await main();
} catch (error) {
  failed += 1;
  failures.push(`the test harness threw: ${describeError(error)}`);
  console.error(`\n[e2e] FATAL ${error instanceof Error ? error.stack : String(error)}`);
} finally {
  await shutdown();
}

console.log(`\n[e2e] ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log('[e2e] failures:');
  for (const failure of failures) console.log(`  - ${failure}`);
  console.log('\n[e2e] the browser client is NOT verified: one or more assertions above failed.');
  process.exit(1);
}
console.log('[e2e] the browser client is verified end to end against the daemon over HTTP.');
process.exit(0);
