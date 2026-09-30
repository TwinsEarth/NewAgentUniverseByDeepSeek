/**
 * The NewAgentUniverse browser client.
 *
 * # What this file is for
 *
 * Upstream agent-universe v2.5.6 shipped `client/src/main.js:1` importing the npm
 * package and running an **in-memory market simulation in the tab**: no daemon
 * connection, no HTTP, no DHT, no persistence, and a `c.totalPaid` read of a
 * field `conservationCheck()` never returned (so the demo printed `undefined`).
 * A GUI that invents its own market cannot be wrong, and therefore cannot be
 * useful.
 *
 * Every button below performs a real HTTP call to a real `nau-daemon` and prints
 * the daemon's own answer — including its refusals, with the HTTP status. All
 * signing happens in this tab with `crypto.subtle` Ed25519.
 *
 * # Rendering rules
 *
 * There is **no `innerHTML` in this file**, and no string is ever assembled into
 * markup. Text goes in through `textContent`; structures are built with
 * `createElement`. That is a deliberate consequence of the audit finding that
 * upstream set `"csp": null` (`tauri.conf.json:22`) while building its log lines
 * with `innerHTML` (`client/src/main.js:18-20`) — an XSS sink with the only
 * mitigation switched off. Here the page ships a real CSP and the code cannot
 * produce markup even by accident.
 *
 * # Canonical JSON
 *
 * `canonicalJson` is **not** reimplemented here; it is imported from
 * `./lib/canonical.mjs`, the same module `client/test/e2e.mjs` proves against
 * `conformance/vectors.json`. One implementation, two runtimes.
 */

import {
  CanonicalError,
  canonicalJson,
  canonicalPayload,
  codepointCompare,
  escapeString,
  isPlainObject,
  kindOf,
  MAX_DEPTH,
  SIGNATURE_FIELD,
  NauApiError,
  NauClient,
  NauClientError,
  Identity,
  agentCardDraft,
  bidDraft,
  bytesToHex,
  describeError,
  formatMinor,
  hexToBytes,
  nextNonce,
  nowSeconds,
  parseDecimalAmount,
  randomSeed,
  resultDraft,
  sha256,
  taskDraft,
  voteDraft,
  PKCS8_ED25519_PREFIX_HEX,
  DID_FINGERPRINT_BYTES,
  MINOR_UNITS_PER_MAJOR,
} from './lib/nau.mjs';

/** The daemon, reached through `serve.mjs`'s same-origin `/api` proxy. */
const api = new NauClient('/api');

/** The identity every signed action uses. Set by the buttons in panel 1. */
let identity = null;

/** The task id the lifecycle panel acts on. */
let currentTaskId = null;

/** The three committee member identities, created once and reused. */
let committee = null;

// --------------------------------------------------------------- DOM plumbing

/**
 * @param {string} id
 * @returns {HTMLElement}
 */
function byId(id) {
  const element = document.getElementById(id);
  if (!element) throw new Error(`missing element #${id} in index.html`);
  return element;
}

/**
 * Replace an element's text. Never markup: `textContent` cannot execute.
 * @param {string} id
 * @param {string} text
 */
function setText(id, text) {
  byId(id).textContent = text;
}

/**
 * Append one line to a `<pre>` log.
 * @param {string} id
 * @param {string} text
 * @param {'info'|'ok'|'error'} [kind]
 */
function log(id, text, kind = 'info') {
  const pre = byId(id);
  const line = document.createElement('span');
  line.className = `log-line log-${kind}`;
  line.textContent = `${new Date().toISOString().slice(11, 19)}  ${text}\n`;
  pre.appendChild(line);
  pre.scrollTop = pre.scrollHeight;
}

/**
 * Render a flat object as a definition list built from `createElement`.
 *
 * Every value is stringified explicitly, so a nested object appears as JSON text
 * rather than `[object Object]`, and `undefined`/`null` appear as
 * `<absent>`/`null` rather than as an invisible blank — the upstream defect this
 * replaces was a demo printing `undefined` for a field that did not exist.
 *
 * @param {string} id
 * @param {Record<string, unknown>} fields
 */
function renderFields(id, fields) {
  const list = byId(id);
  list.replaceChildren();
  for (const [key, value] of Object.entries(fields)) {
    const dt = document.createElement('dt');
    dt.textContent = key;
    const dd = document.createElement('dd');
    dd.textContent = describeValue(value);
    list.append(dt, dd);
  }
}

/**
 * @param {unknown} value
 * @returns {string}
 */
function describeValue(value) {
  if (value === undefined) return '<absent — the API does not return this field>';
  if (value === null) return 'null';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

/**
 * Wrap a button handler so that **every** failure becomes visible text carrying
 * the HTTP status.
 *
 * This is the rule the task states plainly: no button may be a silent no-op.
 * `describeError` renders `NauApiError` as
 * `HTTP 422 unprocessable: <server message>`, so the status is always on screen.
 *
 * @param {string} logId
 * @param {string} label
 * @param {() => Promise<unknown>} action
 * @returns {(event: Event) => Promise<void>}
 */
function handle(logId, label, action) {
  return async (event) => {
    const button = event.currentTarget;
    if (button instanceof HTMLButtonElement) button.disabled = true;
    const started = performance.now();
    const record = { label, status: 'running', ms: 0 };
    requestLog.push(record);
    try {
      const result = await action();
      record.status = 'ok';
      log(logId, `${label} -> OK (${Math.round(performance.now() - started)} ms)`, 'ok');
      if (result !== undefined) log(logId, `  response: ${describeValue(result)}`);
    } catch (error) {
      record.status =
        error instanceof NauApiError ? `HTTP ${error.status} ${error.code}` : 'error';
      record.detail = describeError(error);
      log(logId, `${label} -> FAILED: ${describeError(error)}`, 'error');
      if (error instanceof NauApiError) {
        log(logId, `  HTTP status ${error.status}, error code ${JSON.stringify(error.code)}`);
      }
      // A visible banner as well as a log line, so the failure cannot be missed
      // even if the panel is scrolled out of view.
      showErrorBanner(logId, label, error);
    } finally {
      record.ms = Math.round(performance.now() - started);
      if (button instanceof HTMLButtonElement) button.disabled = false;
      renderRequestLog();
    }
  };
}

/** @type {{label: string, status: string, ms: number, detail?: string}[]} */
const requestLog = [];

/** Re-render the raw request log from its array, with `createElement`. */
function renderRequestLog() {
  const pre = byId('request-log');
  pre.replaceChildren();
  if (requestLog.length === 0) {
    pre.textContent = '(no requests yet)';
    return;
  }
  for (const record of requestLog) {
    const span = document.createElement('span');
    const failed = record.status !== 'ok' && record.status !== 'running';
    span.className = `log-line ${failed ? 'log-error' : record.status === 'ok' ? 'log-ok' : 'log-info'}`;
    span.textContent =
      `${record.label.padEnd(34)} ${record.status.padEnd(22)} ${record.ms} ms` +
      (record.detail ? `  ${record.detail}` : '') +
      '\n';
    pre.appendChild(span);
  }
}

/**
 * Show a failure as a dismissible banner above the panel.
 * @param {string} logId
 * @param {string} label
 * @param {unknown} error
 */
function showErrorBanner(logId, label, error) {
  const panel = byId(logId).closest('.panel') ?? document.body;
  const banner = document.createElement('p');
  banner.className = 'error-banner';
  banner.setAttribute('role', 'alert');
  banner.textContent = `${label} failed — ${describeError(error)}`;
  const dismiss = document.createElement('button');
  dismiss.type = 'button';
  dismiss.textContent = 'dismiss';
  dismiss.addEventListener('click', () => banner.remove());
  banner.appendChild(document.createTextNode(' '));
  banner.appendChild(dismiss);
  panel.prepend(banner);
}

// ------------------------------------------------------------------ identity

/** Render the current identity, or a prompt to create one. */
function renderIdentity() {
  if (!identity) {
    setText('identity-did', '— (generate or load an identity first)');
    setText('identity-public-key', '—');
    setText('identity-seed', '—');
    return;
  }
  const exported = identity.export();
  setText('identity-did', exported.did);
  setText('identity-public-key', exported.public_key_hex);
  setText('identity-seed', exported.seed_hex);
}

/**
 * Require an identity, throwing a readable error if there is none.
 * @returns {Identity}
 */
function requireIdentity() {
  if (!identity) {
    throw new Error('no identity yet — use "Generate a random identity" in panel 1');
  }
  return identity;
}

/** Build the three committee members once. */
async function requireCommittee() {
  if (!committee) {
    committee = await Promise.all(
      [
        'a11ce00000000000000000000000000000000000000000000000000000000001',
        'a11ce00000000000000000000000000000000000000000000000000000000002',
        'a11ce00000000000000000000000000000000000000000000000000000000003',
      ].map((seed) => Identity.fromSeed(seed)),
    );
  }
  return committee;
}

/** A fresh, valid task id (`[A-Za-z0-9_-]{1,64}`). */
function generateTaskId() {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `task-${hex}-${nextNonce() % 1000}`;
}

// ------------------------------------------------------------------- actions

/** `GET /health` plus a short summary line. */
async function refreshHealth() {
  const health = await api.health();
  setText(
    'health-daemon',
    `v${describeValue(health.version)} · protocol ${describeValue(health.protocol)} · ` +
      `upstream ${describeValue(health.upstream)} · ${describeValue(health.stats?.agents)} agents, ` +
      `${describeValue(health.stats?.tasks)} tasks`,
  );
  return health;
}

/** `POST /accounts/{did}/deposit` with a decimal string. */
async function deposit() {
  const me = requireIdentity();
  const text = byId('deposit-amount').value;
  const minor = parseDecimalAmount(text);
  const result = await api.deposit(me.did, text.trim());
  setText('account-balance', `balance ${describeValue(result.balance)} (${result.balance_minor} minor)`);
  return result;
}

/** `GET /accounts/{did}/balance`. */
async function refreshBalance() {
  const me = requireIdentity();
  const result = await api.balance(me.did);
  setText('account-balance', `balance ${describeValue(result.balance)} (${result.balance_minor} minor)`);
  return result;
}

/**
 * The deliberate float probe.
 *
 * Sends `{"amount": 12.5}` — a JSON number — which the daemon refuses with
 * `422` because a float does not survive a round trip through Rust, Python and
 * JavaScript. The handler prints the status.
 */
async function depositFloat() {
  const me = requireIdentity();
  return api.depositFloat(me.did, 12.5);
}

/** `POST /agents` with a signed card. */
async function registerAgent() {
  const me = requireIdentity();
  const skills = byId('agent-skills')
    .value.split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);
  const unsigned = agentCardDraft({
    identity: me,
    name: byId('agent-name').value,
    skills,
    stakeMinor: parseDecimalAmount(byId('agent-stake').value),
  });
  const signed = await me.signObject(unsigned);
  const result = await api.registerAgent(signed);
  log('registry-log', `card signed over ${Object.keys(signed).length} fields; signature ${signed.signature.slice(0, 16)}…`);
  return result;
}

/** `GET /agents`, `?skill=` or `?q=`. */
async function listAgents(kind) {
  const result =
    kind === 'skill'
      ? await api.agents({ skill: byId('agents-skill-query').value })
      : kind === 'q'
        ? await api.agents({ q: byId('agents-text-query').value })
        : await api.agents();
  for (const card of result.agents ?? []) {
    log(
      'registry-log',
      `  ${card.owner}  ${card.name}  skills=[${(card.skills ?? []).map((s) => s.id).join(', ')}]  stake=${formatMinor(card.stake)}`,
    );
  }
  return { count: result.count };
}

/** `POST /tasks` with a signed task. The budget is escrowed from the requester. */
async function publishTask() {
  const me = requireIdentity();
  const budgetMinor = parseDecimalAmount(byId('task-budget').value);
  const id = byId('task-id').value.trim() || generateTaskId();
  byId('task-id').value = id;
  const unsigned = taskDraft({
    id,
    requester: me,
    goal: byId('task-goal').value,
    context: 'the daemon HTTP API reference, English to Chinese',
    done: ['every endpoint documented in the target language'],
    todo: ['read the API reference', 'translate', 'review'],
    requiredSkills: byId('task-skills')
      .value.split(',')
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s.length > 0),
    budgetMinor,
    committee: { n: 3, f: 0 },
    deadline: nowSeconds() + 3_600,
  });
  const signed = await me.signObject(unsigned);
  const result = await api.publishTask(signed);
  currentTaskId = id;
  return result;
}

/** `POST /tasks/{id}/bids` with a signed bid. */
async function submitBid() {
  const me = requireIdentity();
  const taskId = requireTaskId();
  const unsigned = bidDraft({
    taskId,
    bidder: me,
    priceMinor: parseDecimalAmount(byId('task-bid-price').value),
  });
  const signed = await me.signObject(unsigned);
  return api.submitBid(taskId, signed);
}

/** `POST /tasks/{id}/match`. */
async function matchTask() {
  return api.matchTask(requireTaskId());
}

/** `POST /tasks/{id}/start` with the assigned executor. */
async function startTask() {
  const me = requireIdentity();
  return api.startTask(requireTaskId(), me.did);
}

/** `POST /tasks/{id}/results` with a signed envelope and a real SHA-256 digest. */
async function submitResult() {
  const me = requireIdentity();
  const taskId = requireTaskId();
  const unsigned = await resultDraft({
    taskId,
    agent: me,
    summary: 'translated every endpoint in the API reference',
    output: `translation of ${taskId} produced at ${new Date().toISOString()}`,
    evidence: 'verified',
  });
  log('task-log', `  output_digest = ${unsigned.output_digest} (SHA-256 of the output bytes)`);
  const signed = await me.signObject(unsigned);
  return api.submitResult(taskId, signed);
}

/**
 * `POST /tasks/{id}/verify` with the assigned member set and three signed votes.
 *
 * The votes are signed here; the daemon checks each signature, the DID↔key
 * binding, membership and the nonce. There is no `approvals` count to supply,
 * which is exactly the upstream defect (`api/market_actor.rs` invented committee
 * members and their ballots from the caller's number).
 */
async function verifyTask() {
  const taskId = requireTaskId();
  const members = await requireCommittee();
  const signedAt = nowSeconds();
  const votes = [];
  for (const [index, member] of members.entries()) {
    const unsigned = await voteDraft({
      proposal: taskId,
      voter: member,
      decision: 'Accept',
      signedAt,
      nonce: nextNonce() + index,
    });
    votes.push(await member.signObject(unsigned));
  }
  log(
    'task-log',
    `  ${votes.length} votes signed by ${members.map((m) => m.did).join(', ')}`,
  );
  return api.verifyTask(
    taskId,
    members.map((m) => m.did),
    votes,
  );
}

/** `POST /tasks/{id}/settle`. */
async function settleTask() {
  return api.settleTask(requireTaskId());
}

/** `GET /tasks/{id}`. */
async function showTask() {
  const task = await api.task(requireTaskId());
  return {
    id: task.id,
    state: task.state,
    budget: formatMinor(task.budget),
    assigned_to: task.assigned_to,
  };
}

/**
 * The task id the lifecycle buttons act on.
 *
 * The input is authoritative (a user may paste one), with the id generated at
 * startup as the fallback. A button that acts on no task at all is the silent
 * no-op this refuses to be.
 * @returns {string}
 */
function requireTaskId() {
  const fromField = byId('task-id').value.trim();
  const id = fromField.length > 0 ? fromField : (currentTaskId ?? '');
  if (id.length === 0) throw new Error('no task id yet — publish a task in panel 4 first');
  return id;
}

/** `GET /conservation` and `GET /audit`, rendered side by side. */
async function refreshInvariant() {
  const [conservation, audit] = await Promise.all([api.conservation(), api.audit()]);
  renderFields('conservation-fields', conservation);
  renderFields('audit-fields', audit);
  const agree =
    conservation.conserved === audit.conserved &&
    conservation.discrepancy === audit.discrepancy &&
    conservation.sum_of_balances === audit.sum_of_balances;
  setText(
    'invariant-verdict',
    agree
      ? `AGREE — the O(1) counters and the independent O(N) recomputation match; discrepancy ` +
          `${describeValue(conservation.discrepancy)} (exact integers, no epsilon).`
      : 'DISAGREE — the two computations differ. This is the bug the audit exists to find.',
  );
  byId('invariant-verdict').className = agree ? 'verdict verdict-ok' : 'verdict verdict-bad';
  // Guard against the upstream defect class directly: a demo that reads a field
  // the API does not return prints `undefined` and nobody notices. If a caller
  // ever reaches for `totalPaid` here, this says so instead of rendering a blank.
  const missing = ['totalPaid'].filter((field) => !(field in conservation));
  return { conserved: conservation.conserved, discrepancy: conservation.discrepancy, missing };
}

/** `GET /stats`. */
async function refreshStats() {
  const stats = await api.stats();
  renderFields('stats-fields', stats);
  return stats;
}

/** `GET /leaderboard?limit=10`. */
async function refreshLeaderboard() {
  const { leaderboard } = await api.leaderboard(10);
  const list = byId('leaderboard-list');
  list.replaceChildren();
  if (!Array.isArray(leaderboard) || leaderboard.length === 0) {
    const item = document.createElement('li');
    item.textContent = '(empty — no reputation recorded yet)';
    list.appendChild(item);
    return { count: 0 };
  }
  for (const entry of leaderboard) {
    const item = document.createElement('li');
    // textContent only: a DID is data, never markup.
    item.textContent = `${entry.agent_id} — ${entry.overall_bps} bps`;
    list.appendChild(item);
  }
  return { count: leaderboard.length };
}

// ------------------------------------------------------------------ wiring

/**
 * Attach every handler. Each one is wrapped so a failure is visible.
 */
function wire() {
  byId('identity-generate').addEventListener(
    'click',
    handle('identity-note', 'generate identity', async () => {
      identity = await Identity.generate();
      renderIdentity();
      return identity.export();
    }),
  );

  byId('identity-restore').addEventListener(
    'click',
    handle('identity-note', 'load conformance seed', async () => {
      // Deterministic and public: this is the seed pinned by
      // conformance/vectors.json, so the DID below must be
      // did:nau:34750f98bd59fcfc. If it is not, the key derivation is wrong.
      identity = await Identity.fromSeed(
        '0101010101010101010101010101010101010101010101010101010101010101',
      );
      renderIdentity();
      const expected = 'did:nau:34750f98bd59fcfc';
      if (identity.did !== expected) {
        throw new Error(
          `key derivation produced ${identity.did}, but conformance/vectors.json pins ${expected}`,
        );
      }
      return { did: identity.did, matches_conformance_vector: true };
    }),
  );

  byId('deposit-submit').addEventListener('click', handle('account-log', 'deposit (decimal string)', deposit));
  byId('balance-refresh').addEventListener('click', handle('account-log', 'balance', refreshBalance));
  byId('deposit-float').addEventListener('click', handle('account-log', 'deposit (JSON float, expected 422)', depositFloat));

  byId('agent-register').addEventListener('click', handle('registry-log', 'register agent', registerAgent));
  byId('agents-list').addEventListener('click', handle('registry-log', 'GET /agents', () => listAgents('all')));
  byId('agents-discover').addEventListener('click', handle('registry-log', 'discover by skill', () => listAgents('skill')));
  byId('agents-search').addEventListener('click', handle('registry-log', 'search by text', () => listAgents('q')));

  byId('task-publish').addEventListener('click', handle('task-log', 'publish task', publishTask));
  byId('task-bid').addEventListener('click', handle('task-log', 'submit bid', submitBid));
  byId('task-match').addEventListener('click', handle('task-log', 'match', matchTask));
  byId('task-start').addEventListener('click', handle('task-log', 'start', startTask));
  byId('task-result').addEventListener('click', handle('task-log', 'submit result', submitResult));
  byId('task-verify').addEventListener('click', handle('task-log', 'verify (signed votes)', verifyTask));
  byId('task-settle').addEventListener('click', handle('task-log', 'settle', settleTask));
  byId('task-show').addEventListener('click', handle('task-log', 'show task', showTask));

  byId('invariant-refresh').addEventListener('click', handle('invariant-verdict', 'conservation + audit', refreshInvariant));
  byId('stats-refresh').addEventListener('click', handle('invariant-verdict', 'stats', refreshStats));
  byId('leaderboard-refresh').addEventListener('click', handle('invariant-verdict', 'leaderboard', refreshLeaderboard));
  byId('request-log-clear').addEventListener('click', () => {
    requestLog.length = 0;
    renderRequestLog();
  });
}

/**
 * Boot: wire the handlers, then contact the daemon once so the page states
 * immediately whether anything is listening.
 */
async function main() {
  wire();
  byId('task-id').value = generateTaskId();
  renderRequestLog();
  renderIdentity();
  try {
    await refreshHealth();
  } catch (error) {
    log('request-log', `GET /health -> FAILED: ${describeError(error)}`, 'error');
    setText(
      'health-daemon',
      `no daemon reachable through the /api proxy — ${describeError(error)}`,
    );
  }
}

if (typeof document !== 'undefined') {
  main().catch((error) => {
    // The last resort: a startup failure is still shown as text, never swallowed.
    const pre = document.createElement('pre');
    pre.className = 'log log-error';
    pre.textContent = `client failed to start: ${describeError(error)}`;
    document.body.prepend(pre);
  });
}

export { api, byId, describeValue, handle, log, renderFields, setText };
