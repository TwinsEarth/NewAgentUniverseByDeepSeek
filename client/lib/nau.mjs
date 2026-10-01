/**
 * The browser's whole daemon client: `crypto.subtle` Ed25519 identity,
 * canonical-JSON signing, and a typed wrapper over the daemon's HTTP API.
 *
 * Dependency-free by construction — no npm package, no bundler, no build step.
 * `client/app.js` re-exports everything here for the UI, and
 * `client/test/e2e.mjs` imports **these same modules** under Node, so the code
 * the test proves is the code the browser runs.
 *
 * # Why the signing lives in the browser at all
 *
 * Upstream agent-universe v2.5.6 shipped `client/src/main.js:1` importing the
 * npm package and running an in-memory market simulation in the tab: no daemon,
 * no HTTP, no signatures. A UI that shows a market it invented itself proves
 * nothing. Every mutating call here signs a real payload with a real Ed25519
 * key derived from a 32-byte seed and is accepted (or refused) by the running
 * daemon on its own terms.
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
} from './canonical.mjs';

export {
  CanonicalError,
  canonicalJson,
  canonicalPayload,
  codepointCompare,
  escapeString,
  isPlainObject,
  kindOf,
  MAX_DEPTH,
  SIGNATURE_FIELD,
};

/**
 * PKCS#8 DER prefix for a raw Ed25519 seed.
 *
 * `302e020100300506032b657004220420` is `SEQUENCE { INTEGER 0, SEQUENCE {
 * OID 1.3.101.112 }, OCTET STRING (32) }`, i.e. the fixed envelope around the
 * 32-byte seed. This is the same constant `sdks/js/lib/identity.js:34` uses, so
 * a seed produces the same key here, in the Node SDK, and in Rust.
 */
export const PKCS8_ED25519_PREFIX_HEX = '302e020100300506032b657004220420';

/** Bytes of SHA-256 retained for the DID fingerprint. */
export const DID_FINGERPRINT_BYTES = 8;

/** Bytes of Ed25519 raw public key. */
export const PUBLIC_KEY_BYTES = 32;

/** Minor units per major unit: six decimal places (`Money` in `nau-core`). */
export const MINOR_UNITS_PER_MAJOR = 1_000_000;

/** Raised for anything the client refuses to sign or send. */
export class NauClientError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'NauClientError';
  }
}

/**
 * A non-2xx response from the daemon.
 *
 * The UI never hides one of these: {@link NauApiError} carries the HTTP status,
 * the machine-readable `error` code and the server's `message`, and app.js
 * prints all three as visible text. That is the point — upstream's demo shell
 * printed `undefined` for a field that did not exist and never surfaced a
 * status code at all.
 */
export class NauApiError extends Error {
  /**
   * @param {number} status
   * @param {string} method
   * @param {string} path
   * @param {{error?: string, message?: string, allow?: string[]}|null} body
   * @param {string} rawText
   */
  constructor(status, method, path, body, rawText) {
    const code = body && typeof body.error === 'string' ? body.error : 'http_error';
    const message =
      body && typeof body.message === 'string' ? body.message : rawText || 'no response body';
    super(`${method} ${path} -> HTTP ${status} ${code}: ${message}`);
    this.name = 'NauApiError';
    /** @type {number} */
    this.status = status;
    /** @type {string} */
    this.method = method;
    /** @type {string} */
    this.path = path;
    /** @type {string} */
    this.code = code;
    /** @type {string} */
    this.serverMessage = message;
    /** @type {string[]} */
    this.allow = body && Array.isArray(body.allow) ? body.allow : [];
    /** @type {string} */
    this.rawText = rawText;
  }
}

// ---------------------------------------------------------------- hex helpers

/**
 * @param {Uint8Array} bytes
 * @returns {string} lowercase hex
 */
export function bytesToHex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/**
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new NauClientError('hex input must be an even-length hex string');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {Uint8Array}
 */
function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** The WebCrypto implementation, which must be present. */
function subtleCrypto() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new NauClientError(
      'crypto.subtle is unavailable; serve this page over http://localhost (a secure context) ' +
        'or run it on Node 20+',
    );
  }
  return c;
}

/**
 * @param {Uint8Array} bytes
 * @returns {Promise<Uint8Array>} SHA-256 digest
 */
export async function sha256(bytes) {
  const digest = await subtleCrypto().subtle.digest('SHA-256', bytes);
  return new Uint8Array(digest);
}

/** Random 32-byte seed from the platform CSPRNG. */
export function randomSeed() {
  const out = new Uint8Array(32);
  subtleCrypto().getRandomValues(out);
  return out;
}

/** A small non-cryptographic counter so generated nonces strictly increase. */
let nonceCounter = 0;

/**
 * A strictly increasing replay-protection nonce.
 *
 * The daemon keeps one monotonic nonce sequence **per DID** shared by every
 * object that DID signs, so the UI must never reuse one. Entropy from the
 * platform CSPRNG is mixed in so two tabs cannot collide.
 * @returns {number}
 */
export function nextNonce() {
  nonceCounter += 1;
  const t = Date.now();
  return Math.floor(t / 1000) * 1000 + (nonceCounter % 1000);
}

/** Current Unix time in seconds. */
export function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

/**
 * An Ed25519 signing identity, derived from a 32-byte seed exactly as the JS SDK
 * does it (`sdks/js/lib/identity.js`).
 */
export class Identity {
  /**
   * @param {Uint8Array} seed 32 bytes
   * @param {CryptoKey} privateKey PKCS#8-imported Ed25519 key
   * @param {Uint8Array} publicKey raw 32-byte public key
   */
  constructor(seed, privateKey, publicKey) {
    /** @type {Uint8Array} */
    this.seed = seed;
    /** @type {CryptoKey} */
    this.privateKey = privateKey;
    /** @type {Uint8Array} */
    this.publicKey = publicKey;
    /** @type {string} lowercase hex of the raw public key */
    this.publicKeyHex = bytesToHex(publicKey);
  }

  /**
   * Derive from a raw 32-byte seed (or 64 hex characters).
   * @param {Uint8Array|string} seed
   * @returns {Promise<Identity>}
   */
  static async fromSeed(seed) {
    const bytes =
      typeof seed === 'string' ? hexToBytes(seed) : seed instanceof Uint8Array ? seed : null;
    if (!bytes || bytes.length !== 32) {
      throw new NauClientError('seed must be exactly 32 bytes (or 64 hex characters)');
    }
    const pkcs8 = concatBytes(hexToBytes(PKCS8_ED25519_PREFIX_HEX), bytes);
    // `extractable: true` is required because a PKCS#8 Ed25519 key carries no
    // public part; the JWK export below is the only portable way to recover it.
    const privateKey = await subtleCrypto().subtle.importKey(
      'pkcs8',
      pkcs8,
      { name: 'Ed25519' },
      true,
      ['sign'],
    );
    const jwk = await subtleCrypto().subtle.exportKey('jwk', privateKey);
    if (!jwk || typeof jwk.x !== 'string') {
      throw new NauClientError(
        'this WebCrypto implementation does not expose the Ed25519 public key via a JWK export',
      );
    }
    const publicKey = base64UrlToBytes(jwk.x);
    if (publicKey.length !== PUBLIC_KEY_BYTES) {
      throw new NauClientError(`unexpected raw public key length ${publicKey.length}`);
    }
    return new Identity(bytes, privateKey, publicKey).ready();
  }

  /**
   * Derive from an identity export (`{seed_hex}` or `{seedHex}`) — the shape
   * `client/src-tauri` and a README example use, so an identity can be restored.
   * @param {{seed_hex?: string, seedHex?: string}} exported
   * @returns {Promise<Identity>}
   */
  static async fromExport(exported) {
    const hex = exported && (exported.seed_hex ?? exported.seedHex);
    if (typeof hex !== 'string') throw new NauClientError('expected {seed_hex} or {seedHex}');
    return Identity.fromSeed(hex);
  }

  /** @returns {Promise<Identity>} a fresh random identity */
  static async generate() {
    return Identity.fromSeed(randomSeed());
  }

  /**
   * The DID, computed by {@link Identity.ready}, which every factory awaits.
   * @returns {string}
   */
  get did() {
    if (this._did === undefined) {
      throw new NauClientError('Identity DIDs are built by the async factories; call Identity.fromSeed');
    }
    return this._did;
  }

  /**
   * Attach the `did:nau:` fingerprint. SHA-256 is async in WebCrypto, so this
   * cannot happen in the constructor; the async factories await it.
   * @returns {Promise<Identity>}
   */
  async ready() {
    const digest = await sha256(this.publicKey);
    this._did = `did:nau:${bytesToHex(digest.slice(0, DID_FINGERPRINT_BYTES))}`;
    return this;
  }

  /**
   * @param {Uint8Array} message
   * @returns {Promise<Uint8Array>} 64-byte signature
   */
  async sign(message) {
    const sig = await subtleCrypto().subtle.sign({ name: 'Ed25519' }, this.privateKey, message);
    return new Uint8Array(sig);
  }

  /**
   * Sign the canonical payload of `obj`, dropping `signature` at every depth.
   * @param {object} obj
   * @returns {Promise<string>} lowercase hex signature
   */
  async signPayload(obj) {
    return bytesToHex(await this.sign(canonicalPayload(obj)));
  }

  /**
   * Sign an object and return a copy carrying the hex `signature` field.
   * @param {object} obj
   * @returns {Promise<object>}
   */
  async signObject(obj) {
    const signature = await this.signPayload(obj);
    return { ...obj, signature };
  }

  /**
   * Verify a detached signature with this identity's public key.
   * @param {object} obj
   * @param {string} signatureHex
   * @returns {Promise<boolean>}
   */
  async verifyPayload(obj, signatureHex) {
    const key = await subtleCrypto().subtle.importKey(
      'raw',
      this.publicKey,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    const ok = await subtleCrypto().subtle.verify(
      { name: 'Ed25519' },
      key,
      hexToBytes(signatureHex),
      canonicalPayload(obj),
    );
    return ok === true;
  }

  /**
   * The portable form of this identity: the seed is the secret, the public key
   * and DID are derived. Shown in the UI so a session can be reproduced.
   * @returns {{seed_hex: string, public_key_hex: string, did: string}}
   */
  export() {
    return {
      seed_hex: bytesToHex(this.seed),
      public_key_hex: this.publicKeyHex,
      did: this.didValue,
    };
  }
}

/**
 * Decode a base64url string (no padding) to bytes — the encoding a JWK member
 * uses.
 *
 * @param {string} text
 * @returns {Uint8Array}
 */
function base64UrlToBytes(text) {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded.padEnd(padded.length + ((4 - (padded.length % 4)) % 4), '='));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

// --------------------------------------------------------------- money helpers

const DECIMAL_AMOUNT_RE = /^-?(0|[1-9][0-9]*)(\.[0-9]{1,6})?$/;

/**
 * Parse a decimal amount string into exact integer minor units.
 *
 * Floats are never produced: `"12.5"` becomes `12500000`. The daemon refuses a
 * JSON float for the same reason the canonical layer does (a float does not
 * survive a round trip through Rust, Python and JavaScript), and the UI must
 * therefore never *send* one — see the deliberate "try a float" affordance,
 * which sends `12.5` as a JSON number precisely so the 422 is visible.
 *
 * @param {string} text
 * @returns {number} minor units
 */
export function parseDecimalAmount(text) {
  if (typeof text !== 'string') throw new NauClientError('an amount must be a string');
  const trimmed = text.trim();
  if (!DECIMAL_AMOUNT_RE.test(trimmed)) {
    throw new NauClientError(
      `"${text}" is not a decimal amount (at most six decimal places, no exponent)`,
    );
  }
  const negative = trimmed.startsWith('-');
  const unsigned = negative ? trimmed.slice(1) : trimmed;
  const [whole, frac = ''] = unsigned.split('.');
  const minor = Number(whole) * MINOR_UNITS_PER_MAJOR + Number(frac.padEnd(6, '0'));
  if (!Number.isSafeInteger(minor)) throw new NauClientError(`"${text}" is out of range`);
  return negative ? -minor : minor;
}

/**
 * Render exact minor units as a decimal string (the daemon's wire form).
 * @param {number} minor
 * @returns {string}
 */
export function formatMinor(minor) {
  const negative = minor < 0;
  const abs = Math.abs(minor);
  const whole = Math.floor(abs / MINOR_UNITS_PER_MAJOR);
  const frac = String(abs % MINOR_UNITS_PER_MAJOR).padStart(6, '0');
  const trimmed = frac.replace(/0+$/, '');
  const text = trimmed.length > 0 ? `${whole}.${trimmed}` : String(whole);
  return negative ? `-${text}` : text;
}

// ------------------------------------------------------------ domain payloads

/**
 * An agent card draft matching `crates/nau-core/src/domain/agent.rs`.
 *
 * `stake` is money and therefore travels as integer minor units — the same
 * `#[serde(transparent)]` integer the daemon expects.
 *
 * @param {object} input
 * @param {Identity} input.identity
 * @param {string} input.name
 * @param {string[]} input.skills
 * @param {number} input.stakeMinor
 * @param {number} [input.nonce]
 * @param {number} [input.signedAt]
 * @returns {object} the unsigned payload
 */
export function agentCardDraft({ identity, name, skills, stakeMinor, nonce, signedAt }) {
  if (!Array.isArray(skills) || skills.length === 0) {
    throw new NauClientError('an agent card needs at least one skill');
  }
  return {
    owner: identity.did,
    owner_key: identity.publicKeyHex,
    name,
    category: 'general',
    skills: skills.map((id) => ({ id: id.toLowerCase(), version: 1 })),
    pricing: { model: 'auction', unit_price: 0, unit: 'task' },
    sla: { latency_p95_ms: 2_000, availability_bps: 9_500, max_concurrency: 10 },
    stake: stakeMinor,
    endpoints: [],
    signed_at: signedAt ?? nowSeconds(),
    nonce: nonce ?? nextNonce(),
    signature: '',
  };
}

/**
 * A `Task` draft matching `crates/nau-core/src/domain/task.rs`.
 *
 * @param {object} input
 * @param {string} input.id
 * @param {Identity} input.requester
 * @param {string} input.goal
 * @param {string} input.context
 * @param {string[]} input.done
 * @param {string[]} input.todo
 * @param {string[]} input.requiredSkills
 * @param {number} input.budgetMinor
 * @param {{n: number, f: number}} [input.committee]
 * @param {number} [input.deadline]
 * @param {number} [input.nonce]
 * @param {number} [input.signedAt]
 * @returns {object}
 */
export function taskDraft({
  id,
  requester,
  goal,
  context,
  done,
  todo,
  requiredSkills,
  budgetMinor,
  committee = { n: 3, f: 0 },
  deadline,
  nonce,
  signedAt,
}) {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) {
    throw new NauClientError('a task id may only contain ASCII letters, digits, `-` and `_`');
  }
  return {
    id,
    spec: {
      goal,
      context,
      done,
      todo,
      owner: requester.did,
    },
    required_skills: requiredSkills,
    budget: budgetMinor,
    deadline: deadline ?? null,
    verification: { kind: 'committee', n: committee.n, f: committee.f },
    state: 'open',
    requester_key: requester.publicKeyHex,
    nonce: nonce ?? nextNonce(),
    signed_at: signedAt ?? nowSeconds(),
    signature: '',
  };
}

/**
 * A `Bid` draft.
 * @param {object} input
 * @param {string} input.taskId
 * @param {Identity} input.bidder
 * @param {number} input.priceMinor
 * @param {number} [input.etaSecs]
 * @param {number} [input.confidenceBps]
 * @param {number} [input.nonce]
 * @param {number} [input.signedAt]
 * @returns {object}
 */
export function bidDraft({
  taskId,
  bidder,
  priceMinor,
  etaSecs = 30,
  confidenceBps = 9_000,
  nonce,
  signedAt,
}) {
  return {
    task_id: taskId,
    bidder: bidder.did,
    bidder_key: bidder.publicKeyHex,
    price: priceMinor,
    eta_secs: etaSecs,
    confidence_bps: confidenceBps,
    nonce: nonce ?? nextNonce(),
    signed_at: signedAt ?? nowSeconds(),
    signature: '',
  };
}

/**
 * A `ResultEnvelope` draft. The digest is computed from the output text with
 * SHA-256, so the value is real rather than a placeholder.
 * @param {object} input
 * @param {string} input.taskId
 * @param {Identity} input.agent
 * @param {string} input.summary
 * @param {string} input.output
 * @param {'verified'|'cpu_proto'|'unverified'} [input.evidence]
 * @param {number} [input.latencyMs]
 * @param {number} [input.nonce]
 * @param {number} [input.signedAt]
 * @returns {Promise<object>}
 */
export async function resultDraft({
  taskId,
  agent,
  summary,
  output,
  evidence = 'verified',
  latencyMs = 1_500,
  nonce,
  signedAt,
}) {
  const digest = bytesToHex(await sha256(new TextEncoder().encode(output)));
  return {
    task_id: taskId,
    agent: agent.did,
    agent_key: agent.publicKeyHex,
    output_digest: digest,
    summary,
    evidence,
    latency_ms: latencyMs,
    nonce: nonce ?? nextNonce(),
    signed_at: signedAt ?? nowSeconds(),
    signature: '',
  };
}

/**
 * A signed committee `Vote` (see `crates/nau-consensus/src/vote.rs`).
 *
 * The decision serializes as Rust's default enum representation: `"Accept"`.
 * @param {object} input
 * @param {string} input.proposal the task id
 * @param {Identity} input.voter
 * @param {'Accept'|'Reject'} [input.decision]
 * @param {number} [input.round]
 * @param {number} [input.nonce]
 * @param {number} [input.signedAt]
 * @returns {Promise<object>}
 */
export async function voteDraft({
  proposal,
  voter,
  decision = 'Accept',
  round = 0,
  nonce,
  signedAt,
}) {
  return {
    round,
    proposal,
    voter: voter.did,
    voter_key: voter.publicKeyHex,
    decision,
    nonce: nonce ?? nextNonce(),
    signed_at: signedAt ?? nowSeconds(),
    signature: '',
  };
}

// ------------------------------------------------------------------ HTTP layer

/**
 * Validate one path segment before it enters a request target.
 *
 * Percent-encoding is deliberately **not** used here: a DID or a task id is
 * already URL-safe (`[A-Za-z0-9_.:-]`), and `encodeURIComponent` would send
 * `did%3Anau%3A…`, which the daemon correctly refuses with a `422` because a
 * percent-encoded DID is not a DID. A value that is not safe is a programming
 * error, so it throws rather than silently producing a request the server will
 * reject for a confusing reason.
 *
 * @param {string} segment
 * @param {string} what
 * @returns {string}
 */
export function pathSegment(segment, what = 'path segment') {
  if (typeof segment !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(segment)) {
    throw new NauClientError(
      `${what} ${JSON.stringify(segment)} contains characters that are not valid in a request path`,
    );
  }
  return segment;
}

/**
 * A minimal JSON HTTP client for the daemon.
 *
 * `baseUrl` defaults to `/api`, which is the same origin the page was served
 * from; `client/serve.mjs` proxies `/api/*` to the daemon. One origin means CORS
 * never enters the picture, which is why the daemon needs no CORS headers and
 * why nothing here can be defeated by a preflight.
 */
export class NauClient {
  /** @param {string} [baseUrl] */
  constructor(baseUrl = '/api') {
    /** @type {string} */
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  /**
   * Perform one request.
   *
   * Never swallows an error: a non-2xx status becomes a thrown
   * {@link NauApiError} carrying the status, the machine-readable code and the
   * server's message, which is what the UI prints.
   *
   * @param {string} method
   * @param {string} path
   * @param {object|null} [body]
   * @returns {Promise<any>}
   */
  async request(method, path, body = null) {
    const url = `${this.baseUrl}${path}`;
    const init = { method, headers: { accept: 'application/json' } };
    if (body !== null && body !== undefined) {
      init.headers['content-type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    let response;
    try {
      response = await fetch(url, init);
    } catch (cause) {
      throw new NauClientError(
        `${method} ${path} could not reach the daemon (${cause && cause.message ? cause.message : cause})`,
      );
    }
    const rawText = await response.text();
    let parsed = null;
    if (rawText.length > 0) {
      try {
        parsed = JSON.parse(rawText);
      } catch {
        parsed = null;
      }
    }
    if (!response.ok) {
      throw new NauApiError(response.status, method, path, parsed, rawText);
    }
    return parsed;
  }

  /** `GET /health` — version, protocol and market counters. */
  health() {
    return this.request('GET', '/health');
  }

  /** `GET /stats` */
  stats() {
    return this.request('GET', '/stats');
  }

  /** `GET /conservation` — the O(1) invariant check. */
  conservation() {
    return this.request('GET', '/conservation');
  }

  /** `GET /audit` — the independent O(N) recomputation. */
  audit() {
    return this.request('GET', '/audit');
  }

  /** `GET /leaderboard?limit=N` */
  leaderboard(limit = 10) {
    return this.request('GET', `/leaderboard?limit=${encodeURIComponent(String(limit))}`);
  }

  /** `GET /agents?skill=` | `?q=` | all. */
  agents({ skill, q } = {}) {
    const query = skill
      ? `?skill=${encodeURIComponent(skill)}`
      : q
        ? `?q=${encodeURIComponent(q)}`
        : '';
    return this.request('GET', `/agents${query}`);
  }

  /** `GET /agents/{did}` */
  agent(did) {
    return this.request('GET', `/agents/${pathSegment(did, 'a DID')}`);
  }

  /** `POST /agents` with a signed card. */
  registerAgent(card) {
    return this.request('POST', '/agents', card);
  }

  /** `GET /tasks` */
  tasks() {
    return this.request('GET', '/tasks');
  }

  /** `GET /tasks/{id}` */
  task(id) {
    return this.request('GET', `/tasks/${pathSegment(id, 'a task id')}`);
  }

  /** `POST /tasks` with a signed task. */
  publishTask(task) {
    return this.request('POST', '/tasks', task);
  }

  /**
   * `POST /tasks/{id}/bids` with a signed bid.
   * @param {string} taskId
   * @param {object} bid
   */
  submitBid(taskId, bid) {
    return this.request('POST', `/tasks/${pathSegment(taskId, 'a task id')}/bids`, { bid });
  }

  /** `POST /tasks/{id}/match` */
  matchTask(taskId) {
    return this.request('POST', `/tasks/${pathSegment(taskId, 'a task id')}/match`, {});
  }

  /** `POST /tasks/{id}/start` */
  startTask(taskId, executor) {
    return this.request('POST', `/tasks/${pathSegment(taskId, 'a task id')}/start`, { executor });
  }

  /** `POST /tasks/{id}/results` with a signed envelope. */
  submitResult(taskId, envelope) {
    return this.request('POST', `/tasks/${pathSegment(taskId, 'a task id')}/results`, { envelope });
  }

  /**
   * `POST /tasks/{id}/verify` with the assigned member set and their **signed**
   * votes. There is deliberately no `approvals` count: the caller cannot supply
   * its own tally.
   */
  verifyTask(taskId, members, votes) {
    return this.request('POST', `/tasks/${pathSegment(taskId, 'a task id')}/verify`, {
      members,
      votes,
    });
  }

  /** `POST /tasks/{id}/settle` */
  settleTask(taskId) {
    return this.request('POST', `/tasks/${pathSegment(taskId, 'a task id')}/settle`, {});
  }

  /** `GET /accounts/{account}/balance` */
  balance(account) {
    return this.request('GET', `/accounts/${pathSegment(account, 'an account id')}/balance`);
  }

  /**
   * `POST /accounts/{account}/deposit` with a decimal **string** amount.
   * @param {string} account
   * @param {string} amount e.g. `"12.5"`
   */
  deposit(account, amount) {
    return this.request('POST', `/accounts/${pathSegment(account, 'an account id')}/deposit`, {
      amount,
    });
  }

  /**
   * The deliberate float probe: sends the amount as a JSON **number**, which the
   * daemon refuses with `422`. The UI shows the refusal rather than hiding it,
   * because "why can I not send 12.5 as a number?" is the question this answers.
   * @param {string} account
   * @param {number} amount
   */
  depositFloat(account, amount) {
    return this.request('POST', `/accounts/${pathSegment(account, 'an account id')}/deposit`, {
      amount,
    });
  }
}

/**
 * Render any thrown value as a single visible line, including the HTTP status
 * when there is one. app.js feeds this into `textContent`; nothing here ever
 * becomes HTML.
 * @param {unknown} error
 * @returns {string}
 */
export function describeError(error) {
  if (error instanceof NauApiError) {
    const allow = error.allow.length > 0 ? ` (allowed: ${error.allow.join(', ')})` : '';
    return `HTTP ${error.status} ${error.code}${allow}: ${error.serverMessage}`;
  }
  if (error instanceof Error) return `${error.name}: ${error.message}`;
  return String(error);
}
