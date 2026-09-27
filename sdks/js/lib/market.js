/**
 * HTTP client for the agent market.
 *
 * Uses the global `fetch` that ships with Node 18+, so there is no dependency
 * and no install step. Two rules come straight from upstream defects:
 *
 * * every HTTP status >= 400 throws a {@link MarketError} carrying the status
 *   and the server's message — never a bare `undefined`;
 * * a non-JSON error body (an HTML 502 from a proxy, an empty body) must not
 *   produce a raw `SyntaxError`; the text is carried on the error instead.
 */

import { NauError } from './errors.js';

/** The market refused a request, or the transport failed. */
export class MarketError extends NauError {
  /**
   * @param {number} status HTTP status (0 when the transport itself failed)
   * @param {string} message
   * @param {{body?: unknown, route?: string, cause?: unknown}} [options]
   */
  constructor(status, message, options = {}) {
    super(`market request failed (${status}): ${message}`, {
      code: 'market_error',
      cause: options.cause,
    });
    /** @type {number} */
    this.status = status;
    /** @type {string} the server-supplied message. */
    this.detail = message;
    /** @type {unknown} parsed body when it was JSON, else the raw text. */
    this.body = options.body;
    /** @type {string|undefined} the route that failed. */
    this.route = options.route;
  }
}

/** Default route table. Override per endpoint in the constructor. */
export const MARKET_ROUTES = Object.freeze({
  health: ['GET', '/health'],
  deposit: ['POST', '/v1/accounts/deposit'],
  balance: ['GET', '/v1/accounts/{account}/balance'],
  registerAgent: ['POST', '/v1/agents'],
  getAgent: ['GET', '/v1/agents/{did}'],
  discover: ['GET', '/v1/agents/discover'],
  search: ['GET', '/v1/agents/search'],
  publishTask: ['POST', '/v1/tasks'],
  getTask: ['GET', '/v1/tasks/{taskId}'],
  listTasks: ['GET', '/v1/tasks'],
  submitBid: ['POST', '/v1/tasks/{taskId}/bids'],
  matchTask: ['POST', '/v1/tasks/{taskId}/match'],
  submitResult: ['POST', '/v1/tasks/{taskId}/result'],
  verifyResult: ['POST', '/v1/tasks/{taskId}/result/verify'],
  settleTask: ['POST', '/v1/tasks/{taskId}/settle'],
  openDispute: ['POST', '/v1/tasks/{taskId}/dispute'],
  arbitrate: ['POST', '/v1/tasks/{taskId}/arbitrate'],
  conservation: ['GET', '/v1/ledger/conservation'],
  leaderboard: ['GET', '/v1/leaderboard'],
  stats: ['GET', '/v1/stats'],
});

/**
 * Strip `undefined` values and stringify the rest for a query string.
 *
 * @param {object|null} [query]
 * @returns {string}
 */
function toQuery(query) {
  if (query === null || query === undefined) return '';
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (const item of value) params.append(key, String(item));
    } else params.append(key, String(value));
  }
  const text = params.toString();
  return text.length === 0 ? '' : `?${text}`;
}

/**
 * Render a route template such as `/v1/agents/{did}`.
 *
 * @param {string} template
 * @param {Record<string, string>} values
 * @returns {string}
 */
function renderRoute(template, values) {
  return template.replace(/\{(\w+)\}/g, (_, name) => {
    const value = values[name];
    if (value === undefined || value === null || value === '') {
      throw new MarketError(0, `route parameter ${name} is required for ${template}`, { route: template });
    }
    return encodeURIComponent(String(value));
  });
}

/**
 * A client for the agent market HTTP API.
 */
export class MarketClient {
  /**
   * @param {string} [baseUrl]
   * @param {{timeoutMs?: number, headers?: Record<string, string>,
   *   fetch?: typeof fetch, routes?: Record<string, [string, string]>}} [options]
   */
  constructor(baseUrl = 'http://127.0.0.1:8080', options = {}) {
    if (typeof baseUrl !== 'string' || baseUrl.length === 0) {
      throw new TypeError('MarketClient needs a base URL');
    }
    /** @type {string} */
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    /** @type {number} */
    this.timeoutMs = options.timeoutMs ?? 30000;
    /** @type {Record<string, string>} */
    this.headers = { accept: 'application/json', 'content-type': 'application/json', ...options.headers };
    /** @type {typeof fetch} */
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof this.fetchImpl !== 'function') {
      throw new MarketError(0, 'no global fetch available; pass options.fetch');
    }    /** @type {Record<string, [string, string]>} */
    this.routes = { ...MARKET_ROUTES, ...options.routes };
    /** @type {number} */
    this.requestCount = 0;
  }

  /**
   * Perform one request.
   *
   * @param {string} route key of {@link MARKET_ROUTES}
   * @param {{params?: Record<string, string>, query?: object|null, body?: unknown}} [options]
   * @returns {Promise<any>}
   * @throws {MarketError}
   */
  async request(route, options = {}) {
    const entry = this.routes[route];
    if (entry === undefined) throw new MarketError(0, `unknown route ${JSON.stringify(route)}`);
    const [method, template] = entry;
    const pathname = renderRoute(template, options.params ?? {});
    const url = `${this.baseUrl}${pathname}${toQuery(options.query)}`;
    /** @type {RequestInit} */
    const init = { method, headers: { ...this.headers } };
    if (options.body !== undefined && method !== 'GET' && method !== 'HEAD') {
      init.body = JSON.stringify(options.body ?? null);
    }
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    if (controller !== null && this.timeoutMs > 0) {
      init.signal = controller.signal;
      setTimeout(() => controller.abort(), this.timeoutMs).unref?.();
    }
    this.requestCount += 1;
    let response;
    try {
      response = await this.fetchImpl(url, init);
    } catch (err) {
      controller?.abort();
      throw new MarketError(
        0,
        `transport failure for ${method} ${pathname}: ${err instanceof Error ? err.message : String(err)}`,
        { route, cause: err },
      );
    }
    return MarketClient.parseResponse(response, route, method, pathname);
  }

  /**
   * Turn a `Response` into a value, or into a {@link MarketError}.
   *
   * @param {Response} response
   * @param {string} route
   * @param {string} [method]
   * @param {string} [pathname]
   * @returns {Promise<any>}
   */
  static async parseResponse(response, route, method = '', pathname = '') {
    const status = response.status;
    const text = await response.text().catch(() => '');
    let parsed;
    let parseFailed = false;
    if (text.length === 0) parsed = null;
    else {
      try {
        parsed = JSON.parse(text);
      } catch {
        parseFailed = true;
        parsed = text;
      }
    }
    if (status >= 400) {
      // A JSON body's `message`/`error`/`detail` field is the server's own
      // wording; a non-JSON body (an HTML 502 from a proxy, a plain-text error)
      // is reported verbatim instead of being parsed.
      const wireMessage = parsed !== null && typeof parsed === 'object'
        ? parsed.message ?? parsed.error ?? parsed.detail
        : undefined;
      const detail = wireMessage !== undefined
        ? String(wireMessage)
        : parseFailed
          ? `server returned ${status} with a non-JSON body: ${truncate(text)}`
          : `server returned ${status}`;
      throw new MarketError(status, `${detail} [${method} ${pathname}]`.trim(), { body: parsed, route });
    }
    if (text.length === 0) return null;
    if (parseFailed) {
      throw new MarketError(
        status,
        `expected JSON but got a non-JSON body: ${truncate(text)} [${method} ${pathname}]`.trim(),
        { body: text, route },
      );
    }
    return parsed;
  }

  /** @returns {Promise<any>} */
  health() {
    return this.request('health');
  }

  /**
   * @param {{account: string, amountMinor: number|bigint|string, currency?: string,
   *   reference?: string|null, signature?: string}} body
   * @returns {Promise<any>}
   */
  deposit(body) {
    return this.request('deposit', { body: normalizeMoneyFields(body) });
  }

  /**
   * @param {string} account
   * @returns {Promise<any>}
   */
  balance(account) {
    return this.request('balance', { params: { account } });
  }

  /**
   * @param {object|import('./models.js').AgentCard} card
   * @returns {Promise<any>}
   */
  registerAgent(card) {
    return this.request('registerAgent', { body: toWire(card) });
  }

  /**
   * @param {string} did
   * @returns {Promise<any>}
   */
  getAgent(did) {
    return this.request('getAgent', { params: { did } });
  }

  /**
   * @param {{capability?: string, capabilities?: string[], minStakeMinor?: number|bigint,
   *   limit?: number, offset?: number, sort?: string}} [query]
   * @returns {Promise<any>}
   */
  discover(query = {}) {
    const { minStakeMinor, ...rest } = query;
    return this.request('discover', {
      query: { ...rest, min_stake_minor: minStakeMinor },
    });
  }

  /**
   * @param {string} text free-text query
   * @param {{limit?: number, offset?: number}} [options]
   * @returns {Promise<any>}
   */
  search(text, options = {}) {
    return this.request('search', { query: { q: text, ...options } });
  }

  /**
   * @param {object} body task specification (plus optional reward)
   * @returns {Promise<any>}
   */
  publishTask(body) {
    return this.request('publishTask', { body: normalizeMoneyFields(body) });
  }

  /**
   * @param {string} taskId
   * @returns {Promise<any>}
   */
  getTask(taskId) {
    return this.request('getTask', { params: { taskId } });
  }

  /**
   * @param {{state?: string, publisherDid?: string, workerDid?: string,
   *   limit?: number, offset?: number}} [query]
   * @returns {Promise<any>}
   */
  listTasks(query = {}) {
    const { publisherDid, workerDid, ...rest } = query;
    return this.request('listTasks', {
      query: { ...rest, publisher_did: publisherDid, worker_did: workerDid },
    });
  }

  /**
   * @param {string} taskId
   * @param {object|import('./models.js').Bid} bid
   * @returns {Promise<any>}
   */
  submitBid(taskId, bid) {
    return this.request('submitBid', { params: { taskId }, body: toWire(bid) });
  }

  /**
   * @param {string} taskId
   * @param {{workerDid?: string, bidId?: string, priceMinor?: number|bigint}} [body]
   * @returns {Promise<any>}
   */
  matchTask(taskId, body = {}) {
    return this.request('matchTask', { params: { taskId }, body: normalizeMoneyFields(body) });
  }

  /**
   * @param {string} taskId
   * @param {object|import('./models.js').ResultEnvelope} result
   * @returns {Promise<any>}
   */
  submitResult(taskId, result) {
    return this.request('submitResult', { params: { taskId }, body: toWire(result) });
  }

  /**
   * @param {string} taskId
   * @param {{outputHash?: string, evidenceGrade?: string, verifierDid?: string,
   *   approve?: boolean}} [body]
   * @returns {Promise<any>}
   */
  verifyResult(taskId, body = {}) {
    return this.request('verifyResult', { params: { taskId }, body });
  }

  /**
   * @param {string} taskId
   * @param {{outcome?: string, payoutMinor?: number|bigint, slashedMinor?: number|bigint}} [body]
   * @returns {Promise<any>}
   */
  settleTask(taskId, body = {}) {
    return this.request('settleTask', { params: { taskId }, body: normalizeMoneyFields(body) });
  }

  /**
   * @param {string} taskId
   * @param {object|import('./models.js').Dispute} dispute
   * @returns {Promise<any>}
   */
  openDispute(taskId, dispute) {
    return this.request('openDispute', { params: { taskId }, body: toWire(dispute) });
  }

  /**
   * @param {string} taskId
   * @param {{ruling?: string, slashMinor?: number|bigint, payoutMinor?: number|bigint,
   *   arbiterDid?: string, rationale?: string}} [body]
   * @returns {Promise<any>}
   */
  arbitrate(taskId, body = {}) {
    return this.request('arbitrate', { params: { taskId }, body: normalizeMoneyFields(body) });
  }

  /**
   * @param {{account?: string}} [query]
   * @returns {Promise<any>}
   */
  conservation(query = {}) {
    return this.request('conservation', { query });
  }

  /**
   * @param {{limit?: number, capability?: string, sinceUnix?: number}} [query]
   * @returns {Promise<any>}
   */
  leaderboard(query = {}) {
    const { sinceUnix, ...rest } = query;
    return this.request('leaderboard', { query: { ...rest, since_unix: sinceUnix } });
  }

  /** @returns {Promise<any>} */
  stats() {
    return this.request('stats');
  }
}

/**
 * @param {unknown} value
 * @returns {unknown}
 */
function toWire(value) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'object' && typeof (/** @type {any} */ (value).toPayload) === 'function') {
    return /** @type {any} */ (value).toPayload();
  }
  return value;
}

/**
 * Wire spelling of every camelCase money-ish input key.
 *
 * The wire format is snake_case minor units; callers may use either spelling.
 */
const WIRE_KEYS = Object.freeze({
  amountMinor: 'amount_minor',
  priceMinor: 'price_minor',
  payoutMinor: 'payout_minor',
  slashedMinor: 'slashed_minor',
  slashMinor: 'slash_minor',
  bondMinor: 'bond_minor',
  costMinor: 'cost_minor',
  rewardMinor: 'reward_minor',
  penaltyMinor: 'penalty_minor',
  stakeMinor: 'stake_minor',
  maxPriceMinor: 'max_price_minor',
  minStakeMinor: 'min_stake_minor',
  amount_minor: 'amount_minor',
  price_minor: 'price_minor',
  payout_minor: 'payout_minor',
  slashed_minor: 'slashed_minor',
  slash_minor: 'slash_minor',
  bond_minor: 'bond_minor',
  cost_minor: 'cost_minor',
  reward_minor: 'reward_minor',
  penalty_minor: 'penalty_minor',
  stake_minor: 'stake_minor',
  max_price_minor: 'max_price_minor',
  min_stake_minor: 'min_stake_minor',
});

/** Other camelCase -> snake_case renames the wire format expects. */
const WIRE_ALIASES = Object.freeze({
  publisherDid: 'publisher_did',
  workerDid: 'worker_did',
  bidderDid: 'bidder_did',
  challengerDid: 'challenger_did',
  verifierDid: 'verifier_did',
  arbiterDid: 'arbiter_did',
  taskId: 'task_id',
  bidId: 'bid_id',
  evidenceGrade: 'evidence_grade',
  outputHash: 'output_hash',
  outputSchema: 'output_schema',
  deadlineUnix: 'deadline_unix',
  startedUnix: 'started_unix',
  finishedUnix: 'finished_unix',
  openedUnix: 'opened_unix',
  etaSeconds: 'eta_seconds',
  sinceUnix: 'since_unix',
  createdAt: 'created_at',
});

/**
 * Convert money-ish and camelCase fields inside an ad-hoc request body to wire
 * values.
 *
 * Money becomes an integer minor-unit count: a `Money` instance is unwrapped to
 * its `BigInt`, and a `BigInt` becomes a decimal string so `JSON.stringify`
 * cannot throw on it. Safe integers stay integers.
 *
 * @param {unknown} body
 * @returns {any}
 */
function normalizeMoneyFields(body) {
  if (body === null || typeof body !== 'object') return body;
  if (Array.isArray(body)) return body.map(normalizeMoneyFields);
  if (typeof (/** @type {any} */ (body).toPayload) === 'function') {
    return normalizeMoneyFields(/** @type {any} */ (body).toPayload());
  }
  const out = {};
  for (const [rawKey, value] of Object.entries(body)) {
    if (value === undefined) continue;
    const key = WIRE_KEYS[rawKey] ?? WIRE_ALIASES[rawKey] ?? rawKey;
    if (value !== null && typeof value === 'object' && typeof (/** @type {any} */ (value).minorBigInt) === 'function') {
      out[key] = wireMinor(/** @type {any} */ (value).minorBigInt());
    } else if (typeof value === 'bigint') {
      out[key] = wireMinor(value);
    } else if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      out[key] = normalizeMoneyFields(value);
    } else if (Array.isArray(value)) {
      out[key] = value.map(normalizeMoneyFields);
    } else out[key] = value;
  }
  return out;
}

/**
 * A minor-unit count on the wire: an integer when it is safe, a string when it
 * is not (and always a string for a value that arrived as a BigInt).
 *
 * @param {bigint|number} minor
 * @returns {number|string}
 */
function wireMinor(minor) {
  const value = typeof minor === 'bigint' ? minor : BigInt(minor);
  if (value <= BigInt(Number.MAX_SAFE_INTEGER) && value >= BigInt(Number.MIN_SAFE_INTEGER)) {
    return Number(value);
  }
  return value.toString();
}

/**
 * @param {string} text
 * @param {number} [max]
 * @returns {string}
 */
function truncate(text, max = 200) {
  const flat = text.replace(/\s+/g, ' ').trim();
  return flat.length <= max ? flat : `${flat.slice(0, max)}…`;
}

export default MarketClient;
