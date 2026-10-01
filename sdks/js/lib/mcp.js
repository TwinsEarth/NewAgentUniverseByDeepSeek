/**
 * Minimal MCP (Model Context Protocol) HTTP client.
 *
 * Transport: JSON-RPC 2.0 over HTTP POST, the "streamable HTTP" shape used by
 * MCP 2024-11-05. A server may answer either with `application/json` or with an
 * SSE stream (`text/event-stream`), so both are accepted.
 *
 * The handshake is `initialize` -> `notifications/initialized` (a notification,
 * so no response is awaited) -> ordinary calls.
 *
 * Defect fixed here: upstream parsed every response body with `JSON.parse`
 * unconditionally, so a 200 with an HTML or empty body threw a raw
 * `SyntaxError` from deep inside the transport. A non-JSON response now throws
 * {@link McpError} with the status and a snippet of the body.
 */

import { NauError } from './errors.js';

/** The MCP revision implemented by this client. */
export const MCP_PROTOCOL_VERSION = '2024-11-05';

/** The JSON-RPC revision used by MCP. */
export const JSONRPC_VERSION = '2.0';

/** Header carrying the negotiated session id (and its legacy spelling). */
export const MCP_SESSION_HEADER = 'mcp-session-id';
export const MCP_SESSION_HEADER_LEGACY = 'Mcp-Session-Id';

/** The MCP transport or server reported a failure. */
export class McpError extends NauError {
  /**
   * @param {number} status HTTP status, or 0 for a transport/parse failure
   * @param {string} message
   * @param {{code?: number, data?: unknown, body?: unknown, route?: string,
   *   cause?: unknown}} [options]
   */
  constructor(status, message, options = {}) {
    super(`mcp request failed (${status}): ${message}`, {
      code: 'mcp_error',
      cause: options.cause,
    });
    /** @type {number} */
    this.status = status;
    /** @type {string} */
    this.detail = message;
    /** @type {number|undefined} JSON-RPC error code, when the server sent one. */
    this.rpcCode = options.code;
    /** @type {unknown} JSON-RPC `error.data`. */
    this.data = options.data;
    /** @type {unknown} raw body, when there was one. */
    this.body = options.body;
    /** @type {string|undefined} */
    this.route = options.route;
  }
}

/**
 * A JSON-RPC error object turned into an {@link McpError}.
 *
 * @param {any} error
 * @param {string} route
 * @returns {McpError}
 */
function rpcError(error, route) {
  const code = typeof error?.code === 'number' ? error.code : undefined;
  const message = typeof error?.message === 'string' ? error.message : JSON.stringify(error);
  return new McpError(200, `JSON-RPC error ${code ?? '?'}: ${message}`, {
    code,
    data: error?.data,
    body: error,
    route,
  });
}

/**
 * Extract JSON-RPC messages from a `text/event-stream` body.
 *
 * @param {string} text
 * @returns {any[]}
 */
export function parseSse(text) {
  const messages = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    const dataLines = [];
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith('data:')) dataLines.push(line.slice(5).trimStart());
    }
    if (dataLines.length === 0) continue;
    const payload = dataLines.join('\n');
    if (payload.length === 0 || payload === '[DONE]') continue;
    try {
      messages.push(JSON.parse(payload));
    } catch {
      throw new McpError(200, `SSE frame was not JSON: ${truncate(payload)}`, { body: payload });
    }
  }
  return messages;
}

/**
 * An MCP client over streamable HTTP.
 */
export class McpHttpClient {
  /**
   * @param {string} [baseUrl]
   * @param {{timeoutMs?: number, headers?: Record<string, string>,
   *   fetch?: typeof fetch, clientName?: string, clientVersion?: string,
   *   protocolVersion?: string, capabilities?: object}} [options]
   */
  constructor(baseUrl = 'http://127.0.0.1:8081/mcp', options = {}) {
    if (typeof baseUrl !== 'string' || baseUrl.length === 0) {
      throw new TypeError('McpHttpClient needs a base URL');
    }
    /** @type {string} */
    this.baseUrl = baseUrl;
    /** @type {number} */
    this.timeoutMs = options.timeoutMs ?? 30000;
    /** @type {Record<string, string>} */
    this.headers = options.headers ?? {};
    /** @type {typeof fetch} */
    this.fetchImpl = options.fetch !== undefined ? options.fetch : globalThis.fetch;
    if (typeof this.fetchImpl !== 'function') {
      throw new McpError(0, 'no global fetch available; pass options.fetch');
    }
    /** @type {string} */
    this.clientName = options.clientName ?? 'nau-js-sdk';
    /** @type {string} */
    this.clientVersion = options.clientVersion ?? '0.0.0';
    /** @type {string} */
    this.protocolVersion = options.protocolVersion ?? MCP_PROTOCOL_VERSION;
    /** @type {object} */
    this.capabilities = options.capabilities ?? {};
    /** @type {string|null} */
    this.sessionId = null;
    /** @type {any} the `initialize` result, once negotiated. */
    this.serverInfo = null;
    /** @type {any[]} server capabilities from `initialize`. */
    this.serverCapabilities = null;
    /** @type {boolean} */
    this.initialized = false;
    /** @type {number} */
    this.#nextId = 1;
  }

  /** @type {number} */
  #nextId;

  /**
   * Send one JSON-RPC message.
   *
   * @param {object} message
   * @param {{route?: string, expectResponse?: boolean, notification?: boolean}} [options]
   * @returns {Promise<any>} the JSON-RPC `result`, or null for a notification
   */
  async send(message, options = {}) {
    const route = options.route ?? 'mcp';
    const notification = options.notification === true;
    const init = {
      method: 'POST',
      headers: {
        accept: 'application/json, text/event-stream',
        'content-type': 'application/json',
        ...(this.sessionId !== null ? { [MCP_SESSION_HEADER]: this.sessionId } : {}),
        ...this.headers,
      },
      body: JSON.stringify(message),
    };
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    if (controller !== null && this.timeoutMs > 0) {
      init.signal = controller.signal;
      setTimeout(() => controller.abort(), this.timeoutMs).unref?.();
    }
    let response;
    try {
      response = await this.fetchImpl(this.baseUrl, init);
    } catch (err) {
      controller?.abort();
      throw new McpError(
        0,
        `transport failure: ${err instanceof Error ? err.message : String(err)}`,
        { route, cause: err },
      );
    }
    const sessionId = response.headers?.get?.(MCP_SESSION_HEADER)
      ?? response.headers?.get?.(MCP_SESSION_HEADER_LEGACY);
    if (typeof sessionId === 'string' && sessionId.length > 0) this.sessionId = sessionId;

    const text = await response.text().catch(() => '');
    if (response.status >= 400) {
      const body = tryJson(text);
      const detail = body !== null && typeof body === 'object'
        ? String(body.message ?? body.error?.message ?? `server returned ${response.status}`)
        : `server returned ${response.status} with a non-JSON body: ${truncate(text)}`;
      throw new McpError(response.status, `${detail} [${route}]`, { body: body ?? text, route });
    }
    if (notification) return null;
    if (text.trim().length === 0) {
      throw new McpError(200, `empty response body for a request [${route}]`, { body: text, route });
    }

    const contentType = response.headers?.get?.('content-type') ?? '';
    let envelope;
    if (contentType.includes('text/event-stream')) {
      const messages = parseSse(text);
      if (messages.length === 0) {
        throw new McpError(200, `SSE response carried no JSON-RPC message [${route}]`, { body: text, route });
      }
      envelope = messages.find((m) => m !== null && typeof m === 'object' && ('result' in m || 'error' in m))
        ?? messages[messages.length - 1];
    } else {
      envelope = tryJson(text);
      if (envelope === null) {
        throw new McpError(
          200,
          `expected JSON but got a non-JSON body: ${truncate(text)} [${route}]`,
          { body: text, route },
        );
      }
    }
    if (envelope === null || typeof envelope !== 'object') {
      throw new McpError(200, `response envelope was not a JSON object [${route}]`, { body: text, route });
    }
    if (envelope.error !== undefined && envelope.error !== null) throw rpcError(envelope.error, route);
    if (!('result' in envelope)) {
      throw new McpError(200, `response carried neither result nor error [${route}]`, { body: envelope, route });
    }
    return envelope.result ?? null;
  }

  /**
   * The MCP handshake.
   *
   * @returns {Promise<any>} the `initialize` result (serverInfo, capabilities)
   */
  async initialize() {
    const result = await this.send(
      {
        jsonrpc: JSONRPC_VERSION,
        id: this.#nextId++,
        method: 'initialize',
        params: {
          capabilities: this.capabilities,
          clientInfo: { name: this.clientName, version: this.clientVersion },
          protocolVersion: this.protocolVersion,
        },
      },
      { route: 'initialize' },
    );
    this.serverInfo = result?.serverInfo ?? null;
    this.serverCapabilities = result?.capabilities ?? null;
    if (typeof result?.protocolVersion === 'string') this.protocolVersion = result.protocolVersion;

    // A notification: no id, and no response is awaited.
    await this.send(
      { jsonrpc: JSONRPC_VERSION, method: 'notifications/initialized' },
      { route: 'notifications/initialized', notification: true, expectResponse: false },
    );
    this.initialized = true;
    return result;
  }

  /**
   * @returns {Promise<any[]>} `tools/list` result's `tools` array
   */
  async listTools() {
    const result = await this.send(
      { jsonrpc: JSONRPC_VERSION, id: this.#nextId++, method: 'tools/list', params: {} },
      { route: 'tools/list' },
    );
    const tools = result?.tools;
    if (tools === undefined || tools === null) return [];
    if (!Array.isArray(tools)) {
      throw new McpError(200, 'tools/list returned a non-array `tools` field', { body: result });
    }
    return tools;
  }

  /**
   * @param {string} name
   * @param {object} [args]
   * @returns {Promise<any>} the `tools/call` result
   */
  async callTool(name, args = {}) {
    if (typeof name !== 'string' || name.length === 0) {
      throw new McpError(0, 'callTool needs a tool name');
    }
    if (args === null || typeof args !== 'object' || Array.isArray(args)) {
      throw new McpError(0, 'callTool arguments must be an object');
    }
    return this.send(
      {
        jsonrpc: JSONRPC_VERSION,
        id: this.#nextId++,
        method: 'tools/call',
        params: { arguments: args, name },
      },
      { route: `tools/call:${name}` },
    );
  }

  /**
   * Initialize if that has not happened yet.
   *
   * @returns {Promise<any>}
   */
  async ensureInitialized() {
    return this.initialized ? this.serverInfo : this.initialize();
  }
}

/**
 * @param {string} text
 * @returns {any|null}
 */
function tryJson(text) {
  if (text.trim().length === 0) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
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

export default McpHttpClient;
