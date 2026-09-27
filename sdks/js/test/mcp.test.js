/**
 * McpHttpClient against a `node:http` stub on port 0.
 *
 * The upstream defect this pins: a non-JSON 200 body was parsed with a bare
 * `JSON.parse`, so the caller saw a `SyntaxError` from inside the transport
 * instead of an MCP error carrying the status and the body.
 */

import { test, suite, eq, ok, throws, rejects } from './harness.js';
import { startStubServer, sendJson, sendText } from './helpers.js';
import {
  JSONRPC_VERSION,
  MCP_PROTOCOL_VERSION,
  MCP_SESSION_HEADER,
  McpError,
  McpHttpClient,
  parseSse,
} from '../index.js';

/**
 * A stub MCP server: the handshake, `tools/list`, `tools/call`, and a set of
 * deliberately broken endpoints.
 *
 * @returns {Promise<{url: string, requests: any[], close: () => Promise<void>}>}
 */
function mcpStub() {
  return startStubServer((req, res, body) => {
    const message = body === '' ? null : JSON.parse(body);
    const respond = (result) => {
      res.setHeader(MCP_SESSION_HEADER, 'stub-session-1');
      sendJson(res, 200, { jsonrpc: JSONRPC_VERSION, id: message.id, result });
    };
    if (message !== null && message.method === 'initialize') {
      respond({
        capabilities: { tools: { listChanged: false } },
        protocolVersion: MCP_PROTOCOL_VERSION,
        serverInfo: { name: 'stub', version: '9.9.9' },
      });
      return;
    }
    if (message !== null && message.method === 'notifications/initialized') {
      res.setHeader(MCP_SESSION_HEADER, 'stub-session-1');
      res.statusCode = 202;
      res.end();
      return;
    }
    if (message !== null && message.method === 'tools/list') {
      respond({ tools: [{ name: 'echo', description: 'e', inputSchema: { type: 'object' } }] });
      return;
    }
    if (message !== null && message.method === 'tools/call') {
      if (message.params.name === 'missing') {
        sendJson(res, 200, {
          jsonrpc: JSONRPC_VERSION,
          id: message.id,
          error: { code: -32602, message: 'unknown tool', data: { name: 'missing' } },
        });
        return;
      }
      respond({ content: [{ type: 'text', text: JSON.stringify(message.params.arguments) }] });
      return;
    }
    respond(null);
  });
}

suite('mcp: the handshake and the calls', () => {
  test('initialize negotiates, then sends notifications/initialized without awaiting a body', async () => {
    const stub = await mcpStub();
    try {
      const client = new McpHttpClient(stub.url);
      const result = await client.initialize();
      eq(result.serverInfo.name, 'stub');
      eq(client.serverInfo.version, '9.9.9');
      eq(client.initialized, true);
      eq(client.sessionId, 'stub-session-1');

      eq(stub.requests.length, 2);
      const first = JSON.parse(stub.requests[0].body);
      eq(first.method, 'initialize');
      eq(first.jsonrpc, JSONRPC_VERSION);
      eq(typeof first.id, 'number');
      eq(first.params.protocolVersion, MCP_PROTOCOL_VERSION);
      eq(first.params.clientInfo.name, 'nau-js-sdk');
      eq(first.params.capabilities && typeof first.params.capabilities, 'object');

      const second = JSON.parse(stub.requests[1].body);
      eq(second.method, 'notifications/initialized');
      eq(second.id, undefined, 'a notification carries no id');
      eq(stub.requests[1].headers[MCP_SESSION_HEADER], 'stub-session-1', 'the session is reused');
    } finally {
      await stub.close();
    }
  });

  test('listTools returns the tools array', async () => {
    const stub = await mcpStub();
    try {
      const client = new McpHttpClient(stub.url);
      await client.initialize();
      const tools = await client.listTools();
      eq(Array.isArray(tools), true);
      eq(tools.length, 1);
      eq(tools[0].name, 'echo');
      eq(JSON.parse(stub.requests[2].body).method, 'tools/list');
    } finally {
      await stub.close();
    }
  });

  test('callTool sends name and arguments, and returns the result', async () => {
    const stub = await mcpStub();
    try {
      const client = new McpHttpClient(stub.url);
      await client.initialize();
      const result = await client.callTool('echo', { text: 'hi' });
      eq(result.content[0].text, '{"text":"hi"}');
      const sent = JSON.parse(stub.requests[2].body);
      eq(sent.method, 'tools/call');
      eq(sent.params.name, 'echo');
      eq(sent.params.arguments.text, 'hi');
    } finally {
      await stub.close();
    }
  });

  test('ensureInitialized is idempotent', async () => {
    const stub = await mcpStub();
    try {
      const client = new McpHttpClient(stub.url);
      await client.ensureInitialized();
      await client.ensureInitialized();
      eq(stub.requests.filter((r) => JSON.parse(r.body).method === 'initialize').length, 1);
    } finally {
      await stub.close();
    }
  });

  test('a JSON-RPC error becomes an McpError carrying the code and data', async () => {
    const stub = await mcpStub();
    try {
      const client = new McpHttpClient(stub.url);
      await client.initialize();
      const err = await rejects(() => client.callTool('missing'), { name: 'McpError' });
      eq(err.rpcCode, -32602);
      eq(err.data.name, 'missing');
      ok(/unknown tool/.test(err.message));
    } finally {
      await stub.close();
    }
  });

  test('a server that streams SSE is handled', async () => {
    const stub = await startStubServer((req, res, body) => {
      const message = JSON.parse(body);
      res.statusCode = 200;
      res.setHeader('content-type', 'text/event-stream');
      res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: JSONRPC_VERSION, id: message.id, result: { ok: true } })}\n\n`);
      res.end();
    });
    try {
      const client = new McpHttpClient(stub.url);
      const result = await client.send({ jsonrpc: JSONRPC_VERSION, id: 1, method: 'anything', params: {} });
      eq(result.ok, true);
    } finally {
      await stub.close();
    }
  });

  test('parseSse extracts every JSON frame, skips comments and [DONE]', () => {
    const frames = parseSse([
      ': keep-alive',
      '',
      'event: message',
      'data: {"a":1}',
      '',
      'data: {"b":2}',
      '',
      'data: [DONE]',
      '',
    ].join('\n'));
    eq(frames.length, 2);
    eq(frames[0].a, 1);
    eq(frames[1].b, 2);
  });

  test('parseSse refuses a frame that is not JSON, with an McpError', () => {
    const err = throws(() => parseSse('data: {"c":\n\n'), { name: 'McpError' });
    ok(/not JSON/.test(err.message), err.message);
  });

  test('parseSse handles a single well-formed frame', () => {
    eq(parseSse('data: {"a":1}\n\n').length, 1);
    eq(parseSse('data: {"a":1}\n\ndata: {"b":2}\n\n').length, 2);
    eq(parseSse('').length, 0);
    eq(parseSse(': nothing here\n\n').length, 0);
  });
});

suite('mcp: error paths that upstream got wrong', () => {
  test('a 200 with an HTML body throws McpError, never a SyntaxError', async () => {
    const stub = await startStubServer((req, res) => sendText(res, 200, '<html>nope</html>'));
    try {
      const client = new McpHttpClient(stub.url);
      const err = await rejects(() => client.initialize(), { name: 'McpError' });
      ok(!(err instanceof SyntaxError), 'must not be a raw SyntaxError');
      ok(/non-JSON body/.test(err.message), err.message);
      eq(err.status, 200);
      eq(err.code, 'mcp_error');
    } finally {
      await stub.close();
    }
  });

  test('a 200 with an empty body throws McpError for a request', async () => {
    const stub = await startStubServer((req, res) => {
      res.statusCode = 200;
      res.end();
    });
    try {
      const client = new McpHttpClient(stub.url);
      const err = await rejects(() => client.initialize(), { name: 'McpError' });
      eq(err.status, 200);
      ok(/empty response body|neither result nor error|non-JSON/.test(err.message), err.message);
    } finally {
      await stub.close();
    }
  });

  test('an HTTP error status carries the status and the body', async () => {
    const stub = await startStubServer((req, res) => sendJson(res, 500, { message: 'internal' }));
    try {
      const client = new McpHttpClient(stub.url);
      const err = await rejects(() => client.initialize(), { name: 'McpError', status: 500 });
      ok(/internal/.test(err.message));
    } finally {
      await stub.close();
    }
  });

  test('a non-JSON HTTP error body is reported, not parsed', async () => {
    const stub = await startStubServer((req, res) => sendText(res, 503, '<html>down</html>'));
    try {
      const client = new McpHttpClient(stub.url);
      const err = await rejects(() => client.initialize(), { name: 'McpError', status: 503 });
      ok(/down/.test(err.message), err.message);
    } finally {
      await stub.close();
    }
  });

  test('an envelope with neither result nor error is an McpError', async () => {
    const stub = await startStubServer((req, res) => sendJson(res, 200, { jsonrpc: JSONRPC_VERSION, id: 1 }));
    try {
      const client = new McpHttpClient(stub.url);
      const err = await rejects(() => client.initialize(), { name: 'McpError' });
      ok(/neither result nor error/.test(err.message));
    } finally {
      await stub.close();
    }
  });

  test('a transport failure is an McpError with status 0', async () => {
    const client = new McpHttpClient('http://127.0.0.1:1', { timeoutMs: 500 });
    const err = await rejects(() => client.initialize(), { name: 'McpError' });
    eq(err.status, 0);
    ok(/transport failure/.test(err.message));
  });

  test('callTool validates its arguments', async () => {
    const client = new McpHttpClient('http://127.0.0.1:1');
    await rejects(() => client.callTool(''), { name: 'McpError' });
    await rejects(() => client.callTool('echo', null), { name: 'McpError' });
    await rejects(() => client.callTool('echo', [1]), { name: 'McpError' });
  });

  test('the constructor needs a URL and a fetch implementation', () => {
    throws(() => new McpHttpClient(''), { name: 'TypeError' });
    throws(() => new McpHttpClient('http://x', { fetch: null }), { name: 'McpError' });
    eq(MCP_PROTOCOL_VERSION, '2024-11-05');
    eq(JSONRPC_VERSION, '2.0');
    eq(MCP_SESSION_HEADER, 'mcp-session-id');
  });
});
