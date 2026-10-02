/**
 * MarketClient against a `node:http` stub on port 0.
 *
 * Upstream shipped no tests at all for this client, which is how a non-JSON
 * error body turned into an unhandled `SyntaxError` in production.
 */

import { test, suite, eq, ok, throws, rejects } from './harness.js';
import { startStubServer, sendJson, sendText } from './helpers.js';
import {
  AgentCard,
  Bid,
  Dispute,
  Identity,
  MarketClient,
  MarketError,
  ResultEnvelope,
} from '../index.js';

/**
 * A stub market that echoes the request, so a test can assert both the wire
 * format and the parse path.
 *
 * @returns {Promise<{url: string, requests: any[], close: () => Promise<void>}>}
 */
function echoServer() {
  return startStubServer((req, res, body) => {
    if (req.url.startsWith('/health')) return sendJson(res, 200, { status: 'ok' });
    if (req.url.startsWith('/boom-json')) return sendJson(res, 400, { error: 'bad amount' });
    if (req.url.startsWith('/boom-html')) {
      return sendText(res, 502, '<html><body>Bad Gateway</body></html>');
    }
    if (req.url.startsWith('/boom-empty')) return sendText(res, 500, '');
    if (req.url.startsWith('/boom-json-ok-body')) return sendJson(res, 200, 'not-an-object');
    if (req.url.startsWith('/boom-text-ok')) return sendText(res, 200, 'hello, not json');
    if (req.url.startsWith('/boom-204')) {
      res.statusCode = 204;
      res.end();
      return undefined;
    }
    return sendJson(res, 200, { method: req.method, url: req.url, body: body === '' ? null : JSON.parse(body) });
  });
}

suite('market: request shaping', () => {
  test('health is a GET', async () => {
    const stub = await echoServer();
    try {
      const client = new MarketClient(stub.url);
      eq((await client.health()).status, 'ok');
      eq(stub.requests[0].method, 'GET');
      eq(stub.requests[0].url, '/health');
    } finally {
      await stub.close();
    }
  });

  test('the base URL keeps a path prefix and drops a trailing slash', async () => {
    const stub = await echoServer();
    try {
      const client = new MarketClient(`${stub.url}/`);
      eq(client.baseUrl, stub.url);
      await client.health();
      eq(stub.requests[0].url, '/health');
      throws(() => new MarketClient(''), { name: 'TypeError' });
    } finally {
      await stub.close();
    }
  });

  test('route parameters are URL-encoded and query values are filtered', async () => {
    const stub = await echoServer();
    try {
      const client = new MarketClient(stub.url);
      await client.getAgent('did:nau:aa/bb');
      eq(stub.requests[0].url, '/v1/agents/did%3Anau%3Aaa%2Fbb');
      await client.discover({ capability: 'mcp', minStakeMinor: 5, limit: 10, offset: undefined });
      eq(stub.requests[1].url, '/v1/agents/discover?capability=mcp&limit=10&min_stake_minor=5');
      await client.listTasks({ state: 'open', publisherDid: 'did:nau:x' });
      eq(stub.requests[2].url, '/v1/tasks?state=open&publisher_did=did%3Anau%3Ax');
      await client.search('a b');
      eq(stub.requests[3].url, '/v1/agents/search?q=a+b');
    } finally {
      await stub.close();
    }
  });

  test('a missing route parameter is a client-side MarketError', async () => {
    const stub = await echoServer();
    try {
      const client = new MarketClient(stub.url);
      const err = await rejects(() => client.getTask(''), { name: 'MarketError' });
      eq(err.status, 0);
      eq(stub.requests.length, 0, 'no request should have been sent');
    } finally {
      await stub.close();
    }
  });

  test('an unknown route is a MarketError, not a crash', async () => {
    const client = new MarketClient('http://127.0.0.1:1');
    await rejects(() => client.request('nope'), { name: 'MarketError' });
  });

  test('a transport failure is wrapped, with status 0', async () => {
    const client = new MarketClient('http://127.0.0.1:1', { timeoutMs: 500 });
    const err = await rejects(() => client.health(), { name: 'MarketError' });
    eq(err.status, 0);
    ok(/transport failure/.test(err.message));
  });

  test('JSON bodies are sent for POST routes and omitted for GET', async () => {
    const stub = await echoServer();
    try {
      const client = new MarketClient(stub.url);
      await client.publishTask({ description: 'x', priceMinor: 5 });
      eq(stub.requests[0].method, 'POST');
      eq(stub.requests[0].headers['content-type'], 'application/json');
      eq(JSON.parse(stub.requests[0].body).price_minor, 5);
      eq(stub.requests[0].body.includes('priceMinor'), false, 'camelCase must not reach the wire');
      await client.getTask('t1');
      eq(stub.requests[1].body, '');
      eq(stub.requests[1].method, 'GET');
    } finally {
      await stub.close();
    }
  });

  test('extra headers and a custom fetch are honoured', async () => {
    const stub = await echoServer();
    try {
      const seen = [];
      const client = new MarketClient(stub.url, {
        headers: { 'x-agent-did': 'did:nau:abc' },
        fetch: (...args) => {
          seen.push(args[0]);
          return globalThis.fetch(...args);
        },
      });
      await client.health();
      eq(stub.requests[0].headers['x-agent-did'], 'did:nau:abc');
      eq(seen.length, 1);
      eq(client.requestCount, 1);
    } finally {
      await stub.close();
    }
  });

  test('the default route table covers every documented method', () => {
    const client = new MarketClient('http://127.0.0.1:1');
    const methods = [
      'health', 'deposit', 'balance', 'registerAgent', 'getAgent', 'discover', 'search',
      'publishTask', 'getTask', 'listTasks', 'submitBid', 'matchTask', 'submitResult',
      'verifyResult', 'settleTask', 'openDispute', 'arbitrate', 'conservation',
      'leaderboard', 'stats',
    ];
    for (const name of methods) eq(typeof client[name], 'function', `${name} missing`);
    eq(Object.keys(client.routes).length, 20);
  });
});

suite('market: error handling', () => {
  test('a JSON error body becomes a MarketError with the server message', async () => {
    const stub = await echoServer();
    try {
      const client = new MarketClient(stub.url, { routes: { health: ['GET', '/boom-json'] } });
      const err = await rejects(() => client.health(), { name: 'MarketError', status: 400 });
      ok(/bad amount/.test(err.message), err.message);
      // `detail` carries the server's own wording, plus the request context.
      ok(err.detail.startsWith('bad amount'), err.detail);
      ok(err.detail.includes('GET /boom-json'), err.detail);
      eq(err.body.error, 'bad amount');
      ok(err instanceof MarketError);
      ok(err instanceof Error);
    } finally {
      await stub.close();
    }
  });

  test('a NON-JSON error body must not escape as a SyntaxError', async () => {
    const stub = await echoServer();
    try {
      const client = new MarketClient(stub.url, { routes: { health: ['GET', '/boom-html'] } });
      const err = await rejects(() => client.health(), { name: 'MarketError', status: 502 });
      ok(!(err instanceof SyntaxError), 'must not be a raw SyntaxError');
      ok(/non-JSON body/.test(err.message), err.message);
      ok(/Bad Gateway/.test(err.message), 'the body text is carried for diagnosis');
      eq(err.code, 'market_error');
    } finally {
      await stub.close();
    }
  });

  test('an empty error body is still a MarketError', async () => {
    const stub = await echoServer();
    try {
      const client = new MarketClient(stub.url, { routes: { health: ['GET', '/boom-empty'] } });
      const err = await rejects(() => client.health(), { name: 'MarketError', status: 500 });
      ok(/500/.test(err.message));
      eq(err.body, null);
    } finally {
      await stub.close();
    }
  });

  test('a non-JSON body on a 200 also throws, rather than returning a string', async () => {
    const stub = await echoServer();
    try {
      const client = new MarketClient(stub.url, { routes: { health: ['GET', '/boom-text-ok'] } });
      const err = await rejects(() => client.health(), { name: 'MarketError', status: 200 });
      ok(/expected JSON/.test(err.message), err.message);
    } finally {
      await stub.close();
    }
  });

  test('204 with no body resolves to null', async () => {
    const stub = await echoServer();
    try {
      const client = new MarketClient(stub.url, { routes: { health: ['GET', '/boom-204'] } });
      eq(await client.health(), null);
    } finally {
      await stub.close();
    }
  });

  test('parseResponse is usable directly on a Response', async () => {
    const ok200 = await MarketClient.parseResponse(
      new Response('{"a":1}', { status: 200, headers: { 'content-type': 'application/json' } }),
      'health',
      'GET',
      '/health',
    );
    eq(ok200.a, 1);
    const err = await rejects(
      () => MarketClient.parseResponse(new Response('<html>', { status: 503 }), 'health', 'GET', '/health'),
      { name: 'MarketError', status: 503 },
    );
    ok(/non-JSON/.test(err.message));
  });
});

suite('market: the full method surface', () => {
  test('every documented method sends the expected request', async () => {
    const stub = await echoServer();
    try {
      const identity = Identity.generate();
      const client = new MarketClient(stub.url);
      const seen = [];
      /** @param {() => Promise<any>} call */
      const record = async (call) => {
        await call();
        seen.push(stub.requests[stub.requests.length - 1]);
      };

      await record(() => client.health());
      await record(() => client.deposit({ account: 'did:nau:a', amountMinor: 100, currency: 'NAU' }));
      await record(() => client.balance('did:nau:a'));
      await record(() => client.registerAgent(new AgentCard({ did: identity.did, name: 'A' })));
      await record(() => client.getAgent(identity.did));
      await record(() => client.discover({ capability: 'mcp' }));
      await record(() => client.search('text'));
      await record(() => client.publishTask({ description: 'd', priceMinor: 1 }));
      await record(() => client.getTask('t1'));
      await record(() => client.listTasks({ state: 'open' }));
      await record(() => client.submitBid('t1', new Bid({ taskId: 't1', bidderDid: identity.did, priceMinor: 2 })));
      await record(() => client.matchTask('t1', { workerDid: identity.did }));
      await record(() => client.submitResult('t1', new ResultEnvelope({ taskId: 't1', workerDid: identity.did, costMinor: 3 })));
      await record(() => client.verifyResult('t1', { approve: true }));
      await record(() => client.settleTask('t1', { outcome: 'accepted' }));
      await record(() => client.openDispute('t1', new Dispute({ taskId: 't1', challengerDid: identity.did, reason: 'r' })));
      await record(() => client.arbitrate('t1', { ruling: 'slash' }));
      await record(() => client.conservation());
      await record(() => client.leaderboard({ limit: 5 }));
      await record(() => client.stats());

      eq(seen.length, 20);
      const expected = [
        ['GET', '/health'],
        ['POST', '/v1/accounts/deposit'],
        ['GET', '/v1/accounts/did%3Anau%3Aa/balance'],
        ['POST', '/v1/agents'],
        ['GET', `/v1/agents/${encodeURIComponent(identity.did)}`],
        ['GET', '/v1/agents/discover?capability=mcp'],
        ['GET', '/v1/agents/search?q=text'],
        ['POST', '/v1/tasks'],
        ['GET', '/v1/tasks/t1'],
        ['GET', '/v1/tasks?state=open'],
        ['POST', '/v1/tasks/t1/bids'],
        ['POST', '/v1/tasks/t1/match'],
        ['POST', '/v1/tasks/t1/result'],
        ['POST', '/v1/tasks/t1/result/verify'],
        ['POST', '/v1/tasks/t1/settle'],
        ['POST', '/v1/tasks/t1/dispute'],
        ['POST', '/v1/tasks/t1/arbitrate'],
        ['GET', '/v1/ledger/conservation'],
        ['GET', '/v1/leaderboard?limit=5'],
        ['GET', '/v1/stats'],
      ];
      for (let i = 0; i < expected.length; i += 1) {
        eq(seen[i].method, expected[i][0], `${expected[i][1]} method`);
        eq(seen[i].url, expected[i][1], `${expected[i][1]} url`);
      }
      // A model instance must be marshalled to its payload, not to `{}`.
      eq(JSON.parse(seen[3].body).did, identity.did);
      eq(JSON.parse(seen[3].body).stake_minor, 0);
      eq(JSON.parse(seen[10].body).price_minor, 2);
      eq(JSON.parse(seen[15].body).bond_minor, 0);
      // camelCase input is renamed, and a safe minor-unit count stays a number.
      eq(JSON.parse(seen[1].body).amount_minor, 100);
      eq('amountMinor' in JSON.parse(seen[1].body), false);
      // A BigInt arrives as a decimal string, because JSON has no BigInt.
      await client.deposit({ account: 'did:nau:a', amountMinor: 2n ** 60n });
      eq(JSON.parse(stub.requests[stub.requests.length - 1].body).amount_minor, (2n ** 60n).toString());
    } finally {
      await stub.close();
    }
  });

  test('an AgentCard with money serializes to minor units, never a float', async () => {
    const stub = await echoServer();
    try {
      const client = new MarketClient(stub.url);
      await client.registerAgent(new AgentCard({ did: 'did:nau:a', name: 'A', stakeMinor: 1234 }));
      const body = stub.requests[0].body;
      ok(body.includes('"stake_minor":1234'));
      ok(!/\d+\.\d+/.test(body), 'no decimal point in the wire body');
      eq(JSON.parse(body).stake_scale, 6);
    } finally {
      await stub.close();
    }
  });

  test('a timeout aborts the request with a MarketError', async () => {
    const stub = await startStubServer((req, res) => {
      setTimeout(() => sendJson(res, 200, { ok: true }), 200);
    });
    try {
      const client = new MarketClient(stub.url, { timeoutMs: 20 });
      const err = await rejects(() => client.health(), { name: 'MarketError' });
      eq(err.status, 0);
    } finally {
      await stub.close();
    }
  });
});
