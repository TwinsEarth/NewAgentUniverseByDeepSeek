/**
 * The public entry point: the façade, the namespace export, and the end-to-end
 * flow a caller follows.
 */

import { test, suite, eq, ok, throws } from './harness.js';
import { startStubServer, sendJson } from './helpers.js';
import * as sdk from '../index.js';
import {
  Agent,
  AgentCard,
  Identity,
  Keypair,
  MarketClient,
  McpHttpClient,
  Money,
  Task,
  api,
  canonicalJson,
  verifyPayload,
  verifyPayloadBound,
  DidMismatchError,
} from '../index.js';

suite('api: the exported surface', () => {
  test('every name the task requires is exported', () => {
    const required = [
      'VERSION',
      'CanonicalError', 'NonIntegerNumber', 'RootNotObject', 'TooDeep', 'UnsafeInteger',
      'canonicalJson', 'canonicalPayload', 'didFromPublicKey', 'Keypair', 'Identity',
      'verifyPayload', 'verifyPayloadBound', 'Did',
      'Money', 'AgentCard', 'Skill', 'Pricing', 'Sla', 'TaskSpec', 'Task', 'TaskState',
      'Bid', 'ResultEnvelope', 'EvidenceGrade', 'Dispute',
      'MarketClient', 'MarketError', 'McpHttpClient', 'McpError', 'MCP_PROTOCOL_VERSION',
      'shardSize', 'findByPrefix',
    ];
    const missing = required.filter((name) => !(name in sdk));
    eq(missing.join(','), '', 'missing exports');
  });

  test('the error classes are distinct and each carries its code', () => {
    eq(new sdk.NonIntegerNumber(1.5).code, 'non_integer_number');
    eq(new sdk.RootNotObject([]).code, 'root_not_object');
    eq(new sdk.TooDeep(64).code, 'too_deep');
    eq(new sdk.UnsafeInteger(2 ** 53).code, 'unsafe_integer');
    eq(new sdk.CanonicalError('x').code, 'canonical_error');
  });

  test('MCP_PROTOCOL_VERSION is the pinned revision', () => {
    eq(sdk.MCP_PROTOCOL_VERSION, '2024-11-05');
  });

  test('the default export is the namespace, frozen', () => {
    eq(api.VERSION, sdk.VERSION);
    eq(api.canonicalJson, canonicalJson);
    ok(Object.isFrozen(api));
    eq(sdk.default, api);
  });

  test('the API works with no `this` binding surprises', () => {
    const { canonicalJson: cj, didFromPublicKey: dfp } = sdk;
    eq(cj({ a: 1 }), '{"a":1}');
    eq(dfp(Keypair.generate().publicKey).startsWith('did:nau:'), true);
  });
});

suite('api: the end-to-end flow', () => {
  test('sign a card, verify it, bind the DID', () => {
    const identity = Identity.generate();
    const payload = {
      capabilities: ['mcp'],
      did: identity.did,
      name: 'Example',
      stake_minor: 100,
      stake_scale: 6,
    };
    const signature = identity.signPayload(payload);
    eq(verifyPayload(payload, signature, identity.publicKey), true);
    eq(verifyPayloadBound(payload, signature, identity.publicKey, identity.did), true);
    throws(
      () => verifyPayloadBound(payload, signature, identity.publicKey, Identity.generate().did),
      { name: 'DidMismatchError' },
    );
    // The signed bytes are stable across a JSON round-trip, which is what a
    // wire protocol needs.
    eq(canonicalJson(JSON.parse(JSON.stringify(payload))), canonicalJson(payload));
  });

  test('Agent.card signs with the agent identity and Agent.verifyCard checks it', () => {
    const agent = new Agent({ seed: Buffer.alloc(32, 3) });
    const card = agent.card({ name: 'A', capabilities: ['mcp'], stakeMinor: 5 });
    ok(card.signature.length === 128);
    eq(card.did, agent.did);
    eq(Agent.verifyCard(card, agent.identity.publicKey), true);
    eq(Agent.verifyCard(card.toPayload(), agent.identity.publicKey), true);
    // A tampered card fails.
    const tampered = new AgentCard({ ...card.toPayload(), name: 'B' });
    throws(() => Agent.verifyCard(tampered, agent.identity.publicKey), { name: 'SignatureError' });
    // An unsigned card fails loudly rather than silently passing.
    throws(() => Agent.verifyCard(new AgentCard({ did: agent.did }), agent.identity.publicKey), {
      name: 'SignatureError',
    });
  });

  test('Agent can hold a market and an MCP client, both with the version', () => {
    const agent = new Agent({ marketUrl: 'http://127.0.0.1:1', mcpUrl: 'http://127.0.0.1:1' });
    ok(agent.market instanceof MarketClient);
    ok(agent.mcp instanceof McpHttpClient);
    eq(agent.market.headers['x-agent-did'], agent.did);
    eq(agent.mcp.clientVersion, sdk.VERSION);
    eq(new Agent().market, null);
  });

  test('an agent can publish, bid, submit and settle against a stub', async () => {
    const stub = await startStubServer((req, res, body) => {
      sendJson(res, 200, { ok: true, method: req.method, url: req.url, body: body === '' ? null : JSON.parse(body) });
    });
    try {
      const agent = new Agent({ marketUrl: stub.url, seed: Buffer.alloc(32, 4) });
      await agent.market.registerAgent(agent.card({ name: 'A' }));
      await agent.market.publishTask({ description: 'work', priceMinor: 10 });
      await agent.market.submitBid('t1', { taskId: 't1', bidderDid: agent.did, priceMinor: 9 });
      await agent.market.submitResult('t1', { taskId: 't1', workerDid: agent.did, output: { text: 'done' } });
      await agent.market.settleTask('t1', { outcome: 'accepted' });
      eq(stub.requests.length, 5);
      eq(JSON.parse(stub.requests[0].body).did, agent.did);
      eq(JSON.parse(stub.requests[0].body).signature.length, 128);
      // The card's signature must verify over the card as sent.
      const sentCard = JSON.parse(stub.requests[0].body);
      const { signature, ...unsigned } = sentCard;
      eq(verifyPayload(unsigned, signature, agent.identity.publicKey), true);
    } finally {
      await stub.close();
    }
  });

  test('a task walks the whole lifecycle through the real transition table', () => {
    const task = new Task({ id: 't1', spec: { description: 'd' }, priceMinor: 1000 });
    for (const next of ['matched', 'running', 'submitted', 'verifying', 'accepted', 'settled']) {
      task.transition(next);
    }
    eq(task.state, 'settled');
    eq(task.price.minor, 1000);
    eq(Money.parse('1').checkedAdd(Money.parse('0.5')).toDecimalString(), '1.5');
  });
});
