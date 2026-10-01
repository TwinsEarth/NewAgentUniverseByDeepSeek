/**
 * Models: Money exactness, the twelve-state transition table, the enumerations
 * and the payload shapes that get signed.
 */

import { test, suite, eq, ok, throws } from './harness.js';
import {
  AgentCard,
  Bid,
  Dispute,
  EvidenceGrade,
  Identity,
  Money,
  Pricing,
  ResultEnvelope,
  Skill,
  Sla,
  Task,
  TaskSpec,
  TaskState,
  TransitionError,
  MoneyError,
  canonicalJson,
  verifyPayload,
} from '../index.js';

suite('models: Money is integer minor units', () => {
  test('the canonical float trap: 0.1 + 0.2 is exactly 0.3', () => {
    const sum = Money.parse('0.1').checkedAdd(Money.parse('0.2'));
    ok(sum.equals(Money.parse('0.3')), `${sum.toString()} !== 0.3`);
    eq(sum.toDecimalString(), '0.3');
    eq(sum.toCanonicalString(), '0.300000');
    ok(!(0.1 + 0.2 === 0.3), 'the floating-point premise');
  });

  test('parse and toDecimalString round-trip a range of values', () => {
    const cases = [
      ['0', 0n, '0'],
      ['1', 1000000n, '1'],
      ['-1', -1000000n, '-1'],
      ['0.1', 100000n, '0.1'],
      ['0.000001', 1n, '0.000001'],
      ['-0.5', -500000n, '-0.5'],
      ['+2.25', 2250000n, '2.25'],
      ['.5', 500000n, '0.5'],
      ['1.', 1000000n, '1'],
      ['12345.678901', 12345678901n, '12345.678901'],
      ['0.10', 100000n, '0.1'],
      ['1e-3', 1000n, '0.001'],
      ['1E3', 1000000000n, '1000'],
    ];
    for (const [text, minor, decimal] of cases) {
      const m = Money.parse(text);
      eq(m.minorBigInt(), minor, `${text} minor`);
      eq(m.toDecimalString(), decimal, `${text} decimal`);
    }
  });

  test('parse refuses anything inexact', () => {
    for (const bad of ['', '  ', 'x', '1.2.3', '1,000', '0x10', 'Infinity', 'NaN', '--1', '1e', '$1']) {
      throws(() => Money.parse(bad), { name: 'MoneyError' });
    }
    // More precision than the scale can hold must not round silently.
    throws(() => Money.parse('0.0000001'), { name: 'MoneyError' });
    eq(Money.parse('0.0000001', 7).minorBigInt(), 1n);
  });

  test('the scale is part of the value and must match to combine', () => {
    eq(Money.parse('1').scale, 6);
    eq(Money.parse('1', 2).minorBigInt(), 100n);
    eq(Money.parse('1.23', 2).toCanonicalString(), '1.23');
    const err = throws(() => Money.parse('1').checkedAdd(Money.parse('1', 2)), { name: 'MoneyError' });
    ok(/scale/.test(err.message));
  });

  test('checkedAdd and checkedSub are exact and never mutate', () => {
    const a = Money.parse('0.1');
    const b = Money.parse('0.2');
    const sum = a.checkedAdd(b);
    eq(a.toDecimalString(), '0.1', 'operand unchanged');
    eq(b.toDecimalString(), '0.2', 'operand unchanged');
    eq(sum.toDecimalString(), '0.3');
    eq(Money.parse('1').checkedSub(Money.parse('0.999999')).toDecimalString(), '0.000001');
    eq(Money.parse('0').checkedSub(Money.parse('1')).toDecimalString(), '-1');
    // Exactly representable in minor units, so no rounding at all.
    let total = Money.zero();
    for (let i = 0; i < 10; i += 1) total = total.checkedAdd(Money.parse('0.1'));
    eq(total.equals(Money.parse('1')), true);
    eq(total.toCanonicalString(), '1.000000');
  });

  test('minor is a safe integer or an explicit error', () => {
    eq(Money.parse('1.5').minor, 1500000);
    const huge = Money.fromMinor(2n ** 60n);
    eq(huge.minorBigInt(), 2n ** 60n);
    throws(() => huge.minor, { name: 'MoneyError' });
    eq(huge.isSafe, false);
    eq(Money.parse('1').isSafe, true);
  });

  test('the constructor refuses floats, unsafe integers and junk', () => {
    throws(() => new Money(1.5), { name: 'MoneyError' });
    throws(() => new Money(2 ** 53), { name: 'MoneyError' });
    throws(() => new Money('x'), { name: 'MoneyError' });
    throws(() => new Money(1, 1.5), { name: 'MoneyError' });
    throws(() => new Money(1, -1), { name: 'MoneyError' });
    throws(() => new Money(null), { name: 'MoneyError' });
    eq(Money.fromMinor(5n).minorBigInt(), 5n);
  });

  test('compare, equals and the predicates', () => {
    eq(Money.parse('1').compare(Money.parse('2')), -1);
    eq(Money.parse('2').compare(Money.parse('2')), 0);
    eq(Money.parse('3').compare(Money.parse('2')), 1);
    ok(Money.parse('1').equals(Money.fromMinor(1000000)));
    ok(!Money.parse('1').equals(Money.fromMinor(1000000, 2)));
    ok(Money.parse('-1').isNegative);
    ok(Money.zero().isZero);
    ok(!Money.parse('1').isZero);
    eq(Money.zero().toDecimalString(), '0');
    eq(Money.zero().toCanonicalString(), '0.000000');
    eq(Money.parse('-0').toDecimalString(), '0');
  });

  test('checkedMul keeps the scale', () => {
    eq(Money.parse('1.5').checkedMul(3).toDecimalString(), '4.5');
    eq(Money.parse('1.5').checkedMul(3n).toDecimalString(), '4.5');
    throws(() => Money.parse('1').checkedMul(1.5), { name: 'MoneyError' });
  });

  test('money in a signed payload is a string, so no float can appear', () => {
    const pricing = new Pricing({ amountMinor: 1500000, currency: 'NAU' });
    eq(pricing.toJSON().amount_minor, 1500000);
    const text = canonicalJson({ cost: Money.parse('0.1').toDecimalString() });
    eq(text, '{"cost":"0.1"}');
    ok(!/\d\.\d/.test(text) || text.includes('"'), 'money travels as a string');
  });
});

suite('models: the twelve task states', () => {
  test('there are exactly twelve, and they are the Rust core names', () => {
    eq(TaskState.ALL.length, 12);
    eq(
      TaskState.ALL.join(','),
      'open,matched,running,submitted,verifying,accepted,rework,settled,disputed,slashed,cancelled,no_quorum',
    );
    for (const name of TaskState.ALL) eq(TaskState.parse(name), name);
  });

  const TABLE = {
    open: ['matched', 'cancelled', 'no_quorum'],
    matched: ['running', 'open', 'cancelled', 'disputed'],
    running: ['submitted', 'disputed', 'cancelled'],
    submitted: ['verifying', 'disputed'],
    verifying: ['accepted', 'rework', 'no_quorum', 'disputed'],
    rework: ['running', 'open', 'cancelled'],
    accepted: ['settled', 'disputed'],
    disputed: ['settled', 'slashed', 'accepted', 'cancelled'],
    no_quorum: ['open', 'cancelled'],
    settled: [],
    slashed: [],
    cancelled: [],
  };

  test('the transition table is exactly as specified, for every pair', () => {
    for (const from of TaskState.ALL) {
      const allowed = TABLE[from];
      ok(allowed !== undefined, `no expectation for ${from}`);
      eq(
        [...TaskState.TRANSITIONS[from]].sort().join(','),
        [...allowed].sort().join(','),
        `allowed from ${from}`,
      );
      for (const to of TaskState.ALL) {
        eq(
          TaskState.canTransitionTo(from, to),
          allowed.includes(to),
          `${from} -> ${to}`,
        );
      }
    }
  });

  test('terminal states have no outgoing edges', () => {
    for (const state of ['settled', 'slashed', 'cancelled']) {
      eq(TaskState.nextStates(state).length, 0, state);
      ok(TaskState.TERMINAL.includes(state));
      for (const to of TaskState.ALL) ok(!TaskState.canTransitionTo(state, to));
      eq(TaskState.nextStates(state).length, 0);
    }
    eq(TaskState.TERMINAL.length, 3);
  });

  test('the recovery edges upstream lacked', () => {
    ok(TaskState.canTransitionTo('no_quorum', 'open'), 'no_quorum -> open');
    ok(TaskState.canTransitionTo('rework', 'running'), 'rework -> running');
    ok(TaskState.canTransitionTo('matched', 'open'), 'matched -> open (unmatched)');
    ok(TaskState.canTransitionTo('disputed', 'accepted'), 'disputed -> accepted (dismissed)');
  });

  test('unknown states and aliases', () => {
    for (const bad of ['', 'pending', 'OPEN', 'donee', null, 42, {}]) {
      throws(() => TaskState.parse(bad), { name: 'TypeError' });
    }
    // `undefined` is the one input that means "not supplied" rather than
    // "supplied and wrong", so parse refuses it explicitly too.
    throws(() => TaskState.parse(undefined), { name: 'TypeError' });
    eq(TaskState.parse('in_progress'), 'running');
    eq(TaskState.parse('canceled'), 'cancelled');
    eq(TaskState.parse('no-quorum'), 'no_quorum');
  });

  test('unknown states are refused when they name a transition target too', () => {
    // Two *valid* states with no edge between them is `false`, not an error:
    // `open` cannot go straight to `settled`, but both are real states.
    eq(TaskState.canTransitionTo('open', 'settled'), false);
    eq(TaskState.canTransitionTo('open', 'matched'), true);
    // An unknown state is a TypeError on either side of the pair.
    throws(() => TaskState.canTransitionTo('nope', 'settled'), { name: 'TypeError' });
    throws(() => TaskState.canTransitionTo('open', 'nope'), { name: 'TypeError' });
    throws(() => TaskState.canTransitionTo('nope', 'nope'), { name: 'TypeError' });
    throws(() => TaskState.nextStates('nope'), { name: 'TypeError' });
  });

  test('Task.transition applies the table and records history', () => {
    const task = new Task({ id: 't1', spec: { description: 'x' } });
    eq(task.state, 'open');
    eq(task.isTerminal, false);
    task.transition('matched');
    task.transition('running');
    eq(task.attempts, 1);
    task.transition('submitted');
    task.transition('verifying');
    task.transition('rework');
    task.transition('running');
    eq(task.attempts, 2);
    task.transition('submitted');
    task.transition('verifying');
    task.transition('accepted');
    task.transition('settled');
    eq(task.state, 'settled');
    eq(task.isTerminal, true);
    eq(task.history.join('>'), 'open>matched>running>submitted>verifying>rework>running>submitted>verifying>accepted>settled');
    const err = throws(() => task.transition('open'), { name: 'TransitionError' });
    eq(err.code, 'invalid_transition');
    eq(err.from, 'settled');
    eq(err.to, 'open');
    eq(err.allowed.length, 0);
  });

  test('an illegal transition names the allowed targets', () => {
    const task = new Task({ id: 't2' });
    const err = throws(() => task.transition('settled'), { name: 'TransitionError' });
    eq(err.allowed.join(','), 'matched,cancelled,no_quorum');
    ok(/open -> settled/.test(err.message));
  });

  test('transitioning to the current state is an idempotent no-op', () => {
    const task = new Task({ id: 't3', state: 'running' });
    const before = task.history.length;
    task.transition('running');
    eq(task.state, 'running');
    eq(task.history.length, before);
  });

  test('the no_quorum recovery path works end to end', () => {
    const task = new Task({ id: 't4' });
    task.transition('no_quorum');
    task.transition('open');
    task.transition('cancelled');
    eq(task.state, 'cancelled');
    ok(task.isTerminal);
  });

  test('Task.toPayload is canonical and stable', () => {
    const task = new Task({ id: 't5', publisherDid: 'did:nau:aaaa', priceMinor: 250000 });
    const round = new Task(JSON.parse(JSON.stringify(task.toPayload())));
    eq(round.state, task.state);
    eq(round.price.toDecimalString(), '0.25');
    const text = canonicalJson(task.toPayload());
    ok(text.startsWith('{"attempts":'));
    eq(JSON.parse(text).price_minor, 250000);
    eq(Task.fromJSON({ id: 't6' }).state, 'open');
    throws(() => new Task({ state: 'nope' }), { name: 'TypeError' });
  });
});

suite('models: the rest of the enumerations and payloads', () => {
  test('EvidenceGrade is ordered', () => {
    eq(EvidenceGrade.ALL.length, 5);
    eq(EvidenceGrade.parse('hashed'), 'hashed');
    throws(() => EvidenceGrade.parse('trust-me'), { name: 'TypeError' });
    ok(EvidenceGrade.atLeast('zk_proven', 'hashed'));
    ok(!EvidenceGrade.atLeast('none', 'hashed'));
    ok(EvidenceGrade.atLeast('hashed', 'hashed'));
  });

  test('Skill, Pricing and Sla validate their input', () => {
    const skill = new Skill({ name: 'summarize', tags: ['text'] });
    eq(skill.toJSON().name, 'summarize');
    throws(() => new Skill({}), { name: 'TypeError' });
    eq(new Pricing({ amountMinor: 5 }).amount.minor, 5);
    eq(new Sla({}).deadlineSeconds, 3600);
    eq(new Sla({ minEvidenceGrade: 'hashed' }).toJSON().min_evidence_grade, 'hashed');
  });

  test('AgentCard signs and verifies through the identity', () => {
    const identity = Identity.fromSeed(Buffer.alloc(32, 1));
    const card = new AgentCard({
      did: identity.did,
      name: 'CrossLang',
      capabilities: ['text-generation', 'mcp'],
      stakeMinor: 100,
      skills: [{ name: 'generate' }],
      pricing: { amountMinor: 10 },
    });
    eq(card.stakeMinor, 100);
    const signature = identity.signPayload(card.toPayload());
    const signed = new AgentCard({ ...card.toJSON(), signature, did: identity.did });
    eq(signed.stakeMinor, 100);
    eq(signed.toPayload().stake_minor, 100);
    eq(verifyPayload(signed.toPayload(), signature, identity.publicKey), true);
    throws(() => new AgentCard({}), { name: 'TypeError' });
    // The signature field is dropped by canonicalization anyway.
    eq(canonicalJson({ ...card.toPayload(), signature }), canonicalJson(card.toPayload()));
  });

  test('Bid, ResultEnvelope and Dispute quote money as minor units', () => {
    const bid = new Bid({ taskId: 't', bidderDid: 'did:nau:x', priceMinor: 1234 });
    eq(bid.toPayload().price_minor, 1234);
    eq(bid.toPayload().scale, 6);
    const result = new ResultEnvelope({
      taskId: 't',
      workerDid: 'did:nau:w',
      output: { text: 'hi' },
      evidenceGrade: 'hashed',
      costMinor: 900,
    });
    eq(result.toPayload().cost_minor, 900);
    eq(result.grade_ ?? result.evidenceGrade, 'hashed');
    throws(() => new ResultEnvelope({ evidenceGrade: 'nope' }), { name: 'TypeError' });
    const dispute = new Dispute({ taskId: 't', challengerDid: 'did:nau:c', reason: 'wrong', bondMinor: 50 });
    eq(dispute.toPayload().bond_minor, 50);
    eq(dispute.toPayload().reason, 'wrong');
  });

  test('every model payload survives canonicalization unchanged', () => {
    const identity = Identity.generate();
    const payloads = [
      new AgentCard({ did: identity.did, name: 'a' }).toPayload(),
      new Task({ id: 't', publisherDid: identity.did, priceMinor: 1 }).toPayload(),
      new Bid({ taskId: 't', bidderDid: identity.did, priceMinor: 1 }).toPayload(),
      new ResultEnvelope({ taskId: 't', workerDid: identity.did, costMinor: 1 }).toPayload(),
      new Dispute({ taskId: 't', challengerDid: identity.did, bondMinor: 1 }).toPayload(),
      new TaskSpec({ id: 's', description: 'd', maxPriceMinor: 1 }).toPayload(),
      new Skill({ name: 's' }).toJSON(),
      new Pricing({ amountMinor: 1 }).toJSON(),
      new Sla({}).toJSON(),
    ];
    for (const payload of payloads) {
      const text = canonicalJson(payload);
      eq(typeof text, 'string');
      const signature = identity.signPayload(payload);
      eq(verifyPayload(payload, signature, identity.publicKey), true);
      // Round-tripping through JSON must not change the signed bytes, which is
      // the property a wire protocol needs.
      eq(canonicalJson(JSON.parse(text)), text);
    }
  });

  test('MoneyError and TransitionError are exported typed errors', () => {
    ok(new MoneyError('x') instanceof Error);
    ok(new TransitionError('open', 'settled', ['matched']).code === 'invalid_transition');
  });
});
