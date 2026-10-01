/**
 * Ledger: double-entry arithmetic, hash chaining, conservation, sharding and
 * the prefix-search helpers.
 */

import { test, suite, eq, deepEq, ok, throws } from './harness.js';
import {
  BURN_ACCOUNT,
  ConservationError,
  GENESIS_HASH,
  Ledger,
  LedgerEntry,
  LedgerEntryKind,
  LedgerError,
  MINT_ACCOUNT,
  hashEntry,
  merkleRoot,
  shardSize,
  findByPrefix,
} from '../index.js';

/** @param {number} [start] */
const fixedClock = (start = 1000) => {
  let now = start;
  return () => {
    now += 1;
    return now;
  };
};

suite('ledger: double entry', () => {
  test('a deposit mints and credits', () => {
    const ledger = new Ledger({ now: fixedClock() });
    const entry = ledger.deposit('alice', 1000n);
    eq(entry.kind, LedgerEntryKind.DEPOSIT);
    eq(entry.debit, MINT_ACCOUNT);
    eq(entry.credit, 'alice');
    eq(ledger.rawBalance('alice'), 1000n);
    eq(ledger.balance('alice').toDecimalString(), '0.001');
    eq(ledger.length, 1);
    eq(entry.seq, 0);
    ok(entry.verify());
  });

  test('a transfer moves value and leaves the total unchanged', () => {
    const ledger = new Ledger({ now: fixedClock() });
    ledger.deposit('alice', 1000n);
    ledger.transfer('alice', 'bob', 400n);
    eq(ledger.rawBalance('alice'), 600n);
    eq(ledger.rawBalance('bob'), 400n);
    eq(ledger.supplyMinor, 1000n);
    ledger.conservation();
  });

  test('an overdraft is refused', () => {
    const ledger = new Ledger();
    ledger.deposit('alice', 10n);
    const err = throws(() => ledger.transfer('alice', 'bob', 11n), { name: 'LedgerError' });
    eq(err.code, 'ledger_error');
    ok(/insufficient funds/.test(err.message));
    // Explicit opt-in is possible for a replayed/imported log.
    ledger.transfer('alice', 'bob', 11n, { allowOverdraft: true });
    eq(ledger.rawBalance('alice'), -1n);
  });

  test('a slash burns value and lowers the supply', () => {
    const ledger = new Ledger({ now: fixedClock() });
    ledger.deposit('alice', 100n);
    ledger.slash('alice', 40n);
    eq(ledger.rawBalance('alice'), 60n);
    eq(ledger.rawBalance(BURN_ACCOUNT), 40n);
    eq(ledger.supplyMinor, 60n);
    eq(ledger.slashedMinor, 40n);
    const report = ledger.conservation();
    eq(report.ok, true);
    eq(report.deposits.minorBigInt(), 100n);
    eq(report.slashed.minorBigInt(), 40n);
    eq(report.supply.minorBigInt(), 60n);
  });

  test('fees move value like any transfer and leave conservation intact', () => {
    const ledger = new Ledger({ now: fixedClock() });
    ledger.deposit('alice', 100n);
    ledger.transfer('alice', 'house', 10n, { kind: LedgerEntryKind.FEE });
    eq(ledger.feesMinor, 10n);
    eq(ledger.rawBalance('house'), 10n);
    eq(ledger.supplyMinor, 100n);
    // `fees` is reported for accounting. A fee is a transfer to another
    // account, not a burn, so the equation of record is deposits minus slashes
    // and the supply is unchanged.
    const report = ledger.conservation();
    eq(report.ok, true);
    eq(report.fees.minorBigInt(), 10n);
    eq(report.deposits.minorBigInt(), 100n);
    eq(report.supply.minorBigInt(), 100n);
  });

  test('conservation catches a fee that really was burned', () => {
    const ledger = new Ledger({ now: fixedClock() });
    ledger.deposit('alice', 100n);
    // Booked as a fee but sent to the burn account: the supply drops while the
    // fee total rises, which the invariant refuses.
    ledger.transfer('alice', BURN_ACCOUNT, 10n, { kind: LedgerEntryKind.FEE });
    eq(ledger.supplyMinor, 90n);
    eq(ledger.feesMinor, 10n);
    const err = throws(() => ledger.conservation(), { name: 'ConservationError' });
    ok(/conservation violated/.test(err.message), err.message);
    eq(err.supply, '90');
  });

  test('append validates its arguments', () => {
    const ledger = new Ledger();
    throws(() => ledger.append({ kind: 'transfer', debit: 'a', credit: 'b', amountMinor: 0n }), { name: 'LedgerError' });
    throws(() => ledger.append({ kind: 'transfer', debit: 'a', credit: 'b', amountMinor: -1n }), { name: 'LedgerError' });
    throws(() => ledger.append({ kind: 'transfer', debit: 'a', credit: 'a', amountMinor: 1n }), { name: 'LedgerError' });
    throws(() => ledger.append({ kind: 'nope', debit: 'a', credit: 'b', amountMinor: 1n }), { name: 'LedgerError' });
    throws(() => ledger.append({ kind: 'transfer', debit: '', credit: 'b', amountMinor: 1n }), { name: 'LedgerError' });
    throws(() => ledger.append({ kind: 'transfer', debit: 'a', credit: '', amountMinor: 1n }), { name: 'LedgerError' });
  });

  test('conservation throws when the books are corrupted', () => {
    const ledger = new Ledger({ now: fixedClock() });
    ledger.deposit('alice', 100n);
    ledger.balances.set('alice', 200n); // a hand-edited balance
    const err = throws(() => ledger.conservation(), { name: 'ConservationError' });
    eq(err.code, 'conservation_violation');
    eq(err.supply, '200');
    eq(err.net, '100');
  });

  test('accounts() lists every non-zero account, sorted, including the system ones', () => {
    const ledger = new Ledger({ now: fixedClock() });
    ledger.deposit('zeta', 1n);
    ledger.deposit('alpha', 1n);
    ledger.transfer('zeta', 'alpha', 1n);
    // `@mint` is non-zero by construction (it is the counterparty of every
    // deposit) and is listed, because a balance sheet that hides one side of the
    // double entry is not a balance sheet.
    eq(ledger.accounts().join(','), '@mint,alpha');
    ok(ledger.accounts().includes(MINT_ACCOUNT));
    const report = ledger.conservation();
    eq(report.accounts.alpha.minor, '2');
    eq(typeof report.accounts.alpha.minor, 'string');
    eq(report.accounts[MINT_ACCOUNT].minor, '-2');
  });
});

suite('ledger: the hash chain', () => {
  test('each entry commits to its predecessor', () => {
    const ledger = new Ledger({ now: fixedClock() });
    ledger.deposit('a', 1n);
    ledger.deposit('b', 2n);
    eq(ledger.entries[0].prevHash, GENESIS_HASH);
    eq(ledger.entries[1].prevHash, ledger.entries[0].hash);
    eq(ledger.head, ledger.entries[1].hash);
    eq(GENESIS_HASH, '0'.repeat(64));
    deepEq(ledger.verifyChain(), { ok: true, length: 2, brokenAt: null });
  });

  test('a mutated entry is detected', () => {
    const ledger = new Ledger({ now: fixedClock() });
    ledger.deposit('a', 1n);
    ledger.deposit('b', 2n);
    ledger.entries[0].amountMinor = 99n;
    const result = ledger.verifyChain();
    eq(result.ok, false);
    eq(result.brokenAt, 0);
  });

  test('a deleted entry is detected', () => {
    const ledger = new Ledger({ now: fixedClock() });
    ledger.deposit('a', 1n);
    ledger.deposit('b', 2n);
    ledger.entries.splice(1, 1);
    eq(ledger.verifyChain().ok, true, 'the remaining prefix is still a valid chain');
    ledger.entries.push(new LedgerEntry({
      seq: 1,
      timestamp: 1,
      kind: 'transfer',
      debit: 'a',
      credit: 'b',
      amountMinor: 1n,
      prevHash: 'f'.repeat(64),
    }));
    eq(ledger.verifyChain().ok, false);
  });

  test('hashEntry is deterministic and covers the memo and reference', () => {
    const body = {
      seq: 0, timestamp: 1, kind: 'transfer', debit: 'a', credit: 'b',
      amountMinor: 5n, scale: 6, reference: 'r', memo: 'm', prevHash: GENESIS_HASH,
    };
    eq(hashEntry(body), hashEntry({ ...body }));
    ok(hashEntry(body) !== hashEntry({ ...body, memo: 'm2' }));
    ok(hashEntry(body) !== hashEntry({ ...body, reference: 'r2' }));
    ok(hashEntry(body) !== hashEntry({ ...body, amountMinor: 6n }));
    eq(hashEntry(body).length, 64);
    eq(hashEntry(body), hashEntry(body).toLowerCase());
  });

  test('toJSON is stable and re-verifiable', () => {
    const ledger = new Ledger({ now: fixedClock() });
    ledger.deposit('a', 7n);
    const json = ledger.toJSON();
    eq(json.entries.length, 1);
    eq(json.entries[0].amount_minor, '7');
    eq(json.head, ledger.head);
    eq(json.root, ledger.root());
    const revived = new LedgerEntry({ ...json.entries[0] });
    ok(revived.verify());
    eq(revived.hash, ledger.entries[0].hash);
  });
});

suite('ledger: shards, roots and prefix search', () => {
  test('shardSize caps at the capacity', () => {
    eq(shardSize(0, 1024), 0);
    eq(shardSize(10, 1024), 10);
    eq(shardSize(2048, 1024), 1024);
    throws(() => shardSize(-1), { name: 'LedgerError' });
    throws(() => shardSize(1, 0), { name: 'LedgerError' });
  });

  test('shard slices the chain into contiguous runs', () => {
    const ledger = new Ledger({ now: fixedClock() });
    for (let i = 0; i < 5; i += 1) ledger.deposit('a', 1n);
    eq(ledger.shard(0, 2).map((e) => e.seq).join(','), '0,1');
    eq(ledger.shard(1, 2).map((e) => e.seq).join(','), '2,3');
    eq(ledger.shard(2, 2).map((e) => e.seq).join(','), '4');
    eq(ledger.shard(9, 2).length, 0);
    throws(() => ledger.shard(-1), { name: 'LedgerError' });
  });

  test('merkleRoot is deterministic, order-sensitive and handles the odd node', () => {
    const a = 'a'.repeat(64);
    const b = 'b'.repeat(64);
    const c = 'c'.repeat(64);
    eq(merkleRoot([]), GENESIS_HASH);
    eq(merkleRoot([a]), a);
    eq(merkleRoot([a, b]), merkleRoot([a, b]));
    ok(merkleRoot([a, b]) !== merkleRoot([b, a]));
    eq(merkleRoot([a, b, c]), merkleRoot([a, b, c]));
    ok(merkleRoot([a, b, c]) !== merkleRoot([a, b]));
    eq(merkleRoot([a, b, c]).length, 64);
    const ledger = new Ledger({ now: fixedClock() });
    ledger.deposit('a', 1n);
    ledger.deposit('b', 1n);
    eq(ledger.root(), merkleRoot(ledger.entries.map((e) => e.hash)));
  });

  test('findByPrefix selects by a string key', () => {
    const items = [{ id: 'did:nau:aaaa' }, { id: 'did:nau:aabb' }, { id: 'did:nau:bbbb' }];
    eq(findByPrefix('did:nau:aa', items, (i) => i.id).length, 2);
    eq(findByPrefix('did:nau:aa', items, (i) => i.id, 1).length, 1);
    eq(findByPrefix('nope', items, (i) => i.id).length, 0);
    throws(() => findByPrefix(1, items), { name: 'LedgerError' });
    const ledger = new Ledger({ now: fixedClock() });
    ledger.deposit('a', 1n, { reference: 'inv-1' });
    ledger.deposit('b', 1n, { reference: 'inv-2' });
    eq(ledger.findByPrefix('inv-').length, 2);
    eq(ledger.findByPrefix('inv-1').length, 1);
  });
});
