/**
 * An append-only, hash-chained double-entry ledger.
 *
 * The ledger is deliberately local and dependency-free: `MarketClient` is the
 * transport, this is the accounting model it is checked against. Every entry
 * carries the hash of its predecessor, so {@link Ledger#verifyChain} detects
 * both a mutated entry and a deleted one.
 *
 * Conservation is an explicit invariant, not a convention: the sum of all
 * account balances equals total deposits minus total slashed value (upstream
 * v2.5.6 asserted conservation in prose but had no arithmetic for it).
 */

import crypto from 'node:crypto';

import { MoneyError, NauError } from './errors.js';
import { Money, DEFAULT_MONEY_SCALE } from './models.js';

/** A ledger rule was broken. */
export class LedgerError extends NauError {
  constructor(message) {
    super(message, { code: 'ledger_error' });
  }
}

/** Conservation did not hold. */
export class ConservationError extends NauError {
  /**
   * @param {string} message
   * @param {{supply?: string, net?: string}} [detail]
   */
  constructor(message, detail = {}) {
    super(message, { code: 'conservation_violation' });
    if (detail.supply !== undefined) this.supply = detail.supply;
    if (detail.net !== undefined) this.net = detail.net;
  }
}

/** Entry kinds. */
export const LedgerEntryKind = Object.freeze({
  DEPOSIT: 'deposit',
  TRANSFER: 'transfer',
  ESCROW: 'escrow',
  RELEASE: 'release',
  REFUND: 'refund',
  SLASH: 'slash',
  FEE: 'fee',
});

/** The account that mints value; the only one allowed to go negative. */
export const MINT_ACCOUNT = '@mint';
/** The account that burns value through slashing. */
export const BURN_ACCOUNT = '@burn';

/** Hash of the empty chain. */
export const GENESIS_HASH = '0'.repeat(64);

/**
 * Coerce an amount to a BigInt of minor units.
 *
 * A decimal digit string is read as MINOR units, so an entry that has been
 * through {@link LedgerEntry#toJSON} revives with exactly the same value.
 *
 * @param {number|bigint|string} value
 * @returns {bigint}
 */
function toMinor(value) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw new LedgerError(
        `ledger amount ${String(value)} is not a safe integer; pass the value as a decimal string`,
      );
    }
    return BigInt(value);
  }
  if (typeof value === 'string' && /^-?\d+$/.test(value.trim())) return BigInt(value.trim());
  throw new LedgerError(`ledger amount must be an integer or a decimal digit string, got ${typeof value}`);
}

/**
 * Hash of a canonical entry body.
 *
 * @param {object} body
 * @returns {string} 64 lowercase hex characters
 */
export function hashEntry(body) {
  const text = JSON.stringify({
    amount_minor: String(body.amountMinor ?? body.amount_minor),
    credit: body.credit,
    debit: body.debit,
    kind: body.kind,
    memo: body.memo ?? null,
    prev_hash: body.prevHash ?? body.prev_hash ?? GENESIS_HASH,
    reference: body.reference ?? null,
    scale: body.scale,
    seq: body.seq,
    timestamp: body.timestamp,
  });
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

/** Maximum entries a shard will hold before forcing a flush. */
export const DEFAULT_SHARD_CAPACITY = 1024;

/**
 * Number of entries in a shard of `total` entries, capped at `capacity`.
 *
 * A shard is a contiguous run of entries that is flushed as one unit; a chain
 * that never shards grows without bound, so this is the knob that bounds the
 * verification cost of a single proof.
 *
 * @param {number} total
 * @param {number} [capacity]
 * @returns {number}
 */
export function shardSize(total, capacity = DEFAULT_SHARD_CAPACITY) {
  if (!Number.isInteger(total) || total < 0) throw new LedgerError('shardSize needs a non-negative integer total');
  if (!Number.isInteger(capacity) || capacity <= 0) throw new LedgerError('shardSize needs a positive integer capacity');
  return Math.min(total, capacity);
}

/**
 * Find the first item whose string `key` starts with `prefix`.
 *
 * Upstream exposed this as an undocumented helper; it is part of the public
 * surface here because DID and task ids are prefix-searchable by design.
 *
 * @template T
 * @param {string} prefix
 * @param {Iterable<T>} items
 * @param {(item: T) => string} [key]
 * @param {number} [limit]
 * @returns {T[]}
 */
export function findByPrefix(prefix, items, key = (item) => /** @type {any} */ (item), limit = Infinity) {
  if (typeof prefix !== 'string') throw new LedgerError('findByPrefix needs a string prefix');
  const out = [];
  for (const item of items) {
    if (String(key(item)).startsWith(prefix)) {
      out.push(item);
      if (out.length >= limit) break;
    }
  }
  return out;
}

/**
 * Merkle root over a list of entry hashes.
 *
 * Odd levels duplicate their last node, which is the convention used by Bitcoin
 * and by every implementation a reader is likely to compare against. An empty
 * list has the all-zero root so the value is always 64 hex characters.
 *
 * @param {string[]} hashes
 * @returns {string}
 */
export function merkleRoot(hashes) {
  if (hashes.length === 0) return GENESIS_HASH;
  let level = hashes.map((h) => String(h).toLowerCase());
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      next.push(crypto.createHash('sha256').update(left + right, 'utf8').digest('hex'));
    }
    level = next;
  }
  return level[0];
}

/** One immutable ledger entry. */
export class LedgerEntry {
  /**
   * @param {{seq: number, timestamp: number, kind: string, debit: string,
   *   credit: string, amountMinor: number|bigint, scale?: number,
   *   reference?: string|null, memo?: string|null, prevHash?: string,
   *   hash?: string}} init
   */
  constructor(init) {
    /** @type {number} */
    this.seq = init.seq;
    /** @type {number} unix seconds */
    this.timestamp = init.timestamp;
    /** @type {string} */
    this.kind = init.kind;
    /** @type {string} account debited */
    this.debit = init.debit;
    /** @type {string} account credited */
    this.credit = init.credit;
    /** @type {bigint} accepts a decimal digit string so JSON revives exactly. */
    this.amountMinor = toMinor(init.amountMinor ?? init.amount_minor);
    /** @type {number} */
    this.scale = init.scale ?? DEFAULT_MONEY_SCALE;
    /** @type {string|null} */
    this.reference = init.reference ?? null;
    /** @type {string|null} */
    this.memo = init.memo ?? null;
    /** @type {string} */
    this.prevHash = init.prevHash ?? init.prev_hash ?? GENESIS_HASH;
    /** @type {string} */
    this.hash = init.hash ?? hashEntry(this);
  }

  /** @returns {string} */
  get hashHex() {
    return this.hash;
  }

  /** @returns {Money} */
  get amount() {
    return Money.fromMinor(this.amountMinor, this.scale);
  }

  /** @returns {boolean} true when `hash` really covers this entry's body. */
  verify() {
    return this.hash === hashEntry(this);
  }

  /** @returns {object} */
  toJSON() {
    return {
      amount_minor: this.amountMinor.toString(),
      credit: this.credit,
      debit: this.debit,
      hash: this.hash,
      kind: this.kind,
      memo: this.memo,
      prev_hash: this.prevHash,
      reference: this.reference,
      scale: this.scale,
      seq: this.seq,
      timestamp: this.timestamp,
    };
  }
}

/** A signed conservation report. */
export class ConservationReport {
  /**
   * @param {{supplyMinor: bigint|number, depositsMinor: bigint|number,
   *   slashedMinor: bigint|number, feesMinor: bigint|number,
   *   accounts: Record<string, {minor: string, scale: number}>, ok: boolean,
   *   entries: number, head: string, scale?: number}} init
   */
  constructor(init) {
    const scale = init.scale ?? DEFAULT_MONEY_SCALE;
    /** @type {Money} */
    this.supply = Money.fromMinor(BigInt(init.supplyMinor), scale);
    /** @type {Money} */
    this.deposits = Money.fromMinor(BigInt(init.depositsMinor), scale);
    /** @type {Money} */
    this.slashed = Money.fromMinor(BigInt(init.slashedMinor), scale);
    /** @type {Money} */
    this.fees = Money.fromMinor(BigInt(init.feesMinor), scale);
    /** @type {Record<string, {minor: string, scale: number}>} */
    this.accounts = init.accounts;
    /** @type {boolean} */
    this.ok = init.ok;
    /** @type {number} */
    this.entries = init.entries;
    /** @type {string} */
    this.head = init.head;
  }

  /** @returns {object} */
  toJSON() {
    return {
      accounts: this.accounts,
      deposits_minor: this.deposits.minorBigInt().toString(),
      entries: this.entries,
      fees_minor: this.fees.minorBigInt().toString(),
      head: this.head,
      ok: this.ok,
      slashed_minor: this.slashed.minorBigInt().toString(),
      supply_minor: this.supply.minorBigInt().toString(),
    };
  }
}

/**
 * An append-only ledger with balances derived from its entries.
 */
export class Ledger {
  /**
   * @param {{scale?: number, now?: () => number}} [init]
   */
  constructor(init = {}) {
    /** @type {number} */
    this.scale = init.scale ?? DEFAULT_MONEY_SCALE;
    /** @type {LedgerEntry[]} */
    this.entries = [];
    /** @type {Map<string, bigint>} */
    this.balances = new Map();
    /** @type {() => number} */
    this.now = init.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /** @returns {number} */
  get length() {
    return this.entries.length;
  }

  /** @returns {string} hash of the last entry, or the genesis hash. */
  get head() {
    return this.entries.length === 0 ? GENESIS_HASH : this.entries[this.entries.length - 1].hash;
  }

  /**
   * @param {string} account
   * @returns {bigint} signed minor units (negative means the account is short)
   */
  rawBalance(account) {
    return this.balances.get(account) ?? 0n;
  }

  /**
   * @param {string} account
   * @returns {Money}
   */
  balance(account) {
    return Money.fromMinor(this.rawBalance(account), this.scale);
  }

  /** @returns {string[]} accounts with a non-zero balance, sorted. */
  accounts() {
    return [...this.balances.entries()]
      .filter(([, v]) => v !== 0n)
      .map(([k]) => k)
      .sort();
  }

  /** @returns {bigint} */
  get depositsMinor() {
    return this.#sumKind(LedgerEntryKind.DEPOSIT);
  }

  /** @returns {bigint} */
  get slashedMinor() {
    return this.#sumKind(LedgerEntryKind.SLASH);
  }

  /** @returns {bigint} */
  get feesMinor() {
    return this.#sumKind(LedgerEntryKind.FEE);
  }

  /** @returns {bigint} sum of every non-system account balance. */
  get supplyMinor() {
    let total = 0n;
    for (const [account, value] of this.balances) {
      if (account === MINT_ACCOUNT || account === BURN_ACCOUNT) continue;
      total += value;
    }
    return total;
  }

  /**
   * Append an entry.
   *
   * @param {{kind: string, debit: string, credit: string,
   *   amountMinor: number|bigint, reference?: string|null, memo?: string|null,
   *   timestamp?: number}} init
   * @returns {LedgerEntry}
   */
  append(init) {
    const amount = toMinor(init.amountMinor);
    if (amount <= 0n) throw new LedgerError(`ledger amounts must be positive, got ${amount}`);
    if (typeof init.debit !== 'string' || init.debit.length === 0) throw new LedgerError('debit account is required');
    if (typeof init.credit !== 'string' || init.credit.length === 0) throw new LedgerError('credit account is required');
    if (init.debit === init.credit) throw new LedgerError(`debit and credit are the same account (${init.debit})`);
    if (!Object.values(LedgerEntryKind).includes(init.kind)) {
      throw new LedgerError(`unknown ledger entry kind ${JSON.stringify(init.kind)}`);
    }
    const entry = new LedgerEntry({
      seq: this.entries.length,
      timestamp: init.timestamp ?? this.now(),
      kind: init.kind,
      debit: init.debit,
      credit: init.credit,
      amountMinor: amount,
      scale: this.scale,
      reference: init.reference ?? null,
      memo: init.memo ?? null,
      prevHash: this.head,
    });
    this.entries.push(entry);
    this.#move(entry.debit, -amount);
    this.#move(entry.credit, amount);
    return entry;
  }

  /**
   * Record a deposit: mint -> account.
   *
   * @param {string} account
   * @param {number|bigint} amountMinor
   * @param {{reference?: string|null, memo?: string|null}} [options]
   * @returns {LedgerEntry}
   */
  deposit(account, amountMinor, options = {}) {
    return this.append({
      kind: LedgerEntryKind.DEPOSIT,
      debit: MINT_ACCOUNT,
      credit: account,
      amountMinor,
      reference: options.reference ?? null,
      memo: options.memo ?? null,
    });
  }

  /**
   * Record an ordinary transfer.
   *
   * @param {string} from
   * @param {string} to
   * @param {number|bigint} amountMinor
   * @param {{kind?: string, reference?: string|null, memo?: string|null,
   *   allowOverdraft?: boolean}} [options]
   * @returns {LedgerEntry}
   */
  transfer(from, to, amountMinor, options = {}) {
    const amount = toMinor(amountMinor);
    if (options.allowOverdraft !== true && this.rawBalance(from) < amount) {
      throw new LedgerError(
        `insufficient funds: ${from} holds ${this.rawBalance(from)} minor units,`
          + ` cannot transfer ${amount}`,
      );
    }
    return this.append({
      kind: options.kind ?? LedgerEntryKind.TRANSFER,
      debit: from,
      credit: to,
      amountMinor: amount,
      reference: options.reference ?? null,
      memo: options.memo ?? null,
    });
  }

  /**
   * Burn value: account -> burn.
   *
   * @param {string} account
   * @param {number|bigint} amountMinor
   * @param {{reference?: string|null, memo?: string|null}} [options]
   * @returns {LedgerEntry}
   */
  slash(account, amountMinor, options = {}) {
    return this.transfer(account, BURN_ACCOUNT, amountMinor, {
      ...options,
      kind: LedgerEntryKind.SLASH,
    });
  }

  /**
   * Check the books and produce a report.
   *
   * The invariant is `total account balance == deposits - slashed`. Fees are
   * deliberately NOT subtracted: a fee is an ordinary transfer to another
   * account, so it moves value without creating or destroying any, and the
   * `fees` figure in the report is an accounting total rather than a burn. A
   * FEE-kind entry that credits the burn account therefore shows up as a
   * violation, which is exactly the mistake worth catching.
   *
   * @returns {ConservationReport}
   * @throws {ConservationError} when the books do not balance
   */
  conservation() {
    const supply = this.supplyMinor;
    const deposits = this.depositsMinor;
    const slashed = this.slashedMinor;
    const fees = this.feesMinor;
    const net = deposits - slashed;
    const accounts = {};
    for (const account of [...this.balances.keys()].sort()) {
      accounts[account] = { minor: this.rawBalance(account).toString(), scale: this.scale };
    }
    const report = new ConservationReport({
      supplyMinor: supply,
      depositsMinor: deposits,
      slashedMinor: slashed,
      feesMinor: fees,
      accounts,
      ok: supply === net,
      entries: this.entries.length,
      head: this.head,
      scale: this.scale,
    });
    if (!report.ok) {
      throw new ConservationError(
        `conservation violated: accounts hold ${supply} minor units but deposits(${deposits})`
          + ` - slashed(${slashed}) = ${net}`,
        { supply: supply.toString(), net: net.toString() },
      );
    }    return report;
  }

  /**
   * Recompute every hash and check the chain.
   *
   * @returns {{ok: boolean, length: number, brokenAt: number|null}}
   */
  verifyChain() {
    let prev = GENESIS_HASH;
    for (let i = 0; i < this.entries.length; i += 1) {
      const e = this.entries[i];
      if (e.seq !== i || e.prevHash !== prev || !e.verify()) {
        return { ok: false, length: this.entries.length, brokenAt: i };
      }
      prev = e.hash;
    }
    return { ok: true, length: this.entries.length, brokenAt: null };
  }

  /**
   * @param {number} [index] shard index (0-based)
   * @param {number} [capacity]
   * @returns {LedgerEntry[]}
   */
  shard(index = 0, capacity = DEFAULT_SHARD_CAPACITY) {
    if (!Number.isInteger(index) || index < 0) throw new LedgerError('shard index must be a non-negative integer');
    if (!Number.isInteger(capacity) || capacity <= 0) throw new LedgerError('shard capacity must be a positive integer');
    const start = index * capacity;
    return this.entries.slice(start, start + capacity);
  }

  /**
   * Merkle root of every entry hash.
   *
   * @returns {string}
   */
  root() {
    return merkleRoot(this.entries.map((e) => e.hash));
  }

  /**
   * @param {string} prefix
   * @param {number} [limit]
   * @returns {LedgerEntry[]}
   */
  findByPrefix(prefix, limit = Infinity) {
    return findByPrefix(prefix, this.entries, (e) => e.reference ?? e.hash, limit);
  }

  /** @returns {object} */
  toJSON() {
    return {
      entries: this.entries.map((e) => e.toJSON()),
      head: this.head,
      root: this.root(),
      scale: this.scale,
    };
  }

  /**
   * @param {string} account
   * @param {bigint} delta
   */
  #move(account, delta) {
    this.balances.set(account, this.rawBalance(account) + delta);
  }

  /**
   * @param {string} kind
   * @returns {bigint}
   */
  #sumKind(kind) {
    let total = 0n;
    for (const e of this.entries) if (e.kind === kind) total += e.amountMinor;
    return total;
  }
}

export { Money, MoneyError };

export default { Ledger, LedgerEntry, LedgerEntryKind, ConservationReport, LedgerError, ConservationError };
