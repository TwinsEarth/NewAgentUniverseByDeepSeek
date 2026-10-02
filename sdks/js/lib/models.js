/**
 * Domain models: money, agent cards, tasks, bids, results and disputes.
 *
 * Every model is a plain class with an explicit constructor and a `toJSON()`
 * that yields the exact object that gets canonicalized and signed — so a
 * payload can never contain a hidden class instance, which
 * {@link canonicalJson} would reject anyway.
 *
 * # Money is integer minor units, always
 *
 * The conformance fixture refuses floats outright (`100` vs `100.0` vs `1e2`
 * format differently in Rust, Python and JavaScript). {@link Money} therefore
 * stores an integer count of minor units and does all arithmetic in `BigInt`,
 * converting back only after a safe-range check.
 */

import { MoneyError, TransitionError } from './errors.js';

/** Default decimal scale: 6 fractional digits (micro-units). */
export const DEFAULT_MONEY_SCALE = 6;

const DECIMAL_RE = /^([+-]?)(\d*)(?:\.(\d*))?(?:[eE]([+-]?\d+))?$/;

/** @param {string} s @returns {string} */
const stripLeadingZeros = (s) => {
  const t = s.replace(/^0+(?=\d)/, '');
  return t.length === 0 ? '0' : t;
};

/**
 * An exact amount of money, held as an integer count of minor units.
 *
 * ```js
 * Money.parse('0.1').checkedAdd(Money.parse('0.2')).equals(Money.parse('0.3')); // true
 * ```
 */
export class Money {
  /**
   * @param {number|bigint|string} minor integer minor units (a decimal digit
   *   string is read as minor units too, so JSON round-trips are lossless)
   * @param {number} [scale] decimal places per major unit
   */
  constructor(minor, scale = DEFAULT_MONEY_SCALE) {
    if (!Number.isInteger(scale) || scale < 0 || scale > 18) {
      throw new MoneyError(`scale must be an integer in 0..18, got ${String(scale)}`);
    }
    /** @type {bigint} */
    this.#minor = toBigIntMinor(minor);
    /** @type {number} */
    this.scale = scale;
  }

  /** @type {bigint} */
  #minor;

  /**
   * @param {number|bigint|string} minor integer minor units
   * @param {number} [scale]
   * @returns {Money}
   */
  static fromMinor(minor, scale = DEFAULT_MONEY_SCALE) {
    return new Money(minor, scale);
  }

  /** @returns {Money} zero at the default scale. */
  static zero(scale = DEFAULT_MONEY_SCALE) {
    return new Money(0, scale);
  }

  /**
   * Parse a decimal string (or an integer number) into exact minor units.
   *
   * Accepts `'-1.5'`, `'+2'`, `'.5'`, `'1.'`, `'1e-3'`. Rejects `NaN`,
   * `Infinity`, empty strings, and anything with more fractional digits than
   * `scale` can represent (rounding money silently is how you lose money).
   *
   * @param {string|number|bigint} input
   * @param {number} [scale]
   * @returns {Money}
   */
  static parse(input, scale = DEFAULT_MONEY_SCALE) {
    if (typeof input === 'bigint') return new Money(input, scale);
    if (typeof input === 'number') {
      if (!Number.isSafeInteger(input)) {
        throw new MoneyError(
          `Money.parse refuses the non-integer or unsafe number ${String(input)};`
            + ' pass a decimal string of integer minor units instead',
        );
      }
      return new Money(input, scale);
    }
    if (typeof input !== 'string') {
      throw new MoneyError(`Money.parse expects a string, got ${typeof input}`);
    }
    const text = input.trim();
    if (text.length === 0) throw new MoneyError('Money.parse got an empty string');
    const m = DECIMAL_RE.exec(text);
    if (m === null) throw new MoneyError(`Money.parse cannot read ${JSON.stringify(input)}`);
    const [, sign, intPart = '', fracPart = '', expPart] = m;
    if (intPart.length === 0 && fracPart.length === 0) {
      throw new MoneyError(`Money.parse cannot read ${JSON.stringify(input)}`);
    }
    if (typeof scale !== 'number' || !Number.isInteger(scale) || scale < 0 || scale > 18) {
      throw new MoneyError(`scale must be an integer in 0..18, got ${String(scale)}`);
    }
    // Shift the decimal point right by `scale`, then apply the exponent, all in
    // BigInt so nothing rounds.
    let digits = BigInt(`${intPart || '0'}${fracPart}` || '0');
    const shift = BigInt(scale - fracPart.length + (expPart === undefined ? 0 : Number(expPart)));
    if (shift >= 0n) digits *= 10n ** shift;
    else {
      const divisor = 10n ** -shift;
      const remainder = digits % divisor;
      if (remainder !== 0n) {
        throw new MoneyError(
          `Money.parse(${JSON.stringify(input)}) needs more than ${scale} decimal places`,
        );
      }
      digits /= divisor;
    }
    if (sign === '-') digits = -digits;
    return new Money(digits, scale);
  }

  /**
   * @param {Money|number|bigint|string} other
   * @param {number} [scale] used only when `other` is not a Money
   * @returns {Money}
   */
  static coerce(other, scale = DEFAULT_MONEY_SCALE) {
    if (other instanceof Money) return other;
    if (typeof other === 'number' || typeof other === 'bigint') return new Money(other, scale);
    if (typeof other === 'string') return Money.parse(other, scale);
    throw new MoneyError(`cannot use ${typeof other} as Money`);
  }

  /** @returns {number} minor units as a safe integer. @throws {MoneyError} */
  get minor() {
    if (this.#minor > BigInt(Number.MAX_SAFE_INTEGER) || this.#minor < BigInt(Number.MIN_SAFE_INTEGER)) {
      throw new MoneyError(
        `minor units ${this.#minor.toString()} do not fit in a JavaScript safe integer;`
          + ' use minorBigInt() and carry the value as a decimal string',
      );
    }
    return Number(this.#minor);
  }

  /** @returns {bigint} minor units, exact and unbounded. */
  minorBigInt() {
    return this.#minor;
  }

  /** @returns {boolean} true when `minor` would lose precision. */
  get isSafe() {
    return (
      this.#minor <= BigInt(Number.MAX_SAFE_INTEGER) && this.#minor >= BigInt(Number.MIN_SAFE_INTEGER)
    );
  }

  /** @returns {boolean} */
  get isNegative() {
    return this.#minor < 0n;
  }

  /** @returns {boolean} */
  get isZero() {
    return this.#minor === 0n;
  }

  /**
   * @param {Money|number|bigint|string} other
   * @returns {Money} a new Money; scales must agree
   */
  checkedAdd(other) {
    const rhs = Money.coerce(other, this.scale);
    this.#assertScale(rhs);
    return new Money(this.#minor + rhs.#minor, this.scale);
  }

  /**
   * @param {Money|number|bigint|string} other
   * @returns {Money} a new Money; scales must agree
   */
  checkedSub(other) {
    const rhs = Money.coerce(other, this.scale);
    this.#assertScale(rhs);
    return new Money(this.#minor - rhs.#minor, this.scale);
  }

  /**
   * @param {number|bigint} factor integer multiplier
   * @returns {Money}
   */
  checkedMul(factor) {
    if (typeof factor === 'number' && !Number.isSafeInteger(factor)) {
      throw new MoneyError(`checkedMul needs an integer, got ${String(factor)}`);
    }
    const f = typeof factor === 'bigint' ? factor : BigInt(factor);
    return new Money(this.#minor * f, this.scale);
  }

  /**
   * @param {Money} other
   * @returns {number} -1, 0 or 1
   */
  compare(other) {
    const rhs = Money.coerce(other, this.scale);
    this.#assertScale(rhs);
    if (this.#minor < rhs.#minor) return -1;
    if (this.#minor > rhs.#minor) return 1;
    return 0;
  }

  /**
   * @param {Money} other
   * @returns {boolean} true when both the value and the scale agree
   */
  equals(other) {
    return (
      other instanceof Money && other.scale === this.scale && other.#minor === this.#minor
    );
  }

  /**
   * Human-readable decimal string with trailing zeros in the fraction removed.
   *
   * @returns {string} e.g. `'0.1'`, `'-42'`, `'1.000001'`
   */
  toDecimalString() {
    const negative = this.#minor < 0n;
    const abs = negative ? -this.#minor : this.#minor;
    const text = abs.toString().padStart(this.scale + 1, '0');
    const whole = text.slice(0, text.length - this.scale);
    let frac = this.scale === 0 ? '' : text.slice(text.length - this.scale);
    frac = frac.replace(/0+$/, '');
    const body = frac.length > 0 ? `${stripLeadingZeros(whole)}.${frac}` : stripLeadingZeros(whole);
    return negative && !/^0(\.0*)?$/.test(body) ? `-${body}` : body;
  }

  /**
   * Decimal string with exactly `scale` fraction digits.
   *
   * This is the form to put in a signed payload: it is deterministic for a
   * given (minor, scale) pair, whereas {@link toDecimalString} varies the
   * number of digits with the value.
   *
   * @returns {string}
   */
  toCanonicalString() {
    const negative = this.#minor < 0n;
    const abs = negative ? -this.#minor : this.#minor;
    const text = abs.toString().padStart(this.scale + 1, '0');
    const whole = text.slice(0, text.length - this.scale);
    const frac = this.scale === 0 ? '' : text.slice(text.length - this.scale);
    const body = this.scale === 0 ? whole : `${whole}.${frac}`;
    return negative ? `-${body}` : body;
  }

  /** @returns {string} this payload's signed form. */
  toString() {
    return this.toDecimalString();
  }

  /** @returns {string} JSON carries money as a decimal string, never a float. */
  toJSON() {
    return this.toDecimalString();
  }

  /**
   * @param {Money} rhs
   */
  #assertScale(rhs) {
    if (rhs.scale !== this.scale) {
      throw new MoneyError(
        `money scales differ (${this.scale} vs ${rhs.scale}); normalize before adding or subtracting`,
      );
    }
  }
}

/**
 * @param {number|bigint|string} minor
 * @returns {bigint}
 */
function toBigIntMinor(minor) {
  if (typeof minor === 'bigint') return minor;
  if (typeof minor === 'number') {
    if (!Number.isInteger(minor)) {
      throw new MoneyError(
        `money minor units must be integers, got ${String(minor)}`
          + ' (Money.parse handles decimal strings)',
      );
    }
    if (!Number.isSafeInteger(minor)) {
      throw new MoneyError(
        `money minor units ${String(minor)} exceed the JavaScript safe-integer range;`
          + ' pass a BigInt or a decimal string',
      );
    }
    return BigInt(minor);
  }
  if (typeof minor === 'string') {
    // A decimal digit string is read as INTEGER minor units, so a Money that has
    // been through JSON revives without gaining or losing a factor of 10**scale.
    if (/^-?\d+$/.test(minor.trim())) return BigInt(minor.trim());
    return Money.parse(minor).minorBigInt();
  }
  throw new MoneyError(`money minor units must be an integer, got ${typeof minor}`);
}

/** A capability an agent advertises. */
export class Skill {
  /**
   * @param {{name: string, version?: string, description?: string, tags?: string[],
   *   inputSchema?: object|null, [k: string]: unknown}} init
   */
  constructor(init = {}) {
    if (typeof init.name !== 'string' || init.name.length === 0) {
      throw new TypeError('Skill.name is required');
    }
    /** @type {string} */
    this.name = init.name;
    /** @type {string} */
    this.version = init.version ?? '1.0.0';
    /** @type {string} */
    this.description = init.description ?? '';
    /** @type {string[]} */
    this.tags = [...(init.tags ?? [])];
    /** @type {object|null} */
    this.inputSchema = init.inputSchema ?? null;
  }

  /** @returns {object} */
  toJSON() {
    return {
      name: this.name,
      version: this.version,
      description: this.description,
      tags: [...this.tags],
      input_schema: this.inputSchema,
    };
  }
}

/** What an agent charges. */
export class Pricing {
  /**
   * @param {{amountMinor?: number|bigint, currency?: string, scale?: number,
   *   per?: string, amount?: Money|string}} [init]
   */
  constructor(init = {}) {
    const scale = init.scale ?? DEFAULT_MONEY_SCALE;
    /** @type {Money} */
    this.amount =
      init.amount instanceof Money
        ? init.amount
        : Money.fromMinor(init.amountMinor ?? init.amount_minor ?? 0, scale);
    /** @type {string} */
    this.currency = init.currency ?? 'NAU';
    /** @type {string} per-unit basis: `'task'`, `'token'`, `'second'`. */
    this.per = init.per ?? 'task';
  }

  /** @returns {number} */
  get amountMinor() {
    return this.amount.minor;
  }

  /** @returns {object} */
  toJSON() {
    return {
      amount_minor: this.amount.minor,
      currency: this.currency,
      scale: this.amount.scale,
      per: this.per,
    };
  }
}

/** Service-level agreement terms. */
export class Sla {
  /**
   * @param {{deadlineSeconds?: number, minEvidenceGrade?: string,
   *   penaltyMinor?: number|bigint, rewardMinor?: number|bigint, scale?: number}} [init]
   */
  constructor(init = {}) {
    const scale = init.scale ?? DEFAULT_MONEY_SCALE;
    /** @type {number} */
    this.deadlineSeconds = init.deadlineSeconds ?? init.deadline_seconds ?? 3600;
    /** @type {string} */
    this.minEvidenceGrade = EvidenceGrade.parse(
      init.minEvidenceGrade ?? init.min_evidence_grade ?? EvidenceGrade.SELF_ATTESTED,
    );
    /** @type {Money} */
    this.penalty = Money.fromMinor(init.penaltyMinor ?? init.penalty_minor ?? 0, scale);
    /** @type {Money} */
    this.reward = Money.fromMinor(init.rewardMinor ?? init.reward_minor ?? 0, scale);
  }

  /** @returns {object} */
  toJSON() {
    return {
      deadline_seconds: this.deadlineSeconds,
      min_evidence_grade: this.minEvidenceGrade,
      penalty_minor: this.penalty.minor,
      reward_minor: this.reward.minor,
      scale: this.penalty.scale,
    };
  }
}

/** A registered agent's public card. */
export class AgentCard {
  /**
   * @param {{did: string, name?: string, capabilities?: string[], skills?: (Skill|object)[],
   *   endpoint?: string|null, stakeMinor?: number|bigint, stake?: number,
   *   pricing?: Pricing|object, sla?: Sla|object, metadata?: object,
   *   signature?: string, scale?: number, [k: string]: unknown}} init
   */
  constructor(init = {}) {
    if (typeof init.did !== 'string' || init.did.length === 0) {
      throw new TypeError('AgentCard.did is required');
    }
    const scale = init.scale ?? DEFAULT_MONEY_SCALE;
    /** @type {string} */
    this.did = init.did;
    /** @type {string} */
    this.name = init.name ?? '';
    /** @type {string[]} */
    this.capabilities = [...(init.capabilities ?? [])];
    /** @type {Skill[]} */
    this.skills = (init.skills ?? []).map((s) => (s instanceof Skill ? s : new Skill(s)));
    /** @type {string|null} */
    this.endpoint = init.endpoint ?? null;
    /** @type {Money} stake and scale are read in either spelling, so a card
     * rehydrated from its own {@link AgentCard#toJSON} keeps its stake. */
    this.stake = Money.fromMinor(
      init.stakeMinor ?? init.stake_minor ?? init.stake ?? 0,
      init.stakeScale ?? init.stake_scale ?? scale,
    );
    /** @type {Pricing} */
    this.pricing = init.pricing instanceof Pricing ? init.pricing : new Pricing(init.pricing ?? {});
    /** @type {Sla} */
    this.sla = init.sla instanceof Sla ? init.sla : new Sla(init.sla ?? {});
    /** @type {object} */
    this.metadata = init.metadata ?? {};
    /** @type {string} hex signature over the canonical payload, if signed. */
    this.signature = init.signature ?? '';
  }

  /** @returns {number} */
  get stakeMinor() {
    return this.stake.minor;
  }

  /**
   * The exact object that is signed / verified.
   *
   * @returns {object}
   */
  toPayload() {
    const payload = {
      capabilities: [...this.capabilities],
      did: this.did,
      endpoint: this.endpoint,
      metadata: { ...this.metadata },
      name: this.name,
      pricing: this.pricing.toJSON(),
      skills: this.skills.map((s) => s.toJSON()),
      sla: this.sla.toJSON(),
      stake_minor: this.stake.minor,
      stake_scale: this.stake.scale,
    };
    if (this.signature) payload.signature = this.signature;
    return payload;
  }

  /** @returns {object} alias of {@link toPayload} */
  toJSON() {
    return this.toPayload();
  }
}

/** Why a result should be believed. */
export class EvidenceGrade {
  constructor() {
    throw new TypeError('EvidenceGrade is an enumeration; use EvidenceGrade.parse(value)');
  }

  static NONE = 'none';
  static SELF_ATTESTED = 'self_attested';
  static HASHED = 'hashed';
  static THIRD_PARTY_VERIFIED = 'third_party_verified';
  static ZK_PROVEN = 'zk_proven';

  /** @type {readonly string[]} */
  static ALL = Object.freeze([
    EvidenceGrade.NONE,
    EvidenceGrade.SELF_ATTESTED,
    EvidenceGrade.HASHED,
    EvidenceGrade.THIRD_PARTY_VERIFIED,
    EvidenceGrade.ZK_PROVEN,
  ]);

  /** @type {Readonly<Record<string, number>>} ordinal strength, higher is better. */
  static RANK = Object.freeze({
    [EvidenceGrade.NONE]: 0,
    [EvidenceGrade.SELF_ATTESTED]: 1,
    [EvidenceGrade.HASHED]: 2,
    [EvidenceGrade.THIRD_PARTY_VERIFIED]: 3,
    [EvidenceGrade.ZK_PROVEN]: 4,
  });

  /**
   * @param {string} value
   * @returns {string}
   */
  static parse(value) {
    if (
      typeof value === 'string'
      && Object.prototype.hasOwnProperty.call(EvidenceGrade.RANK, value)
    ) {
      return value;
    }
    throw new TypeError(
      `unknown evidence grade ${JSON.stringify(value)}; expected one of ${EvidenceGrade.ALL.join(', ')}`,
    );
  }

  /**
   * @param {string} a
   * @param {string} b
   * @returns {boolean} true when `a` is at least as strong as `b`
   */
  static atLeast(a, b) {
    return EvidenceGrade.RANK[EvidenceGrade.parse(a)] >= EvidenceGrade.RANK[EvidenceGrade.parse(b)];
  }
}

/** The specification of work to be done. */
export class TaskSpec {
  /**
   * @param {{id?: string|null, description?: string, capabilities?: string[],
   *   input?: object|null, outputSchema?: object|null, maxPriceMinor?: number|bigint,
   *   scale?: number}} [init]
   */
  constructor(init = {}) {
    const scale = init.scale ?? DEFAULT_MONEY_SCALE;
    /** @type {string|null} */
    this.id = init.id ?? null;
    /** @type {string} */
    this.description = init.description ?? '';
    /** @type {string[]} */
    this.capabilities = [...(init.capabilities ?? [])];
    /** @type {object|null} */
    this.input = init.input ?? null;
    /** @type {object|null} */
    this.outputSchema = init.outputSchema ?? init.output_schema ?? null;
    /** @type {Money} */
    this.maxPrice = Money.fromMinor(
      init.maxPriceMinor ?? init.max_price_minor ?? 0,
      init.scale ?? scale,
    );
  }

  /** @returns {object} */
  toPayload() {
    return {
      capabilities: [...this.capabilities],
      description: this.description,
      id: this.id,
      input: this.input,
      max_price_minor: this.maxPrice.minor,
      output_schema: this.outputSchema,
      scale: this.maxPrice.scale,
    };
  }

  /** @returns {object} */
  toJSON() {
    return this.toPayload();
  }
}

/**
 * The twelve task states, matching `crates/nau-core`.
 *
 * The transition table is in {@link TaskState.TRANSITIONS}. Two recovery edges
 * that upstream v2.5.6 lacked are present here:
 *
 * * `no_quorum -> open` (retry a round that could not reach quorum);
 * * `rework -> running` (the agent is asked to redo the work directly).
 */
export class TaskState {
  constructor() {
    throw new TypeError('TaskState is an enumeration; use TaskState.parse(value)');
  }

  static OPEN = 'open';
  static MATCHED = 'matched';
  static RUNNING = 'running';
  static SUBMITTED = 'submitted';
  static VERIFYING = 'verifying';
  static ACCEPTED = 'accepted';
  static REWORK = 'rework';
  static SETTLED = 'settled';
  static DISPUTED = 'disputed';
  static SLASHED = 'slashed';
  static CANCELLED = 'cancelled';
  static NO_QUORUM = 'no_quorum';

  /** @type {readonly string[]} in declaration order, exactly twelve states. */
  static ALL = Object.freeze([
    TaskState.OPEN,
    TaskState.MATCHED,
    TaskState.RUNNING,
    TaskState.SUBMITTED,
    TaskState.VERIFYING,
    TaskState.ACCEPTED,
    TaskState.REWORK,
    TaskState.SETTLED,
    TaskState.DISPUTED,
    TaskState.SLASHED,
    TaskState.CANCELLED,
    TaskState.NO_QUORUM,
  ]);

  /** @type {Readonly<Record<string, readonly string[]>>} */
  static TRANSITIONS = Object.freeze({
    [TaskState.OPEN]: Object.freeze([TaskState.MATCHED, TaskState.CANCELLED, TaskState.NO_QUORUM]),
    [TaskState.MATCHED]: Object.freeze([
      TaskState.RUNNING,
      TaskState.OPEN,
      TaskState.CANCELLED,
      TaskState.DISPUTED,
    ]),
    [TaskState.RUNNING]: Object.freeze([
      TaskState.SUBMITTED,
      TaskState.DISPUTED,
      TaskState.CANCELLED,
    ]),
    [TaskState.SUBMITTED]: Object.freeze([TaskState.VERIFYING, TaskState.DISPUTED]),
    [TaskState.VERIFYING]: Object.freeze([
      TaskState.ACCEPTED,
      TaskState.REWORK,
      TaskState.NO_QUORUM,
      TaskState.DISPUTED,
    ]),
    [TaskState.REWORK]: Object.freeze([TaskState.RUNNING, TaskState.OPEN, TaskState.CANCELLED]),
    [TaskState.ACCEPTED]: Object.freeze([TaskState.SETTLED, TaskState.DISPUTED]),
    [TaskState.DISPUTED]: Object.freeze([
      TaskState.SETTLED,
      TaskState.SLASHED,
      TaskState.ACCEPTED,
      TaskState.CANCELLED,
    ]),
    [TaskState.NO_QUORUM]: Object.freeze([TaskState.OPEN, TaskState.CANCELLED]),
    [TaskState.SETTLED]: Object.freeze([]),
    [TaskState.SLASHED]: Object.freeze([]),
    [TaskState.CANCELLED]: Object.freeze([]),
  });

  /** @type {Readonly<Record<string, string>>} accepted aliases -> canonical state. */
  static ALIASES = Object.freeze({
    in_progress: TaskState.RUNNING,
    awaiting_verification: TaskState.VERIFYING,
    done: TaskState.SETTLED,
    canceled: TaskState.CANCELLED,
    dispute: TaskState.DISPUTED,
    noquorum: TaskState.NO_QUORUM,
    'no-quorum': TaskState.NO_QUORUM,
  });

  /** @type {readonly string[]} states with no outgoing edges. */
  static TERMINAL = Object.freeze([TaskState.SETTLED, TaskState.SLASHED, TaskState.CANCELLED]);

  /**
   * @param {string} value
   * @returns {string} the canonical state name
   */
  static parse(value) {
    if (typeof value === 'string') {
      // `hasOwnProperty` matters: a plain lookup would find Object.prototype
      // members such as `constructor` and accept them as aliases.
      if (Object.prototype.hasOwnProperty.call(TaskState.ALIASES, value)) {
        return TaskState.ALIASES[value];
      }
      if (TaskState.ALL.includes(value)) return value;
    }
    throw new TypeError(
      `unknown task state ${JSON.stringify(value)}; expected one of ${TaskState.ALL.join(', ')}`,
    );
  }

  /**
   * @param {string} from
   * @param {string} to
   * @returns {boolean}
   */
  static canTransitionTo(from, to) {
    const src = TaskState.parse(from);
    const dst = TaskState.parse(to);
    return TaskState.TRANSITIONS[src].includes(dst);
  }

  /**
   * @param {string} from
   * @returns {string[]} copy of the allowed next states
   */
  static nextStates(from) {
    return [...TaskState.TRANSITIONS[TaskState.parse(from)]];
  }
}

/** A unit of work in the market. */
export class Task {
  /**
   * @param {{id?: string, spec?: TaskSpec|object, state?: string, publisherDid?: string,
   *   workerDid?: string|null, priceMinor?: number|bigint, deadlineUnix?: number|null,
   *   attempts?: number, history?: string[], scale?: number, createdUnix?: number|null}} [init]
   */
  constructor(init = {}) {
    const scale = init.scale ?? DEFAULT_MONEY_SCALE;
    /** @type {string} */
    this.id = init.id ?? '';
    /** @type {TaskSpec} */
    this.spec = init.spec instanceof TaskSpec ? init.spec : new TaskSpec(init.spec ?? {});
    /** @type {string} */
    this.state = TaskState.parse(init.state ?? TaskState.OPEN);
    /** @type {string} */
    this.publisherDid = init.publisherDid ?? init.publisher_did ?? '';
    /** @type {string|null} */
    this.workerDid = init.workerDid ?? init.worker_did ?? null;
    /** @type {Money} */
    this.price = Money.fromMinor(init.priceMinor ?? init.price_minor ?? 0, scale);
    /** @type {number|null} */
    this.deadlineUnix = init.deadlineUnix ?? init.deadline_unix ?? null;
    /** @type {number} */
    this.attempts = init.attempts ?? 0;
    /** @type {string[]} */
    this.history = [...(init.history ?? [this.state])];
    /** @type {number|null} */
    this.createdUnix = init.createdUnix ?? init.created_unix ?? null;
  }

  /** @returns {Task} */
  static fromJSON(json) {
    return new Task(json);
  }

  /** @returns {string} */
  get id_() {
    return this.id;
  }

  /** @returns {boolean} true when no further transition is possible. */
  get isTerminal() {
    return TaskState.TERMINAL.includes(this.state);
  }

  /**
   * @param {string} next
   * @returns {boolean}
   */
  canTransitionTo(next) {
    return TaskState.canTransitionTo(this.state, next);
  }

  /** @returns {string[]} */
  nextStates() {
    return TaskState.nextStates(this.state);
  }

  /**
   * Move to `next`, recording history.
   *
   * A no-op transition to the same state is allowed, because re-issuing an
   * idempotent request must not fail; anything else must be in the table.
   *
   * @param {string} next
   * @returns {Task} this
   * @throws {TransitionError}
   */
  transition(next) {
    const dst = TaskState.parse(next);
    if (dst === this.state) return this;
    const allowed = this.nextStates();
    if (!allowed.includes(dst)) throw new TransitionError(this.state, dst, allowed);
    this.state = dst;
    this.history.push(dst);
    if (dst === TaskState.RUNNING) this.attempts += 1;
    return this;
  }

  /** @returns {object} */
  toPayload() {
    return {
      attempts: this.attempts,
      deadline_unix: this.deadlineUnix,
      id: this.id,
      price_minor: this.price.minor,
      publisher_did: this.publisherDid,
      scale: this.price.scale,
      spec: this.spec.toJSON(),
      state: this.state,
      worker_did: this.workerDid,
    };
  }

  /** @returns {object} */
  toJSON() {
    return this.toPayload();
  }
}

/** An offer to perform a task. */
export class Bid {
  /**
   * @param {{taskId?: string, bidderDid?: string, priceMinor?: number|bigint,
   *   etaSeconds?: number|null, reputation?: number|null, nonce?: string|null,
   *   scale?: number, signature?: string}} [init]
   */
  constructor(init = {}) {
    const scale = init.scale ?? DEFAULT_MONEY_SCALE;
    /** @type {string} */
    this.taskId = init.taskId ?? init.task_id ?? '';
    /** @type {string} */
    this.bidderDid = init.bidderDid ?? init.bidder_did ?? '';
    /** @type {Money} */
    this.price = Money.fromMinor(init.priceMinor ?? init.price_minor ?? 0, init.scale ?? scale);
    /** @type {number|null} */
    this.etaSeconds = init.etaSeconds ?? init.eta_seconds ?? null;
    /** @type {number|null} */
    this.reputation = init.reputation ?? null;
    /** @type {string|null} */
    this.nonce = init.nonce ?? null;
    /** @type {string} */
    this.signature = init.signature ?? '';
  }

  /** @returns {object} */
  toPayload() {
    const payload = {
      bidder_did: this.bidderDid,
      eta_seconds: this.etaSeconds,
      nonce: this.nonce,
      price_minor: this.price.minor,
      reputation: this.reputation,
      scale: this.price.scale,
      task_id: this.taskId,
    };
    if (this.signature) payload.signature = this.signature;
    return payload;
  }

  /** @returns {object} */
  toJSON() {
    return this.toPayload();
  }
}

/** A result submitted for a task. */
export class ResultEnvelope {
  /**
   * @param {{taskId?: string, workerDid?: string, output?: unknown, outputHash?: string|null,
   *   evidenceGrade?: string, evidence?: object|null, costMinor?: number|bigint,
   *   startedUnix?: number|null, finishedUnix?: number|null, scale?: number,
   *   signature?: string}} [init]
   */
  constructor(init = {}) {
    const scale = init.scale ?? DEFAULT_MONEY_SCALE;
    /** @type {string} */
    this.taskId = init.taskId ?? init.task_id ?? '';
    /** @type {string} */
    this.workerDid = init.workerDid ?? init.worker_did ?? '';
    /** @type {unknown} */
    this.output = init.output ?? null;
    /** @type {string|null} */
    this.outputHash = init.outputHash ?? init.output_hash ?? null;
    /** @type {string} */
    this.evidenceGrade = EvidenceGrade.parse(
      init.evidenceGrade ?? init.evidence_grade ?? EvidenceGrade.SELF_ATTESTED,
    );
    /** @type {object|null} */
    this.evidence = init.evidence ?? null;
    /** @type {Money} */
    this.cost = Money.fromMinor(init.costMinor ?? init.cost_minor ?? 0, init.scale ?? scale);
    /** @type {number|null} */
    this.startedUnix = init.startedUnix ?? init.started_unix ?? null;
    /** @type {number|null} */
    this.finishedUnix = init.finishedUnix ?? init.finished_unix ?? null;
    /** @type {string} */
    this.signature = init.signature ?? '';
  }

  /** @returns {object} */
  toPayload() {
    const payload = {
      cost_minor: this.cost.minor,
      evidence: this.evidence,
      evidence_grade: this.evidenceGrade,
      finished_unix: this.finishedUnix,
      output: this.output,
      output_hash: this.outputHash,
      scale: this.cost.scale,
      started_unix: this.startedUnix,
      task_id: this.taskId,
      worker_did: this.workerDid,
    };
    if (this.signature) payload.signature = this.signature;
    return payload;
  }

  /** @returns {object} */
  toJSON() {
    return this.toPayload();
  }
}

/** A contested result. */
export class Dispute {
  /**
   * @param {{taskId?: string, challengerDid?: string, reason?: string,
   *   evidence?: object|null, bondMinor?: number|bigint, scale?: number,
   *   openedUnix?: number|null, signature?: string}} [init]
   */
  constructor(init = {}) {
    const scale = init.scale ?? DEFAULT_MONEY_SCALE;
    /** @type {string} */
    this.taskId = init.taskId ?? init.task_id ?? '';
    /** @type {string} */
    this.challengerDid = init.challengerDid ?? init.challenger_did ?? '';
    /** @type {string} */
    this.reason = init.reason ?? '';
    /** @type {object|null} */
    this.evidence = init.evidence ?? null;
    /** @type {Money} */
    this.bond = Money.fromMinor(init.bondMinor ?? init.bond_minor ?? 0, init.scale ?? scale);
    /** @type {number|null} */
    this.openedUnix = init.openedUnix ?? init.opened_unix ?? null;
    /** @type {string} */
    this.signature = init.signature ?? '';
  }

  /** @returns {object} */
  toPayload() {
    const payload = {
      bond_minor: this.bond.minor,
      challenger_did: this.challengerDid,
      evidence: this.evidence,
      opened_unix: this.openedUnix,
      reason: this.reason,
      scale: this.bond.scale,
      task_id: this.taskId,
    };
    if (this.signature) payload.signature = this.signature;
    return payload;
  }

  /** @returns {object} */
  toJSON() {
    return this.toPayload();
  }
}

export default {
  Money,
  Skill,
  Pricing,
  Sla,
  AgentCard,
  EvidenceGrade,
  TaskSpec,
  Task,
  TaskState,
  Bid,
  ResultEnvelope,
  Dispute,
};
