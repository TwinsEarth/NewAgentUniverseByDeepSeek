/**
 * Typed errors shared by the SDK.
 *
 * Every error carries a stable machine-readable `code` string as well as a
 * human message, so callers can branch on the code while tests can assert on
 * either. `instanceof` works for both the base class and the subclasses
 * because of the `Object.setPrototypeOf` calls below (ES5 down-level emit is
 * not the only reason: it also keeps `Error.captureStackTrace` behaviour
 * predictable across realms).
 */

/** Base class for every error this SDK raises. */
export class NauError extends Error {
  /**
   * @param {string} message
   * @param {{ code?: string, cause?: unknown }} [options]
   */
  constructor(message, options = {}) {
    super(message);
    this.name = new.target.name;
    this.code = options.code ?? 'nau_error';
    if (options.cause !== undefined) this.cause = options.cause;
    Object.setPrototypeOf(this, new.target.prototype);
    if (typeof Error.captureStackTrace === 'function') {
      Error.captureStackTrace(this, new.target);
    }
  }

  /** Machine-readable code, useful in `switch` statements and logs. */
  get errorCode() {
    return this.code;
  }
}

/** Base class for canonicalization failures. */
export class CanonicalError extends NauError {
  constructor(message, options = {}) {
    super(message, { code: 'canonical_error', ...options });
  }
}

/** The root of a signing payload was not a JSON object. */
export class RootNotObject extends CanonicalError {
  /**
   * @param {unknown} value the offending value
   */
  constructor(value) {
    super(
      `canonical payload root must be a JSON object, found ${describeKind(value)}`,
      { code: 'root_not_object' },
    );
    /** The offending value. */
    this.value = value;
  }
}

/** A float / exponent-form number appeared in a signing payload. */
export class NonIntegerNumber extends CanonicalError {
  /**
   * @param {unknown} value
   * @param {string} [path]
   */
  constructor(value, path = '$') {
    super(
      `non-integer number ${describeKind(value) === 'number' ? String(value) : JSON.stringify(value)}`
        + ` at ${path}: signing payloads admit integers only`
        + ' (carry money as integer minor units, never as a float)',
      { code: 'non_integer_number' },
    );
    /** The offending number. */
    this.value = value;
    /** JSON-pointer-ish path of the offending value. */
    this.path = path;
  }
}

/**
 * An integer that does not survive `Number` exactly.
 *
 * This is the documented portability boundary: `2^63 - 1` and `2^64 - 1` are
 * representable in Rust and Python but not in JavaScript. The caller must pass
 * such a value as a decimal *string*, or not at all. The fix is never to round
 * it silently, because that would sign a payload that does not exist.
 */
export class UnsafeInteger extends CanonicalError {
  /**
   * @param {number} value
   * @param {string} [path]
   */
  constructor(value, path = '$') {
    super(
      `integer ${String(value)} at ${path} is outside the JavaScript safe-integer range`
        + ' (|n| > 2^53 - 1) and cannot round-trip through JSON.parse/JSON.stringify:'
        + ' pass the value as a decimal string instead',
      { code: 'unsafe_integer' },
    );
    /** The offending number, as JavaScript parsed it. */
    this.value = value;
    /** JSON-pointer-ish path of the offending value. */
    this.path = path;
  }
}

/** A payload nested deeper than the 64-level bound. */
export class TooDeep extends CanonicalError {
  /**
   * @param {number} [limit]
   * @param {string} [path]
   */
  constructor(limit = 64, path = '$') {
    super(
      `canonical payload nests deeper than ${limit} levels (at ${path})`,
      { code: 'too_deep' },
    );
    /** The configured bound. */
    this.limit = limit;
    /** Path at which the bound was exceeded. */
    this.path = path;
  }
}

/** A value that JSON cannot represent was passed for canonicalization. */
export class UnsupportedType extends CanonicalError {
  /**
   * @param {string} kind
   * @param {string} [path]
   */
  constructor(kind, path = '$') {
    super(
      `cannot canonicalize a value of type ${kind} at ${path}:`
        + ' signing payloads admit only null, boolean, integer, string, array and plain object',
      { code: 'unsupported_type' },
    );
    /** The offending type. */
    this.kind = kind;
    /** JSON-pointer-ish path of the offending value. */
    this.path = path;
  }
}

/** A non-plain object (Date, Map, Set, class instance) was passed. */
export class NonPlainObject extends CanonicalError {
  /**
   * @param {string} kind
   * @param {string} [path]
   */
  constructor(kind, path = '$') {
    super(
      `cannot canonicalize a ${kind} instance at ${path}:`
        + ' only plain objects are serializable, and a valid-looking signature over'
        + ' an accidentally-empty payload is worse than an error',
      { code: 'non_plain_object' },
    );
    /** The offending type. */
    this.kind = kind;
    /** JSON-pointer-ish path of the offending value. */
    this.path = path;
  }
}

/** A signature could not be produced or did not verify. */
export class SignatureError extends NauError {
  /**
   * @param {string} message
   * @param {{ cause?: unknown }} [options]
   */
  constructor(message, options = {}) {
    super(message, { code: 'signature_error', ...options });
  }
}

/** A DID string was malformed. */
export class DidError extends NauError {
  /**
   * @param {string} message
   */
  constructor(message) {
    super(message, { code: 'did_error' });
  }
}

/** A DID did not match the public key supplied alongside it. */
export class DidMismatchError extends NauError {
  /**
   * @param {string} did
   * @param {string} fingerprint
   */
  constructor(did, fingerprint) {
    super(
      `DID ${did} does not match the supplied public key (fingerprint ${fingerprint})`,
      { code: 'did_mismatch' },
    );
    /** The DID as supplied. */
    this.did = did;
    /** The fingerprint derived from the public key. */
    this.fingerprint = fingerprint;
  }
}

/** A key derivation problem: wrong seed length, unusable DER. */
export class KeyError extends NauError {
  /**
   * @param {string} message
   */
  constructor(message) {
    super(message, { code: 'key_error' });
  }
}

/** An amount of money was not an integer minor-unit count, or scales clashed. */
export class MoneyError extends NauError {
  /**
   * @param {string} message
   */
  constructor(message) {
    super(message, { code: 'money_error' });
  }
}

/** A task state transition was refused. */
export class TransitionError extends NauError {
  /**
   * @param {string} from
   * @param {string} to
   * @param {string[]} allowed
   */
  constructor(from, to, allowed) {
    super(
      `illegal task state transition ${from} -> ${to}`
        + ` (allowed from ${from}: ${allowed.length > 0 ? allowed.join(', ') : 'none; terminal state'})`,
      { code: 'invalid_transition' },
    );
    /** Source state. */
    this.from = from;
    /** Requested destination state. */
    this.to = to;
    /** States reachable from `from`. */
    this.allowed = allowed;
  }
}

/**
 * A short, human-readable description of any value's JSON-ish kind.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function describeKind(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  const t = typeof value;
  if (t !== 'object') return t;
  const tag = Object.prototype.toString.call(value).slice(8, -1);
  return tag === 'Object' ? 'object' : tag;
}

export default {
  NauError,
  CanonicalError,
  RootNotObject,
  NonIntegerNumber,
  UnsafeInteger,
  TooDeep,
  UnsupportedType,
  NonPlainObject,
  SignatureError,
  DidError,
  DidMismatchError,
  KeyError,
  MoneyError,
  TransitionError,
  describeKind,
};
