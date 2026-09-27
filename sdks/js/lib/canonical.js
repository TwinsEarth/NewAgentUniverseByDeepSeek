/**
 * Canonical JSON — the byte-level signing contract (protocol `nau/1`).
 *
 * The rules are fixed by `conformance/vectors.json` and implemented a third
 * time in `crates/nau-core/src/identity/canonical.rs`. They are:
 *
 * 1. The value must be a JSON **object** at the root.
 * 2. Every object key named `signature` is dropped, **at every depth**.
 * 3. Object keys are emitted in ascending **Unicode code point** order.
 * 4. No whitespace: separators are exactly `,` and `:`.
 * 5. Strings are raw UTF-8. Only `"`, `\` and the seven short control escapes
 *    are escaped; any other control character becomes lowercase `\u00xx`.
 * 6. Numbers must be integers that survive JavaScript exactly
 *    (`Number.isSafeInteger`); floats and wide integers are rejected.
 * 7. Nesting is bounded to {@link MAX_DEPTH} levels.
 *
 * Where this deliberately differs from upstream v2.5.6:
 *
 * * upstream removed `signature` only at the root, so a nested signed structure
 *   had its inner signature covered by the outer one;
 * * upstream's `stableStringify` could emit the bare token `undefined`
 *   (producing `{"a":undefined,"b":1}`, which is not JSON), threw an uncaught
 *   error on `BigInt`, and silently serialized a `Date` as `{}` — a
 *   valid-looking signature over the wrong payload;
 * * upstream used `JSON.stringify`, which turns `NaN`/`Infinity` into `null`;
 * * upstream used the default `Array.prototype.sort()`, which compares UTF-16
 *   code units and therefore orders U+10000 *before* U+E000.
 *
 * Serialization never silently signs `null`: every failure throws.
 */

import {
  CanonicalError,
  NonIntegerNumber,
  NonPlainObject,
  RootNotObject,
  TooDeep,
  UnsafeInteger,
  UnsupportedType,
  describeKind,
} from './errors.js';

/** Object key removed (at every depth) before signing or verifying. */
export const SIGNATURE_FIELD = 'signature';

/** Maximum object/array nesting accepted while canonicalizing. */
export const MAX_DEPTH = 64;

/** Maximum string length accepted by {@link codepointCompare}'s callers. */
const SHORT_ESCAPES = Object.freeze({
  0x08: '\\b',
  0x09: '\\t',
  0x0a: '\\n',
  0x0c: '\\f',
  0x0d: '\\r',
});

/**
 * Compare two strings by **Unicode code point**, not UTF-16 code unit.
 *
 * `Array.prototype.sort()`'s default comparator compares UTF-16 code units, so
 * `'\u{1F600}'.charCodeAt(0) === 0xd83d` sorts an astral key *before* `'\uE000'`
 * (`0xe000`). Rust's `&str` ordering and Python's `sort_keys=True` both compare
 * code points. The conformance vector `astral-plane-key-ordering` pins this.
 *
 * Iterating with `[...str]` yields whole code points (`String.prototype[Symbol
 * .iterator]` is code-point aware), so comparing `codePointAt(0)` per element
 * matches Rust and Python exactly.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number} negative, zero or positive
 */
export function codepointCompare(a, b) {
  const ai = [...a];
  const bi = [...b];
  const n = Math.min(ai.length, bi.length);
  for (let i = 0; i < n; i += 1) {
    const d = ai[i].codePointAt(0) - bi[i].codePointAt(0);
    if (d !== 0) return d;
  }
  return ai.length - bi.length;
}

/**
 * Escape a string exactly as the contract requires: raw UTF-8 everywhere except
 * `"`, `\` and control characters.
 *
 * This is a hand-written replacement for `JSON.stringify`, which is not used
 * for scalars at all here — `JSON.stringify` is only trusted for string
 * escaping after the value's type has been checked by the caller, and this
 * function avoids even that dependency.
 *
 * @param {string} s
 * @returns {string} the quoted, escaped literal
 */
export function escapeString(s) {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (cp < 0x20) {
      const short = SHORT_ESCAPES[cp];
      out += short !== undefined ? short : `\\u${cp.toString(16).padStart(4, '0')}`;
    } else out += ch;
  }
  return `${out}"`;
}

/**
 * True when `value` is a plain object (object literal or `Object.create(null)`).
 *
 * `Date`, `Map`, `Set` and class instances are rejected rather than serialized
 * as `{}`, which is the upstream defect this exists to prevent.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

/**
 * Name the kind of a value for error messages (plain objects never reach it).
 *
 * @param {unknown} value
 * @returns {string}
 */
function kindOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  const t = typeof value;
  if (t !== 'object') return t;
  const tag = Object.prototype.toString.call(value).slice(8, -1);
  return tag === 'Object' ? 'object' : tag;
}

/** Types that cannot appear in JSON at all, reported as UnsupportedType. */
const UNSUPPORTED_TYPES = new Set(['undefined', 'bigint', 'function', 'symbol']);

/**
 * Append the canonical form of `value` to `out`.
 *
 * @param {string[]} out
 * @param {unknown} value
 * @param {number} depth
 * @param {string} path
 */
function writeValue(out, value, depth, path) {
  if (depth > MAX_DEPTH) throw new TooDeep(MAX_DEPTH, path);

  if (value === null) {
    out.push('null');
    return;
  }
  if (value === true) {
    out.push('true');
    return;
  }
  if (value === false) {
    out.push('false');
    return;
  }

  switch (typeof value) {
    case 'number': {
      if (!Number.isInteger(value)) throw new NonIntegerNumber(value, path);
      if (!Number.isSafeInteger(value)) throw new UnsafeInteger(value, path);
      // `-0` and `0` are the same JSON number; String(-0) is "0" already.
      out.push(String(value));
      return;
    }
    case 'string': {
      out.push(escapeString(value));
      return;
    }
    case 'bigint':
    case 'undefined':
    case 'function':
    case 'symbol':
      throw new UnsupportedType(typeof value, path);
    case 'object':
      break;
    default:
      throw new UnsupportedType(typeof value, path);
  }

  if (Array.isArray(value)) {
    out.push('[');
    for (let i = 0; i < value.length; i += 1) {
      if (i > 0) out.push(',');
      writeValue(out, value[i], depth + 1, `${path}[${i}]`);
    }
    out.push(']');
    return;
  }

  if (!isPlainObject(value)) throw new NonPlainObject(kindOf(value), path);

  // Collect keys, drop `signature` at EVERY depth, then sort by code point.
  const keys = Object.keys(value)
    .filter((k) => k !== SIGNATURE_FIELD)
    .sort(codepointCompare);

  out.push('{');
  for (let i = 0; i < keys.length; i += 1) {
    const key = keys[i];
    if (i > 0) out.push(',');
    out.push(escapeString(key), ':');
    writeValue(out, value[key], depth + 1, `${path}.${key}`);
  }
  out.push('}');
}

/**
 * Canonicalize a signing payload.
 *
 * @param {unknown} obj must be a plain object
 * @returns {string} canonical JSON text
 * @throws {RootNotObject} when the root is not an object
 * @throws {NonIntegerNumber} on floats and exponent-form numbers
 * @throws {UnsafeInteger} on integers outside `|n| <= 2^53 - 1`
 * @throws {TooDeep} beyond {@link MAX_DEPTH} levels
 * @throws {UnsupportedType} on `undefined`, `BigInt`, functions, symbols
 * @throws {NonPlainObject} on `Date`, `Map`, `Set` and class instances
 */
export function canonicalJson(obj) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new RootNotObject(obj);
  }
  if (!isPlainObject(obj)) throw new NonPlainObject(kindOf(obj), '$');
  const out = [];
  writeValue(out, obj, 0, '$');
  return out.join('');
}

/**
 * Canonicalize a signing payload to the exact bytes that get signed.
 *
 * @param {unknown} obj
 * @returns {Buffer} UTF-8 bytes of {@link canonicalJson}
 */
export function canonicalPayload(obj) {
  return Buffer.from(canonicalJson(obj), 'utf8');
}

/**
 * Canonicalize any JSON value, including a non-object root.
 *
 * Signing must use {@link canonicalJson}; this exists for hashing sub-structures
 * (mirroring `canonical_string` in the Rust core).
 *
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalString(value) {
  const out = [];
  writeValue(out, value, 0, '$');
  return out.join('');
}

/**
 * Validate that a value could be canonicalized at all, without producing text.
 *
 * @param {unknown} obj
 * @returns {boolean} always true (throws otherwise)
 */
export function assertCanonicalizable(obj) {
  canonicalJson(obj);
  return true;
}

export { CanonicalError, describeKind, isPlainObject, kindOf, UNSUPPORTED_TYPES };

export default canonicalJson;
