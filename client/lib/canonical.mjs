/**
 * Canonical JSON — the byte-level signing contract (protocol `nau/1`).
 *
 * This is the browser's copy of the rules pinned by `conformance/vectors.json`
 * and implemented for Node in `sdks/js/lib/canonical.js` and for Rust in
 * `crates/nau-core/src/identity/canonical.rs`. It exists as a **module shared by
 * the browser and the test harness** so that the exact function the UI signs
 * with is the exact function `client/test/e2e.mjs` proves against the checked-in
 * vectors — there is no second, test-only implementation that could drift.
 *
 * The rules are:
 *
 * 1. The value must be a JSON **object** at the root.
 * 2. Every object key named `signature` is dropped, **at every depth**.
 * 3. Object keys are emitted in ascending **Unicode code point** order.
 * 4. No whitespace: separators are exactly `,` and `:`.
 * 5. Strings are raw UTF-8. Only `"`, `\` and the seven short control escapes
 *    are escaped; any other control character becomes lowercase `\u00xx`.
 * 6. Numbers must be integers that survive JavaScript exactly
 *    (`Number.isSafeInteger`); floats and wide integers throw.
 * 7. Nesting is bounded to {@link MAX_DEPTH} levels.
 *
 * Where this deliberately differs from upstream agent-universe v2.5.6 (the
 * defects `docs/GAP-ANALYSIS.md` §9.5 records against its client):
 *
 * * upstream removed `signature` only at the root, so a nested signed structure
 *   had its inner signature covered by the outer one;
 * * upstream's `stableStringify` could emit the bare token `undefined`, threw on
 *   `BigInt` and silently serialized a `Date` as `{}`;
 * * upstream used `Array.prototype.sort()`, which compares UTF-16 code units and
 *   therefore orders U+10000 *before* U+E000.
 *
 * There is no `Buffer` here: this file runs unchanged in a browser and in Node.
 */

/** Object key removed (at every depth) before signing or verifying. */
export const SIGNATURE_FIELD = 'signature';

/** Maximum object/array nesting accepted while canonicalizing. */
export const MAX_DEPTH = 64;

/** Control characters with a one-character JSON escape. */
const SHORT_ESCAPES = Object.freeze({
  0x08: '\\b',
  0x09: '\\t',
  0x0a: '\\n',
  0x0c: '\\f',
  0x0d: '\\r',
});

/** A canonicalization failure that is never silently swallowed. */
export class CanonicalError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'CanonicalError';
  }
}

/**
 * Compare two strings by **Unicode code point**, not UTF-16 code unit.
 *
 * `Array.prototype.sort()`'s default comparator compares UTF-16 code units, so
 * `'\u{1F600}'.charCodeAt(0) === 0xd83d` sorts an astral key *before* `'\uE000'`
 * (`0xe000`). Rust's `&str` ordering and Python's `sort_keys=True` both compare
 * code points; the `astral-plane-key-ordering` vector pins this.
 *
 * Iterating a string with `for...of` (or spreading it) yields whole code points,
 * so comparing `codePointAt(0)` per element matches Rust and Python exactly.
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
export function isPlainObject(value) {
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
export function kindOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  const t = typeof value;
  if (t !== 'object') return t;
  const tag = Object.prototype.toString.call(value).slice(8, -1);
  return tag === 'Object' ? 'object' : tag;
}

/**
 * True when `key` is dropped at every depth.
 *
 * @param {string} key
 * @returns {boolean}
 */
function isDroppedKey(key) {
  return key === SIGNATURE_FIELD;
}

/**
 * Append the canonical form of `value` to `out`.
 *
 * @param {string[]} out
 * @param {unknown} value
 * @param {number} depth
 * @param {string} path
 */
function writeValue(out, value, depth, path) {
  if (depth > MAX_DEPTH) {
    throw new CanonicalError(`nesting deeper than ${MAX_DEPTH} levels at ${path}`);
  }

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
      if (!Number.isInteger(value)) {
        throw new CanonicalError(
          `float at ${path}: ${value} — floats are refused, send minor units as an integer`,
        );
      }
      if (!Number.isSafeInteger(value)) {
        throw new CanonicalError(
          `integer at ${path} (${value}) exceeds Number.MAX_SAFE_INTEGER and cannot be signed portably`,
        );
      }
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
      throw new CanonicalError(`unsupported ${typeof value} at ${path}`);
    case 'object':
      break;
    default:
      throw new CanonicalError(`unsupported ${typeof value} at ${path}`);
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

  if (!isPlainObject(value)) {
    throw new CanonicalError(`non-plain object (${kindOf(value)}) at ${path}`);
  }

  // Collect keys, drop `signature` at EVERY depth, then sort by code point.
  const keys = Object.keys(value).filter((k) => !isDroppedKey(k)).sort(codepointCompare);

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
 * @throws {CanonicalError} on any value that cannot be reproduced byte-for-byte
 */
export function canonicalJson(obj) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new CanonicalError(`a signing payload must be a JSON object, got ${kindOf(obj)}`);
  }
  if (!isPlainObject(obj)) throw new CanonicalError(`non-plain object (${kindOf(obj)}) at $`);
  const out = [];
  writeValue(out, obj, 0, '$');
  return out.join('');
}

/**
 * UTF-8 bytes of {@link canonicalJson} — exactly what gets signed.
 *
 * @param {unknown} obj
 * @returns {Uint8Array}
 */
export function canonicalPayload(obj) {
  return new TextEncoder().encode(canonicalJson(obj));
}
