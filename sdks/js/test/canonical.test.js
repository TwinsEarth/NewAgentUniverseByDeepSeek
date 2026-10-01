/**
 * Canonicalization edge cases beyond the fixture: the code-point comparator,
 * escaping, the typed refusals, and the depth bound.
 */

import { test, suite, eq, ok, throws } from './harness.js';
import {
  canonicalJson,
  canonicalPayload,
  canonicalString,
  codepointCompare,
  escapeString,
  isPlainObject,
  MAX_DEPTH,
  SIGNATURE_FIELD,
  NonIntegerNumber,
  NonPlainObject,
  RootNotObject,
  TooDeep,
  UnsafeInteger,
  UnsupportedType,
} from '../index.js';

suite('canonical: the code-point comparator', () => {
  test('the fixture astral case is ordered by code point, not UTF-16 code unit', () => {
    // a (U+0061) < U+E000 < U+1F600 by code point.
    // By UTF-16 code unit the astral key starts with the surrogate 0xD83D, so a
    // naive sort puts it FIRST. The fixture pins the difference.
    const value = { '\u{1F600}': 'astral', '\uE000': 'bmp-private-use', a: 'ascii', signature: '' };
    eq(canonicalJson(value), '{"a":"ascii","\uE000":"bmp-private-use","\u{1F600}":"astral"}');

    const naive = Object.keys(value).filter((k) => k !== 'signature').sort();
    eq(naive.join('|'), 'a|\u{1F600}|\uE000', 'the naive UTF-16 sort really does disagree');
    eq(naive[1], '\u{1F600}');
    eq(naive[2], '\uE000');

    const correct = Object.keys(value).filter((k) => k !== 'signature').sort(codepointCompare);
    eq(correct.join('|'), 'a|\uE000|\u{1F600}');

    // And the byte order proves it, not just the JS string order.
    eq(
      Buffer.from(canonicalJson(value), 'utf8').toString('hex'),
      '7b2261223a226173636969222c22ee8080223a22626d702d707269766174652d757365222c22f09f9880223a2261737472616c227d',
    );
  });

  test('codepointCompare is a total order', () => {
    const keys = ['a', 'A', '\uE000', '\u{1F600}', 'ab', 'a\u{1F600}', '', '中'];
    const sorted = [...keys].sort(codepointCompare);
    for (let i = 1; i < sorted.length; i += 1) {
      ok(codepointCompare(sorted[i - 1], sorted[i]) <= 0, `${sorted[i - 1]} <= ${sorted[i]}`);
    }
    eq(codepointCompare('a', 'a'), 0);
    // The magnitude is the code-point delta of the first differing characters,
    // so only the sign is contractual.
    eq(codepointCompare('a', 'ab') < 0, true);
    eq(codepointCompare('ab', 'a') > 0, true);
    eq(codepointCompare('\uE000', '\u{1F600}') < 0, true);
    eq(codepointCompare('\u{10000}', '\uE000') > 0, true, 'the case a UTF-16 sort gets wrong');
    // Prefixes sort before their extensions, as the fixture's `z`/`zero` shows.
    // Only the SIGN is contractual: for a prefix there is no differing code point,
    // so the code-point-delta rule does not define a magnitude. Assert the
    // total-order property (anti-symmetry) rather than an invented number.
    eq(Math.sign(codepointCompare('z', 'zero')), -Math.sign(codepointCompare('zero', 'z')));
    ok(codepointCompare('z', 'zero') < 0);
    ok(codepointCompare('ab', 'abc') < 0);
    ok(codepointCompare('abc', 'ab') > 0);
  });

  test('the fixture z/zero prefix ordering falls out of the comparator', () => {
    eq(canonicalJson({ zero: 0, z: null }), '{"z":null,"zero":0}');
  });
});

suite('canonical: escaping', () => {
  test('escapeString matches the contract for every control character', () => {
    eq(escapeString(''), '""');
    eq(escapeString('abc'), '"abc"');
    eq(escapeString('"'), '"\\""');
    eq(escapeString('\\'), '"\\\\"');
    const short = { 0x08: '\\b', 0x09: '\\t', 0x0a: '\\n', 0x0c: '\\f', 0x0d: '\\r' };
    for (let cp = 0; cp < 0x20; cp += 1) {
      const ch = String.fromCharCode(cp);
      const expected = short[cp] ?? `\\u${cp.toString(16).padStart(4, '0')}`;
      eq(escapeString(ch), `"${expected}"`, `control U+${cp.toString(16).padStart(4, '0')}`);
    }
  });

  test('U+007F and U+0085 are NOT escaped (they are not < 0x20)', () => {
    eq(escapeString('\u007f'), '"\u007f"');
    eq(escapeString('\u0085'), '"\u0085"');
    eq(escapeString('\u00a0'), '"\u00a0"');
  });

  test('non-ASCII stays raw UTF-8 in the bytes', () => {
    const bytes = canonicalPayload({ zh: '智能体宇宙' });
    eq(bytes.toString('utf8'), '{"zh":"智能体宇宙"}');
    ok(!bytes.toString('utf8').includes('\\u'), 'no unicode escapes');
    eq(bytes.length, Buffer.byteLength('{"zh":"智能体宇宙"}', 'utf8'));
  });

  test('lone surrogates are replaced by U+FFFD rather than corrupting the bytes', () => {
    // Whatever the caller does, signing must produce well-formed UTF-8.
    const bytes = canonicalPayload({ s: '\ud800' });
    eq(bytes.toString('utf8'), '{"s":"\uFFFD"}');
    eq(bytes.toString('utf8'), Buffer.from(bytes.toString('utf8'), 'utf8').toString('utf8'));
    eq(JSON.parse(bytes.toString('utf8')).s, '\uFFFD');
  });
});

suite('canonical: typed refusals', () => {
  test('every refusal has a stable code and a class of its own', () => {
    /** @type {[() => unknown, string, typeof Error][]} */
    const cases = [
      [() => canonicalJson([1]), 'root_not_object', RootNotObject],
      [() => canonicalJson('x'), 'root_not_object', RootNotObject],
      [() => canonicalJson({ a: 1.5 }), 'non_integer_number', NonIntegerNumber],
      [() => canonicalJson({ a: 2 ** 53 }), 'unsafe_integer', UnsafeInteger],
      [() => canonicalJson({ a: 1n }), 'unsupported_type', UnsupportedType],
      [() => canonicalJson({ a: undefined }), 'unsupported_type', UnsupportedType],
      [() => canonicalJson({ a: () => 0 }), 'unsupported_type', UnsupportedType],
      [() => canonicalJson({ a: Symbol('s') }), 'unsupported_type', UnsupportedType],
      [() => canonicalJson({ a: new Date() }), 'non_plain_object', NonPlainObject],
      [() => canonicalJson({ a: new Map() }), 'non_plain_object', NonPlainObject],
      [() => canonicalJson({ a: new Set() }), 'non_plain_object', NonPlainObject],
    ];
    for (const [fn, code, cls] of cases) {
      const err = throws(fn);
      eq(err.code, code, `${code} code`);
      ok(err instanceof cls, `expected ${cls.name}, got ${err.name}`);
      ok(err instanceof Error);
      ok(typeof err.message === 'string' && err.message.length > 0);
    }
  });

  test('errors carry the path to the offending value', () => {
    eq(throws(() => canonicalJson({ a: { b: [0, 1.5] } })).path, '$.a.b[1]');
    eq(throws(() => canonicalJson({ a: 2 ** 60 })).path, '$.a');
  });

  test('an object with a null prototype is a plain object', () => {
    const value = Object.create(null);
    value.a = 1;
    eq(canonicalJson(value), '{"a":1}');
    ok(isPlainObject(value));
  });

  test('a "__proto__" own key is treated like any other key', () => {
    // JSON.parse creates it as an own property, so it must survive.
    const value = JSON.parse('{"__proto__":1,"a":2}');
    eq(canonicalJson(value), '{"__proto__":1,"a":2}');
  });

  test('array holes are refused (they are undefined, not null)', () => {
    const sparse = [1];
    sparse[2] = 3;
    throws(() => canonicalJson({ a: sparse }), { name: 'UnsupportedType' });
  });

  test('symbol-keyed and non-enumerable keys are ignored, as JSON does', () => {
    const value = { a: 1 };
    Object.defineProperty(value, 'hidden', { value: 2, enumerable: false });
    value[Symbol('s')] = 3;
    eq(canonicalJson(value), '{"a":1}');
  });

  test('the signature key is dropped at every depth, and nothing else is', () => {
    eq(SIGNATURE_FIELD, 'signature');
    eq(canonicalJson({ signature: 'x' }), '{}');
    eq(canonicalJson({ Signature: 'x' }), '{"Signature":"x"}');
    eq(canonicalJson({ signature_x: 1 }), '{"signature_x":1}');
    eq(canonicalString([{ signature: 'x' }]), '[{}]');
    eq(canonicalJson({ a: [{ signature: 'x' }] }), '{"a":[{}]}');
    eq(canonicalJson({ a: { b: { c: { signature: 'x', keep: 1 } } } }), '{"a":{"b":{"c":{"keep":1}}}}');
  });

  test('signature is dropped from an array of objects', () => {
    eq(canonicalJson({ list: [{ signature: 'a', n: 1 }, { signature: 'b', n: 2 }] }), '{"list":[{"n":1},{"n":2}]}');
  });
});

suite('canonical: boundaries and stability', () => {
  test('MAX_DEPTH is 64 and enforced at the boundary, not beyond it', () => {
    eq(MAX_DEPTH, 64);
    /** @param {number} n */
    const nest = (n) => {
      let value = 1;
      for (let i = 0; i < n; i += 1) value = { n: value };
      return value;
    };
    canonicalJson({ root: nest(63) }); // 64 levels: the last allowed
    throws(() => canonicalJson({ root: nest(64) }), { name: 'TooDeep', code: 'too_deep' });
    const err = throws(() => canonicalJson({ root: nest(64) }));
    eq(err.limit, 64);
  });

  test('arrays count towards depth too', () => {
    let value = 1;
    for (let i = 0; i < 64; i += 1) value = [value];
    throws(() => canonicalJson({ root: value }), { name: 'TooDeep' });
  });

  test('-0 and 0 canonicalize identically', () => {
    eq(canonicalJson({ n: -0 }), '{"n":0}');
    eq(canonicalJson({ n: -0 }), canonicalJson({ n: 0 }));
  });

  test('empty object, empty array and null are stable', () => {
    eq(canonicalJson({}), '{}');
    eq(canonicalJson({ a: {}, b: [], c: null }), '{"a":{},"b":[],"c":null}');
    eq(canonicalJson({ a: [1, [2, [3]]] }), '{"a":[1,[2,[3]]]}');
  });

  test('canonicalString canonicalizes a non-object root (for hashing sub-values)', () => {
    eq(canonicalString([1, 2]), '[1,2]');
    eq(canonicalString('x'), '"x"');
    eq(canonicalString(null), 'null');
    throws(() => canonicalJson([1, 2]), { name: 'RootNotObject' });
  });

  test('the same input gives the same bytes every time', () => {
    const value = { b: [1, { c: '中' }], a: 2 ** 40, s: 'x\ny' };
    const first = canonicalJson(value);
    for (let i = 0; i < 50; i += 1) eq(canonicalJson(value), first);
    eq(canonicalPayload(value).toString('utf8'), first);
  });

  test('key insertion order does not affect the output', () => {
    const a = {};
    const b = {};
    for (const key of ['z', 'm', 'a']) a[key] = 1;
    for (const key of ['a', 'z', 'm']) b[key] = 1;
    eq(canonicalJson(a), canonicalJson(b));
    eq(canonicalJson(a), '{"a":1,"m":1,"z":1}');
  });
});
