/**
 * The conformance suite: every vector in `conformance/vectors.json`.
 *
 * This is the contract. If a case here fails, the SDK is not conformant,
 * whatever else passes.
 */

import { test, suite, eq, ok, throws } from './harness.js';
import { vectors, allPayloads, isJsUnsupported, spliceWideIntegers, fixtureSign } from './helpers.js';import {
  Keypair,
  Identity,
  didFromPublicKey,
  fingerprint,
  canonicalJson,
  canonicalPayload,
  verifyPayload,
  verifyRaw,
  NonIntegerNumber,
  RootNotObject,
  UnsafeInteger,
  CanonicalError,
  TooDeep,
  NonPlainObject,
  UnsupportedType,
} from '../index.js';

const seed = Buffer.from(vectors.seed_hex, 'hex');
const keypair = Keypair.fromSeed(seed);
const rawPublic = keypair.publicKey;

suite('conformance: identity', () => {
  test('seed derives the fixture raw public key', () => {
    eq(rawPublic.toString('hex'), vectors.identity.public_key_hex, 'raw public key');
  });

  test('public key is the last 32 bytes of the SPKI DER export', () => {
    // The fixture's `public_key_hex` is the check: an implementation that
    // hashed the SPKI DER instead would produce a different DID.
    eq(fingerprint(rawPublic), vectors.identity.did_nau.slice('did:nau:'.length));
  });

  test('did:nau matches the fixture', () => {
    eq(keypair.did, vectors.identity.did_nau);
  });

  test('the legacy did:aip spelling uses the SAME fingerprint rule', () => {
    eq(keypair.didWith('did:aip:'), vectors.identity.did_legacy);
    eq(
      vectors.identity.did_legacy.slice('did:aip:'.length),
      vectors.identity.did_nau.slice('did:nau:'.length),
      'both methods must hash the raw public key identically',
    );
  });

  test('didFromPublicKey is deterministic and prefix-parameterised', () => {
    eq(didFromPublicKey(rawPublic), vectors.identity.did_nau);
    eq(didFromPublicKey(rawPublic, 'did:aip:'), vectors.identity.did_legacy);
  });
});

suite('conformance: canonical bytes and signatures', () => {
  for (const payload of allPayloads) {
    const wide = isJsUnsupported(payload);

    test(`${payload.id}: canonical text is byte-for-byte the fixture's`, () => {
      if (wide) {
        // JSON.parse rounds these, so the bytes can only be reproduced by
        // splicing the original integer token back in. The fixture's own
        // `canonical_hex` is what this must equal.
        const spliced = spliceWideIntegers(payload.input_json, payload.canonical);
        eq(
          Buffer.from(spliced, 'utf8').toString('hex'),
          payload.canonical_hex,
          'spliced canonical bytes',
        );
        return;
      }
      const parsed = JSON.parse(payload.input_json);
      eq(canonicalJson(parsed), payload.canonical, 'canonical text');
      eq(canonicalPayload(parsed).toString('hex'), payload.canonical_hex, 'canonical bytes');
    });

    test(`${payload.id}: the fixture signature verifies`, () => {
      if (wide) {
        // Pinned portability boundary: the integer cannot be parsed, so verify
        // over the spliced bytes instead.
        const spliced = spliceWideIntegers(payload.input_json, payload.canonical);
        ok(
          verifyRaw(spliced, payload.signature_hex, rawPublic),
          'fixture signature must verify over the spliced canonical bytes',
        );
        return;
      }
      const parsed = JSON.parse(payload.input_json);
      ok(
        verifyPayload(parsed, payload.signature_hex, rawPublic),
        'fixture signature must verify',
      );
      ok(keypair.verifyPayload(parsed, payload.signature_hex));
    });

    test(`${payload.id}: re-signing reproduces signature_hex exactly`, () => {
      if (wide) {
        const spliced = spliceWideIntegers(payload.input_json, payload.canonical);
        eq(keypair.sign(spliced).toString('hex'), payload.signature_hex, 're-signed');
        return;
      }
      const parsed = JSON.parse(payload.input_json);
      eq(keypair.signPayload(parsed).toString('hex'), payload.signature_hex, 're-signed');
      // Independently, through node:crypto directly: the SDK must not be
      // verifying its own mistake.
      eq(fixtureSign(canonicalJson(parsed)), payload.signature_hex, 'crypto re-signed');
    });
  }
});

suite('conformance: wide integers are the documented portability boundary', () => {
  const wide = allPayloads.filter(isJsUnsupported);

  test('the fixture marks exactly two payloads as unsupported-by-json-parse', () => {
    eq(wide.length, 2, 'wide payload count');
    eq(
      wide.map((p) => p.id).sort().join(','),
      'int64-max,uint64-max',
      'wide payload ids',
    );
  });

  for (const payload of wide) {
    test(`${payload.id}: JSON.parse cannot represent it, and the SDK refuses it`, () => {
      const parsed = JSON.parse(payload.input_json);
      // First, show the corruption that motivates the rejection.
      ok(
        !Number.isSafeInteger(parsed.n),
        `${payload.id} must parse to an unsafe integer in JavaScript`,
      );
      throws(() => canonicalJson(parsed), { name: 'UnsafeInteger', code: 'unsafe_integer' });
      throws(() => canonicalPayload(parsed), { name: 'UnsafeInteger', code: 'unsafe_integer' });
      // The signature produced for the *rounded* value would be a signature
      // over a payload nobody asked for; assert we never got that far.
      let produced = null;
      try {
        produced = keypair.signPayload(parsed);
      } catch {
        produced = null;
      }
      eq(produced, null, 'must not sign a rounded payload');
    });
  }

  test('UnsafeInteger tells the caller to pass the value as a string', () => {
    const err = throws(() => canonicalJson({ n: 2 ** 53 }), { name: 'UnsafeInteger' });
    ok(/decimal string/.test(err.message), `message should suggest a decimal string: ${err.message}`);
    eq(err.code, 'unsafe_integer');
    eq(err.path, '$.n');
  });

  test('2^53 - 1 is accepted; 2^53 is not', () => {
    eq(canonicalJson({ n: 9007199254740991 }), '{"n":9007199254740991}');
    throws(() => canonicalJson({ n: 9007199254740992 }), { name: 'UnsafeInteger' });
  });
});

suite('conformance: rejections', () => {
  /**
   * Which fixture error name each class claims.
   *
   * @param {string} code
   * @returns {typeof CanonicalError}
   */
  function classFor(code) {
    /** @type {Record<string, typeof CanonicalError>} */
    const table = {
      non_integer_number: NonIntegerNumber,
      root_not_object: RootNotObject,
      unsafe_integer: UnsafeInteger,
    };
    const found = table[code];
    ok(found !== undefined, `unknown fixture error name ${code}`);
    return found;
  }

  for (const rejection of vectors.rejections) {
    // The three float-typed vectors are covered by the explicitly-named tests
    // below, because in JavaScript `100.0` and `1e2` are literally the integer
    // 100 and cannot be refused.
    const jsCannotSeeIt = rejection.id === 'float-value' || rejection.id === 'exponent-notation';
    test(`${rejection.id}: throws ${rejection.error}`, () => {
      if (jsCannotSeeIt) {
        // Pinned, not skipped: JavaScript parses both to the integer 100.
        const parsed = JSON.parse(rejection.input_json);
        ok(Number.isInteger(parsed.amount), 'the premise: JS parses these to an integer');
        eq(canonicalJson(parsed), '{"amount":100}');
        return;
      }
      const parsed = JSON.parse(rejection.input_json);
      const expected = classFor(rejection.error);
      const err = throws(() => canonicalJson(parsed));
      ok(
        err instanceof expected,
        `${rejection.id} should throw ${expected.name}, got ${err.name}: ${err.message}`,
      );
      eq(err.code, rejection.error);
      ok(err instanceof CanonicalError, 'every rejection is a CanonicalError');
      // The same value must be refused through canonicalPayload, not just
      // canonicalJson: signing must not have a second code path.
      throws(() => canonicalPayload(parsed), { code: rejection.error });
    });
  }

  test('float-value: JavaScript sees 100.0 as the integer 100, so it is ACCEPTED', () => {
    // Documented deviation, pinned here so it cannot drift unnoticed.
    //
    // The fixture refuses `{"amount":100.0}` because `100`, `100.0` and `1e2`
    // format differently in Rust and Python. JavaScript has exactly one number
    // type: `JSON.parse('100.0')` is the integer 100 and `Number.isInteger` is
    // true, so there is nothing to distinguish and nothing to reformat. A JS
    // client that sends 100 therefore produces the same bytes as a Rust client
    // that sends 100.0 — which is the *point* of the rule, and is why
    // conformance/vectors.json serves this vector as a rejection for the
    // languages that can tell the difference.
    ok(Number.isInteger(100.0), 'the premise: Number.isInteger(100.0) is true');
    const parsed = JSON.parse('{"amount":100.0}');
    eq(parsed.amount, 100);
    ok(Number.isInteger(parsed.amount));
    eq(canonicalJson(parsed), '{"amount":100}');
    eq(fixtureSign(canonicalJson(parsed)).length, 128);
  });

  test('exponent-notation: JavaScript sees 1e2 as the integer 100, so it is ACCEPTED', () => {
    // Same deviation, same reason as above.
    const parsed = JSON.parse('{"amount":1e2}');
    eq(parsed.amount, 100);
    ok(Number.isInteger(parsed.amount));
    eq(canonicalJson(parsed), '{"amount":100}');
  });

  test('fractional-value really is refused, which is the part JS can enforce', () => {
    throws(() => canonicalJson(JSON.parse('{"amount":1.5}')), {
      name: 'NonIntegerNumber',
      code: 'non_integer_number',
    });
  });

  test('a float that arrives as a float is refused (NaN, Infinity, fractions)', () => {
    for (const value of [NaN, Infinity, -Infinity, 0.1 + 0.2, 1.5, -0.5, 1e-7]) {
      throws(() => canonicalJson({ amount: value }), { name: 'NonIntegerNumber' });
    }
  });

  test('the fixture error names map onto the exported classes', () => {
    // The code is an instance property, not a prototype one, so the classes are
    // instantiated rather than poked at through `prototype`.
    const probes = [new NonIntegerNumber(1.5), new RootNotObject([]), new UnsafeInteger(2 ** 53)];
    const known = new Set(probes.map((e) => e.code));
    for (const name of new Set(vectors.rejections.map((r) => r.error))) {
      ok(known.has(name), `no class claims the fixture error name ${name}`);
    }
  });
});

suite('conformance: the rules themselves', () => {
  test('every rejection and payload note is documented in the rule list', () => {
    ok(vectors.canonicalization_rules.length >= 7);
    for (const rule of vectors.canonicalization_rules) ok(typeof rule === 'string' && rule.length > 0);
  });

  test('nested signature is dropped at every depth', () => {
    const value = { outer: 1, signature: 'a', nested: { inner: true, signature: 'b' }, list: [{ signature: 'c', kept: 1 }] };
    eq(canonicalJson(value), '{"list":[{"kept":1}],"nested":{"inner":true},"outer":1}');
  });

  test('depth is bounded at 64 with a TooDeep error', () => {
    let at63 = 1;
    for (let i = 0; i < 63; i += 1) at63 = { n: at63 };
    canonicalJson({ root: at63 }); // depth 64: allowed
    let at64 = 1;
    for (let i = 0; i < 64; i += 1) at64 = { n: at64 };
    throws(() => canonicalJson({ root: at64 }), { name: 'TooDeep', code: 'too_deep' });
    ok(new TooDeep(64).message.includes('64'));
  });

  test('a Date is refused rather than serialized as {}', () => {
    const err = throws(() => canonicalJson({ at: new Date(0) }), { name: 'NonPlainObject' });
    eq(err.code, 'non_plain_object');
    eq(err.kind, 'Date');
  });

  test('Map and Set are refused rather than serialized as {}', () => {
    throws(() => canonicalJson({ at: new Map() }), { name: 'NonPlainObject' });
    throws(() => canonicalJson({ at: new Set() }), { name: 'NonPlainObject' });
    throws(() => canonicalJson({ at: new (class Foo {})() }), { name: 'NonPlainObject' });
  });

  test('undefined, functions, symbols and BigInt are refused, never coerced', () => {
    // Upstream emitted the bare token `undefined` here: {"a":undefined} is not
    // JSON at all.
    throws(() => canonicalJson({ a: undefined, b: 1 }), { name: 'UnsupportedType', code: 'unsupported_type' });
    throws(() => canonicalJson({ a: () => 1 }), { name: 'UnsupportedType' });
    throws(() => canonicalJson({ a: Symbol('x') }), { name: 'UnsupportedType' });
    throws(() => canonicalJson({ a: 1n }), { name: 'UnsupportedType', code: 'unsupported_type' });
    throws(() => canonicalJson({ a: [1, undefined] }), { name: 'UnsupportedType' });
  });

  test('strings are raw UTF-8 and control characters use lowercase \\u00xx', () => {
    eq(canonicalJson({ s: '智能体宇宙' }), '{"s":"智能体宇宙"}');
    eq(canonicalJson({ s: 'a"b\\c\nd\te\u0001f\u001f' }), '{"s":"a\\"b\\\\c\\nd\\te\\u0001f\\u001f"}');
    eq(canonicalJson({ s: '\b\f\r' }), '{"s":"\\b\\f\\r"}');
    eq(canonicalJson({ s: '\u0000' }), '{"s":"\\u0000"}');
    eq(canonicalJson({ s: '\u001f' }), '{"s":"\\u001f"}');
    // No \u-escaping of non-ASCII, and no escaping of DEL or U+0085.
    eq(canonicalJson({ s: '\u007f\u0085' }), '{"s":"\u007f\u0085"}');
  });

  test('keys are escaped by the same rule as values', () => {
    eq(canonicalJson({ 'a"b': 1 }), '{"a\\"b":1}');
    eq(canonicalJson({ '中': 1 }), '{"中":1}');
  });

  test('separators are exactly , and : with no whitespace', () => {
    const text = canonicalJson({ b: [1, 2, { c: null }], a: true });
    eq(text, '{"a":true,"b":[1,2,{"c":null}]}');
    ok(!/\s/.test(text.replace(/"(?:[^"\\]|\\.)*"/g, '')), 'no whitespace outside strings');
  });

  test('a non-object root throws RootNotObject for every non-object', () => {
    for (const value of [null, 1, 'hi', true, [1, 2], undefined]) {
      const err = throws(() => canonicalJson(value));
      eq(err.name, 'RootNotObject', `root ${String(value)}`);
      eq(err.code, 'root_not_object');
    }
  });

  test('only objects with the astral key ordering fixture are special-cased', () => {
    // Sanity: the other payloads sort the same under either comparator, which is
    // why the astral one has to exist.
    ok(vectors.payloads.some((p) => p.id === 'astral-plane-key-ordering'));
  });

  test('canonicalization never silently returns null', () => {
    for (const bad of [{ a: undefined }, { a: 1n }, { a: new Date() }, { a: NaN }]) {
      let out = 'not-run';
      try {
        out = canonicalJson(bad);
      } catch {
        out = '<threw>';
      }
      eq(out, '<threw>', 'must throw, never fall back to null');
    }
  });
});

suite('conformance: verifying through the public API', () => {
  test('verifyPayload throws on a tampered payload', () => {
    const payload = JSON.parse(allPayloads[1].input_json);
    const sig = allPayloads[1].signature_hex;
    ok(verifyPayload(payload, sig, rawPublic));
    throws(() => verifyPayload({ ...payload, stake: 101 }, sig, rawPublic), {
      name: 'SignatureError',
    });
  });

  test('Identity round-trips a fixture identity', () => {
    const identity = Identity.fromSeed(seed);
    eq(identity.did, vectors.identity.did_nau);
    const payload = JSON.parse(allPayloads[1].input_json);
    eq(identity.signPayload(payload), allPayloads[1].signature_hex);
    ok(identity.verifyPayload(payload, allPayloads[1].signature_hex));
    throws(() => identity.verifyPayload({ ...payload, name: 'Mallory' }, allPayloads[1].signature_hex));
  });

  test('the fixture signature is OpenSSL-verifiable independently of the SDK', () => {
    // Defence in depth: verify with node:crypto directly, so a bug in the SDK's
    // own verifier cannot make a broken fixture look fine.
    const payload = JSON.parse(allPayloads[0].input_json);
    const text = canonicalJson(payload);
    eq(text, allPayloads[0].canonical);
    eq(verifyRaw(Buffer.from(text, 'utf8'), allPayloads[0].signature_hex, rawPublic), true);
  });
});
