// Generates conformance/vectors.json — the single source of truth shared by the
// Rust, Python and JavaScript test suites.
//
// The signatures here are produced by Node's OpenSSL-backed Ed25519
// implementation, i.e. by an implementation that shares NO code with the Rust
// crate. When the Rust test verifies these signatures over its own
// canonicalization of the same input, that is a genuine cross-implementation
// check rather than a self-consistency check (which is all upstream v2.5.6 had).
//
// Run:  node conformance/generate.mjs

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

// Ed25519 PKCS#8 wraps the 32-byte seed with this fixed prefix.
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SEED = Buffer.alloc(32, 0x01);

const privateKey = crypto.createPrivateKey({
  key: Buffer.concat([PKCS8_PREFIX, SEED]),
  format: 'der',
  type: 'pkcs8',
});
const spki = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
const rawPublicKey = spki.subarray(spki.length - 32);

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest();

// --- the canonicalization rules, implemented independently of Rust ---
const SIGNATURE_FIELD = 'signature';

function canonicalize(value) {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new Error(`non-integer number ${value}`);
    if (!Number.isSafeInteger(value)) {
      throw new Error(`number ${value} exceeds the JavaScript safe-integer range`);
    }
    return String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    // Compare by Unicode CODE POINT (not UTF-16 code unit, which is what the
    // default Array.prototype.sort() uses and which disagrees for astral keys).
    const keys = Object.keys(value)
      .filter((k) => k !== SIGNATURE_FIELD)
      .sort((a, b) => {
        const ai = [...a];
        const bi = [...b];
        for (let i = 0; i < Math.min(ai.length, bi.length); i++) {
          const d = ai[i].codePointAt(0) - bi[i].codePointAt(0);
          if (d !== 0) return d;
        }
        return ai.length - bi.length;
      });
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
  }
  throw new Error(`cannot canonicalize a value of type ${typeof value}`);
}

const didNau = `did:nau:${sha256(rawPublicKey).subarray(0, 8).toString('hex')}`;
const didLegacy = `did:aip:${sha256(rawPublicKey).subarray(0, 8).toString('hex')}`;

// Each entry supplies the input JSON text and the canonical form it must reduce
// to. `input_json` is text (not an object) so that 64-bit integers survive.
const payloads = [
  {
    id: 'upstream-v2.5.6-compat',
    note:
      'Byte-identical to the vector asserted by upstream gsn-core/tests/cross_lang_signature.rs, ' +
      'proving identities and signatures minted by agent-universe v2.5.6 remain verifiable.',
    input_json:
      '{"did":"did:aip:34750f98bd59fcfc","name":"CrossLang","capabilities":["text-generation","mcp"],"stake":100,"signature":""}',
    canonical:
      '{"capabilities":["text-generation","mcp"],"did":"did:aip:34750f98bd59fcfc","name":"CrossLang","stake":100}',
  },
  {
    id: 'basic-card',
    note: 'A normal agent card: key order in the input is deliberately scrambled.',
    input_json:
      '{"stake":100,"name":"CrossLang","did":"did:nau:34750f98bd59fcfc","capabilities":["text-generation","mcp"],"signature":""}',
    canonical:
      '{"capabilities":["text-generation","mcp"],"did":"did:nau:34750f98bd59fcfc","name":"CrossLang","stake":100}',
  },
  {
    id: 'nested-signature-stripped-at-depth',
    note:
      'Every key named "signature" is removed at EVERY depth, not just the top level. ' +
      'Upstream removed only the root key, so a nested signed structure would have had its ' +
      'inner signature covered by the outer signature.',
    input_json:
      '{"outer":1,"signature":"deadbeef","nested":{"inner":true,"signature":"cafe"},"list":[{"signature":"x","kept":1}]}',
    canonical: '{"list":[{"kept":1}],"nested":{"inner":true},"outer":1}',
  },
  {
    id: 'non-ascii-left-raw',
    note: 'Non-ASCII must be emitted as raw UTF-8, never \\u-escaped.',
    input_json: '{"zh":"智能体宇宙","mixed":"a中b","signature":""}',
    canonical: '{"mixed":"a中b","zh":"智能体宇宙"}',
  },
  {
    id: 'control-characters-escaped-minimally',
    note:
      'Only ", \\ and the seven short control escapes are escaped; other control ' +
      'characters use lowercase \\u00xx. Nothing else is escaped.',
    input_json: '{"s":"a\\"b\\\\c\\nd\\te\\u0001f\\u001f","signature":""}',
    canonical: '{"s":"a\\"b\\\\c\\nd\\te\\u0001f\\u001f"}',
  },
  {
    id: 'astral-plane-key-ordering',
    note:
      'Keys are ordered by Unicode code point. JavaScript must NOT use the default ' +
      'Array.prototype.sort(), which compares UTF-16 code units and orders U+10000 ' +
      'before U+E000.',
    input_json: '{"\\ud83d\\ude00":"astral","\\ue000":"bmp-private-use","a":"ascii","signature":""}',
    // a (U+0061) < U+E000 < U+1F600, so code-point order differs from the
    // UTF-16 code-unit order a naive JS sort would produce.
    canonical: '{"a":"ascii","\uE000":"bmp-private-use","\u{1F600}":"astral"}',
  },
  {
    id: 'integers-typed-and-null-and-empty',
    note: 'null values, an empty array, an empty object and negative integers are all legal.',
    input_json: '{"z":null,"arr":[],"obj":{},"neg":-42,"zero":0,"signature":""}',
    // "z" sorts before "zero" (prefix is shorter), so the ordering is not the
    // intuitive one — this is exactly the kind of case the fixture pins down.
    canonical: '{"arr":[],"neg":-42,"obj":{},"z":null,"zero":0}',
  },
  {
    id: 'js-safe-integer-boundary',
    note: 'The largest integer every language can represent exactly in one pass: 2^53 - 1.',
    input_json: '{"n":9007199254740991,"signature":""}',
    canonical: '{"n":9007199254740991}',
  },
];

// Vectors that only 64-bit languages can reproduce. The signature is still
// provided, so the JS suite can verify it even though JS cannot produce it.
const widePayloads = [
  {
    id: 'int64-max',
    note:
      '2^63 - 1 does not survive JavaScript JSON.parse (it becomes 9223372036854776000), ' +
      'so the JS SDK must pass it as a string or refuse it. Recorded here to pin the ' +
      'documented portability boundary.',
    input_json: '{"n":9223372036854775807,"signature":""}',
    canonical: '{"n":9223372036854775807}',
    languages: { javascript: 'unsupported-by-json-parse' },
  },
  {
    id: 'uint64-max',
    note: '2^64 - 1: exact in Rust and Python, unrepresentable in JS.',
    input_json: '{"n":18446744073709551615,"signature":""}',
    canonical: '{"n":18446744073709551615}',
    languages: { javascript: 'unsupported-by-json-parse' },
  },
];

const rejections = [
  {
    id: 'float-value',
    note:
      'Floats are refused outright. This is the single most important cross-language fix: ' +
      '100 vs 100.0 vs 1e2 format differently in Rust, Python and JavaScript, so a signed ' +
      'payload containing a float cannot be reproduced byte-for-byte. Money therefore travels ' +
      'as integer minor units.',
    input_json: '{"amount":100.0}',
    error: 'non_integer_number',
  },
  {
    id: 'fractional-value',
    input_json: '{"amount":1.5}',
    error: 'non_integer_number',
  },
  {
    id: 'exponent-notation',
    note: 'serde_json parses 1e2 as a float, so it is refused as well.',
    input_json: '{"amount":1e2}',
    error: 'non_integer_number',
  },
  {
    id: 'root-is-array',
    note: 'A signing payload must be a JSON object at the root.',
    input_json: '[1,2,3]',
    error: 'root_not_object',
  },
  {
    id: 'root-is-string',
    input_json: '"hello"',
    error: 'root_not_object',
  },
];

const sign = (canonical) => crypto.sign(null, Buffer.from(canonical, 'utf8'), privateKey).toString('hex');

// Sanity-check the JS canonicalizer against the authored canonical strings for
// everything JavaScript can represent, so an error in this file is caught here.
const checkable = [...payloads, ...widePayloads].filter(
  (p) => !(p.languages && p.languages.javascript),
);
for (const p of checkable) {
  const derived = canonicalize(JSON.parse(p.input_json));
  if (derived !== p.canonical) {
    // Only the astral case builds its canonical string dynamically; report clearly.
    throw new Error(
      `canonical mismatch for ${p.id}\n  derived:   ${derived}\n  expected:  ${p.canonical}`,
    );
  }
}

const document = {
  protocol: 'nau/1',
  generated_by:
    'node:crypto (OpenSSL) Ed25519 + this file\'s independent canonicalizer. ' +
    'No code is shared with the Rust implementation.',
  canonicalization_rules: [
    'The value must be a JSON object at the root.',
    'Every object key named "signature" is dropped, at every depth.',
    'Object keys are emitted in ascending Unicode CODE POINT order.',
    'No whitespace: separators are exactly "," and ":".',
    'Strings are raw UTF-8; only " \\ and the short control escapes are escaped; other control characters use lowercase \\u00xx.',
    'Numbers must be integers fitting i64 or u64. Floats, exponent notation and out-of-range values are rejected.',
    'Nesting is bounded to 64 levels.',
  ],
  seed_hex: SEED.toString('hex'),
  identity: {
    public_key_hex: rawPublicKey.toString('hex'),
    did_nau: didNau,
    did_legacy: didLegacy,
    note: 'did = "did:nau:" + first 8 bytes of SHA-256(raw 32-byte public key), lowercase hex.',
  },
  payloads: [...payloads, ...widePayloads].map((p) => ({
    ...p,
    signature_hex: sign(p.canonical),
    canonical_hex: Buffer.from(p.canonical, 'utf8').toString('hex'),
  })),
  rejections,
};

const out = path.join(here, 'vectors.json');
fs.writeFileSync(out, JSON.stringify(document, null, 2) + '\n');
console.log(`wrote ${out}`);
console.log(`public key  : ${rawPublicKey.toString('hex')}`);
console.log(`did:nau     : ${didNau}`);
console.log(`did:aip:    : ${didLegacy}`);
console.log(`payloads    : ${document.payloads.length}`);
console.log(`rejections  : ${document.rejections.length}`);
