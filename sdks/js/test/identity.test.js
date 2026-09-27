/**
 * Identity: key derivation, the single DID scheme, signing, verification and
 * every rejection path.
 */

import crypto from 'node:crypto';

import { test, suite, eq, ok, throws } from './harness.js';
import { vectors, SEED } from './helpers.js';
import {
  Did,
  Identity,
  Keypair,
  DidError,
  DidMismatchError,
  KeyError,
  SignatureError,
  PKCS8_ED25519_PREFIX_HEX,
  PUBLIC_KEY_BYTES,
  SEED_BYTES,
  SIGNATURE_BYTES,
  canonicalPayload,
  didFromPublicKey,
  fingerprint,
  rawPublicKeyFromPrivate,
  sha256,
  toKeyBytes,
  toSignatureBytes,
  verifyPayload,
  verifyPayloadBound,
  verifyRaw,
} from '../index.js';

const rawPublic = Buffer.from(vectors.identity.public_key_hex, 'hex');

suite('identity: key derivation', () => {
  test('the PKCS#8 prefix is the fixed Ed25519 seed wrapper', () => {
    eq(PKCS8_ED25519_PREFIX_HEX, '302e020100300506032b657004220420');
    eq(PKCS8_ED25519_PREFIX_HEX.length, 32);
  });

  test('the raw public key is the last 32 bytes of the SPKI DER', () => {
    const kp = Keypair.fromSeed(SEED);
    const spki = crypto.createPublicKey(kp.privateKey).export({ format: 'der', type: 'spki' });
    eq(spki.length, PUBLIC_KEY_BYTES + 12, 'Ed25519 SPKI is 12 bytes of header plus 32');
    eq(kp.publicKey.toString('hex'), Buffer.from(spki).subarray(spki.length - 32).toString('hex'));
    eq(kp.publicKey.toString('hex'), vectors.identity.public_key_hex);
    eq(rawPublicKeyFromPrivate(kp.privateKey).toString('hex'), vectors.identity.public_key_hex);
  });

  test('fromSeed accepts a Buffer, a Uint8Array and hex', () => {
    const fromBuffer = Keypair.fromSeed(SEED);
    const fromArray = Keypair.fromSeed(new Uint8Array(SEED));
    const fromHex = Keypair.fromSeed(vectors.seed_hex);
    eq(fromBuffer.publicKey.toString('hex'), fromArray.publicKey.toString('hex'));
    eq(fromBuffer.publicKey.toString('hex'), fromHex.publicKey.toString('hex'));
  });

  test('a wrong seed length is a KeyError, not a wrong key', () => {
    throws(() => Keypair.fromSeed(Buffer.alloc(31, 1)), { name: 'KeyError' });
    throws(() => Keypair.fromSeed(Buffer.alloc(33, 1)), { name: 'KeyError' });
    throws(() => Keypair.fromSeed('abcd'), { name: 'KeyError' });
    throws(() => Keypair.fromSeed('zz'.repeat(32)), { name: 'KeyError' });
    throws(() => Keypair.fromSeed(42), { name: 'KeyError' });
    eq(SEED_BYTES, 32);
  });

  test('generate produces distinct, working keys from the CSPRNG', () => {
    const a = Keypair.generate();
    const b = Keypair.generate();
    ok(a.seed.toString('hex') !== b.seed.toString('hex'));
    eq(a.seed.length, SEED_BYTES);
    eq(a.publicKey.length, PUBLIC_KEY_BYTES);
    ok(a.verify('x', a.sign('x')));
    ok(!a.verify('x', b.sign('x')));
  });

  test('exportSeedHex / exportPublicKeyHex / exportSeed round-trip', () => {
    const kp = Keypair.fromSeed(SEED);
    eq(kp.exportSeedHex(), vectors.seed_hex);
    eq(kp.exportPublicKeyHex(), vectors.identity.public_key_hex);
    eq(kp.exportSeed().toString('hex'), vectors.seed_hex);
    eq(Keypair.fromHex(kp.exportSeedHex()).publicKey.toString('hex'), kp.publicKey.toString('hex'));
    eq(Keypair.fromHex(`${kp.exportSeedHex()}${kp.exportPublicKeyHex()}`).did, kp.did);
    eq(Keypair.fromHex({ seedHex: kp.exportSeedHex() }).did, kp.did);
    throws(() => Keypair.fromHex('abc'), { name: 'KeyError' });
    throws(() => Keypair.fromHex(7), { name: 'KeyError' });
  });

  test('exportSeed returns a copy, so mutating it cannot change the key', () => {
    const kp = Keypair.fromSeed(SEED);
    const copy = kp.exportSeed();
    copy.fill(0);
    eq(kp.exportSeedHex(), vectors.seed_hex);
  });
});

suite('identity: exactly one DID scheme', () => {
  test('did = did:nau: + sha256(rawPublicKey)[0..8] in lowercase hex', () => {
    const expected = `did:nau:${sha256(rawPublic).subarray(0, 8).toString('hex')}`;
    eq(didFromPublicKey(rawPublic), expected);
    eq(expected, vectors.identity.did_nau);
    eq(fingerprint(rawPublic).length, 16);
    ok(/^[0-9a-f]{16}$/.test(fingerprint(rawPublic)));
  });

  test('the fingerprint hashes the RAW key, never the SPKI DER', () => {
    const kp = Keypair.fromSeed(SEED);
    const spki = Buffer.from(crypto.createPublicKey(kp.privateKey).export({ format: 'der', type: 'spki' }));
    const wrongDid = `did:nau:${sha256(spki).subarray(0, 8).toString('hex')}`;
    ok(wrongDid !== kp.did, 'a DER-based DID would not match the fixture, which is the upstream bug');
    eq(kp.did, vectors.identity.did_nau);
  });

  test('didFromPublicKey accepts hex and Uint8Array too', () => {
    eq(didFromPublicKey(vectors.identity.public_key_hex), vectors.identity.did_nau);
    eq(didFromPublicKey(new Uint8Array(rawPublic)), vectors.identity.did_nau);
    throws(() => didFromPublicKey('abcd'), { name: 'KeyError' });
    throws(() => didFromPublicKey(Buffer.alloc(31)), { name: 'KeyError' });
  });

  test('an invalid prefix is refused (no accidental second scheme)', () => {
    throws(() => didFromPublicKey(rawPublic, 'nau:'), { name: 'DidError' });
    throws(() => didFromPublicKey(rawPublic, 'did:NAU:'), { name: 'DidError' });
    throws(() => didFromPublicKey(rawPublic, 42), { name: 'DidError' });
  });

  test('the legacy did:aip spelling is emitted only on request', () => {
    const kp = Keypair.fromSeed(SEED);
    eq(kp.did, vectors.identity.did_nau);
    eq(kp.didWith('did:aip:'), vectors.identity.did_legacy);
    // Both methods hash the same input, so a card and a manifest agree.
    eq(kp.did.slice(8), kp.didWith('did:aip:').slice(8));
  });
});

suite('identity: Did parsing', () => {
  test('parses a well-formed DID', () => {
    const did = Did.parse(vectors.identity.did_nau);
    eq(did.method, 'nau');
    eq(did.prefix, 'did:nau:');
    eq(did.fingerprint, '34750f98bd59fcfc');
    eq(did.asString(), vectors.identity.did_nau);
    eq(did.toString(), vectors.identity.did_nau);
    eq(String(did), vectors.identity.did_nau);
    eq(did.toJSON(), vectors.identity.did_nau);
    eq(did.toCanonicalString(), vectors.identity.did_nau);
    eq(did.isLegacy, false);
  });

  test('the legacy method parses by the same rule and is flagged', () => {
    const did = Did.parse(vectors.identity.did_legacy);
    eq(did.method, 'aip');
    eq(did.isLegacy, true);
    eq(did.fingerprint, '34750f98bd59fcfc');
    eq(did.toCanonicalString(), vectors.identity.did_nau);
  });

  test('rejections: malformed, empty, non-string, short and non-hex', () => {
    const bad = [
      '',
      'nau:34750f98bd59fcfc',
      'did:nau',
      'did:nau:',
      'did::34750f98bd59fcfc',
      'did:nau:zzzzzzzzzzzzzzzz',
      'did:nau:34750f98bd59fcf',
      'did:nau:34750f98bd59fcfc:extra',
      'did:NAU:34750f98bd59fcfc',
      ' did:nau:34750f98bd59fcfc',
      'did:nau:34750f98bd59fcfc ',
    ];
    for (const value of bad) {
      const err = throws(() => Did.parse(value), { name: 'DidError' });
      eq(err.code, 'did_error');
    }
    for (const value of [null, undefined, 42, {}, []]) {
      throws(() => Did.parse(value), { name: 'DidError' });
    }
  });

  test('matchesPublicKey compares the fingerprint of the raw key', () => {
    const did = Did.parse(vectors.identity.did_nau);
    ok(did.matchesPublicKey(rawPublic));
    ok(did.matchesPublicKey(vectors.identity.public_key_hex));
    ok(!did.matchesPublicKey(Keypair.generate().publicKey));
    throws(() => did.matchesPublicKey(Buffer.alloc(4)), { name: 'KeyError' });
  });
});

suite('identity: signing and verification', () => {
  test('sign produces 64 bytes that verify, and a changed byte does not', () => {
    const kp = Keypair.fromSeed(SEED);
    const sig = kp.sign('hello');
    eq(sig.length, SIGNATURE_BYTES);
    ok(verifyRaw('hello', sig, kp.publicKey));
    ok(kp.verify('hello', sig));
    ok(!kp.verify('hellp', sig));
    const tampered = Buffer.from(sig);
    tampered[0] ^= 0x01;
    ok(!kp.verify('hello', tampered));
    ok(!verifyRaw('hello', tampered, kp.publicKey));
  });

  test('hex and Buffer signatures are interchangeable', () => {
    const kp = Keypair.fromSeed(SEED);
    const sig = kp.sign('x');
    ok(verifyRaw('x', sig.toString('hex'), kp.publicKey));
    ok(verifyRaw('x', new Uint8Array(sig), kp.publicKey));
    ok(verifyRaw(Buffer.from('x'), sig.toString('hex'), kp.exportPublicKeyHex()));
    eq(toSignatureBytes(sig.toString('hex')).toString('hex'), sig.toString('hex'));
  });

  test('a malformed signature or key is a typed error, not a silent false', () => {
    const kp = Keypair.fromSeed(SEED);
    throws(() => verifyRaw('x', 'abcd', kp.publicKey), { name: 'SignatureError' });
    throws(() => verifyRaw('x', 'zz'.repeat(64), kp.publicKey), { name: 'SignatureError' });
    throws(() => verifyRaw('x', 42, kp.publicKey), { name: 'SignatureError' });
    throws(() => verifyRaw(42, kp.sign('x'), kp.publicKey), { name: 'SignatureError' });
    throws(() => verifyRaw('x', kp.sign('x'), 'abcd'), { name: 'KeyError' });
    eq(SIGNATURE_BYTES, 64);
  });

  test('verifyRaw accepts a Keypair or Identity as the key argument', () => {
    const kp = Keypair.fromSeed(SEED);
    const identity = new Identity(kp);
    const sig = kp.sign('y');
    ok(verifyRaw('y', sig, kp));
    ok(verifyRaw('y', sig, identity));
  });

  test('signPayload / verifyPayload use the canonical bytes', () => {
    const identity = Identity.fromSeed(SEED);
    const payload = { did: identity.did, name: 'A', stake: 1 };
    const sigHex = identity.signPayload(payload);
    eq(sigHex.length, 128);
    ok(identity.verifyPayload(payload, sigHex));
    eq(verifyPayload(payload, sigHex, identity.publicKey), true);
    // Key order must not matter.
    ok(identity.verifyPayload({ stake: 1, name: 'A', did: identity.did }, sigHex));
    // Any change must fail, including a nested one.
    throws(() => identity.verifyPayload({ ...payload, stake: 2 }, sigHex), { name: 'SignatureError' });
    throws(() => verifyPayload({ ...payload }, 'ab'.repeat(64), identity.publicKey), { name: 'SignatureError' });
  });

  test('canonicalPayload is what signPayload signs', () => {
    const identity = Identity.fromSeed(SEED);
    const payload = { b: 1, a: 2 };
    const sig = identity.signPayload(payload);
    // If canonicalization were skipped, signing `JSON.stringify(payload)` would
    // produce the same bytes. It must not.
    const naive = Buffer.from(JSON.stringify(payload), 'utf8');
    ok(!verifyRaw(naive, sig, identity.publicKey), 'JSON.stringify order must not verify');
    eq(canonicalPayload(payload).toString('utf8'), '{"a":2,"b":1}');
    ok(verifyRaw(canonicalPayload(payload), sig, identity.publicKey));
  });
  test('signRaw and signPayload are separate paths over the same key', () => {
    const identity = Identity.fromSeed(SEED);
    eq(identity.signRaw('abc').toString('hex'), Keypair.fromSeed(SEED).sign('abc').toString('hex'));
    eq(identity.signPayload({ a: 1 }).length, 128);
  });

  test('signing never silently signs null', () => {
    const identity = Identity.fromSeed(SEED);
    throws(() => identity.signPayload({ a: undefined }), { name: 'UnsupportedType' });
    throws(() => identity.signPayload({ a: 1n }), { name: 'UnsupportedType' });
    throws(() => identity.signPayload({ a: new Date() }), { name: 'NonPlainObject' });
    throws(() => identity.signPayload({ a: 1.5 }), { name: 'NonIntegerNumber' });
    throws(() => identity.signPayload([1]), { name: 'RootNotObject' });
  });
});

suite('identity: bound verification', () => {
  test('verifyPayloadBound accepts a matching DID', () => {
    const identity = Identity.fromSeed(SEED);
    const payload = { did: identity.did, n: 1 };
    const sig = identity.signPayload(payload);
    eq(verifyPayloadBound(payload, sig, identity.publicKey, identity.did), true);
    eq(vectors.identity.did_nau, identity.did);
  });

  test('verifyPayloadBound refuses a DID that is not this key fingerprint', () => {
    const identity = Identity.fromSeed(SEED);
    const other = Identity.generate();
    const payload = { did: identity.did, n: 1 };
    const sig = identity.signPayload(payload);
    const err = throws(
      () => verifyPayloadBound(payload, sig, identity.publicKey, other.did),
      { name: 'DidMismatchError' },
    );
    eq(err.code, 'did_mismatch');
    eq(err.did, other.did);
    eq(err.fingerprint, fingerprint(identity.publicKey));
  });

  test('a valid signature over a payload whose own did field is a lie is still caught', () => {
    // The upstream defect: a JS card could name one did and be signed by a key
    // that hashed differently, so nothing could correlate the two.
    const identity = Identity.fromSeed(SEED);
    const lie = { did: 'did:nau:0000000000000000', n: 1 };
    const sig = identity.signPayload(lie);
    eq(verifyPayload(lie, sig, identity.publicKey), true, 'the signature itself is fine');
    throws(
      () => verifyPayloadBound(lie, sig, identity.publicKey, lie.did),
      { name: 'DidMismatchError' },
    );
    eq(verifyPayloadBound(lie, sig, identity.publicKey, identity.did), true);
  });

  test('a malformed DID is a DidError before any signature work happens', () => {
    const identity = Identity.fromSeed(SEED);
    const payload = { n: 1 };
    const sig = identity.signPayload(payload);
    throws(() => verifyPayloadBound(payload, sig, identity.publicKey, 'nope'), { name: 'DidError' });
  });
});

suite('identity: Identity wrapper', () => {
  test('generate and fromSeed', () => {
    const fresh = Identity.generate();
    ok(fresh.did.startsWith('did:nau:'));
    const seeded = Identity.fromSeed(SEED);
    eq(seeded.did, vectors.identity.did_nau);
    eq(seeded.exportPublicKeyHex(), vectors.identity.public_key_hex);
    eq(seeded.exportSeedHex(), vectors.seed_hex);
    eq(seeded.publicKey.length, 32);
    eq(seeded.seed.length, 32);
  });

  test('Identity wraps a Keypair and refuses anything else', () => {
    const kp = Keypair.fromSeed(SEED);
    const identity = new Identity(kp);
    eq(identity.keypair, kp);
    throws(() => new Identity('nope'), { name: 'KeyError' });
  });

  test('toJSON exposes the public parts and the seed', () => {
    const identity = Identity.fromSeed(SEED);
    eq(identity.toJSON().did, vectors.identity.did_nau);
    eq(identity.toJSON().publicKeyHex, vectors.identity.public_key_hex);
    eq(identity.keypair.toJSON().seedHex, vectors.seed_hex);
  });

  test('toKeyBytes and toSignatureBytes validate length', () => {
    eq(toKeyBytes(rawPublic).length, 32);
    throws(() => toKeyBytes(Buffer.alloc(3)), { name: 'KeyError' });
    throws(() => toKeyBytes(null), { name: 'KeyError' });
    eq(toSignatureBytes(Buffer.alloc(64)).length, 64);
    throws(() => toSignatureBytes(Buffer.alloc(63)), { name: 'SignatureError' });
  });

  test('the error classes are exported and form a hierarchy', () => {
    for (const cls of [DidError, DidMismatchError, KeyError, SignatureError]) {
      ok(typeof cls === 'function' && cls.prototype instanceof Error);
    }
  });
});
