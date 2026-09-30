/**
 * Ed25519 identity for the `nau` protocol.
 *
 * # One DID scheme, not two
 *
 * Upstream shipped two mutually incompatible derivations:
 *
 * * `lib/keychain.js` computed `did:au:` + `sha256(SPKI DER)[:32]`;
 * * `lib/aca.js` computed `did:aip:` + `sha256(raw public key)[:16]`.
 *
 * A JS-created agent card therefore could never be correlated with its own
 * manifest. This module implements exactly ONE scheme:
 *
 * ```
 * did = "did:nau:" + lowercase hex of the first 8 bytes of
 *                   SHA-256(the raw 32-byte Ed25519 public key)
 * ```
 *
 * The `did:aip:` prefix from upstream v2.5.6 can still be *parsed* (and
 * `Keypair#didWith('did:aip:')` can still *emit* it) purely so that identities
 * minted by v2.5.6 remain verifiable. Nothing here ever creates a second
 * scheme: `didFromPublicKey` has one body and one default prefix.
 */

import crypto from 'node:crypto';

import { DidError, DidMismatchError, KeyError, SignatureError } from './errors.js';
import { canonicalPayload } from './canonical.js';

/**
 * Ed25519 PKCS#8 wraps the 32-byte seed with this fixed 16-byte prefix.
 * See `conformance/generate.mjs`, which builds the same key.
 */
export const PKCS8_ED25519_PREFIX_HEX = '302e020100300506032b657004220420';

/** Default DID method prefix. There is only ever this one. */
export const DID_PREFIX = 'did:nau:';

/** Number of SHA-256 bytes used as the DID fingerprint (8 bytes = 16 hex chars). */
export const DID_FINGERPRINT_BYTES = 8;

/** Length of an Ed25519 public key (and seed, and signature). */
export const PUBLIC_KEY_BYTES = 32;
export const SEED_BYTES = 32;
export const SIGNATURE_BYTES = 64;

const PKCS8_ED25519_PREFIX = Buffer.from(PKCS8_ED25519_PREFIX_HEX, 'hex');
const HEX_RE = /^[0-9a-fA-F]+$/;
const DID_RE = /^did:([a-z0-9]+):([A-Za-z0-9._%-]+)$/;

/**
 * SHA-256 digest.
 *
 * @param {Buffer|Uint8Array|string} data
 * @returns {Buffer}
 */
export function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

/**
 * Coerce key material to a Buffer, rejecting anything that is not exactly 32
 * bytes.
 *
 * @param {Buffer|Uint8Array|string} bytes
 * @param {string} [label]
 * @returns {Buffer}
 */
export function toKeyBytes(bytes, label = 'key') {
  let buf;
  if (Buffer.isBuffer(bytes)) buf = bytes;
  else if (bytes instanceof Uint8Array) buf = Buffer.from(bytes);
  else if (typeof bytes === 'string') {
    if (!HEX_RE.test(bytes) || bytes.length !== PUBLIC_KEY_BYTES * 2) {
      throw new KeyError(`${label} hex must be exactly ${PUBLIC_KEY_BYTES * 2} hex characters`);
    }
    buf = Buffer.from(bytes, 'hex');
  } else {
    throw new KeyError(`${label} must be a Buffer, Uint8Array or hex string`);
  }
  if (buf.length !== PUBLIC_KEY_BYTES) {
    throw new KeyError(`${label} must be exactly ${PUBLIC_KEY_BYTES} bytes, got ${buf.length}`);
  }
  return Buffer.from(buf);
}

/**
 * The raw 32-byte public key of an Ed25519 private key.
 *
 * The SPKI DER export ends with the raw key, so the last 32 bytes are the key
 * itself; the preceding bytes are the fixed `302a300506032b6570032100` header.
 *
 * @param {crypto.KeyObject} privateKey
 * @returns {Buffer}
 */
export function rawPublicKeyFromPrivate(privateKey) {
  const spki = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  if (spki.length < PUBLIC_KEY_BYTES) {
    throw new KeyError(`unexpected SPKI length ${spki.length}`);
  }
  return Buffer.from(spki.subarray(spki.length - PUBLIC_KEY_BYTES));
}

/**
 * Hex fingerprint of a public key: the first 8 bytes of its SHA-256.
 *
 * @param {Buffer|Uint8Array|string} pubBytes
 * @returns {string} 16 lowercase hex characters
 */
export function fingerprint(pubBytes) {
  const raw = toKeyBytes(pubBytes, 'publicKey');
  return sha256(raw).subarray(0, DID_FINGERPRINT_BYTES).toString('hex');
}

/**
 * Derive a DID from a raw public key.
 *
 * @param {Buffer|Uint8Array|string} pubBytes raw 32-byte Ed25519 public key
 * @param {string} [prefix] defaults to `did:nau:`
 * @returns {string}
 */
export function didFromPublicKey(pubBytes, prefix = DID_PREFIX) {
  if (typeof prefix !== 'string' || !/^did:[a-z0-9]+:$/.test(prefix)) {
    throw new DidError(`invalid DID prefix ${JSON.stringify(prefix)}; expected e.g. "did:nau:"`);
  }
  return prefix + fingerprint(pubBytes);
}

/**
 * Extract 32 raw bytes from a public key, a {@link Keypair}, or an
 * {@link Identity}.
 *
 * @param {unknown} value
 * @returns {Buffer}
 */
function resolvePublicKeyBytes(value) {
  if (value !== null && typeof value === 'object' && Buffer.isBuffer(value.publicKey)) {
    return toKeyBytes(value.publicKey, 'publicKey');
  }
  return toKeyBytes(/** @type {never} */ (value), 'publicKey');
}

/**
 * Normalise a signature argument (64-byte Buffer, Uint8Array or 128-char hex).
 *
 * @param {Buffer|Uint8Array|string} sig
 * @returns {Buffer}
 */
export function toSignatureBytes(sig) {
  let buf;
  if (Buffer.isBuffer(sig)) buf = sig;
  else if (sig instanceof Uint8Array) buf = Buffer.from(sig);
  else if (typeof sig === 'string') {
    if (!HEX_RE.test(sig) || sig.length !== SIGNATURE_BYTES * 2) {
      throw new SignatureError(
        `signature hex must be exactly ${SIGNATURE_BYTES * 2} hex characters, got ${sig.length}`,
      );
    }
    buf = Buffer.from(sig, 'hex');
  } else {
    throw new SignatureError('signature must be a Buffer, Uint8Array or hex string');
  }
  if (buf.length !== SIGNATURE_BYTES) {
    throw new SignatureError(
      `signature must be exactly ${SIGNATURE_BYTES} bytes, got ${buf.length}`,
    );
  }
  return Buffer.from(buf);
}

/**
 * An Ed25519 keypair.
 */
export class Keypair {
  /**
   * @param {Buffer} seed 32-byte seed
   * @param {crypto.KeyObject} privateKey
   * @param {Buffer} publicKey raw 32 bytes
   */
  constructor(seed, privateKey, publicKey) {
    /** @type {Buffer} the 32-byte seed, retained for export/rehydration. */
    this.seed = Buffer.from(seed);
    /** @type {Buffer} the raw 32-byte public key. */
    this.publicKey = Buffer.from(publicKey);
    /** @type {crypto.KeyObject} */
    this.privateKey = privateKey;
  }

  /** @returns {Keypair} a keypair from a fresh CSPRNG seed. */
  static generate() {
    return Keypair.fromSeed(crypto.randomBytes(SEED_BYTES));
  }

  /**
   * @param {Buffer|Uint8Array|string} bytes32 seed, exactly 32 bytes (or 64 hex)
   * @returns {Keypair}
   */
  static fromSeed(bytes32) {
    let seed;
    if (typeof bytes32 === 'string') {
      if (!HEX_RE.test(bytes32) || bytes32.length !== SEED_BYTES * 2) {
        throw new KeyError(`seed hex must be exactly ${SEED_BYTES * 2} hex characters`);
      }
      seed = Buffer.from(bytes32, 'hex');
    } else if (Buffer.isBuffer(bytes32)) {
      seed = Buffer.from(bytes32);
    } else if (bytes32 instanceof Uint8Array) {
      seed = Buffer.from(bytes32);
    } else {
      throw new KeyError('seed must be a Buffer, Uint8Array or hex string');
    }
    if (seed.length !== SEED_BYTES) {
      throw new KeyError(`seed must be exactly ${SEED_BYTES} bytes, got ${seed.length}`);
    }
    const privateKey = crypto.createPrivateKey({
      key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
      format: 'der',
      type: 'pkcs8',
    });
    return new Keypair(seed, privateKey, rawPublicKeyFromPrivate(privateKey));
  }

  /**
   * Rehydrate from a 64-byte hex string (seed || public key) or `{seedHex}`.
   *
   * @param {string|{seedHex?: string, seed_hex?: string}|Buffer} input
   * @returns {Keypair}
   */
  static fromHex(input) {
    const hex = typeof input === 'string'
      ? input
      : input && typeof input === 'object'
        ? (input.seedHex ?? input.seed_hex)
        : undefined;
    if (typeof hex !== 'string') throw new KeyError('fromHex expects a hex string or {seedHex}');
    if (hex.length !== SEED_BYTES * 2 && hex.length !== SEED_BYTES * 2 + PUBLIC_KEY_BYTES * 2) {
      throw new KeyError(
        `keypair hex must be ${SEED_BYTES * 2} or ${SEED_BYTES * 2 + PUBLIC_KEY_BYTES * 2} characters`,
      );
    }
    if (!HEX_RE.test(hex)) throw new KeyError('keypair hex contains non-hex characters');
    return Keypair.fromSeed(hex.slice(0, SEED_BYTES * 2));
  }

  /** @returns {Buffer} copy of the 32-byte seed. */
  exportSeed() {
    return Buffer.from(this.seed);
  }

  /** @returns {string} the seed as lowercase hex. */
  exportSeedHex() {
    return this.seed.toString('hex');
  }

  /** @returns {string} lowercase hex of the raw public key. */
  exportPublicKeyHex() {
    return this.publicKey.toString('hex');
  }

  /** @returns {string} the canonical `did:nau:` DID for this key. */
  get did() {
    return didFromPublicKey(this.publicKey);
  }

  /** @returns {string} SPKI DER, base64 (usable as a JWK-ish transport form). */
  exportSpkiBase64() {
    const spki = crypto.createPublicKey(this.privateKey).export({ format: 'der', type: 'spki' });
    return Buffer.from(spki).toString('base64');
  }

  /**
   * The DID under another method prefix.
   *
   * Exists only so that `did:aip:` identities minted by upstream v2.5.6 can be
   * produced for interoperability tests; the fingerprint rule is identical.
   *
   * @param {string} prefix e.g. `'did:aip:'`
   * @returns {string}
   */
  didWith(prefix) {
    return didFromPublicKey(this.publicKey, prefix);
  }

  /**
   * @param {Buffer|Uint8Array|string} message
   * @returns {Buffer} 64-byte Ed25519 signature
   */
  sign(message) {
    if (typeof message === 'string') return crypto.sign(null, Buffer.from(message, 'utf8'), this.privateKey);
    if (Buffer.isBuffer(message) || message instanceof Uint8Array) {
      return crypto.sign(null, Buffer.from(message), this.privateKey);
    }
    throw new SignatureError('sign expects a string, Buffer or Uint8Array');
  }

  /**
   * @param {Buffer|Uint8Array|string} message
   * @param {Buffer|Uint8Array|string} signature 64 bytes or 128 hex chars
   * @returns {boolean} true/false; never throws for a merely-wrong signature
   */
  verify(message, signature) {
    return verifyRaw(message, signature, this.publicKey);
  }

  /**
   * @param {object} obj canonicalized exactly as {@link canonicalPayload} does
   * @returns {Buffer} 64-byte signature
   */
  signPayload(obj) {
    return this.sign(canonicalPayload(obj));
  }

  /**
   * @param {object} obj
   * @param {Buffer|Uint8Array|string} signature
   * @returns {boolean}
   */
  verifyPayload(obj, signature) {
    return this.verify(canonicalPayload(obj), signature);
  }

  /** @returns {{did: string, publicKeyHex: string, seedHex: string}} */
  toJSON() {
    return { did: this.did, publicKeyHex: this.exportPublicKeyHex(), seedHex: this.exportSeedHex() };
  }
}

/**
 * Verify a raw Ed25519 signature.
 *
 * @param {Buffer|Uint8Array|string} message
 * @param {Buffer|Uint8Array|string} signature
 * @param {Buffer|Uint8Array|string|Keypair|Identity} publicKey
 * @returns {boolean} false on a bad signature; throws only on malformed input
 */
export function verifyRaw(message, signature, publicKey) {
  const sig = toSignatureBytes(signature);
  const pub = resolvePublicKeyBytes(publicKey);
  const data = typeof message === 'string'
    ? Buffer.from(message, 'utf8')
    : Buffer.isBuffer(message) || message instanceof Uint8Array
      ? Buffer.from(message)
      : null;
  if (data === null) throw new SignatureError('verify expects the message as a string, Buffer or Uint8Array');
  const key = crypto.createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pub]),
    format: 'der',
    type: 'spki',
  });
  try {
    return crypto.verify(null, data, key, sig) === true;
  } catch (err) {
    // OpenSSL rejects some malformed signatures by throwing; a wrong signature
    // is a false, not a crash.
    if (err instanceof Error && /signature/i.test(err.message)) return false;
    throw new SignatureError(`Ed25519 verification failed: ${/** @type {Error} */ (err).message}`, { cause: err });
  }
}

/**
 * Verify a signature over the canonical form of `obj`.
 *
 * @param {object} obj
 * @param {Buffer|Uint8Array|string} sigHex 128 hex characters (or 64-byte Buffer)
 * @param {Buffer|Uint8Array|string|Keypair|Identity} publicKeyBytes raw 32 bytes
 * @returns {true} always true on success
 * @throws {SignatureError} when the signature does not verify
 */
export function verifyPayload(obj, sigHex, publicKeyBytes) {
  const payload = canonicalPayload(obj);
  if (!verifyRaw(payload, sigHex, publicKeyBytes)) {
    throw new SignatureError(
      `signature does not verify over the canonical payload: ${payload.toString('utf8')}`,
    );
  }
  return true;
}

/**
 * Verify a signature AND that the DID supplied alongside the key really is the
 * fingerprint of that key.
 *
 * This is the check upstream could not perform, because its two DID schemes
 * hashed different inputs.
 *
 * @param {object} obj
 * @param {Buffer|Uint8Array|string} sigHex
 * @param {Buffer|Uint8Array|string|Keypair|Identity} publicKeyBytes
 * @param {string} did
 * @returns {true}
 * @throws {DidMismatchError} when the DID is not this key's fingerprint
 * @throws {SignatureError} when the signature does not verify
 */
export function verifyPayloadBound(obj, sigHex, publicKeyBytes, did) {
  const fp = fingerprint(resolvePublicKeyBytes(publicKeyBytes));
  const parsed = Did.parse(did);
  if (parsed.fingerprint !== fp) throw new DidMismatchError(parsed.asString(), fp);
  return verifyPayload(obj, sigHex, publicKeyBytes);
}

/**
 * A parsed DID.
 *
 * One scheme: the fingerprint is always the first 8 SHA-256 bytes of the raw
 * public key. `did:aip:` and `did:au:` strings are accepted for legacy
 * interoperability, but they are parsed by the *same* rule.
 */
export class Did {
  /**
   * @param {string} method
   * @param {string} fingerprintHex
   * @param {string} prefix e.g. `'did:nau:'`
   * @param {string} original the exact input string
   */
  constructor(method, fingerprintHex, prefix, original) {
    /** @type {string} DID method name, e.g. `nau`. */
    this.method = method;
    /** @type {string} the fingerprint, lowercase hex. */
    this.fingerprint = fingerprintHex.toLowerCase();
    /** @type {string} the method prefix, e.g. `did:nau:`. */
    this.prefix = prefix;
    /** @type {string} the DID as supplied. */
    this.did = original;
  }

  /**
   * @param {string} str
   * @returns {Did}
   * @throws {DidError} on anything that is not `did:<method>:<fingerprint>`
   */
  static parse(str) {
    if (typeof str !== 'string' || str.length === 0) {
      throw new DidError(`DID must be a non-empty string, got ${describeValue(str)}`);
    }
    const m = DID_RE.exec(str);
    if (m === null) {
      throw new DidError(
        `malformed DID ${JSON.stringify(str)}: expected did:<method>:<fingerprint>`,
      );
    }
    const [, method, fingerprintHex] = m;
    if (!/^[0-9a-fA-F]+$/.test(fingerprintHex) || fingerprintHex.length % 2 !== 0) {
      throw new DidError(`malformed DID ${JSON.stringify(str)}: fingerprint must be even-length hex`);
    }
    if (fingerprintHex.length < DID_FINGERPRINT_BYTES * 2) {
      throw new DidError(
        `malformed DID ${JSON.stringify(str)}: fingerprint must be at least`
          + ` ${DID_FINGERPRINT_BYTES * 2} hex characters`,
      );
    }
    return new Did(method, fingerprintHex, `did:${method}:`, str);
  }

  /**
   * @param {Buffer|Uint8Array|string|Keypair|Identity} publicKeyBytes
   * @returns {boolean} true when this DID's fingerprint matches the key
   */
  matchesPublicKey(publicKeyBytes) {
    return this.fingerprint === fingerprint(resolvePublicKeyBytes(publicKeyBytes));
  }

  /** @returns {string} the DID as supplied (round-trips exactly). */
  asString() {
    return this.did;
  }

  /** @returns {string} the canonical `did:nau:` form of this fingerprint. */
  toCanonicalString() {
    return DID_PREFIX + this.fingerprint;
  }

  /** @returns {string} same as {@link asString}; makes `String(did)` work. */
  toString() {
    return this.did;
  }

  /** @returns {string} JSON serialisation is the bare DID string. */
  toJSON() {
    return this.did;
  }

  /** @returns {boolean} */
  get isLegacy() {
    return this.method !== 'nau';
  }
}

/** @param {unknown} v @returns {string} */
function describeValue(v) {
  if (typeof v === 'string') return JSON.stringify(v);
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v;
}

/**
 * A {@link Keypair} plus the payload-level convenience methods.
 */
export class Identity {
  /**
   * @param {Keypair} [keypair]
   */
  constructor(keypair = Keypair.generate()) {
    if (!(keypair instanceof Keypair)) {
      if (typeof keypair === 'object' && keypair !== null && Buffer.isBuffer(keypair.publicKey)) {
        // Duck-typed keypair (e.g. across a module boundary).
        // eslint-disable-next-line no-param-reassign
        keypair = Object.assign(Object.create(Keypair.prototype), keypair);
      } else {
        throw new KeyError('Identity expects a Keypair');
      }
    }
    /** @type {Keypair} */
    this.keypair = keypair;
  }

  /** @returns {Identity} from a fresh seed. */
  static generate() {
    return new Identity(Keypair.generate());
  }

  /**
   * @param {Buffer|Uint8Array|string} seed32
   * @returns {Identity}
   */
  static fromSeed(seed32) {
    return new Identity(Keypair.fromSeed(seed32));
  }

  /** @returns {string} `did:nau:…` */
  get did() {
    return this.keypair.did;
  }

  /** @returns {Buffer} raw 32-byte public key */
  get publicKey() {
    return this.keypair.publicKey;
  }

  /** @returns {Buffer} 32-byte seed */
  get seed() {
    return this.keypair.seed;
  }

  /** @returns {string} hex of the seed */
  exportSeedHex() {
    return this.keypair.exportSeedHex();
  }

  /** @returns {string} hex of the raw public key */
  exportPublicKeyHex() {
    return this.keypair.exportPublicKeyHex();
  }

  /**
   * @param {object} obj
   * @returns {string} 128 lowercase hex characters over the canonical payload
   */
  signPayload(obj) {
    return this.keypair.signPayload(obj).toString('hex');
  }

  /**
   * @param {object} obj
   * @param {string} sigHex
   * @returns {true}
   * @throws {SignatureError} when verification fails
   */
  verifyPayload(obj, sigHex) {
    return verifyPayload(obj, sigHex, this.publicKey);
  }

  /**
   * @param {Buffer|Uint8Array|string} message
   * @returns {Buffer} 64-byte signature
   */
  signRaw(message) {
    return this.keypair.sign(message);
  }

  /**
   * @param {Buffer|Uint8Array|string} message
   * @param {Buffer|Uint8Array|string} signature
   * @returns {boolean}
   */
  verifyRaw(message, signature) {
    return verifyRaw(message, signature, this.publicKey);
  }

  /** @returns {{did: string, publicKeyHex: string}} */
  toJSON() {
    return { did: this.did, publicKeyHex: this.exportPublicKeyHex() };
  }
}

export default {
  Keypair,
  Identity,
  Did,
  didFromPublicKey,
  fingerprint,
  verifyPayload,
  verifyPayloadBound,
  verifyRaw,
  toKeyBytes,
  toSignatureBytes,
  rawPublicKeyFromPrivate,
};
