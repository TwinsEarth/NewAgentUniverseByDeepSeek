/**
 * `@nau/sdk` — the JavaScript SDK for the agent universe protocol `nau/1`.
 *
 * Public entry point. Zero dependencies: only `node:crypto`, `node:fs`,
 * `node:path` and the global `fetch` are used.
 *
 * ```js
 * import { Identity, canonicalJson, verifyPayload } from '@nau/sdk';
 *
 * const id = Identity.generate();
 * const card = { did: id.did, name: 'CrossLang', capabilities: ['mcp'], stake_minor: 100 };
 * const sig = id.signPayload(card);
 * verifyPayload(card, sig, id.publicKey); // true, or throws
 * console.log(canonicalJson(card));
 * ```
 */

export {
  VERSION,
  VERSION_FILE,
  REPO_ROOT,
  VERSION_IS_FALLBACK,
  FALLBACK_VERSION,
  VERSION_FILENAME,
  findVersionFile,
} from './lib/version.js';

export {
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
} from './lib/errors.js';

export {
  canonicalJson,
  canonicalPayload,
  canonicalString,
  codepointCompare,
  escapeString,
  assertCanonicalizable,
  isPlainObject,
  SIGNATURE_FIELD,
  MAX_DEPTH,
} from './lib/canonical.js';

export {
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
  sha256,
  DID_PREFIX,
  DID_FINGERPRINT_BYTES,
  PKCS8_ED25519_PREFIX_HEX,
  PUBLIC_KEY_BYTES,
  SEED_BYTES,
  SIGNATURE_BYTES,
} from './lib/identity.js';

export {
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
  DEFAULT_MONEY_SCALE,
} from './lib/models.js';

export {
  Ledger,
  LedgerEntry,
  LedgerEntryKind,
  LedgerError,
  ConservationError,
  ConservationReport,
  hashEntry,
  merkleRoot,
  shardSize,
  findByPrefix,
  DEFAULT_SHARD_CAPACITY,
  GENESIS_HASH,
  MINT_ACCOUNT,
  BURN_ACCOUNT,
} from './lib/ledger.js';

export { MarketClient, MarketError, MARKET_ROUTES } from './lib/market.js';

export {
  McpHttpClient,
  McpError,
  parseSse,
  MCP_PROTOCOL_VERSION,
  JSONRPC_VERSION,
  MCP_SESSION_HEADER,
  MCP_SESSION_HEADER_LEGACY,
} from './lib/mcp.js';

import { VERSION } from './lib/version.js';
import { canonicalJson } from './lib/canonical.js';
import {
  Identity,
  Keypair,
  Did,
  didFromPublicKey,
  fingerprint,
  verifyPayload,
  verifyPayloadBound,
} from './lib/identity.js';
import { SignatureError } from './lib/errors.js';
import { AgentCard, Money, Task, TaskState } from './lib/models.js';
import { MarketClient } from './lib/market.js';
import { McpHttpClient } from './lib/mcp.js';

/**
 * A convenience façade that binds one identity to the two clients.
 *
 * Nothing in here is required — the individual exports are the API — but the
 * common case is "one agent talking to one market and one MCP server".
 */
export class Agent {
  /**
   * @param {{identity?: Identity, keypair?: Keypair, seed?: Buffer|string,
   *   marketUrl?: string, mcpUrl?: string, marketOptions?: object,
   *   mcpOptions?: object}} [init]
   */
  constructor(init = {}) {
    /** @type {Identity} */
    this.identity = init.identity
      ?? (init.keypair !== undefined
        ? new Identity(init.keypair)
        : init.seed !== undefined
          ? Identity.fromSeed(init.seed)
          : Identity.generate());
    /** @type {MarketClient|null} */
    this.market = init.marketUrl === undefined
      ? null
      : new MarketClient(init.marketUrl, { headers: { 'x-agent-did': this.identity.did }, ...init.marketOptions });
    /** @type {McpHttpClient|null} */
    this.mcp = init.mcpUrl === undefined
      ? null
      : new McpHttpClient(init.mcpUrl, { clientName: 'nau-js-sdk', clientVersion: VERSION, ...init.mcpOptions });
  }

  /** @returns {string} */
  get did() {
    return this.identity.did;
  }

  /**
   * Build a signed {@link AgentCard} for this identity.
   *
   * @param {object} [fields]
   * @returns {AgentCard}
   */
  card(fields = {}) {
    const draft = new AgentCard({ ...fields, did: this.identity.did });
    const signature = this.identity.signPayload(draft.toPayload());
    return new AgentCard({ ...fields, did: this.identity.did, signature });
  }

  /**
   * Verify a card's signature and that its DID matches the supplied key.
   *
   * @param {AgentCard|object} card
   * @param {Buffer|Uint8Array|string} publicKeyBytes
   * @returns {true}
   */
  static verifyCard(card, publicKeyBytes) {
    const payload = typeof /** @type {any} */ (card).toPayload === 'function'
      ? /** @type {any} */ (card).toPayload()
      : { ...card };
    const sig = payload.signature;
    if (typeof sig !== 'string' || sig.length === 0) {
      throw new SignatureError(`agent card ${String(payload.did)} has no signature`);
    }
    const did = payload.did;
    return verifyPayloadBound(payload, sig, publicKeyBytes, did);
  }
}

/** Everything the module exposes, as a single namespace object. */
export const api = Object.freeze({
  VERSION,
  Agent,
  AgentCard,
  Did,
  Identity,
  Keypair,
  MarketClient,
  McpHttpClient,
  Money,
  Task,
  TaskState,
  canonicalJson,
  didFromPublicKey,
  fingerprint,
  verifyPayload,
  verifyPayloadBound,
});

export default api;
