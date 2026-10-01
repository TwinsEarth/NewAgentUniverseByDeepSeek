/**
 * Type definitions for `@nau/sdk` (protocol `nau/1`).
 *
 * These declarations match `index.js` export for export; `test/types.test.js`
 * asserts that every name declared here exists at runtime and vice versa, so
 * the two cannot drift silently. That matters: upstream v2.5.6's `.d.ts`
 * omitted several methods that the implementation actually had
 * (`shardSize`, `findByPrefix`, `Task.transition`, the market internals),
 * which made them unreachable from TypeScript.
 */

/// <reference types="node" />

// ---------------------------------------------------------------------------
// version
// ---------------------------------------------------------------------------

/** The repository version, read from the top-level `VERSION` file at load time. */
export const VERSION: string;
/** Absolute path of the `VERSION` file that was read, or null when falling back. */
export const VERSION_FILE: string | null;
/** Directory containing `VERSION`, i.e. the repository root. */
export const REPO_ROOT: string | null;
/** True when no `VERSION` file could be found. */
export const VERSION_IS_FALLBACK: boolean;
/** Sentinel used when no `VERSION` file exists. Never a real release. */
export const FALLBACK_VERSION: string;
/** Name of the repository file that holds the authoritative version. */
export const VERSION_FILENAME: 'VERSION';
/** Walk up from `start` looking for the `VERSION` file; null when absent. */
export function findVersionFile(start?: string): string | null;

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

/** Base class for every error this SDK raises. */
export class NauError extends Error {
  readonly code: string;
  readonly errorCode: string;
  cause?: unknown;
}

export class CanonicalError extends NauError {}
export class RootNotObject extends CanonicalError {
  readonly value: unknown;
}
export class NonIntegerNumber extends CanonicalError {
  readonly value: unknown;
  readonly path: string;
}
export class UnsafeInteger extends CanonicalError {
  readonly value: number;
  readonly path: string;
}
export class TooDeep extends CanonicalError {
  readonly limit: number;
  readonly path: string;
}
export class UnsupportedType extends CanonicalError {
  readonly kind: string;
  readonly path: string;
}
export class NonPlainObject extends CanonicalError {
  readonly kind: string;
  readonly path: string;
}
export class SignatureError extends NauError {}
export class DidError extends NauError {}
export class DidMismatchError extends NauError {
  readonly did: string;
  readonly fingerprint: string;
}
export class KeyError extends NauError {}
export class MoneyError extends NauError {}
export class TransitionError extends NauError {
  readonly from: string;
  readonly to: string;
  readonly allowed: string[];
}
export class LedgerError extends NauError {}
export class ConservationError extends NauError {
  readonly supply?: string;
  readonly net?: string;
}
export class MarketError extends NauError {
  readonly status: number;
  readonly detail: string;
  readonly body: unknown;
  readonly route?: string;
}
export class McpError extends NauError {
  readonly status: number;
  readonly detail: string;
  readonly rpcCode?: number;
  readonly data?: unknown;
  readonly body?: unknown;
  readonly route?: string;
}

export function describeKind(value: unknown): string;

// ---------------------------------------------------------------------------
// canonicalization
// ---------------------------------------------------------------------------

/** Object key removed (at every depth) before signing or verifying. */
export const SIGNATURE_FIELD: 'signature';
/** Maximum object/array nesting accepted while canonicalizing. */
export const MAX_DEPTH: 64;

export type JsonScalar = null | boolean | number | string;
export type JsonValue = JsonScalar | JsonValue[] | { [key: string]: JsonValue };
/** What a signing payload may contain: a plain object at the root. */
export type CanonicalObject = { [key: string]: JsonValue };

/**
 * Canonicalize a signing payload.
 *
 * @throws RootNotObject when the root is not an object
 * @throws NonIntegerNumber on floats and exponent-form numbers
 * @throws UnsafeInteger on integers outside the safe range
 * @throws TooDeep beyond 64 levels
 * @throws UnsupportedType on undefined, BigInt, functions and symbols
 * @throws NonPlainObject on Date, Map, Set and class instances
 */
export function canonicalJson(obj: unknown): string;
/** The exact UTF-8 bytes that get signed. */
export function canonicalPayload(obj: unknown): Buffer;
/** Canonicalize any JSON value, including a non-object root. */
export function canonicalString(value: unknown): string;
/** Compare two strings by Unicode code point (not UTF-16 code unit). */
export function codepointCompare(a: string, b: string): number;
/** Escape a string as the contract requires (raw UTF-8, minimal escapes). */
export function escapeString(s: string): string;
/** Throw unless `obj` can be canonicalized; otherwise return true. */
export function assertCanonicalizable(obj: unknown): true;
export function isPlainObject(value: unknown): boolean;

// ---------------------------------------------------------------------------
// identity
// ---------------------------------------------------------------------------

/** Ed25519 PKCS#8 seed prefix. */
export const PKCS8_ED25519_PREFIX_HEX: string;
/** The one and only DID method prefix. */
export const DID_PREFIX: 'did:nau:';
export const DID_FINGERPRINT_BYTES: 8;
export const PUBLIC_KEY_BYTES: 32;
export const SEED_BYTES: 32;
export const SIGNATURE_BYTES: 64;

export type PublicKeyLike = Buffer | Uint8Array | string | Keypair | Identity;
export type SignatureLike = Buffer | Uint8Array | string;

export function sha256(data: Buffer | Uint8Array | string): Buffer;
export function toKeyBytes(bytes: Buffer | Uint8Array | string, label?: string): Buffer;
export function toSignatureBytes(sig: SignatureLike): Buffer;
export function rawPublicKeyFromPrivate(privateKey: import('node:crypto').KeyObject): Buffer;
/** `did = "did:nau:" + sha256(rawPublicKey).slice(0, 8).toString('hex')` */
export function didFromPublicKey(pubBytes: Buffer | Uint8Array | string, prefix?: string): string;
/** First 8 SHA-256 bytes of the raw public key, lowercase hex. */
export function fingerprint(pubBytes: Buffer | Uint8Array | string): string;
/** Verify a raw Ed25519 signature; returns false rather than throwing. */
export function verifyRaw(message: Buffer | Uint8Array | string, signature: SignatureLike, publicKey: PublicKeyLike): boolean;
/** Verify a signature over the canonical payload; throws on failure. */
export function verifyPayload(obj: unknown, sigHex: SignatureLike, publicKeyBytes: PublicKeyLike): true;
/** Verify the signature AND that `did` is that public key's fingerprint. */
export function verifyPayloadBound(obj: unknown, sigHex: SignatureLike, publicKeyBytes: PublicKeyLike, did: string): true;

export class Keypair {
  constructor(seed: Buffer, privateKey: import('node:crypto').KeyObject, publicKey: Buffer);
  /** A keypair from a fresh CSPRNG seed. */
  static generate(): Keypair;
  /** Deterministic keypair from a 32-byte seed. */
  static fromSeed(bytes32: Buffer | Uint8Array | string): Keypair;
  /** Rehydrate from 64 hex characters (seed) or 128 (seed || public key). */
  static fromHex(input: string | { seedHex?: string; seed_hex?: string } | Buffer): Keypair;
  readonly seed: Buffer;
  readonly publicKey: Buffer;
  readonly privateKey: import('node:crypto').KeyObject;
  /** `did:nau:…` for this key. */
  readonly did: string;
  exportSeed(): Buffer;
  exportSeedHex(): string;
  exportPublicKeyHex(): string;
  exportSpkiBase64(): string;
  /** The same fingerprint under another method prefix (legacy interop only). */
  didWith(prefix: string): string;
  sign(message: Buffer | Uint8Array | string): Buffer;
  verify(message: Buffer | Uint8Array | string, signature: SignatureLike): boolean;
  signPayload(obj: unknown): Buffer;
  verifyPayload(obj: unknown, signature: SignatureLike): boolean;
  toJSON(): { did: string; publicKeyHex: string; seedHex: string };
}

export class Identity {
  constructor(keypair?: Keypair);
  static generate(): Identity;
  static fromSeed(seed32: Buffer | Uint8Array | string): Identity;
  readonly keypair: Keypair;
  readonly did: string;
  readonly publicKey: Buffer;
  readonly seed: Buffer;
  exportSeedHex(): string;
  exportPublicKeyHex(): string;
  /** 128 lowercase hex characters over the canonical payload. */
  signPayload(obj: unknown): string;
  /** Throws SignatureError when the signature does not verify. */
  verifyPayload(obj: unknown, sigHex: SignatureLike): true;
  signRaw(message: Buffer | Uint8Array | string): Buffer;
  verifyRaw(message: Buffer | Uint8Array | string, signature: SignatureLike): boolean;
  toJSON(): { did: string; publicKeyHex: string };
}

export class Did {
  constructor(method: string, fingerprintHex: string, prefix: string, original: string);
  static parse(str: string): Did;
  readonly method: string;
  readonly fingerprint: string;
  readonly prefix: string;
  readonly did: string;
  readonly isLegacy: boolean;
  matchesPublicKey(publicKeyBytes: PublicKeyLike): boolean;
  asString(): string;
  toCanonicalString(): string;
  toString(): string;
  toJSON(): string;
}

// ---------------------------------------------------------------------------
// models
// ---------------------------------------------------------------------------

export const DEFAULT_MONEY_SCALE: 6;

/** An exact amount of money: an integer count of minor units. */
export class Money {
  constructor(minor: number | bigint, scale?: number);
  static fromMinor(minor: number | bigint, scale?: number): Money;
  static zero(scale?: number): Money;
  /** Parse a decimal string ('0.1', '1e-3', '-2.5') into exact minor units. */
  static parse(input: string | number | bigint, scale?: number): Money;
  static coerce(other: Money | number | bigint | string, scale?: number): Money;
  readonly scale: number;
  /** Minor units as a safe integer; throws when out of range. */
  readonly minor: number;
  /** Minor units, exact and unbounded. */
  minorBigInt(): bigint;
  readonly isSafe: boolean;
  readonly isNegative: boolean;
  readonly isZero: boolean;
  checkedAdd(other: Money | number | bigint | string): Money;
  checkedSub(other: Money | number | bigint | string): Money;
  checkedMul(factor: number | bigint): Money;
  compare(other: Money): -1 | 0 | 1;
  equals(other: Money): boolean;
  /** Decimal string with trailing fractional zeros removed. */
  toDecimalString(): string;
  /** Decimal string with exactly `scale` fraction digits: the signed form. */
  toCanonicalString(): string;
  toString(): string;
  toJSON(): string;
}

export interface SkillInit {
  name: string;
  version?: string;
  description?: string;
  tags?: string[];
  inputSchema?: object | null;
}
export class Skill {
  constructor(init: SkillInit);
  name: string;
  version: string;
  description: string;
  tags: string[];
  inputSchema: object | null;
  toJSON(): object;
}

export interface PricingInit {
  amountMinor?: number | bigint;
  amount?: Money | string;
  currency?: string;
  scale?: number;
  per?: string;
}
export class Pricing {
  constructor(init?: PricingInit);
  amount: Money;
  currency: string;
  per: string;
  readonly amountMinor: number;
  toJSON(): object;
}

export interface SlaInit {
  deadlineSeconds?: number;
  minEvidenceGrade?: string;
  penaltyMinor?: number | bigint;
  rewardMinor?: number | bigint;
  scale?: number;
}
export class Sla {
  constructor(init?: SlaInit);
  deadlineSeconds: number;
  minEvidenceGrade: string;
  penalty: Money;
  reward: Money;
  toJSON(): object;
}

export interface AgentCardInit {
  did: string;
  name?: string;
  capabilities?: string[];
  skills?: (Skill | SkillInit)[];
  endpoint?: string | null;
  stakeMinor?: number | bigint;
  stake?: number;
  pricing?: Pricing | PricingInit;
  sla?: Sla | SlaInit;
  metadata?: object;
  signature?: string;
  scale?: number;
}
export class AgentCard {
  constructor(init: AgentCardInit);
  did: string;
  name: string;
  capabilities: string[];
  skills: Skill[];
  endpoint: string | null;
  stake: Money;
  pricing: Pricing;
  sla: Sla;
  metadata: object;
  signature: string;
  readonly stakeMinor: number;
  /** The exact object that is signed and verified. */
  toPayload(): object;
  toJSON(): object;
}

/** Evidence strength, weakest to strongest. */
export class EvidenceGrade {
  private constructor();
  static readonly NONE: 'none';
  static readonly SELF_ATTESTED: 'self_attested';
  static readonly HASHED: 'hashed';
  static readonly THIRD_PARTY_VERIFIED: 'third_party_verified';
  static readonly ZK_PROVEN: 'zk_proven';
  static readonly ALL: readonly string[];
  static readonly RANK: Readonly<Record<string, number>>;
  static parse(value: string): string;
  static atLeast(a: string, b: string): boolean;
}

export interface TaskSpecInit {
  id?: string | null;
  description?: string;
  capabilities?: string[];
  input?: object | null;
  outputSchema?: object | null;
  maxPriceMinor?: number | bigint;
  scale?: number;
}
export class TaskSpec {
  constructor(init?: TaskSpecInit);
  id: string | null;
  description: string;
  capabilities: string[];
  input: object | null;
  outputSchema: object | null;
  maxPrice: Money;
  toPayload(): object;
  toJSON(): object;
}

/** The twelve task states. */
export type TaskStateName =
  | 'open'
  | 'matched'
  | 'running'
  | 'submitted'
  | 'verifying'
  | 'accepted'
  | 'rework'
  | 'settled'
  | 'disputed'
  | 'slashed'
  | 'cancelled'
  | 'no_quorum';

export class TaskState {
  private constructor();
  static readonly OPEN: 'open';
  static readonly MATCHED: 'matched';
  static readonly RUNNING: 'running';
  static readonly SUBMITTED: 'submitted';
  static readonly VERIFYING: 'verifying';
  static readonly ACCEPTED: 'accepted';
  static readonly REWORK: 'rework';
  static readonly SETTLED: 'settled';
  static readonly DISPUTED: 'disputed';
  static readonly SLASHED: 'slashed';
  static readonly CANCELLED: 'cancelled';
  static readonly NO_QUORUM: 'no_quorum';
  static readonly ALL: readonly TaskStateName[];
  static readonly TRANSITIONS: Readonly<Record<TaskStateName, readonly TaskStateName[]>>;
  static readonly ALIASES: Readonly<Record<string, TaskStateName>>;
  static readonly TERMINAL: readonly TaskStateName[];
  static parse(value: string): TaskStateName;
  static canTransitionTo(from: string, to: string): boolean;
  static nextStates(from: string): TaskStateName[];
}

export interface TaskInit {
  id?: string;
  spec?: TaskSpec | TaskSpecInit;
  state?: string;
  publisherDid?: string;
  workerDid?: string | null;
  priceMinor?: number | bigint;
  deadlineUnix?: number | null;
  attempts?: number;
  history?: string[];
  scale?: number;
  createdUnix?: number | null;
}
export class Task {
  constructor(init?: TaskInit);
  static fromJSON(json: TaskInit): Task;
  id: string;
  spec: TaskSpec;
  state: TaskStateName;
  publisherDid: string;
  workerDid: string | null;
  price: Money;
  deadlineUnix: number | null;
  attempts: number;
  history: string[];
  createdUnix: number | null;
  readonly isTerminal: boolean;
  canTransitionTo(next: string): boolean;
  nextStates(): TaskStateName[];
  /** Throws TransitionError unless the edge is in the transition table. */
  transition(next: string): this;
  toPayload(): object;
  toJSON(): object;
}

export interface BidInit {
  taskId?: string;
  bidderDid?: string;
  priceMinor?: number | bigint;
  etaSeconds?: number | null;
  reputation?: number | null;
  nonce?: string | null;
  scale?: number;
  signature?: string;
}
export class Bid {
  constructor(init?: BidInit);
  taskId: string;
  bidderDid: string;
  price: Money;
  etaSeconds: number | null;
  reputation: number | null;
  nonce: string | null;
  signature: string;
  toPayload(): object;
  toJSON(): object;
}

export interface ResultEnvelopeInit {
  taskId?: string;
  workerDid?: string;
  output?: unknown;
  outputHash?: string | null;
  evidenceGrade?: string;
  evidence?: object | null;
  costMinor?: number | bigint;
  startedUnix?: number | null;
  finishedUnix?: number | null;
  scale?: number;
  signature?: string;
}
export class ResultEnvelope {
  constructor(init?: ResultEnvelopeInit);
  taskId: string;
  workerDid: string;
  output: unknown;
  outputHash: string | null;
  evidenceGrade: string;
  evidence: object | null;
  cost: Money;
  startedUnix: number | null;
  finishedUnix: number | null;
  signature: string;
  toPayload(): object;
  toJSON(): object;
}

export interface DisputeInit {
  taskId?: string;
  challengerDid?: string;
  reason?: string;
  evidence?: object | null;
  bondMinor?: number | bigint;
  scale?: number;
  openedUnix?: number | null;
  signature?: string;
}
export class Dispute {
  constructor(init?: DisputeInit);
  taskId: string;
  challengerDid: string;
  reason: string;
  evidence: object | null;
  bond: Money;
  openedUnix: number | null;
  signature: string;
  toPayload(): object;
  toJSON(): object;
}

// ---------------------------------------------------------------------------
// ledger
// ---------------------------------------------------------------------------

export const DEFAULT_SHARD_CAPACITY: 1024;
export const GENESIS_HASH: string;
export const MINT_ACCOUNT: '@mint';
export const BURN_ACCOUNT: '@burn';

export const LedgerEntryKind: Readonly<{
  DEPOSIT: 'deposit';
  TRANSFER: 'transfer';
  ESCROW: 'escrow';
  RELEASE: 'release';
  REFUND: 'refund';
  SLASH: 'slash';
  FEE: 'fee';
}>;

export function hashEntry(body: object): string;
export function merkleRoot(hashes: string[]): string;
/** Entries in a shard of `total`, capped at `capacity`. */
export function shardSize(total: number, capacity?: number): number;
/** Items whose string key starts with `prefix`. */
export function findByPrefix<T>(
  prefix: string,
  items: Iterable<T>,
  key?: (item: T) => string,
  limit?: number,
): T[];

export interface LedgerEntryInit {
  seq: number;
  timestamp: number;
  kind: string;
  debit: string;
  credit: string;
  amountMinor: number | bigint;
  scale?: number;
  reference?: string | null;
  memo?: string | null;
  prevHash?: string;
  hash?: string;
}
export class LedgerEntry {
  constructor(init: LedgerEntryInit);
  seq: number;
  timestamp: number;
  kind: string;
  debit: string;
  credit: string;
  amountMinor: bigint;
  scale: number;
  reference: string | null;
  memo: string | null;
  prevHash: string;
  hash: string;
  readonly hashHex: string;
  readonly amount: Money;
  /** True when `hash` really covers this entry's body. */
  verify(): boolean;
  toJSON(): object;
}

export interface ConservationReportInit {
  supplyMinor: bigint | number;
  depositsMinor: bigint | number;
  slashedMinor: bigint | number;
  feesMinor: bigint | number;
  accounts: Record<string, { minor: string; scale: number }>;
  ok: boolean;
  entries: number;
  head: string;
  scale?: number;
}
export class ConservationReport {
  constructor(init: ConservationReportInit);
  supply: Money;
  deposits: Money;
  slashed: Money;
  fees: Money;
  accounts: Record<string, { minor: string; scale: number }>;
  ok: boolean;
  entries: number;
  head: string;
  toJSON(): object;
}

export class Ledger {
  constructor(init?: { scale?: number; now?: () => number });
  readonly scale: number;
  readonly entries: LedgerEntry[];
  readonly balances: Map<string, bigint>;
  readonly now: () => number;
  readonly length: number;
  readonly head: string;
  readonly depositsMinor: bigint;
  readonly slashedMinor: bigint;
  readonly feesMinor: bigint;
  readonly supplyMinor: bigint;
  rawBalance(account: string): bigint;
  balance(account: string): Money;
  accounts(): string[];
  append(init: {
    kind: string;
    debit: string;
    credit: string;
    amountMinor: number | bigint;
    reference?: string | null;
    memo?: string | null;
    timestamp?: number;
  }): LedgerEntry;
  deposit(account: string, amountMinor: number | bigint, options?: { reference?: string | null; memo?: string | null }): LedgerEntry;
  transfer(
    from: string,
    to: string,
    amountMinor: number | bigint,
    options?: { kind?: string; reference?: string | null; memo?: string | null; allowOverdraft?: boolean },
  ): LedgerEntry;
  slash(account: string, amountMinor: number | bigint, options?: { reference?: string | null; memo?: string | null }): LedgerEntry;
  /** Throws ConservationError when the books do not balance. */
  conservation(): ConservationReport;
  verifyChain(): { ok: boolean; length: number; brokenAt: number | null };
  shard(index?: number, capacity?: number): LedgerEntry[];
  root(): string;
  findByPrefix(prefix: string, limit?: number): LedgerEntry[];
  toJSON(): object;
}

// ---------------------------------------------------------------------------
// market
// ---------------------------------------------------------------------------

export type MarketRouteName =
  | 'health'
  | 'deposit'
  | 'balance'
  | 'registerAgent'
  | 'getAgent'
  | 'discover'
  | 'search'
  | 'publishTask'
  | 'getTask'
  | 'listTasks'
  | 'submitBid'
  | 'matchTask'
  | 'submitResult'
  | 'verifyResult'
  | 'settleTask'
  | 'openDispute'
  | 'arbitrate'
  | 'conservation'
  | 'leaderboard'
  | 'stats';

export const MARKET_ROUTES: Readonly<Record<MarketRouteName, readonly [string, string]>>;

export interface MarketClientOptions {
  timeoutMs?: number;
  headers?: Record<string, string>;
  fetch?: typeof fetch;
  routes?: Record<string, [string, string]>;
}

export class MarketClient {
  constructor(baseUrl?: string, options?: MarketClientOptions);
  baseUrl: string;
  timeoutMs: number;
  headers: Record<string, string>;
  fetchImpl: typeof fetch;
  routes: Record<string, [string, string]>;
  requestCount: number;
  /** Low-level escape hatch; throws MarketError on >= 400 or a non-JSON body. */
  request(
    route: string,
    options?: { params?: Record<string, string>; query?: object | null; body?: unknown },
  ): Promise<any>;
  static parseResponse(response: Response, route: string, method?: string, pathname?: string): Promise<any>;
  health(): Promise<any>;
  deposit(body: { account: string; amountMinor: number | bigint | string; currency?: string; reference?: string | null; signature?: string }): Promise<any>;
  balance(account: string): Promise<any>;
  registerAgent(card: AgentCard | object): Promise<any>;
  getAgent(did: string): Promise<any>;
  discover(query?: { capability?: string; capabilities?: string[]; minStakeMinor?: number | bigint; limit?: number; offset?: number; sort?: string }): Promise<any>;
  search(text: string, options?: { limit?: number; offset?: number }): Promise<any>;
  publishTask(body: object): Promise<any>;
  getTask(taskId: string): Promise<any>;
  listTasks(query?: { state?: string; publisherDid?: string; workerDid?: string; limit?: number; offset?: number }): Promise<any>;
  submitBid(taskId: string, bid: Bid | object): Promise<any>;
  matchTask(taskId: string, body?: { workerDid?: string; bidId?: string; priceMinor?: number | bigint }): Promise<any>;
  submitResult(taskId: string, result: ResultEnvelope | object): Promise<any>;
  verifyResult(taskId: string, body?: { outputHash?: string; evidenceGrade?: string; verifierDid?: string; approve?: boolean }): Promise<any>;
  settleTask(taskId: string, body?: { outcome?: string; payoutMinor?: number | bigint; slashedMinor?: number | bigint }): Promise<any>;
  openDispute(taskId: string, dispute: Dispute | object): Promise<any>;
  arbitrate(taskId: string, body?: { ruling?: string; slashMinor?: number | bigint; payoutMinor?: number | bigint; arbiterDid?: string; rationale?: string }): Promise<any>;
  conservation(query?: { account?: string }): Promise<any>;
  leaderboard(query?: { limit?: number; capability?: string; sinceUnix?: number }): Promise<any>;
  stats(): Promise<any>;
}

// ---------------------------------------------------------------------------
// mcp
// ---------------------------------------------------------------------------

export const MCP_PROTOCOL_VERSION: '2024-11-05';
export const JSONRPC_VERSION: '2.0';
export const MCP_SESSION_HEADER: 'mcp-session-id';
export const MCP_SESSION_HEADER_LEGACY: 'Mcp-Session-Id';

export interface McpHttpClientOptions {
  timeoutMs?: number;
  headers?: Record<string, string>;
  fetch?: typeof fetch;
  clientName?: string;
  clientVersion?: string;
  protocolVersion?: string;
  capabilities?: object;
}

export class McpHttpClient {
  constructor(baseUrl?: string, options?: McpHttpClientOptions);
  baseUrl: string;
  timeoutMs: number;
  headers: Record<string, string>;
  fetchImpl: typeof fetch;
  clientName: string;
  clientVersion: string;
  protocolVersion: string;
  capabilities: object;
  sessionId: string | null;
  serverInfo: any;
  serverCapabilities: any;
  initialized: boolean;
  /** Send one JSON-RPC message; throws McpError on any failure. */
  send(message: object, options?: { route?: string; expectResponse?: boolean; notification?: boolean }): Promise<any>;
  /** `initialize` then `notifications/initialized`. */
  initialize(): Promise<any>;
  listTools(): Promise<any[]>;
  callTool(name: string, args?: object): Promise<any>;
  ensureInitialized(): Promise<any>;
}

/** Extract JSON-RPC messages from a `text/event-stream` body. */
export function parseSse(text: string): any[];

// ---------------------------------------------------------------------------
// façade
// ---------------------------------------------------------------------------

export interface AgentInit {
  identity?: Identity;
  keypair?: Keypair;
  seed?: Buffer | string;
  marketUrl?: string;
  mcpUrl?: string;
  marketOptions?: MarketClientOptions;
  mcpOptions?: McpHttpClientOptions;
}

export class Agent {
  constructor(init?: AgentInit);
  identity: Identity;
  market: MarketClient | null;
  mcp: McpHttpClient | null;
  readonly did: string;
  /** A card signed by this identity. */
  card(fields?: Partial<AgentCardInit>): AgentCard;
  /** Verify a card's signature and that its DID matches the key. */
  static verifyCard(card: AgentCard | object, publicKeyBytes: PublicKeyLike): true;
}

export const api: Readonly<Record<string, unknown>>;

/** The namespace object; the same value as {@link api}. */
export default api;
