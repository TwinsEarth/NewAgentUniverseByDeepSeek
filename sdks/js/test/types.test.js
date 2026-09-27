/**
 * `index.d.ts` must match `index.js`.
 *
 * Upstream's `.d.ts` omitted methods the implementation actually had
 * (`shardSize`, `findByPrefix`, `Task.transition`, and most of the market
 * client), which made them unreachable from TypeScript. This is a mechanical
 * check in both directions: a declared name must exist at runtime, and an
 * exported runtime name must be declared.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';

import { test, suite, eq, ok } from './harness.js';
import { SDK_ROOT } from './helpers.js';
import * as sdk from '../index.js';

const dts = readFileSync(path.join(SDK_ROOT, 'index.d.ts'), 'utf8');

/** Names declared by `export ...` statements in the .d.ts. */
function declaredNames() {
  const names = new Set();
  const exportRe = /^export\s+(?:declare\s+)?(?:abstract\s+)?(?:class|function|const|let|var|interface|type|enum)\s+([A-Za-z_$][\w$]*)/gm;
  for (const m of dts.matchAll(exportRe)) names.add(m[1]);
  // `export { a, b as c }` blocks, possibly spanning lines.
  const blockRe = /^export\s*\{([^}]*)\}/gm;
  for (const m of dts.matchAll(blockRe)) {
    for (const piece of m[1].split(',')) {
      const text = piece.trim();
      if (text.length === 0) continue;
      const asMatch = /\s+as\s+([A-Za-z_$][\w$]*)$/.exec(text);
      names.add(asMatch !== null ? asMatch[1] : text.replace(/^type\s+/, ''));
    }
  }
  // The default export has no name to capture.
  if (/^export\s+default\s+/m.test(dts)) names.add('default');
  return names;
}

/** Names exported at runtime, including the default. */
function runtimeNames() {
  return new Set(Object.keys(sdk));
}

const declared = declaredNames();
const runtime = runtimeNames();

/** Names that exist only in the type layer. */
const TYPE_ONLY = new Set([
  'JsonScalar',
  'JsonValue',
  'CanonicalObject',
  'PublicKeyLike',
  'SignatureLike',
  'SkillInit',
  'PricingInit',
  'SlaInit',
  'AgentCardInit',
  'TaskSpecInit',
  'TaskStateName',
  'TaskInit',
  'BidInit',
  'ResultEnvelopeInit',
  'DisputeInit',
  'LedgerEntryInit',
  'ConservationReportInit',
  'MarketRouteName',
  'MarketClientOptions',
  'McpHttpClientOptions',
  'AgentInit',
]);

suite('types: index.d.ts matches index.js', () => {
  test('every runtime export is declared in index.d.ts', () => {
    const missing = [...runtime].filter((name) => !declared.has(name));
    eq(missing.sort().join(','), '', 'these exports have no type declaration');
  });

  test('every declared name exists at runtime, except type-only names', () => {
    const extra = [...declared].filter((name) => !runtime.has(name) && !TYPE_ONLY.has(name));
    eq(extra.sort().join(','), '', 'these declarations have no runtime export');
  });

  test('the type-only allowlist has no stale entries', () => {
    for (const name of TYPE_ONLY) {
      ok(declared.has(name), `${name} is listed as type-only but is not declared`);
      ok(!runtime.has(name), `${name} is listed as type-only but exists at runtime`);
    }
  });

  test('the surface the upstream declaration forgot is declared', () => {
    // These are named explicitly because their absence was a real defect.
    for (const name of ['shardSize', 'findByPrefix', 'merkleRoot', 'hashEntry']) {
      ok(declared.has(name), `${name} must be declared`);
      eq(typeof sdk[name], 'function', `${name} must be exported`);
    }
    ok(/transition\(next: string\): this/.test(dts), 'Task.transition must be declared');
    ok(/nextStates\(\): TaskStateName\[\]/.test(dts), 'Task.nextStates must be declared');
    ok(/canTransitionTo\(next: string\): boolean/.test(dts), 'Task.canTransitionTo must be declared');
    ok(/request\(\s*route: string/.test(dts), 'MarketClient.request must be declared');
    ok(/parseResponse\(/.test(dts), 'MarketClient.parseResponse must be declared');
    ok(/send\(message: object/.test(dts), 'McpHttpClient.send must be declared');
    ok(/ensureInitialized\(\)/.test(dts), 'McpHttpClient.ensureInitialized must be declared');
    ok(/matchesPublicKey\(/.test(dts), 'Did.matchesPublicKey must be declared');
    ok(/minorBigInt\(\): bigint/.test(dts), 'Money.minorBigInt must be declared');
    ok(/toCanonicalString\(\): string/.test(dts), 'Money.toCanonicalString must be declared');
  });

  test('the whole 20-method market surface is declared', () => {
    const methods = [
      'health', 'deposit', 'balance', 'registerAgent', 'getAgent', 'discover', 'search',
      'publishTask', 'getTask', 'listTasks', 'submitBid', 'matchTask', 'submitResult',
      'verifyResult', 'settleTask', 'openDispute', 'arbitrate', 'conservation',
      'leaderboard', 'stats',
    ];
    const classBody = dts.slice(dts.indexOf('export class MarketClient'));
    const body = classBody.slice(0, classBody.indexOf('\n}\n'));
    for (const name of methods) {
      ok(new RegExp(`\\b${name}\\(`).test(body), `MarketClient.${name} must be declared`);
      eq(typeof sdk.MarketClient.prototype[name], 'function', `MarketClient.${name} must exist`);
    }
  });

  test('declare every exported error class, and they all extend Error', () => {
    const errorNames = [...runtime].filter((name) => /Error$/.test(name));
    ok(errorNames.length >= 10, `expected the full error hierarchy, found ${errorNames.length}`);
    for (const name of errorNames) {
      ok(declared.has(name), `${name} must be declared`);
      ok(sdk[name].prototype instanceof Error, `${name} must extend Error`);
    }
  });

  test('the declarations mention no version literal', () => {
    ok(!/\b\d+\.\d+\.\d+\b/.test(dts), 'index.d.ts must not restate the version');
    ok(/export const VERSION: string/.test(dts));
  });

  test('the default export is declared', () => {
    ok(/export const api: Readonly<Record<string, unknown>>/.test(dts));
    ok(sdk.default !== undefined);
    eq(sdk.default.VERSION, sdk.VERSION);
  });
});
