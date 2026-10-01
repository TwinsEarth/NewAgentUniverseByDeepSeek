/**
 * The test entry point: `node test/run.js` from this directory, or
 * `node sdks/js/test/run.js` from the repository root.
 *
 * No install step, no test framework, no dependencies. Exits non-zero if
 * anything fails.
 */

import { runAll } from './harness.js';

// Importing a test file registers its suites; nothing runs until runAll().
await import('./version.test.js');
await import('./canonical.test.js');
await import('./conformance.test.js');
await import('./identity.test.js');
await import('./models.test.js');
await import('./ledger.test.js');
await import('./market.test.js');
await import('./mcp.test.js');
await import('./api.test.js');
await import('./types.test.js');

const { passed, failed, failures } = await runAll();

// The conformance fixture is the contract; make its presence explicit in the
// output so a run against a truncated checkout cannot look green by accident.
const { vectors } = await import('./helpers.js');
process.stdout.write(
  `conformance fixture: ${vectors.payloads.length} payloads,`
    + ` ${vectors.rejections.length} rejections, protocol ${vectors.protocol}\n`,
);

if (failed > 0) {
  process.stdout.write('\nFAILURES\n');
  for (const f of failures) process.stdout.write(`  ${f.test}\n`);
  process.exit(1);
}
process.exit(0);
