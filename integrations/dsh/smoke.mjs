// Smoke-test the bundle's module without the harness.
//
// The harness's own loader is the real test, but it needs a session. This checks the parts that
// fail silently if they are wrong: that the module imports at all, that `apply` is what Cordis
// will call, that every tool passes `defineTool`'s validation, and that the two read-only tools
// that need no node actually run.
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

// Resolved relative to this file, so the check works from a checkout, from a tarball unpacked
// anywhere, and from the repository it lives in. An absolute path here would have made the check
// pass only on the machine that wrote it.
const MODULE = fileURLToPath(new URL('./lib/tools.js', import.meta.url));

// * * * AND THE SAME RULE, APPLIED TO THE BINARY -- WHICH IT WAS NOT * * *
//
// The paragraph above was already in this file, and eleven lines below it the default binary was
// hard-coded:
//
//     mod.apply(ctx, { bin: process.env.NAU_BIN ||
//       'E:/DS/NewAgentUniverseByDeepSeek/target/debug/nau.exe' });
//
// That is the author's own machine, with the author's own drive letter, and a `.exe` suffix that
// only exists on Windows. So the `dsh-bundle` gate could never pass on Linux or macOS, and it never
// had -- it reported `could not run \`E:/DS/NewAgentUniverseByDeepSeek/...\`` on all three CI
// runners, and nobody saw it because until v3.9.13 the gate suite did not run in CI at all.
//
// Deriving it is the same technique the line above already uses, plus the platform suffix: the
// binary is `nau.exe` on Windows and `nau` elsewhere, which is why the suffix is computed rather
// than written.
const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));
const DEFAULT_BIN = path.join(
  REPO_ROOT,
  'target',
  'debug',
  process.platform === 'win32' ? 'nau.exe' : 'nau',
);

const registered = [];
const ctx = {
  tools: {
    register(tool) {
      registered.push(tool);
      return tool;
    },
  },
};

const mod = await import(pathToFileURL(MODULE).href);
console.log('exports:', Object.keys(mod).join(', '));
if (typeof mod.apply !== 'function') {
  console.error('FAIL: the module does not export an `apply` function, which is what Cordis calls');
  process.exit(1);
}
console.log('inject:', JSON.stringify(mod.inject));

mod.apply(ctx, { bin: process.env.NAU_BIN || DEFAULT_BIN });

console.log(`registered ${registered.length} tool(s):`);
for (const tool of registered) {
  const params = Object.keys(tool.parameters || {});
  console.log(`  ${tool.name}  params=[${params.join(', ')}]  hasExecute=${typeof tool.execute === 'function'}`);
}

const expected = ['nau_version', 'nau_inspect', 'nau_conformance', 'nau_amount', 'nau_node_status'];
const missing = expected.filter((n) => !registered.some((t) => t.name === n));
if (missing.length) {
  console.error('FAIL: not registered:', missing.join(', '));
  process.exit(1);
}

// The two tools that need no node: run them for real.
const abort = new AbortController();
const exec = { signal: abort.signal };

for (const name of ['nau_version', 'nau_conformance', 'nau_amount']) {
  const tool = registered.find((t) => t.name === name);
  const args = name === 'nau_amount' ? { decimal: '12.5' } : {};
  try {
    const out = await tool.execute(args, exec);
    const parsed = JSON.parse(out);
    console.log(`  ran ${name}: exit_code=${parsed.exit_code} ok=${parsed.ok}`);
    if (name === 'nau_version') console.log(`    ${parsed.stdout.split('\n').join(' | ')}`);
    if (name === 'nau_amount') console.log(`    ${parsed.stdout.trim()}`);
  } catch (e) {
    console.error(`  FAILED ${name}: ${e.message}`);
    process.exitCode = 1;
  }
}

// The bounds: a missing binary must be a named error, not an empty success.
const other = await import(`${pathToFileURL(MODULE).href}?fresh=1`);
const registered2 = [];
other.apply({ tools: { register: (t) => registered2.push(t) } }, { bin: 'definitely-not-a-real-binary-xyz' });
const versionTool = registered2.find((t) => t.name === 'nau_version');
try {
  await versionTool.execute({}, exec);
  console.error('FAIL: a missing binary produced an answer instead of an error');
  process.exitCode = 1;
} catch (e) {
  const namesSetting = /NAU_BIN|config\.bin/.test(e.message);
  console.log(`  missing binary -> error that names the setting: ${namesSetting}`);
  if (!namesSetting) {
    console.error(`  FAIL: the error does not say what to fix: ${e.message}`);
    process.exitCode = 1;
  }
}
