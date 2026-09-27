/**
 * A ~40-line test runner. `node:test` exists, but its summary counts depend on
 * the reporter, and this suite reports an exact pass/fail count and an exact
 * exit code without parsing anything.
 */

const suites = [];
let currentSuite = null;

/**
 * Register a test in the current file's suite.
 *
 * @param {string} name
 * @param {() => void|Promise<void>} fn
 */
export function test(name, fn) {
  if (currentSuite === null) throw new Error('test() called outside a suite');
  currentSuite.tests.push({ name, fn });
}

/** Group the tests of one file. */
export function suite(name, body) {
  currentSuite = { name, tests: [] };
  suites.push(currentSuite);
  try {
    body();
  } finally {
    currentSuite = null;
  }
}

/** Deep-ish equality good enough for the assertions here. */
export function eq(actual, expected, message) {
  if (!Object.is(actual, expected)) {
    throw new Error(
      `${message ?? 'values differ'}\n  actual:   ${render(actual)}\n  expected: ${render(expected)}`,
    );
  }
}

/** @param {unknown} actual @param {unknown} expected @param {string} [message] */
export function deepEq(actual, expected, message) {
  const a = JSON.stringify(sortDeep(actual));
  const b = JSON.stringify(sortDeep(expected));
  if (a !== b) {
    throw new Error(`${message ?? 'values differ'}\n  actual:   ${a}\n  expected: ${b}`);
  }
}

/** @param {unknown} value @param {string} [message] */
export function ok(value, message) {
  if (!value) throw new Error(message ?? `expected a truthy value, got ${render(value)}`);
}

/** @param {unknown} value @param {string} [message] */
export function notOk(value, message) {
  if (value) throw new Error(message ?? `expected a falsy value, got ${render(value)}`);
}

/**
 * Assert that `fn` throws, optionally with a specific `code` and/or class name.
 *
 * @param {() => unknown} fn
 * @param {{code?: string, name?: string, match?: RegExp}} [expect]
 * @returns {Error} the thrown error
 */
export function throws(fn, expect = {}) {
  let thrown = null;
  try {
    fn();
  } catch (err) {
    thrown = err;
  }
  if (thrown === null) {
    throw new Error(`expected a throw${expect.name ? ` of ${expect.name}` : ''}, but nothing was thrown`);
  }
  if (expect.name !== undefined && thrown.name !== expect.name) {
    throw new Error(`expected a ${expect.name}, got ${thrown.name}: ${thrown.message}`);
  }
  if (expect.code !== undefined && thrown.code !== expect.code) {
    throw new Error(`expected code ${expect.code}, got ${thrown.code}: ${thrown.message}`);
  }
  if (expect.match !== undefined && !expect.match.test(String(thrown.message))) {
    throw new Error(`message ${JSON.stringify(thrown.message)} does not match ${expect.match}`);
  }
  return thrown;
}

/**
 * @param {() => Promise<unknown>} fn
 * @param {{code?: string, name?: string, match?: RegExp, status?: number}} [expect]
 * @returns {Promise<Error>}
 */
export async function rejects(fn, expect = {}) {
  let thrown = null;
  try {
    await fn();
  } catch (err) {
    thrown = err;
  }
  if (thrown === null) throw new Error('expected a rejection, but the promise resolved');
  if (expect.name !== undefined && thrown.name !== expect.name) {
    throw new Error(`expected a ${expect.name}, got ${thrown.name}: ${thrown.message}`);
  }
  if (expect.code !== undefined && thrown.code !== expect.code) {
    throw new Error(`expected code ${expect.code}, got ${thrown.code}: ${thrown.message}`);
  }
  if (expect.status !== undefined && thrown.status !== expect.status) {
    throw new Error(`expected status ${expect.status}, got ${thrown.status}: ${thrown.message}`);
  }
  if (expect.match !== undefined && !expect.match.test(String(thrown.message))) {
    throw new Error(`message ${JSON.stringify(thrown.message)} does not match ${expect.match}`);
  }
  return thrown;
}

/** @param {unknown} value @returns {string} */
function render(value) {
  if (typeof value === 'string') return JSON.stringify(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/** @param {unknown} value @returns {unknown} */
function sortDeep(value) {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = sortDeep(value[key]);
    return out;
  }
  return value;
}

/**
 * Run every registered suite.
 *
 * @returns {Promise<{passed: number, failed: number, failures: {test: string, error: Error}[]}>}
 */
export async function runAll() {
  let passed = 0;
  const failures = [];
  const t0 = Date.now();
  for (const s of suites) {
    process.stdout.write(`\n${s.name}\n`);
    for (const t of s.tests) {
      const label = `  ${t.name}`;
      try {
        // eslint-disable-next-line no-await-in-loop
        await t.fn();
        passed += 1;
        process.stdout.write(`${label} ... ok\n`);
      } catch (err) {
        failures.push({ test: `${s.name} > ${t.name}`, error: err });
        process.stdout.write(`${label} ... FAIL\n`);
        const message = err && err.stack ? err.stack : String(err);
        process.stdout.write(`${message.split('\n').map((l) => `      ${l}`).join('\n')}\n`);
      }
    }
  }
  const ms = Date.now() - t0;
  process.stdout.write(
    `\n${passed} passed, ${failures.length} failed, ${passed + failures.length} total (${ms} ms)\n`,
  );
  return { passed, failed: failures.length, failures };
}
