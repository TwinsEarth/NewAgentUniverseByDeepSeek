/**
 * The version must be READ, never restated.
 *
 * Upstream v2.5.6 restated it in `js/index.js`, `js/package.json`,
 * `js/package-lock.json` (twice), `js/lib/aca.js`, `js/lib/mcp.js` and
 * `js/test/test.js`, and four other files had already drifted to `2.3.6` /
 * `v2.3.4`. These tests make that impossible to repeat by accident.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';

import { test, suite, eq, ok } from './harness.js';
import { REPO_ROOT, SDK_ROOT, sdkFiles } from './helpers.js';
import { VERSION, VERSION_FILE, REPO_ROOT as SDK_REPO_ROOT, VERSION_IS_FALLBACK, FALLBACK_VERSION, findVersionFile } from '../index.js';

/**
 * Remove comments and string literals, so a scan only sees real values.
 *
 * @param {string} text
 * @returns {string}
 */
function stripCommentsAndStrings(text) {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const two = text.slice(i, i + 2);
    if (two === '//') {
      const end = text.indexOf('\n', i);
      i = end === -1 ? text.length : end;
    } else if (two === '/*') {
      const end = text.indexOf('*/', i + 2);
      i = end === -1 ? text.length : end + 2;
    } else if (text[i] === '"' || text[i] === "'" || text[i] === '`') {
      const quote = text[i];
      i += 1;
      while (i < text.length && text[i] !== quote) {
        if (text[i] === '\\') i += 1;
        i += 1;
      }
      i += 1;
      out += '""';
    } else {
      out += text[i];
      i += 1;
    }
  }
  return out;
}

suite('version: read from the repository VERSION file', () => {  test('VERSION equals the contents of <repo>/VERSION', () => {
    const text = readFileSync(path.join(REPO_ROOT, 'VERSION'), 'utf8').trim();
    eq(VERSION, text);
    // Deliberately NOT `eq(VERSION, '1.0.1')`: pinning the literal here would make
    // this test fail on the next version bump for no reason, which is the same
    // "restate the version" mistake the SDK itself avoids. Assert the shape and
    // the fallback behaviour instead.
    ok(/^\d+\.\d+\.\d+/.test(VERSION), `VERSION looks like a release: ${VERSION}`);
    eq(VERSION_IS_FALLBACK, false);
  });

  test('the file was located by walking up from lib/version.js', () => {
    eq(VERSION_FILE, path.join(REPO_ROOT, 'VERSION'));
    eq(SDK_REPO_ROOT, REPO_ROOT);
    eq(VERSION_IS_FALLBACK, false);
    eq(findVersionFile(), VERSION_FILE);
    ok(FALLBACK_VERSION !== VERSION, 'the fallback is a sentinel, not a release');
    eq(FALLBACK_VERSION, '0.0.0-unknown');
  });

  test('no shipped file restates the version', () => {
    const offenders = [];
    for (const file of sdkFiles()) {
      const rel = path.relative(SDK_ROOT, file);
      // The test tree and the prose are allowed to mention a version; the
      // shipped code and manifests are not.
      if (rel.startsWith(`test${path.sep}`) || file.endsWith('.md')) continue;
      if (rel === path.join('lib', 'version.js')) continue;
      const text = readFileSync(file, 'utf8');
      // Comments, string literals and template literals legitimately contain
      // decimal examples ('1e-3') and quoted defaults ('1.0.0'); what must not
      // appear is a version restated as a value.
      if (/\b\d+\.\d+\.\d+\b/.test(stripCommentsAndStrings(text))) offenders.push(rel);
    }
    eq(offenders.join(','), '', 'these files restate a version instead of reading VERSION');
  });

  test('package.json has no version field and no dependencies', () => {
    const pkg = JSON.parse(readFileSync(path.join(SDK_ROOT, 'package.json'), 'utf8'));
    eq(pkg.version, undefined, 'the only version is the VERSION file');
    eq(pkg.dependencies, undefined);
    eq(pkg.devDependencies, undefined);
    eq(pkg.type, 'module');
    eq(pkg.main, 'index.js');
    eq(pkg.types, 'index.d.ts');
    eq(pkg.scripts.test, 'node test/run.js');
  });

  test('lib/version.js documents the fallback', () => {
    const text = readFileSync(path.join(SDK_ROOT, 'lib', 'version.js'), 'utf8');
    ok(/FALLBACK_VERSION/.test(text));
    ok(/fallback/i.test(text));
    ok(/VERSION/.test(text));
  });
});
