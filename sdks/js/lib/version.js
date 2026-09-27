/**
 * The single source of truth for the SDK version is the repository `VERSION`
 * file. This module READS that file at load time; it never restates the
 * version.
 *
 * Why: upstream v2.5.6 hard-coded the version in `js/index.js`,
 * `js/package.json`, `js/package-lock.json` (twice), `js/lib/aca.js`,
 * `js/lib/mcp.js` and `js/test/test.js`, and four more files had already
 * drifted to `2.3.6` / `v2.3.4`. A version is not a thing to copy.
 *
 * Resolution: starting at this file's own directory, walk up the directory
 * tree and use the first `VERSION` file found. That finds
 * `<repo>/VERSION`, because this file lives at `<repo>/sdks/js/lib/`.
 *
 * Fallback (documented, deliberately noisy-free): if no `VERSION` file is
 * found anywhere up to the filesystem root — i.e. this module was copied out
 * of the repository, or the package was installed as a dependency tarball
 * without the file — `FALLBACK_VERSION` below is used. It is a sentinel
 * rather than a plausible version number, so a mistake is visible instead of
 * silently reporting a stale release.
 */

import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Used only when no `VERSION` file can be found. Never a real release. */
export const FALLBACK_VERSION = '0.0.0-unknown';

/** Name of the repository file that holds the authoritative version. */
export const VERSION_FILENAME = 'VERSION';

/** Directory containing this module. */
const here = (() => {
  try {
    return path.dirname(fileURLToPath(import.meta.url));
  } catch {
    // Bundled into a CommonJS shim with no `import.meta`.
    return typeof __dirname === 'string' ? __dirname : process.cwd();
  }
})();

/**
 * Walk up from `start` looking for `VERSION`.
 *
 * @param {string} [start] directory to begin at
 * @returns {string | null} absolute path of the file, or null
 */
export function findVersionFile(start = here) {
  let dir = path.resolve(start);
  for (;;) {
    const candidate = path.join(dir, VERSION_FILENAME);
    try {
      if (existsSync(candidate) && readFileSync(candidate, 'utf8').trim().length > 0) {
        return candidate;
      }
    } catch {
      // Unreadable/permission denied: keep walking upward.
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function loadVersion() {
  const file = findVersionFile();
  if (file === null) return { version: FALLBACK_VERSION, file: null };
  try {
    const text = readFileSync(file, 'utf8').trim();
    if (text.length === 0) return { version: FALLBACK_VERSION, file: null };
    // Take the first line only; allow a trailing `v` and trailing comments.
    const first = (text.split(/\r?\n/, 1)[0] ?? '').trim();
    const cleaned = first.replace(/^v/, '').replace(/\s+#.*$/, '').trim();
    return { version: cleaned.length > 0 ? cleaned : FALLBACK_VERSION, file };
  } catch {
    return { version: FALLBACK_VERSION, file: null };
  }
}

const loaded = loadVersion();

/** The repository version, read from `VERSION` at load time. */
export const VERSION = loaded.version;

/** Absolute path of the `VERSION` file that was read (null when falling back). */
export const VERSION_FILE = loaded.file;

/** Directory that contains the `VERSION` file, i.e. the repository root. */
export const REPO_ROOT = loaded.file === null ? null : path.dirname(loaded.file);

/** True when `VERSION` could not be located. */
export const VERSION_IS_FALLBACK = loaded.file === null;

export default VERSION;
